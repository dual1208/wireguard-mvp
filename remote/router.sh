#!/bin/sh
# Sourceable native OpenWrt backend. The controller owns the host mutation lock.
# All parameters come from the validated, root-owned config.env.
router_fail() { printf 'BLOCKED: %s\n' "$*" >&2; return 1; }
router_self() {
    case "$ROLE" in villa) SELF=$V; OTHER=$C;; cave) SELF=$C; OTHER=$V;; *) return 1;; esac
}
router_section_hash() {
    # Hash private-bearing UCI only on its owner; never output its contents.
    for s in network.wgmvp network.wgmvp_peer firewall.wgmvp firewall.wgmvp_diag_in firewall.wgmvp_diag_out; do
        uci -q show "$s" || return 1
    done | sha256sum | awk '{print $1}'
}
router_install() (
    set -eu
    router_self
    [ "$(cat "$ROOT/owner")" = "$OWNER" ]
    [ ! -e "$ROOT/router.remove" ] || { router_fail 'finish project removal before reinstalling'; exit 1; }
    if [ -e "$ROOT/router.sections.sha256" ]; then
        [ "$(router_section_hash)" = "$(cat "$ROOT/router.sections.sha256")" ] || {
            router_fail 'owned UCI configuration drift'; exit 1;
        }
        return 0
    fi
    # Configuration objects cannot be adopted solely because their names match.
    for s in network.wgmvp network.wgmvp_peer firewall.wgmvp firewall.wgmvp_diag_in firewall.wgmvp_diag_out; do
        if uci -q show "$s" >/dev/null 2>&1; then router_fail "section collision $s"; exit 1; fi
    done
    [ -z "$(uci changes network)$(uci changes firewall)" ] || {
        router_fail 'uncommitted unrelated UCI changes'; exit 1;
    }
    umask 077
    mkdir -p "$ROOT/backups"
    cp -p /etc/config/network "$ROOT/backups/network.before-project"
    cp -p /etc/config/firewall "$ROOT/backups/firewall.before-project"
    chmod 600 "$ROOT/backups/network.before-project" "$ROOT/backups/firewall.before-project"
    # printf is a shell builtin: private key is stdin data, never process argv.
    {
        cat "$ROOT/router-config.batch"
        printf "set network.wgmvp.private_key='%s'\n" "$(cat "$ROOT/private.key")"
        printf "set network.wgmvp_peer.public_key='%s'\n" "$(cat "$ROOT/public.gz")"
    } | uci batch
    uci commit network
    uci commit firewall
    chmod 600 /etc/config/network
    router_section_hash > "$ROOT/router.sections.sha256"
)
router_check() {
    router_self || return 1
    [ "$ROOT" = /etc/wgmvp ] && [ "$IFACE" = wgmvp ] && [ "$OWNER" = wgmvp-r1 ] || return 1
    [ "$(cat "$ROOT/owner" 2>/dev/null)" = "$OWNER" ] || { router_fail 'owner mismatch'; return 1; }
    [ "$(uci -q get network.wgmvp.wgmvp_owner)" = "$OWNER" ] || { router_fail 'network section is not owned'; return 1; }
    [ "$(uci -q get firewall.wgmvp.wgmvp_owner)" = "$OWNER" ] || { router_fail 'zone is not owned'; return 1; }
}
router_guard() {
    router_check || return 1
    if nft list table inet wgmvp_guard >/dev/null 2>&1; then
        nft list table inet wgmvp_guard | grep -Fq "comment \"$OWNER\"" || return 1
        [ -f "$ROOT/router.guard.canonical" ] || return 1
        nft -s list table inet wgmvp_guard | cmp -s - "$ROOT/router.guard.canonical"
        return $?
    fi
    nft -f "$ROOT/router-guard.nft" || return 1
    nft -s list table inet wgmvp_guard > "$ROOT/router.guard.canonical" || return 1
}
router_routes() {
    # netifd owns live remote /32 routes. This backend owns only the persistent
    # less-specific drop and three narrowly scoped policy rules.
    if [ ! -f "$ROOT/routes.owned" ]; then
        [ -z "$(ip -4 route show exact "$POOL")" ] || return 1
        [ -z "$(ip -4 rule show | awk '$1=="1000:" || $1=="1001:" || $1=="1002:"')" ] || return 1
        printf '%s\n' "$OWNER" > "$ROOT/routes.owned"
    fi
    [ "$(cat "$ROOT/routes.owned")" = "$OWNER" ] || return 1
    ip -4 route show exact "$POOL" | grep -Fq "blackhole $POOL" || {
        [ -z "$(ip -4 route show exact "$POOL")" ] || return 1
        ip -4 route add blackhole "$POOL" metric 32760 proto 186 || return 1
    }
    for pref in 1000 1001 1002; do
        current=$(ip -4 rule show | awk -v p="$pref:" '$1==p')
        [ -z "$current" ] || case "$pref:$current" in
            "1000:"*"to $POOL lookup local"*) continue;;
            "1001:"*"to $POOL lookup main"*) continue;;
            "1002:"*"to $ENDPOINT"*"fwmark 0x77203"*"lookup main"*) continue;;
            *) router_fail "rule priority $pref occupied"; return 1;;
        esac
        case "$pref" in
            1000) ip -4 rule add pref 1000 to "$POOL" lookup local;;
            1001) ip -4 rule add pref 1001 to "$POOL" lookup main;;
            1002) ip -4 rule add pref 1002 to "$ENDPOINT/32" fwmark 0x77203 lookup main;;
        esac || return 1
    done
}
router_start() (
    set -eu
    # netifd reads protocol handlers at daemon startup. Installing the package
    # does not teach an already-running daemon the new protocol; config reload
    # alone cannot fix that. Never restart unrelated networking implicitly.
    handlers=$(ubus call network get_proto_handlers) || exit 1
    handler=$(printf '%s\n' "$handlers" | jsonfilter -e '@.wireguard') || exit 1
    [ -n "$handler" ] || {
        router_fail 'running netifd has no WireGuard handler; a separately authorized network-service restart is required'
        exit 1
    }
    router_install
    router_check
    # No interface can be started by boot/netifd before controller guard ordering.
    [ "$(uci -q get network.wgmvp.auto)" = 0 ]
    router_guard
    router_routes
    fw4 check >/dev/null
    if ! nft list chain inet fw4 input_wgmvp >/dev/null 2>&1; then fw4 reload >/dev/null; fi
    nft list chain inet fw4 input_wgmvp >/dev/null
    if ip link show dev "$IFACE" >/dev/null 2>&1; then
        [ "$(cat /sys/class/net/wgmvp/ifalias)" = "$OWNER" ] || router_fail 'unowned live interface'
        ip link show dev "$IFACE" | grep -q '<[^>]*UP'
        [ "$(wg show "$IFACE" public-key)" = "$(cat "$ROOT/public.$ROLE")" ]
        [ "$(wg show "$IFACE" peers)" = "$(cat "$ROOT/public.gz")" ]
        [ "$(wg show "$IFACE" allowed-ips | cut -f2- | tr ', ' '\n\n' | sed '/^$/d' | sort)" = "$(printf '%s/32\n' "$G" "$OTHER" | sort)" ]
        ip -4 route get "$OTHER" from "$SELF" | grep -q 'dev wgmvp'
        return 0
    fi
    router_section_hash > "$ROOT/interface.start.pending"
    ifup "$IFACE"
    count=0
    until ip link show dev "$IFACE" >/dev/null 2>&1; do
        count=$((count+1)); [ "$count" -le 15 ] || { ifdown "$IFACE"; return 1; }
        sleep 1
    done
    ip link set dev "$IFACE" alias "$OWNER"
    # Only this new device gets IPv6 disabled; no global IPv6 changes.
    sysctl -qw net.ipv6.conf.wgmvp.disable_ipv6=1
    count=0
    until [ "$(wg show "$IFACE" public-key)" = "$(cat "$ROOT/public.$ROLE")" ] &&
        ip -4 route get "$OTHER" from "$SELF" 2>/dev/null | grep -q 'dev wgmvp'; do
        count=$((count+1)); [ "$count" -le 15 ] || { ifdown "$IFACE"; return 1; }; sleep 1
    done
    rm -f "$ROOT/interface.start.pending"
    wg show "$IFACE" public-key
)
router_stop() (
    set -eu
    # Partial install failure can leave no sections/interface. Do not demand
    # complete configuration before quiescing a known-owned project interface.
    [ "$(cat "$ROOT/owner")" = "$OWNER" ]
    if ip link show dev "$IFACE" >/dev/null 2>&1; then
        alias=$(cat /sys/class/net/wgmvp/ifalias)
        if [ "$alias" != "$OWNER" ]; then
            [ -z "$alias" ] && [ -f "$ROOT/interface.start.pending" ] &&
                [ "$(router_section_hash)" = "$(cat "$ROOT/interface.start.pending")" ] &&
                [ "$(wg show "$IFACE" public-key)" = "$(cat "$ROOT/public.$ROLE")" ] || {
                router_fail 'refusing to delete unowned interface'; exit 1;
            }
        fi
        ifdown "$IFACE"
        # The interface belongs to netifd. It removes its own host routes.
        count=0
        while ip link show dev "$IFACE" >/dev/null 2>&1; do
            count=$((count+1)); [ "$count" -le 10 ] || return 1; sleep 1
        done
    fi
    # Keep drop routes and guards in place while the project is stopped.
)
_router_remove_scope() { printf '%s\n' "$OWNER" "$ROLE" "$IFACE" "$POOL" "$ENDPOINT"; }
_router_remove_hash() (
    # Capture first so a failed UCI read cannot become a successful empty hash.
    data=$(uci -q show "$1") || exit 1
    printf '%s\n' "$data" | sha256sum | awk '{print $1}'
)
_router_remove_changes() {
    changes=$(uci changes "$1") || return 1
    # A killed delete/commit may leave only these exact project deletions staged.
    printf '%s\n' "$changes" | awk -v package="$1" '
        NF && !(package=="network" && ($0=="-network.wgmvp" || $0=="-network.wgmvp_peer")) &&
              !(package=="firewall" && ($0=="-firewall.wgmvp" || $0=="-firewall.wgmvp_diag_in" || $0=="-firewall.wgmvp_diag_out")) {bad=1}
        END {exit bad}' || { router_fail 'unrelated staged UCI changes block removal'; return 1; }
}
_router_remove_section() {
    # A missing section is meaningful only after its containing package was read.
    uci -q show "${1%%.*}" >/dev/null || return 1
    if uci -q get "$1" >/dev/null 2>&1; then
        [ "$2" != absent ] || { router_fail "section reappeared after removal: $1"; return 1; }
        [ "$(uci -q get "$1.wgmvp_owner")" = "$OWNER" ] &&
            [ "$(_router_remove_hash "$1")" = "$(cat "$remove_state/$1.sha256")" ] || {
            router_fail "surviving UCI section changed: $1"; return 1;
        }
        [ "$2" != delete ] || uci -q delete "$1" || return 1
    fi
}
_router_remove_rule() {
    rules=$(ip -4 rule show) || return 1
    current=$(printf '%s\n' "$rules" | awk -v p="$1:" '$1==p {$1=$1; print}')
    [ -n "$current" ] || return 0
    [ "$2" != absent ] || { router_fail "rule priority $1 reappeared after removal"; return 1; }
    case "$1" in
        1000) expected="1000: from all to $POOL lookup local";;
        1001) expected="1001: from all to $POOL lookup main";;
        1002) expected="1002: from all to $ENDPOINT fwmark 0x77203 lookup main"
              current=$(printf '%s\n' "$current" | sed 's@/32 @ @g');;
        *) return 1;;
    esac
    [ "$current" = "$expected" ] || { router_fail "foreign rule at priority $1"; return 1; }
    [ "$2" = delete ] || return 0
    case "$1" in
        1000) ip -4 rule del pref 1000 to "$POOL" lookup local;;
        1001) ip -4 rule del pref 1001 to "$POOL" lookup main;;
        1002) ip -4 rule del pref 1002 to "$ENDPOINT/32" fwmark 0x77203 lookup main;;
    esac
}
_router_remove_route() {
    current=$(ip -4 route show exact "$POOL") || return 1
    current=$(printf '%s\n' "$current" | awk 'NF {$1=$1; print}')
    [ -n "$current" ] || return 0
    [ "$1" != absent ] && [ "$current" = "blackhole $POOL proto 186 metric 32760" ] || {
        router_fail 'pool route is foreign or reappeared after removal'; return 1;
    }
    [ "$1" != delete ] || ip -4 route del blackhole "$POOL" metric 32760 proto 186
}
_router_remove_guard() {
    nft list tables >/dev/null || return 1
    if nft list table inet wgmvp_guard >/dev/null 2>&1; then
        [ "$1" != absent ] || { router_fail 'guard reappeared after removal'; return 1; }
        nft -s list table inet wgmvp_guard | cmp -s - "$remove_state/guard.canonical" || {
            router_fail 'guard changed during removal'; return 1;
        }
        [ "$1" != delete ] || nft delete table inet wgmvp_guard || return 1
    fi
}
router_remove() (
    set -eu
    umask 077
    router_self
    [ "$(cat "$ROOT/owner")" = "$OWNER" ]
    remove_state=$ROOT/router.remove
    sections='network.wgmvp_peer network.wgmvp firewall.wgmvp_diag_in firewall.wgmvp_diag_out firewall.wgmvp'
    if [ ! -e "$remove_state" ]; then
        router_stop
        router_check
        [ -z "$(uci changes network)$(uci changes firewall)" ] || {
            router_fail 'uncommitted UCI changes before removal'; exit 1;
        }
        [ "$(router_section_hash)" = "$(cat "$ROOT/router.sections.sha256")" ] &&
            [ "$(cat "$ROOT/routes.owned")" = "$OWNER" ] || {
            router_fail 'owned configuration drift blocks removal'; exit 1;
        }
        # Publish complete original identities before the first configuration delete.
        remove_stage=$(mktemp -d "$ROOT/.router.remove.XXXXXX")
        _router_remove_scope > "$remove_stage/scope"
        for s in $sections; do
            [ "$(uci -q get "$s.wgmvp_owner")" = "$OWNER" ] || exit 1
            _router_remove_hash "$s" > "$remove_stage/$s.sha256" || exit 1
        done
        cp "$ROOT/router.guard.canonical" "$remove_stage/guard.canonical"
        [ ! -e "$remove_state" ] && mv "$remove_stage" "$remove_state"
    fi
    [ -d "$remove_state" ] && [ ! -L "$remove_state" ] || exit 1
    _router_remove_scope | cmp -s - "$remove_state/scope" || { router_fail 'removal ownership/scope changed'; exit 1; }
    for s in $sections; do
        [ -f "$remove_state/$s.sha256" ] && [ ! -L "$remove_state/$s.sha256" ] || exit 1
        awk 'NR!=1 || length($0)!=64 || $0 !~ /^[0-9a-f]+$/ {bad=1} END {exit (bad || NR!=1)}' "$remove_state/$s.sha256" || exit 1
    done
    [ -f "$remove_state/guard.canonical" ] && [ ! -L "$remove_state/guard.canonical" ] || exit 1
    mode=check
    [ ! -f "$remove_state/complete" ] || mode=absent
    for s in $sections; do _router_remove_section "$s" "$mode"; done
    for pref in 1000 1001 1002; do _router_remove_rule "$pref" "$mode"; done
    _router_remove_route "$mode"
    _router_remove_guard "$mode"
    _router_remove_changes network
    _router_remove_changes firewall
    if [ "$mode" = absent ]; then
        [ -z "$(uci changes network)$(uci changes firewall)" ] || {
            router_fail 'new UCI changes appeared after completed removal'; exit 1;
        }
        ip link show >/dev/null
        if ip link show dev "$IFACE" >/dev/null 2>&1; then router_fail 'interface reappeared after removal'; exit 1; fi
        printf 'router: already removed\n'
        exit 0
    fi
    router_stop
    for s in $sections; do _router_remove_section "$s" delete; done
    for package in network firewall; do
        _router_remove_changes "$package"
        uci commit "$package"
    done
    fw4 check >/dev/null && fw4 reload >/dev/null
    for pref in 1000 1001 1002; do _router_remove_rule "$pref" delete; done
    _router_remove_route delete
    # The guard remains until the owned interface, routes and configuration are gone.
    _router_remove_guard delete
    rm -f "$ROOT/router.sections.sha256" "$ROOT/router.guard.canonical" "$ROOT/routes.owned" "$ROOT/interface.start.pending"
    : > "$remove_state/complete"
    printf 'router: owned objects removed; removal record retained\n'
)
router_status() {
    router_check || return 1
    ip -4 route show exact "$POOL"
    ip -4 rule show
    nft list table inet wgmvp_guard
    if ip link show dev "$IFACE" >/dev/null 2>&1; then
        ip -4 address show dev "$IFACE"
        for field in public-key listen-port peers endpoints allowed-ips latest-handshakes transfer persistent-keepalive; do
            wg show "$IFACE" "$field" || return 1
        done
    fi
}
