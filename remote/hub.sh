#!/bin/sh
# Source this file; the controller supplies configuration, a per-host lock,
# an armed persistent rollback lease, and reviewed host/recovery fingerprints.
# No command is executed merely by sourcing this file. Do not enable xtrace.

_hub_error() { printf 'hub: %s\n' "$*" >&2; return 1; }

_hub_config() {
    case $- in *x*) set +x; _hub_error 'xtrace is forbidden'; return 1;; esac
    : "${ROOT:=/etc/wgmvp}" "${IFACE:=wgmvp}" "${NS:=wgmvp}"
    : "${POOL:=10.203.77.0/29}" "${G:=10.203.77.1}"
    : "${V:=10.203.77.2}" "${C:=10.203.77.3}"
    : "${PORT:=51820}" "${MTU:=1380}" "${OWNER:=wgmvp-r1}"
    case "$ROOT" in /*) ;; *) _hub_error 'ROOT must be absolute'; return 1;; esac
    case "$ROOT" in *[!a-zA-Z0-9_./-]*|*/../*|*/..|*/./*|*/.|*/) _hub_error 'unsafe ROOT'; return 1;; esac
    # Stable names deliberately limit the scope of this MVP implementation.
    [ "$IFACE" = wgmvp ] && [ "$NS" = wgmvp ] || {
        _hub_error 'this implementation requires IFACE=NS=wgmvp'; return 1;
    }
    case "$OWNER" in ''|*[!a-zA-Z0-9_-]*) _hub_error 'invalid owner'; return 1;; esac
    [ "${#OWNER}" -le 48 ] || return 1
    for _hub_ip in "$G" "$V" "$C"; do
        printf '%s\n' "$_hub_ip" | awk -F. '
            NF != 4 {exit 1}
            {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i > 255 ||
                (length($i)>1 && substr($i,1,1)=="0")) exit 1}' || {
            _hub_error 'invalid IPv4 address'; return 1;
        }
    done
    # A changed addressing plan requires another implementation review.
    [ "$POOL" = 10.203.77.0/29 ] && [ "$G" = 10.203.77.1 ] &&
        [ "$V" = 10.203.77.2 ] && [ "$C" = 10.203.77.3 ] || {
        _hub_error 'unexpected MVP address plan'; return 1;
    }
    case "$PORT:$MTU" in *[!0-9:]*|:*|*:) _hub_error 'invalid port or MTU'; return 1;; esac
    [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] &&
        [ "$MTU" -ge 1280 ] && [ "$MTU" -le 1420 ] || {
        _hub_error 'port or MTU outside reviewed bounds'; return 1;
    }
    _hub_state=$ROOT/hub
}

_hub_require_root() {
    [ "$(id -u)" = 0 ] || { _hub_error 'root required'; return 1; }
    for _hub_cmd in ip nft wg sysctl stat awk sort cmp ss readlink realpath; do
        command -v "$_hub_cmd" >/dev/null 2>&1 || {
            _hub_error "required tool absent: $_hub_cmd"; return 1;
        }
    done
    [ -d "$ROOT" ] && [ ! -L "$ROOT" ] &&
        [ "$(realpath -e "$ROOT")" = "$ROOT" ] &&
        [ "$(stat -c '%u:%a' "$ROOT")" = 0:700 ] || {
        _hub_error 'ROOT must be a canonical, root-owned 0700 directory'; return 1;
    }
}

_hub_config_record() {
    printf '%s\n' "$OWNER" "$IFACE" "$NS" "$POOL" "$G" "$V" "$C" "$PORT" "$MTU"
}

_hub_file_safe() {
    [ -f "$1" ] && [ ! -L "$1" ] &&
        [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ] || {
        _hub_error "unsafe or missing state file: $1"; return 1;
    }
}

_hub_load_state() {
    [ -d "$_hub_state" ] && [ ! -L "$_hub_state" ] &&
        [ "$(stat -c '%u:%a' "$_hub_state")" = 0:700 ] || {
        _hub_error 'unsafe or missing hub state directory'; return 1;
    }
    _hub_file_safe "$_hub_state/config" && _hub_file_safe "$_hub_state/owner-token" &&
        _hub_file_safe "$_hub_state/boot-id" || return 1
    _hub_config_record | cmp -s - "$_hub_state/config" || {
        _hub_error 'configuration differs from recorded owner'; return 1;
    }
    _hub_token=$(cat "$_hub_state/owner-token") || return 1
    case "$_hub_token" in ''|*[!a-f0-9-]*) _hub_error 'invalid owner token'; return 1;; esac
    [ "${#_hub_token}" = 36 ] || return 1
    _hub_mark=$OWNER:$_hub_token
}

_hub_ns_exists() {
    ip netns list | awk -v n="$NS" '$1==n {found=1} END {exit !found}'
}

_hub_table_exists() { nft list table inet wgmvp_outer >/dev/null 2>&1; }

_hub_assert_namespace() {
    _hub_file_safe "$_hub_state/namespace.identity" || return 1
    [ "$(stat -Lc '%d:%i' "/run/netns/$NS")" = "$(cat "$_hub_state/namespace.identity")" ] || {
        _hub_error 'namespace identity changed'; return 1;
    }
}

_hub_assert_table() {
    # nft prints a table's comment before its chains. Never match a rule comment.
    awk -v expected="$_hub_mark" 'NR==2 {
        line=$0; sub(/^[ \t]+/, "", line)
        valid=(line == "comment \"" expected "\"")
    } END {exit !valid}' || { _hub_error 'nft table ownership mismatch'; return 1; }
}

_hub_assert_link() {
    # Moving namespaces may clear the creation alias; it is restored before UP.
    printf '%s\n' "$1" | awk -v expected="$_hub_mark" '
        {for(i=1;i<NF;i++) if($i=="alias" && $(i+1)==expected) valid=1}
        END {exit !valid}' || { _hub_error 'interface ownership mismatch'; return 1; }
    if [ -e "$_hub_state/interface.ifindex" ]; then
        _hub_file_safe "$_hub_state/interface.ifindex" || return 1
        [ "$(printf '%s\n' "$1" | awk -F: 'NR==1 {print $1}')" = \
            "$(cat "$_hub_state/interface.ifindex")" ] || {
            _hub_error 'interface identity changed'; return 1;
        }
    fi
}

_hub_assert_moving_link() {
    # The sole missing-alias exception is an unfinished, journaled transfer of
    # our still-DOWN, owner-keyed interface into the exact namespace we created.
    # Normal running state and an object with a foreign alias never qualify.
    [ ! -e "$_hub_state/ready" ] || return 1
    _hub_file_safe "$_hub_state/move.pending" && _hub_assert_namespace &&
        _hub_file_safe "$ROOT/public.gz" || return 1
    _hub_move_boot=$(cat "$_hub_state/boot-id") || return 1
    [ "$_hub_move_boot" = "$(cat /proc/sys/kernel/random/boot_id)" ] || return 1
    _hub_move_public=$(cat "$ROOT/public.gz") || return 1
    [ "$(cat "$_hub_state/move.pending")" = "$(printf '%s\n' "$_hub_mark" "$_hub_move_boot" \
        "$(cat "$_hub_state/namespace.identity")" "$_hub_move_public")" ] || return 1
    printf '%s\n' "$1" | awk -v mark="$_hub_mark" '
        /<([^>]*,)?UP(,|>)/ {bad=1}
        /(^|[[:space:]])wireguard([[:space:]]|$)/ {wg=1}
        {for(i=1;i<NF;i++) if($i=="alias" && $(i+1)!=mark) bad=1}
        END {exit (bad || !wg)}' || return 1
    if [ -e "$_hub_state/interface.ifindex" ]; then
        _hub_file_safe "$_hub_state/interface.ifindex" || return 1
        [ "$(printf '%s\n' "$1" | awk -F: 'NR==1 {print $1}')" = "$(cat "$_hub_state/interface.ifindex")" ] || return 1
    fi
    _hub_move_host_links=$(ip -o link show) || return 1
    printf '%s\n' "$_hub_move_host_links" | awk -F': ' -v dev="$IFACE" '
        {name=$2; sub(/@.*/, "", name); if(name==dev) bad=1} END {exit bad}' || return 1
    _hub_move_links=$(ip -n "$NS" -o link show) || return 1
    printf '%s\n' "$_hub_move_links" | awk -F': ' -v dev="$IFACE" '
        NF {name=$2; sub(/@.*/, "", name); count++; if(name!="lo" && name!=dev) bad=1}
        END {exit (bad || count!=2)}' || return 1
    _hub_move_addresses=$(ip -n "$NS" -o address show dev "$IFACE") || return 1
    [ -z "$_hub_move_addresses" ] || return 1
    [ "$(ip netns exec "$NS" wg show "$IFACE" public-key)" = "$_hub_move_public" ] || return 1
}

_hub_outer_policy() {
    cat <<EOF
table inet wgmvp_outer {
    comment "$_hub_mark"
    chain input {
        type filter hook input priority -10; policy accept;
        meta nfproto ipv6 udp dport $PORT counter drop comment "wgmvp IPv6 listener denied"
        meta nfproto ipv4 udp dport $PORT counter accept comment "wgmvp authenticated transport"
    }
}
EOF
}

_hub_inner_policy() {
    cat <<EOF
table inet wgmvp {
    comment "$_hub_mark"
    chain bench_input { }
    chain bench_output { }
    chain bench_forward { }
    chain input {
        type filter hook input priority 0; policy drop;
        iifname "$IFACE" ip saddr { $V, $C } ip daddr $G icmp type { echo-request, echo-reply } counter accept
        iifname "$IFACE" ip saddr { $V, $C } ip daddr $G icmp type { destination-unreachable, time-exceeded, parameter-problem } ct state related counter accept
        jump bench_input
        counter drop comment "wgmvp input denied"
    }
    chain output {
        type filter hook output priority 0; policy drop;
        oifname "$IFACE" ip saddr $G ip daddr { $V, $C } icmp type { echo-request, echo-reply } counter accept
        oifname "$IFACE" ip saddr $G ip daddr { $V, $C } icmp type { destination-unreachable, time-exceeded, parameter-problem } ct state related counter accept
        jump bench_output
        counter drop comment "wgmvp output denied"
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        iifname "$IFACE" oifname "$IFACE" ip saddr $V ip daddr $C icmp type { echo-request, echo-reply } counter accept
        iifname "$IFACE" oifname "$IFACE" ip saddr $C ip daddr $V icmp type { echo-request, echo-reply } counter accept
        jump bench_forward
        counter drop comment "wgmvp forward denied"
    }
}
EOF
}

_hub_read_public_keys() {
    for _hub_peer in gz villa cave; do
        _hub_file_safe "$ROOT/public.$_hub_peer" || return 1
        awk 'NR!=1 || length($0)!=44 || substr($0,44)!="=" ||
            substr($0,1,43) !~ /^[A-Za-z0-9+\/]+$/ {bad=1}
            END {exit (bad || NR!=1)}' "$ROOT/public.$_hub_peer" || {
            _hub_error 'invalid public key file'; return 1;
        }
    done
    _hub_gpub=$(cat "$ROOT/public.gz") || return 1
    _hub_vpub=$(cat "$ROOT/public.villa") || return 1
    _hub_cpub=$(cat "$ROOT/public.cave") || return 1
    [ "$_hub_gpub" != "$_hub_vpub" ] && [ "$_hub_gpub" != "$_hub_cpub" ] &&
        [ "$_hub_vpub" != "$_hub_cpub" ] || { _hub_error 'peer keys must differ'; return 1; }
}

_hub_inventory_available() {
    # A failed discovery command must not mean "no conflicting object".
    ip netns list >/dev/null && ip link show >/dev/null && nft list tables >/dev/null || return 1
}

_hub_validate_running() {
    _hub_assert_namespace && _hub_read_public_keys || return 1
    _hub_link=$(ip -n "$NS" -d -o link show dev "$IFACE") || return 1
    _hub_assert_link "$_hub_link" || return 1
    printf '%s\n' "$_hub_link" | awk -v m="$MTU" '
        /<[^>]*UP[,>]/ {up=1}
        {for(i=1;i<NF;i++) if($i=="mtu" && $(i+1)==m) mtu=1}
        END {exit !(up && mtu)}' || { _hub_error 'interface is down or MTU changed'; return 1; }
    ip -n "$NS" -o link show | awk -F': ' -v dev="$IFACE" '
        {name=$2; sub(/@.*/, "", name); if(name!="lo" && name!=dev) bad=1; count++}
        END {exit (bad || count!=2)}' || { _hub_error 'unexpected namespace interface'; return 1; }
    [ "$(ip netns exec "$NS" wg show "$IFACE" public-key)" = "$_hub_gpub" ] &&
        [ "$(ip netns exec "$NS" wg show "$IFACE" listen-port)" = "$PORT" ] || {
        _hub_error 'WireGuard local configuration changed'; return 1;
    }
    _hub_actual=$(ip netns exec "$NS" wg show "$IFACE" allowed-ips | sort) || return 1
    _hub_expected=$(printf '%s\t%s/32\n%s\t%s/32\n' "$_hub_vpub" "$V" "$_hub_cpub" "$C" | sort)
    [ "$_hub_actual" = "$_hub_expected" ] || { _hub_error 'peer source prefixes changed'; return 1; }
    for _hub_scope in outer inner; do
        _hub_file_safe "$_hub_state/$_hub_scope.observed" || return 1
    done
    nft -s list table inet wgmvp_outer | cmp -s - "$_hub_state/outer.observed" || {
        _hub_error 'host shim differs from recorded policy'; return 1;
    }
    ip netns exec "$NS" nft -s list ruleset | cmp -s - "$_hub_state/inner.observed" || {
        _hub_error 'namespace firewall differs from permanent policy'; return 1;
    }
    for _hub_family in 4 6; do
        _hub_file_safe "$_hub_state/routes$_hub_family.observed" || return 1
        ip -n "$NS" -"$_hub_family" route show table all | cmp -s - "$_hub_state/routes$_hub_family.observed" || {
            _hub_error 'namespace routes changed'; return 1;
        }
        _hub_file_safe "$_hub_state/rules$_hub_family.observed" || return 1
        ip -n "$NS" -"$_hub_family" rule show | cmp -s - "$_hub_state/rules$_hub_family.observed" || {
            _hub_error 'namespace policy routing changed'; return 1;
        }
    done
    for _hub_setting in net.ipv4.ip_forward=1 \
        net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 \
        net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 \
        net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.default.secure_redirects=0 \
        net.ipv6.conf.all.forwarding=0 net.ipv6.conf.all.accept_ra=0 \
        net.ipv6.conf.default.accept_ra=0 \
        net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1; do
        [ "$(ip netns exec "$NS" sysctl -n "${_hub_setting%=*}")" = "${_hub_setting#*=}" ] || {
            _hub_error 'namespace forwarding or protocol guards changed'; return 1;
        }
    done
}

_hub_start_abort() {
    _hub_exit=$1
    trap - 0 HUP INT TERM
    if [ "$_hub_complete" != yes ]; then
        printf 'hub: incomplete start; invoking owned-object teardown\n' >&2
        hub_stop >&2 || printf 'hub: teardown incomplete; preserve lease and inspect owned state\n' >&2
    fi
    exit "$_hub_exit"
}

hub_start() (
    umask 077
    _hub_config && _hub_require_root && _hub_inventory_available || exit 1
    if [ -e "$_hub_state" ]; then
        _hub_load_state || exit 1
        if [ -f "$_hub_state/ready" ]; then
            if [ "$(cat "$_hub_state/boot-id")" != "$(cat /proc/sys/kernel/random/boot_id)" ]; then
                # The controller must reconcile its persistent pending lease first.
                # A committed service can then rebuild ephemeral state after boot.
                if _hub_ns_exists || ip link show dev "$IFACE" >/dev/null 2>&1 || _hub_table_exists; then
                    _hub_error 'objects unexpectedly exist after boot; reconcile before startup'; exit 1
                fi
                hub_stop && hub_start
                exit "$?"
            fi
            _hub_validate_running || exit 1
            printf 'hub: already running with verified permanent policy\n'
            exit 0
        fi
        _hub_error 'incomplete prior start; run owned rollback before reapplying'; exit 1
    fi
    if _hub_ns_exists || ip link show dev "$IFACE" >/dev/null 2>&1 || _hub_table_exists; then
        _hub_error 'unowned project name is already present'; exit 1
    fi
    _hub_sockets=$(ss -H -lun) || exit 1
    if printf '%s\n' "$_hub_sockets" | awk -v p="$PORT" '$4 ~ ":" p "$" {found=1} END {exit !found}'; then
        _hub_error 'selected outer UDP port is already bound'; exit 1
    fi
    _hub_read_public_keys && _hub_file_safe "$ROOT/private.key" || exit 1
    [ "$(wg pubkey < "$ROOT/private.key")" = "$_hub_gpub" ] || {
        _hub_error 'local private key does not match local public key'; exit 1;
    }
    printf 'hub: plan: new isolated namespace, two peer host routes, ICMP-only forwarding, IPv4 UDP shim\n'
    mkdir -m 700 "$_hub_state" || exit 1
    _hub_config_record > "$_hub_state/config" || exit 1
    cat /proc/sys/kernel/random/uuid > "$_hub_state/owner-token" || exit 1
    cat /proc/sys/kernel/random/boot_id > "$_hub_state/boot-id" || exit 1
    _hub_load_state || exit 1
    _hub_complete=no
    trap '_hub_start_abort "$?"' 0
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    _hub_outer_policy > "$_hub_state/outer.nft" || exit 1
    _hub_inner_policy > "$_hub_state/inner.nft" || exit 1
    nft -c -f "$_hub_state/outer.nft" || exit 1
    ip netns add "$NS" || exit 1
    stat -Lc '%d:%i' "/run/netns/$NS" > "$_hub_state/namespace.identity" || exit 1
    ip netns exec "$NS" nft -c -f "$_hub_state/inner.nft" || exit 1
    ip netns exec "$NS" nft -f "$_hub_state/inner.nft" || exit 1
    ip netns exec "$NS" sysctl -qw \
        net.ipv4.ip_forward=1 \
        net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 \
        net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 \
        net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.default.secure_redirects=0 \
        net.ipv6.conf.all.forwarding=0 net.ipv6.conf.all.accept_ra=0 \
        net.ipv6.conf.default.accept_ra=0 \
        net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 || exit 1
    ip -n "$NS" link set lo up || exit 1
    ip -n "$NS" route add blackhole "$POOL" metric 42760 || exit 1
    ip link add name "$IFACE" alias "$_hub_mark" type wireguard || exit 1
    # Keying this DOWN interface before moving gives interrupted-transfer
    # cleanup cryptographic identity even when the kernel clears its alias.
    wg set "$IFACE" private-key "$ROOT/private.key" || exit 1
    [ "$(wg show "$IFACE" public-key)" = "$_hub_gpub" ] || exit 1
    printf '%s\n' "$_hub_mark" "$(cat "$_hub_state/boot-id")" \
        "$(cat "$_hub_state/namespace.identity")" "$_hub_gpub" > "$_hub_state/move.pending" || exit 1
    # Record the index AFTER movement: the destination namespace may remap it.
    ip link set dev "$IFACE" netns "$NS" || exit 1
    _hub_link=$(ip -n "$NS" -d -o link show dev "$IFACE") || exit 1
    _hub_assert_moving_link "$_hub_link" || exit 1
    ip -n "$NS" link set dev "$IFACE" alias "$_hub_mark" || exit 1
    printf '%s\n' "$_hub_link" | awk -F: 'NR==1 {print $1}' > "$_hub_state/interface.ifindex" || exit 1
    _hub_link=$(ip -n "$NS" -d -o link show dev "$IFACE") || exit 1
    _hub_assert_link "$_hub_link" || exit 1
    rm "$_hub_state/move.pending" || exit 1
    ip -n "$NS" link set dev "$IFACE" mtu "$MTU" || exit 1
    ip netns exec "$NS" wg set "$IFACE" private-key "$ROOT/private.key" listen-port "$PORT" \
        peer "$_hub_vpub" allowed-ips "$V/32" \
        peer "$_hub_cpub" allowed-ips "$C/32" || exit 1
    ip -n "$NS" address add "$G/32" dev "$IFACE" || exit 1
    # Native route installation requires the nexthop device UP. Both namespace
    # default-drop policy and the outer IPv6 deny are installed before this.
    nft -f "$_hub_state/outer.nft" || exit 1
    ip -n "$NS" link set dev "$IFACE" up || exit 1
    ip -n "$NS" route add "$V/32" dev "$IFACE" src "$G" || exit 1
    ip -n "$NS" route add "$C/32" dev "$IFACE" src "$G" || exit 1
    nft -s list table inet wgmvp_outer > "$_hub_state/outer.observed" || exit 1
    ip netns exec "$NS" nft -s list ruleset > "$_hub_state/inner.observed" || exit 1
    for _hub_family in 4 6; do
        ip -n "$NS" -"$_hub_family" route show table all > "$_hub_state/routes$_hub_family.observed" || exit 1
        ip -n "$NS" -"$_hub_family" rule show > "$_hub_state/rules$_hub_family.observed" || exit 1
    done
    : > "$_hub_state/diagnostics" || exit 1
    _hub_validate_running || exit 1
    : > "$_hub_state/ready" || exit 1
    _hub_complete=yes
    printf 'hub: ready; no host route or host forwarding sysctl changed\n'
)

_hub_stop_diagnostics() {
    [ -e "$_hub_state/diagnostics" ] || return 0
    _hub_file_safe "$_hub_state/diagnostics" || return 1
    # Registrations are PID + /proc/PID/stat starttime (field 22), no commands.
    while read -r _hub_pid _hub_start _hub_extra; do
        [ -n "$_hub_pid" ] || continue
        case "$_hub_pid:$_hub_start" in *[!0-9:]*|:*|*:) _hub_error 'invalid diagnostic registration'; return 1;; esac
        [ -z "$_hub_extra" ] && [ "$_hub_pid" -gt 1 ] || return 1
        [ -d "/proc/$_hub_pid" ] || continue
        _hub_live_start=$(sed 's/^.*) //' "/proc/$_hub_pid/stat" | awk '{print $20}') || return 1
        [ "$_hub_live_start" = "$_hub_start" ] || continue
        [ "$(stat -Lc '%d:%i' "/proc/$_hub_pid/ns/net")" = "$(stat -Lc '%d:%i' "/run/netns/$NS")" ] || {
            _hub_error 'registered process is outside the owned namespace'; return 1;
        }
        kill -TERM "$_hub_pid" 2>/dev/null || [ ! -d "/proc/$_hub_pid" ] || return 1
    done < "$_hub_state/diagnostics"
    # Give only registered diagnostic processes a bounded exit interval.
    _hub_wait=0
    while [ "$_hub_wait" -lt 3 ]; do
        _hub_pids=$(ip netns pids "$NS") || return 1
        [ -n "$_hub_pids" ] || return 0
        sleep 1
        _hub_wait=$((_hub_wait + 1))
    done
    # Never kill an arbitrary namespace resident, even during rollback.
    _hub_error 'namespace still has processes; interface will be removed, namespace retained'
}

hub_stop() (
    umask 077
    _hub_config && _hub_require_root && _hub_inventory_available || exit 1
    if [ ! -e "$_hub_state" ]; then
        if _hub_ns_exists || ip link show dev "$IFACE" >/dev/null 2>&1 || _hub_table_exists; then
            _hub_error 'refusing to remove unowned project names'; exit 1
        fi
        printf 'hub: already absent\n'; exit 0
    fi
    _hub_load_state || exit 1
    # Validate every potentially removed object before changing any of them.
    _hub_has_ns=no
    if _hub_ns_exists; then
        _hub_assert_namespace || exit 1
        _hub_has_ns=yes
        if ip -n "$NS" link show dev "$IFACE" >/dev/null 2>&1; then
            _hub_link=$(ip -n "$NS" -d -o link show dev "$IFACE") || exit 1
            _hub_assert_link "$_hub_link" || _hub_assert_moving_link "$_hub_link" || exit 1
        fi
    fi
    if ip link show dev "$IFACE" >/dev/null 2>&1; then
        _hub_link=$(ip -d -o link show dev "$IFACE") || exit 1
        _hub_assert_link "$_hub_link" || exit 1
    fi
    if _hub_table_exists; then
        nft list table inet wgmvp_outer | _hub_assert_table || exit 1
    fi
    printf 'hub: plan: terminate registered diagnostics, remove owned interface, then namespace and UDP shim\n'
    _hub_clean=yes
    if [ "$_hub_has_ns" = yes ]; then
        _hub_stop_diagnostics || _hub_clean=no
        # A foreign link appearing later must not be destroyed with the namespace.
        _hub_links=$(ip -n "$NS" -o link show) || exit 1
        if ! printf '%s\n' "$_hub_links" | awk -F': ' -v dev="$IFACE" '
            NF {name=$2; sub(/@.*/, "", name); if(name!="lo" && name!=dev) bad=1}
            END {exit bad}'; then
            _hub_clean=no
            _hub_error 'unexpected namespace interface; retaining namespace' || :
        fi
        if ip -n "$NS" link show dev "$IFACE" >/dev/null 2>&1; then
            ip -n "$NS" link set dev "$IFACE" down || exit 1
            ip -n "$NS" link delete dev "$IFACE" || exit 1
        fi
        _hub_pids=$(ip netns pids "$NS") || exit 1
        if [ -n "$_hub_pids" ]; then
            _hub_clean=no
            _hub_error 'unknown or lingering processes retain the namespace' || :
        elif [ "$_hub_clean" = yes ]; then
            ip netns delete "$NS" || exit 1
        fi
    fi
    if ip link show dev "$IFACE" >/dev/null 2>&1; then
        ip link set dev "$IFACE" down || exit 1
        ip link delete dev "$IFACE" || exit 1
    fi
    if _hub_table_exists; then nft delete table inet wgmvp_outer || exit 1; fi
    rm -f "$_hub_state/ready" || exit 1
    [ "$_hub_clean" = yes ] || exit 1
    # Keep private keys and public identities for subsequent reapplication.
    # Delete only the enumerated state files; unknown files block rmdir.
    for _hub_file in config owner-token boot-id namespace.identity interface.ifindex move.pending \
        outer.nft inner.nft outer.observed inner.observed diagnostics \
        routes4.observed routes6.observed rules4.observed rules6.observed; do
        rm -f "$_hub_state/$_hub_file" || exit 1
    done
    rmdir "$_hub_state" || exit 1
    printf 'hub: owned network state removed; keys retained\n'
)

hub_status() (
    _hub_config && _hub_require_root && _hub_inventory_available || exit 1
    if [ ! -e "$_hub_state" ]; then
        if _hub_ns_exists || ip link show dev "$IFACE" >/dev/null 2>&1 || _hub_table_exists; then
            _hub_error 'conflicting unowned project object'; exit 1
        fi
        printf 'hub: absent\n'; exit 0
    fi
    _hub_load_state && _hub_validate_running || exit 1
    printf 'hub: namespace, peers, permanent firewall, routes and interface verified\n'
    printf 'hub: handshake age is transport evidence; end-to-end probes remain required\n'
    ip netns exec "$NS" wg show "$IFACE" latest-handshakes || exit 1
    ip netns exec "$NS" wg show "$IFACE" transfer || exit 1
)
