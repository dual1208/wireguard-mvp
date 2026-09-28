#!/bin/sh
# Finite unknown-key test on an authorized router. Keys stay on their owner.
unknown_safe_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && ls -ldn "$1" |
        awk '$1=="-rw-------" && $2==1 && $3==0 {good=1} END {exit !good}'
}
unknown_ns_exists() {
    namespaces=$(ip netns list) || return 2
    printf '%s\n' "$namespaces" | awk -v name="$nsname" '$1==name {yes=1} END {exit !yes}'
}
unknown_link_owned() {
    printf '%s\n' "$1" | awk -v mark="$mark" '
        {for(i=1;i<NF;i++) if($i=="alias" && $(i+1)==mark) owned=1}
        END {exit !owned}'
}
unknown_move_link_owned() {
    # A move can clear ifalias. Only a DOWN WireGuard link with the recorded
    # index/key may use this narrow interrupted-move recovery path.
    unknown_safe_file "$state/move.intent" && unknown_safe_file "$state/interface.ifindex" &&
        unknown_safe_file "$state/public.key" || return 1
    [ "$(cat "$state/move.intent")" = "$token" ] || return 1
    index=$(cat "$state/interface.ifindex") || return 1
    case "$index" in ''|*[!0-9]*) return 1;; esac
    printf '%s\n' "$1" | awk -v expected_index="$index" '
        NR==1 {seen=1; actual=$1; sub(/:$/, "", actual); if(actual!=expected_index) bad=1}
        /<[^>]*,?UP[,>]/ {bad=1}
        {for(i=1;i<=NF;i++) {if($i=="alias") bad=1; if($i=="wireguard") wg=1}}
        END {exit (!seen || bad || !wg)}' || return 1
    if [ "$2" = namespace ]; then
        key=$(ip netns exec "$nsname" wg show wgmvp_uk public-key) || return 1
    elif [ "$2" = host ]; then
        key=$(wg show wgmvp_uk public-key) || return 1
    else return 1; fi
    [ "$key" = "$(cat "$state/public.key")" ]
}
unknown_pristine_namespace() {
    # Only used for the creation-before-identity-record crash window. The private
    # nonce name plus durable intent establish provenance; pristine contents
    # establish that no subsequent setup or unrelated work has been adopted.
    unknown_safe_file "$state/creation.intent" &&
        [ "$(cat "$state/creation.intent")" = "$token" ] || return 1
    [ "$(cat "$state/boot")" = "$(cat /proc/sys/kernel/random/boot_id)" ] || return 1
    pids=$(ip netns pids "$nsname") || return 1
    [ -z "$pids" ] || return 1
    links=$(ip -n "$nsname" -o link show) || return 1
    printf '%s\n' "$links" | awk -F': ' '
        {count++; if($2!="lo" || $0 ~ /<[^>]*,?UP[,>]/) bad=1}
        END {exit (count!=1 || bad)}' || return 1
    addresses=$(ip -n "$nsname" -o address show) || return 1
    [ -z "$addresses" ] || return 1
    routes=$(ip -n "$nsname" -4 route show table all) || return 1
    [ -z "$routes" ] || return 1
    routes=$(ip -n "$nsname" -6 route show table all) || return 1
    [ -z "$routes" ] || return 1
    tables=$(ip netns exec "$nsname" nft list tables) || return 1
    [ -z "$tables" ]
}
unknown_cleanup_locked() (
    set -eu
    state=$ROOT/unknown-key
    [ -d "$state" ] || exit 0
    case "$ROLE" in villa|cave) ;; *) exit 1;; esac
    [ ! -L "$state" ] || exit 1
    ls -ldn "$state" | awk '$1=="drwx------" && $3==0 {good=1} END {exit !good}' || exit 1
    for file in owner token boot namespace.name creation.intent; do unknown_safe_file "$state/$file" || exit 1; done
    [ "$(cat "$state/owner")" = "$OWNER" ] || exit 1
    token=$(cat "$state/token") || exit 1
    case "$token" in ''|*[!a-f0-9-]*) exit 1;; esac
    [ "${#token}" = 36 ] || exit 1
    mark="$OWNER:unknown:$token"
    nsname=$(cat "$state/namespace.name") || exit 1
    [ "$nsname" = "wgmvp_uk-$token" ] || exit 1
    ip netns list >/dev/null || exit 1
    ip link show >/dev/null || exit 1
    if unknown_ns_exists; then
        [ "$(cat "$state/boot")" = "$(cat /proc/sys/kernel/random/boot_id)" ] || exit 1
        if [ -s "$state/ns" ]; then
            unknown_safe_file "$state/ns" || exit 1
            current_ns=$(ip netns exec "$nsname" readlink /proc/self/ns/net) || exit 1
            [ "$current_ns" = "$(cat "$state/ns")" ] || exit 1
        else
            unknown_pristine_namespace || exit 1
        fi
        if ip -n "$nsname" link show dev wgmvp_uk >/dev/null 2>&1; then
            link=$(ip -n "$nsname" -d -o link show dev wgmvp_uk) || exit 1
            unknown_link_owned "$link" || unknown_move_link_owned "$link" namespace || exit 1
            ip -n "$nsname" link set dev wgmvp_uk down || exit 1
            ip -n "$nsname" link delete dev wgmvp_uk || exit 1
        fi
        pids=$(ip netns pids "$nsname") || exit 1
        [ -z "$pids" ] || exit 1
        links=$(ip -n "$nsname" -o link show) || exit 1
        printf '%s\n' "$links" | awk -F': ' '{count++; if($2!="lo") bad=1} END {exit (count!=1 || bad)}' || exit 1
        ip netns delete "$nsname" || exit 1
    else
        [ "$?" = 1 ] || exit 1
    fi
    if ip link show dev wgmvp_uk >/dev/null 2>&1; then
        [ "$(cat "$state/boot")" = "$(cat /proc/sys/kernel/random/boot_id)" ] || exit 1
        link=$(ip -d -o link show dev wgmvp_uk) || exit 1
        unknown_link_owned "$link" || unknown_move_link_owned "$link" host || exit 1
        ip link set dev wgmvp_uk down || exit 1
        ip link delete dev wgmvp_uk || exit 1
    fi
    for f in owner token boot namespace.name creation.intent ns ns.pending private.key public.key move.intent interface.ifindex; do rm -f "$state/$f" || exit 1; done
    rmdir "$state" || exit 1
)
unknown_finish() {
    unknown_exit=$1
    trap - EXIT HUP INT TERM
    unknown_cleanup_locked || unknown_exit=1
    exit "$unknown_exit"
}
unknown_run_locked() (
    set -eu
    umask 077
    case "$ROLE" in villa) self=$V;; cave) self=$C;; *) exit 1;; esac
    [ ! -e "$ROOT/unknown-key" ] || exit 1
    ip link show >/dev/null || exit 1
    if ip link show dev wgmvp_uk >/dev/null 2>&1; then exit 1; fi
    ip netns list >/dev/null || exit 1
    if ip netns list | awk '$1=="wgmvp_uk" {yes=1} END {exit !yes}'; then exit 1; fi
    state=$ROOT/unknown-key
    mkdir -m 700 "$state" || exit 1
    printf '%s\n' "$OWNER" > "$state/owner" || exit 1
    cat /proc/sys/kernel/random/uuid > "$state/token" || exit 1
    token=$(cat "$state/token") || exit 1
    mark="$OWNER:unknown:$token"
    nsname=wgmvp_uk-$token
    printf '%s\n' "$nsname" > "$state/namespace.name" || exit 1
    cat /proc/sys/kernel/random/boot_id > "$state/boot" || exit 1
    printf '%s\n' "$token" > "$state/creation.intent" || exit 1
    if unknown_ns_exists; then exit 1; else [ "$?" = 1 ] || exit 1; fi
    trap 'unknown_finish "$?"' EXIT
    trap 'exit 1' HUP INT TERM
    wg genkey > "$state/private.key" || exit 1
    wg pubkey < "$state/private.key" > "$state/public.key" || exit 1
    for peer in gz villa cave; do
        [ "$(cat "$state/public.key")" != "$(cat "$ROOT/public.$peer")" ] || exit 1
    done
    ip netns add "$nsname" || exit 1
    ip netns exec "$nsname" readlink /proc/self/ns/net > "$state/ns.pending" || exit 1
    [ -s "$state/ns.pending" ] || exit 1
    mv "$state/ns.pending" "$state/ns" || exit 1
    ip netns exec "$nsname" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 || exit 1
    ip netns exec "$nsname" nft -f - <<EOF
table inet wgmvp_unknown {
    comment "$mark"
    chain input { type filter hook input priority 0; policy drop;
        iifname "wgmvp_uk" ip saddr $G ip daddr $self icmp type echo-reply accept
    }
    chain output { type filter hook output priority 0; policy drop;
        oifname "wgmvp_uk" ip saddr $self ip daddr $G icmp type echo-request accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
}
EOF
    [ "$?" = 0 ] || exit 1
    ip -n "$nsname" link set lo up || exit 1
    ip link add wgmvp_uk alias "$mark" type wireguard || exit 1
    # Configure the owner-local identity before moving; UDP remains in host ns.
    wg set wgmvp_uk private-key "$state/private.key" fwmark 0x77203 peer "$(cat "$ROOT/public.gz")" allowed-ips "$G/32" endpoint "$ENDPOINT:$PORT" || exit 1
    cat /sys/class/net/wgmvp_uk/ifindex > "$state/interface.ifindex" || exit 1
    printf '%s\n' "$token" > "$state/move.intent" || exit 1
    ip link set wgmvp_uk netns "$nsname" || exit 1
    ip -n "$nsname" link set wgmvp_uk alias "$mark" || exit 1
    ip -n "$nsname" address add "$self/32" dev wgmvp_uk || exit 1
    ip -n "$nsname" link set wgmvp_uk mtu 1380 up || exit 1
    ip -n "$nsname" route add "$G/32" dev wgmvp_uk || exit 1
    printf 'FRESH_UNREGISTERED_PUBLIC_KEY '; cat "$state/public.key"
    printf 'UNKNOWN_KEY_LISTEN_PORT '; ip netns exec "$nsname" wg show wgmvp_uk listen-port
    set +e
    timeout -s TERM -k 2 10 ip netns exec "$nsname" ping -I "$self" -c 3 -w 8 "$G"
    ping_code=$?
    set -e
    printf 'UNKNOWN_KEY_PING_EXIT %s\n' "$ping_code"
    ip netns exec "$nsname" wg show wgmvp_uk latest-handshakes
    ip netns exec "$nsname" wg show wgmvp_uk transfer
    [ "$ping_code" -ne 0 ] || exit 1
    handshake=$(ip netns exec "$nsname" wg show wgmvp_uk latest-handshakes) || exit 1
    [ "$(printf '%s\n' "$handshake" | awk '{print $2}')" = 0 ] || exit 1
)
unknown_main() (
    set -eu
    ROOT=/etc/wgmvp
    [ "$(id -u)" = 0 ] && [ ! -L "$ROOT" ] && [ "$(cat "$ROOT/owner")" = wgmvp-r1 ]
    . "$ROOT/config.env"
    [ "$ROOT:$OWNER" = /etc/wgmvp:wgmvp-r1 ]
    case "$ROLE" in villa|cave) ;; *) exit 1;; esac
    exec 9>"$ROOT/state/mutex"
    flock -x -n 9
    case "${1:-}" in
      run)
        [ -f "$ROOT/state/pending" ]
        [ "$(sed -n '2p' "$ROOT/state/pending")" = "$(cat /proc/sys/kernel/random/boot_id)" ]
        tick=$(cut -d. -f1 /proc/uptime); deadline=$(sed -n '4p' "$ROOT/state/pending")
        [ "$deadline" -gt "$((tick+30))" ]
        unknown_run_locked;;
      cleanup) unknown_cleanup_locked;;
      *) exit 1;;
    esac
)
if [ "${WGMVP_UNKNOWN_SOURCE_ONLY:-0}" != 1 ]; then unknown_main "$@"; fi
