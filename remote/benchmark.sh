#!/bin/sh
# Finite benchmark backend. Sourceable; standalone commands are listed below.
# Controller integration calls benchmark_cleanup_locked while holding its FD 9.
# Keys are never read. Every opened permission depends on a 120-second kernel
# timeout element; TCP established state cannot extend it.

_bench_fail() { printf 'benchmark: %s\n' "$*" >&2; return 1; }
_bench_uint() { case "$1" in ''|*[!0-9]*) return 1;; esac; }
_bench_safe_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && ls -ldn "$1" |
        awk '$1=="-rw-------" && $2==1 && $3==0 {good=1} END {exit !good}'
}
_bench_safe_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] && ls -ldn "$1" |
        awk '$1=="drwx------" && $3==0 {good=1} END {exit !good}'
}
_bench_starttime() {
    [ -r "/proc/$1/stat" ] || return 1
    _bench_proc=$(cat "/proc/$1/stat") || return 1
    printf '%s\n' "${_bench_proc##*) }" | awk '$1!="Z" && NF>=20 {print $20}'
}
_bench_context() {
    case $- in *x*) set +x; _bench_fail 'xtrace is forbidden'; return 1;; esac
    ROOT=/etc/wgmvp
    [ "$(id -u)" = 0 ] && _bench_safe_dir "$ROOT" || return 1
    _bench_safe_file "$ROOT/config.env" && _bench_safe_file "$ROOT/owner" || return 1
    [ "$(cat "$ROOT/owner")" = wgmvp-r1 ] || return 1
    . "$ROOT/config.env"
    [ "$ROOT" = /etc/wgmvp ] && [ "$OWNER" = wgmvp-r1 ] && [ "$IFACE" = wgmvp ] || return 1
    [ "$G:$V:$C" = 10.203.77.1:10.203.77.2:10.203.77.3 ] || return 1
    case "$ROLE" in gz) _bench_self=$G; _bench_table=wgmvp;;
        villa) _bench_self=$V; _bench_table=wgmvp_guard;;
        cave) _bench_self=$C; _bench_table=wgmvp_guard;; *) return 1;; esac
    _bench_root=$ROOT/bench
    _bench_port=52080
    _bench_boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    _bench_ns=$(readlink /proc/self/ns/net) || return 1
    [ "$ROLE" != gz ] || [ "$NS" = wgmvp ] || return 1
}
_bench_namespace() {
    if [ "$ROLE" = gz ]; then
        . "$ROOT/hub.sh"
        _hub_config && _hub_load_state && _hub_assert_namespace || return 1
        _bench_ns=$(ip netns exec "$NS" readlink /proc/self/ns/net) || return 1
    fi
}
_bench_exec() {
    if [ "$ROLE" = gz ]; then ip netns exec "$NS" "$@"; else "$@"; fi
}
_bench_nft() { _bench_exec nft "$@"; }
_bench_lock() {
    [ -d "$ROOT/state" ] && [ ! -L "$ROOT/state/mutex" ] || return 1
    exec 9>"$ROOT/state/mutex"
    _bench_attempts=0
    until flock -x -n 9; do
        _bench_attempts=$((_bench_attempts+1))
        [ "$_bench_attempts" -lt 12 ] || { _bench_fail 'project operation still holds lock'; return 1; }
        sleep 1
    done
}
_bench_storage() {
    [ -d "$_bench_root" ] || return 1
    _bench_safe_dir "$_bench_root" &&
        _bench_safe_file "$_bench_root/owner" && [ "$(cat "$_bench_root/owner")" = "$OWNER" ] || return 1
}
_bench_load() {
    _bench_storage || return 1
    _bench_safe_file "$_bench_root/active" || return 1
    _bench_token=$(cat "$_bench_root/active") || return 1
    case "$_bench_token" in ''|*[!a-f0-9-]*) return 1;; esac
    [ "${#_bench_token}" = 36 ] || return 1
    _bench_dir=$_bench_root/sessions/$_bench_token
    _bench_safe_dir "$_bench_dir" || return 1
    _bench_safe_file "$_bench_dir/session" || return 1
    [ "$(sed -n '1p' "$_bench_dir/session")" = "$OWNER" ] || return 1
    _bench_session_boot=$(sed -n '2p' "$_bench_dir/session")
    _bench_client=$(sed -n '3p' "$_bench_dir/session")
    _bench_server=$(sed -n '4p' "$_bench_dir/session")
    [ "$(sed -n '5p' "$_bench_dir/session")" = "$ROLE" ] || return 1
    _bench_began=$(sed -n '6p' "$_bench_dir/session")
    _bench_uint "$_bench_began" || return 1
    _bench_pair_valid || return 1
    _bench_mark=$OWNER:bench:$_bench_token
}
_bench_pair_valid() {
    case "$_bench_client" in "$G"|"$V"|"$C") ;; *) return 1;; esac
    case "$_bench_server" in "$G"|"$V"|"$C") ;; *) return 1;; esac
    [ "$_bench_client" != "$_bench_server" ] || return 1
    [ "$ROLE" = gz ] || [ "$_bench_self" = "$_bench_client" ] || [ "$_bench_self" = "$_bench_server" ]
}
_bench_table_owned() {
    _bench_namespace || return 1
    _bench_listing=$(_bench_nft list table inet "$_bench_table") || return 1
    _bench_owner=$OWNER
    [ "$ROLE" != gz ] || _bench_owner=$_hub_mark
    printf '%s\n' "$_bench_listing" | awk -v owner="$_bench_owner" '
        NR==2 {line=$0; sub(/^[ \t]+/, "", line); good=(line=="comment \""owner"\"")}
        END {exit !good}'
}
_bench_gate_owned() {
    _bench_namespace || return 1
    _bench_listing=$(_bench_nft list set inet "$_bench_table" wgmvp_bench_gate) || return 1
    printf '%s\n' "$_bench_listing" | awk -v owner="$_bench_mark" '
        {line=$0; sub(/^[ \t]+/, "", line); if(line=="comment \""owner"\"") good=1}
        END {exit !good}'
}
_bench_gate_active() {
    _bench_gate_owned && _bench_nft get element inet "$_bench_table" wgmvp_bench_gate "{ $_bench_client }" >/dev/null
}
_bench_chains() {
    if [ "$ROLE" = gz ]; then printf '%s\n' bench_input bench_output bench_forward;
    else printf '%s\n' bench_rx bench_tx; fi
}
_bench_rule() {
    # One exact directional tuple, always gated by the client-address element.
    _bench_chain=$1; _bench_direction=$2; _bench_proto=$3
    if [ "$_bench_direction" = request ]; then
        _bench_source=$_bench_client; _bench_dest=$_bench_server
        _bench_gate='ip saddr @wgmvp_bench_gate'; _bench_service=dport
    else
        _bench_source=$_bench_server; _bench_dest=$_bench_client
        _bench_gate='ip daddr @wgmvp_bench_gate'; _bench_service=sport
    fi
    case "$_bench_chain" in
        bench_input|bench_rx) _bench_devices='iifname "wgmvp"';;
        bench_output|bench_tx) _bench_devices='oifname "wgmvp"';;
        bench_forward) _bench_devices='iifname "wgmvp" oifname "wgmvp"';;
        *) return 1;;
    esac
    printf 'add rule inet %s %s %s ip saddr %s ip daddr %s %s %s %s %s counter accept comment "%s:%s-%s"\n' \
        "$_bench_table" "$_bench_chain" "$_bench_devices" "$_bench_source" "$_bench_dest" \
        "$_bench_gate" "$_bench_proto" "$_bench_service" "$_bench_port" "$_bench_mark" "$_bench_direction" "$_bench_proto"
    if [ "$ROLE" != gz ]; then
        case "$_bench_chain" in bench_rx) _bench_fwchain=input_wgmvp;; bench_tx) _bench_fwchain=output_wgmvp;; esac
        # This ACCEPT cannot bypass the earlier independent timeout-gated guard.
        printf 'insert rule inet fw4 %s %s ip saddr %s ip daddr %s %s %s %s counter accept comment "%s:%s-%s"\n' \
            "$_bench_fwchain" "$_bench_devices" "$_bench_source" "$_bench_dest" \
            "$_bench_proto" "$_bench_service" "$_bench_port" "$_bench_mark" "$_bench_direction" "$_bench_proto"
    fi
}
_bench_policy() {
    printf 'add set inet %s wgmvp_bench_gate { type ipv4_addr; flags timeout; timeout 120s; size 1; comment "%s"; }\n' \
        "$_bench_table" "$_bench_mark"
    printf 'add element inet %s wgmvp_bench_gate { %s timeout 120s }\n' "$_bench_table" "$_bench_client"
    if [ "$ROLE" = gz ] && [ "$_bench_self" != "$_bench_client" ] && [ "$_bench_self" != "$_bench_server" ]; then
        _bench_request_chain=bench_forward; _bench_response_chain=bench_forward
    elif [ "$_bench_self" = "$_bench_client" ]; then
        if [ "$ROLE" = gz ]; then _bench_request_chain=bench_output; _bench_response_chain=bench_input;
        else _bench_request_chain=bench_tx; _bench_response_chain=bench_rx; fi
    else
        if [ "$ROLE" = gz ]; then _bench_request_chain=bench_input; _bench_response_chain=bench_output;
        else _bench_request_chain=bench_rx; _bench_response_chain=bench_tx; fi
    fi
    for _bench_protocol in tcp udp; do
        _bench_rule "$_bench_request_chain" request "$_bench_protocol"
        _bench_rule "$_bench_response_chain" response "$_bench_protocol"
    done
}
_bench_record_pid() {
    _bench_pid=$1; _bench_record=$2
    _bench_start=$(_bench_starttime "$_bench_pid") || return 1
    _bench_uint "$_bench_start" || return 1
    [ "$(readlink "/proc/$_bench_pid/ns/net")" = "$_bench_ns" ] || return 1
    printf '%s\n' "$_bench_token" "$_bench_boot" "$_bench_pid" "$_bench_start" "$_bench_ns" > "$_bench_record"
}
_bench_pid_matches() {
    _bench_safe_file "$1" || return 1
    [ "$(sed -n '1p' "$1")" = "$_bench_token" ] &&
        [ "$(sed -n '2p' "$1")" = "$_bench_boot" ] || return 1
    _bench_pid=$(sed -n '3p' "$1")
    _bench_start=$(sed -n '4p' "$1")
    _bench_uint "$_bench_pid" && _bench_uint "$_bench_start" && [ "$_bench_pid" -gt 1 ] || return 1
    [ "$(_bench_starttime "$_bench_pid")" = "$_bench_start" ] &&
        [ "$(readlink "/proc/$_bench_pid/ns/net")" = "$(sed -n '5p' "$1")" ]
}
_bench_processes_stop() {
    for _bench_record in "$_bench_dir/"*.child "$_bench_dir/"*.wrapper; do
        [ -e "$_bench_record" ] || continue
        if _bench_pid_matches "$_bench_record"; then kill -TERM "$_bench_pid" 2>/dev/null || :; fi
    done
    sleep 1
    for _bench_record in "$_bench_dir/"*.child "$_bench_dir/"*.wrapper; do
        [ -e "$_bench_record" ] || continue
        if _bench_pid_matches "$_bench_record"; then kill -KILL "$_bench_pid" 2>/dev/null || :; fi
    done
}
_bench_delete_rules() {
    _bench_delete_table=$1; _bench_delete_chain=$2
    _bench_rules=$(_bench_nft -a list chain inet "$_bench_delete_table" "$_bench_delete_chain") || return 1
    _bench_handles=$(printf '%s\n' "$_bench_rules" | awk -v mark="$_bench_mark:" '
        index($0,"comment \""mark) && $(NF-1)=="handle" && $NF~/^[0-9]+$/ {print $NF}') || return 1
    for _bench_handle in $_bench_handles; do
        _bench_nft delete rule inet "$_bench_delete_table" "$_bench_delete_chain" handle "$_bench_handle" || return 1
    done
}
_bench_close_locked() {
    [ -e "$_bench_root/active" ] || return 0
    _bench_load || return 1
    _bench_namespace_exists=yes
    if [ "$ROLE" = gz ]; then
        _bench_namespaces=$(ip netns list) || return 1
        if ! printf '%s\n' "$_bench_namespaces" | awk -v n="$NS" '$1==n {found=1} END {exit !found}'; then
            # A reboot or earlier teardown removed the named namespace. Still
            # stop registered surviving diagnostics without adopting another ns.
            _bench_namespace_exists=no
        fi
    fi
    _bench_has_table=no
    if [ "$_bench_namespace_exists" = yes ]; then
        _bench_nft list tables >/dev/null || return 1
        if _bench_nft list table inet "$_bench_table" >/dev/null 2>&1; then
            _bench_table_owned || return 1
            _bench_has_table=yes
        fi
    fi
    if [ "$_bench_has_table" = yes ] && _bench_nft list set inet "$_bench_table" wgmvp_bench_gate >/dev/null 2>&1; then
        _bench_gate_owned || { _bench_fail 'foreign timeout set'; return 1; }
        # Revoke first, even if a diagnostic subsequently refuses to exit.
        _bench_nft flush set inet "$_bench_table" wgmvp_bench_gate || return 1
    fi
    _bench_processes_stop || return 1
    if [ "$_bench_has_table" = yes ]; then
        for _bench_chain in $(_bench_chains); do
            _bench_delete_rules "$_bench_table" "$_bench_chain" || return 1
        done
    fi
    if [ "$ROLE" != gz ]; then
        for _bench_chain in input_wgmvp output_wgmvp; do
            # fw4 reload may already have removed the temporary chains/rules.
            if _bench_nft list chain inet fw4 "$_bench_chain" >/dev/null 2>&1; then
                _bench_delete_rules fw4 "$_bench_chain" || return 1
            fi
        done
    fi
    if [ "$_bench_has_table" = yes ] && _bench_nft list set inet "$_bench_table" wgmvp_bench_gate >/dev/null 2>&1; then
        _bench_nft delete set inet "$_bench_table" wgmvp_bench_gate || return 1
    fi
    printf '%s\n' "$_bench_token" > "$_bench_root/last-session"
    rm "$_bench_root/active" || return 1
    printf 'BENCH_CLOSED %s\n' "$_bench_token"
}
_bench_expire_locked() {
    [ -e "$_bench_root/active" ] || return 0
    _bench_load || return 1
    read -r _bench_uptime _bench_unused < /proc/uptime
    _bench_now=${_bench_uptime%%.*}
    _bench_uint "$_bench_now" || return 1
    if [ "$_bench_session_boot" != "$_bench_boot" ] || [ "$_bench_now" -lt "$_bench_began" ] ||
        [ $((_bench_now - _bench_began)) -ge 120 ]; then
        _bench_close_locked
    fi
}
benchmark_cleanup_locked() (
    umask 077
    _bench_context || exit 1
    # Caller must be the controller role child with its inherited mutex/token.
    [ -n "${WGMVP_LOCK_TOKEN:-}" ] && [ -f "$ROOT/state/lock/identity" ] &&
        [ "$(cat "$ROOT/state/lock/identity")" = "$WGMVP_LOCK_TOKEN" ] || exit 1
    : >&9
    _bench_close_locked
)
_bench_open() {
    _bench_client=$1; _bench_server=$2
    _bench_pair_valid || return 1
    if [ ! -e "$_bench_root" ]; then
        mkdir -m 700 "$_bench_root" && printf '%s\n' "$OWNER" > "$_bench_root/owner" || return 1
        mkdir -m 700 "$_bench_root/sessions" || return 1
    fi
    _bench_storage && _bench_table_owned || return 1
    [ ! -e "$_bench_root/active" ] || { _bench_fail 'close previous session first'; return 1; }
    if _bench_nft list set inet "$_bench_table" wgmvp_bench_gate >/dev/null 2>&1; then
        _bench_fail 'unowned or stale benchmark set'; return 1
    fi
    if [ "$ROLE" = gz ]; then _hub_validate_running || return 1;
    else . "$ROOT/router.sh"; router_check && router_guard || return 1; fi
    for _bench_chain in $(_bench_chains); do
        _bench_listing=$(_bench_nft -a list chain inet "$_bench_table" "$_bench_chain") || return 1
        if printf '%s\n' "$_bench_listing" | grep -q '# handle'; then
            # The chain header itself has a handle. Rules are indented two levels.
            printf '%s\n' "$_bench_listing" | awk '/^[ \t]+[^}]/ && /# handle/ && $1!="chain" {bad=1} END {exit bad}' || {
                _bench_fail 'benchmark chain is not empty'; return 1;
            }
        fi
    done
    _bench_token=$(cat /proc/sys/kernel/random/uuid) || return 1
    _bench_mark=$OWNER:bench:$_bench_token
    _bench_dir=$_bench_root/sessions/$_bench_token
    mkdir -m 700 "$_bench_dir" || return 1
    read -r _bench_uptime _bench_unused < /proc/uptime
    _bench_began=${_bench_uptime%%.*}
    _bench_uint "$_bench_began" || return 1
    printf '%s\n' "$OWNER" "$_bench_boot" "$_bench_client" "$_bench_server" "$ROLE" "$_bench_began" > "$_bench_dir/session" || return 1
    printf '%s\n' "$_bench_token" > "$_bench_root/active" || return 1
    _bench_policy > "$_bench_dir/open.nft" || return 1
    if ! _bench_nft -c -f "$_bench_dir/open.nft" || ! _bench_nft -f "$_bench_dir/open.nft"; then
        _bench_close_locked || :
        return 1
    fi
    printf 'BENCH_OPEN %s expires=120s client=%s server=%s port=%s\n' "$_bench_token" "$_bench_client" "$_bench_server" "$_bench_port"
}
_bench_spawn() {
    _bench_kind=$1; shift
    [ ! -e "$_bench_dir/$_bench_kind.wrapper" ] && [ ! -e "$_bench_dir/$_bench_kind.child" ] || return 1
    case "$_bench_kind" in server|cpu) _bench_seconds=45;; client|load) _bench_seconds=20;; idle) _bench_seconds=12;; *) return 1;; esac
    (
        # POSIX ignored HUP survives exec; these bounded workers need no nohup
        # binary. Close the mutex so they never hold up expiry/owned cleanup.
        trap '' HUP
        exec 9>&-
        if [ "$ROLE" = gz ]; then
            exec ip netns exec "$NS" timeout -s TERM -k 2 "$_bench_seconds" "$ROOT/benchmark.sh" _worker "$_bench_token" "$_bench_kind" "$@"
        else
            exec timeout -s TERM -k 2 "$_bench_seconds" "$ROOT/benchmark.sh" _worker "$_bench_token" "$_bench_kind" "$@"
        fi
    ) > "$_bench_dir/$_bench_kind.json" 2> "$_bench_dir/$_bench_kind.stderr" < /dev/null &
    _bench_spawned=$!
    _bench_count=0
    until _bench_record_pid "$_bench_spawned" "$_bench_dir/$_bench_kind.wrapper"; do
        _bench_count=$((_bench_count+1)); [ "$_bench_count" -le 3 ] || return 1; sleep 1
    done
    _bench_count=0
    until [ -f "$_bench_dir/$_bench_kind.child" ]; do
        _bench_count=$((_bench_count+1)); [ "$_bench_count" -le 3 ] || return 1; sleep 1
    done
}
_bench_worker() {
    _bench_requested_token=$1; _bench_kind=$2; shift 2
    _bench_load && _bench_namespace || return 1
    [ "$_bench_token" = "$_bench_requested_token" ] && [ "$_bench_boot" = "$_bench_session_boot" ] || return 1
    case "$_bench_kind" in server|client|idle|load|cpu) ;; *) return 1;; esac
    [ ! -e "$_bench_dir/$_bench_kind.child" ] || return 1
    _bench_record_pid $$ "$_bench_dir/$_bench_kind.child" || return 1
    case "$_bench_kind" in
        server)
            [ "$_bench_self" = "$_bench_server" ] || return 1
            exec iperf3 -4 -s -1 -B "$_bench_server" -p "$_bench_port" -J;;
        client)
            [ "$_bench_self" = "$_bench_client" ] || return 1
            case "${1:-}:${2:-}" in tcp:1|tcp:4)
                exec iperf3 -4 -c "$_bench_server" -B "$_bench_client" -p "$_bench_port" -J -t 10 -O 2 -P "$2";;
                udp:1|udp:5|udp:10|udp:20)
                exec iperf3 -4 -c "$_bench_server" -B "$_bench_client" -p "$_bench_port" -J -t 10 -O 2 -P 1 -u -b "${2}M" -l 1200;;
                udp-df:1)
                _bench_uint "$MTU" && [ "$MTU" -ge 1280 ] && [ "$MTU" -le 1420 ] || return 1
                [ "$(cat /sys/class/net/wgmvp/mtu)" = "$MTU" ] || return 1
                exec iperf3 -4 -c "$_bench_server" -B "$_bench_client" -p "$_bench_port" -J -t 10 -O 0 -P 1 -u \
                    --dont-fragment -b 1M -l "$((MTU-28))";;
                *) return 1;; esac;;
        idle|load)
            [ "$_bench_self" = "$_bench_client" ] || return 1
            if [ "$_bench_kind" = idle ]; then _bench_samples=10; else _bench_samples=30; fi
            exec ping -I "$_bench_client" -c "$_bench_samples" -i 0.5 -W 1 "$_bench_server";;
        cpu)
            _bench_count=0
            while [ "$_bench_count" -lt 40 ]; do
                printf 'UPTIME '; cat /proc/uptime
                cat /proc/loadavg
                awk '/^cpu/ {print}' /proc/stat
                cat /proc/softirqs
                _bench_count=$((_bench_count+1)); sleep 1
            done;;
    esac
}
_bench_server() {
    _bench_load && [ "$_bench_self" = "$_bench_server" ] && _bench_gate_active || return 1
    _bench_spawn server || return 1
    _bench_endpoint=$(awk -v ip="$_bench_server" 'BEGIN {split(ip,a,"."); printf "%02X%02X%02X%02X:CB70",a[4],a[3],a[2],a[1]}')
    _bench_count=0
    until awk -v endpoint="$_bench_endpoint" '$2==endpoint && $4=="0A" {found=1} END {exit !found}' "/proc/$_bench_spawned/net/tcp"; do
        _bench_count=$((_bench_count+1)); [ "$_bench_count" -le 5 ] || return 1; sleep 1
    done
    printf 'BENCH_SERVER_READY %s\n' "$_bench_token"
}
_bench_client() {
    _bench_load && [ "$_bench_self" = "$_bench_client" ] && _bench_gate_active || return 1
    case "${1:-}:${2:-}" in tcp:1|tcp:4|udp:1|udp:5|udp:10|udp:20|udp-df:1) ;; *) return 1;; esac
    if [ -e "$_bench_dir/cpu.child" ]; then _bench_pid_matches "$_bench_dir/cpu.child" || return 1;
    else _bench_spawn cpu || return 1; fi
    _bench_spawn load || return 1
    _bench_spawn client "$1" "$2" || return 1
    _bench_client_wrapper=$_bench_spawned
    # Keep the mutex in this parent through the finite client operation. Children
    # close it, so a dead parent cannot strand cleanup behind a diagnostic.
    wait "$_bench_client_wrapper"
}
benchmark_main() (
    umask 077
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH
    _bench_context || exit 1
    _bench_action=${1:-status}; if [ "$#" -gt 0 ]; then shift; fi
    case "$_bench_action" in
        result)
            _bench_load || exit 1
            case "${1:-}" in server|client|cpu|idle|load) ;; *) exit 1;; esac
            _bench_safe_file "$_bench_dir/$1.json" || exit 1
            cat "$_bench_dir/$1.json"; exit;;
        status)
            [ -e "$_bench_root/active" ] || { printf 'BENCH_ABSENT\n'; exit 0; }
            _bench_load && _bench_gate_owned || exit 1
            _bench_nft list set inet "$_bench_table" wgmvp_bench_gate; exit;;
        open|close|server|client|idle|sample|expire) ;; *) _bench_fail 'usage: open CLIENT SERVER | server | client tcp 1|4 | client udp 1|5|10|20 | client udp-df 1 | idle | sample | close | expire | status | result KIND'; exit 1;;
    esac
    case "$_bench_action" in close|expire) [ -e "$_bench_root/active" ] || exit 0;; esac
    for _bench_cmd in nft ip iperf3 timeout flock readlink; do command -v "$_bench_cmd" >/dev/null 2>&1 || exit 1; done
    _bench_lock || exit 1
    case "$_bench_action" in
        open) [ "$#" = 2 ] && _bench_open "$1" "$2";;
        close) _bench_close_locked;;
        server) _bench_server;;
        client) [ "$#" = 2 ] && _bench_client "$1" "$2";;
        idle) _bench_load && _bench_namespace && [ "$_bench_self" = "$_bench_client" ] && _bench_spawn idle && wait "$_bench_spawned";;
        sample) _bench_load && _bench_namespace && _bench_spawn cpu;;
        expire) _bench_expire_locked;;
    esac
)

if [ "${0##*/}" = benchmark.sh ]; then
    if [ "${1:-}" = _worker ]; then
        # Do not wrap this branch in a subshell: $$ must identify the process
        # which subsequently execs iperf/ping, not a waiting parent shell.
        umask 077
        PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH
        shift
        _bench_context && _bench_worker "$@"
    else benchmark_main "$@"; fi
fi
