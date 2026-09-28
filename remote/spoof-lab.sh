#!/bin/sh
# Source only. The coordinator verifies identity, fingerprints and recovery,
# stages this reviewed file, then calls spoof_lab_run under an armed host lease.
# All network objects belong to three new, isolated namespaces. No veth, host
# interface, host route, public listener or production peer is changed.

_spoof_fail() { printf 'spoof-lab: %s\n' "$*" >&2; return 1; }
_spoof_safe_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]
}
_spoof_safe_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a:%h' "$1")" = 0:600:1 ]
}
_spoof_namespace_owned() {
    _spoof_safe_file "$_sl_dir/$1.identity" || return 1
    _sl_identity=$(cat "$_sl_dir/$1.identity") || return 1
    printf '%s\n' "$_sl_identity" | grep -Eq '^[0-9]+:[0-9]+$' || return 1
    _sl_actual=$(stat -Lc '%d:%i' "/run/netns/$1") || return 1
    [ "$_sl_actual" = "$_sl_identity" ]
}
_spoof_links_owned() {
    # A namespace containing an unexpected link is retained for inspection.
    _sl_links=$(ip -n "$1" -d -o link show) || return 1
    printf '%s\n' "$_sl_links" | awk '
      {name=$2; sub(/:$/, "", name); sub(/@.*/, "", name)
       if(name=="lo") {loops++; next}
       if(name!="wgs-a" && name!="wgs-b") {bad=1; exit}
      } END {exit (bad || loops!=1)}' || return 1
    _sl_link_names=$(printf '%s\n' "$_sl_links" | awk '$2!="lo:" {name=$2; sub(/:$/, "", name); sub(/@.*/, "", name); print name}') || return 1
    for _sl_link_name in $_sl_link_names; do
        _sl_line=$(printf '%s\n' "$_sl_links" | awk -v n="$_sl_link_name:" '$2==n {print}') || return 1
        _sl_alias=$(printf '%s\n' "$_sl_line" | awk '{for(i=1;i<NF;i++) if($i=="alias") print $(i+1)}') || return 1
        if [ "$_sl_alias" = "$_sl_mark" ]; then continue; fi
        # Native WG movement clears ifalias. Only the narrow, recorded move gap
        # may be recovered: exact namespace identity, index, boot and public key.
        [ -z "$_sl_alias" ] || return 1
        _spoof_safe_file "$_sl_dir/$_sl_link_name.move" || return 1
        _sl_index=$(printf '%s\n' "$_sl_line" | awk -F: 'NR==1 {print $1}') || return 1
        _sl_move_boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
        [ "$_sl_index" = "$(sed -n '1p' "$_sl_dir/$_sl_link_name.move")" ] &&
            [ "$1" = "$(sed -n '2p' "$_sl_dir/$_sl_link_name.move")" ] &&
            [ "$_sl_move_boot" = "$(sed -n '3p' "$_sl_dir/$_sl_link_name.move")" ] || return 1
        printf '%s\n' "$_sl_line" | grep -Eq '(^|[[:space:]])wireguard([[:space:]]|$)' || return 1
        _sl_public=$(ip netns exec "$1" wg show "$_sl_link_name" public-key) || return 1
        [ -n "$_sl_public" ] && [ "$_sl_public" = "$(sed -n '4p' "$_sl_dir/$_sl_link_name.move")" ] || return 1
    done
}
_spoof_no_processes() {
    _sl_pids=$(ip netns pids "$1") || return 1
    [ -z "$_sl_pids" ]
}

# The same cleanup can be retried after a terminated invocation, using its
# retained root-only directory. Missing identity records never authorize delete.
spoof_lab_cleanup() (
    set -eu
    case $- in *x*) set +x; _spoof_fail 'xtrace is forbidden'; exit 1;; esac
    _sl_dir=${1:?owned lab directory}
    case "$_sl_dir" in /etc/wgmvp/spoof-lab-*) ;; *) exit 1;; esac
    _spoof_safe_dir "$_sl_dir" && _spoof_safe_file "$_sl_dir/scope" || exit 1
    _sl_token=$(sed -n '1p' "$_sl_dir/scope") || exit 1
    case "$_sl_token" in ''|*[!a-f0-9-]*) exit 1;; esac
    [ "${#_sl_token}" = 36 ] || exit 1
    [ "$_sl_dir" = "/etc/wgmvp/spoof-lab-$_sl_token" ] || exit 1
    _sl_mark=wgmvp-r1:spoof:$_sl_token
    _sl_short=$(printf '%s' "$_sl_token" | cut -c1-8)
    _sl_a=wgs-a-$_sl_short; _sl_b=wgs-b-$_sl_short; _sl_t=wgs-t-$_sl_short
    [ "$(sed -n '2p' "$_sl_dir/scope")" = "$_sl_a $_sl_b $_sl_t" ] || exit 1
    _sl_ok=1
    for _sl_ns in "$_sl_a" "$_sl_b" "$_sl_t"; do
        if [ -e "/run/netns/$_sl_ns" ]; then
            if ! _spoof_namespace_owned "$_sl_ns" || ! _spoof_links_owned "$_sl_ns" ||
                ! _spoof_no_processes "$_sl_ns"; then
                _spoof_fail 'namespace ownership, links or processes require inspection' || :
                _sl_ok=0
                continue
            fi
            # Remove devices before unlinking ANY namespace: WireGuard sockets
            # retain their birth namespace and can otherwise form a ref cycle.
            _sl_devices=$(printf '%s\n' "$_sl_links" | awk '$2!="lo:" {name=$2; sub(/:$/, "", name); sub(/@.*/, "", name); print name}') || exit 1
            for _sl_dev in $_sl_devices; do
                case "$_sl_dev" in wgs-a|wgs-b) ;; *) exit 1;; esac
                if ip -n "$_sl_ns" link set "$_sl_dev" down; then
                    ip -n "$_sl_ns" link delete "$_sl_dev" || _sl_ok=0
                else _sl_ok=0; fi
            done
        fi
    done
    for _sl_ns in "$_sl_a" "$_sl_b" "$_sl_t"; do
        if [ -e "/run/netns/$_sl_ns" ]; then
            if _spoof_namespace_owned "$_sl_ns" && _spoof_links_owned "$_sl_ns" &&
                _spoof_no_processes "$_sl_ns" &&
                [ "$(printf '%s\n' "$_sl_links" | awk 'END {print NR}')" = 1 ]; then
                ip netns delete "$_sl_ns" || _sl_ok=0
            else _sl_ok=0; fi
        fi
    done
    # Exact private filenames only; keep synthetic captures and summaries.
    for _sl_key in a.key b.key; do
        if [ -e "$_sl_dir/$_sl_key" ]; then
            _spoof_safe_file "$_sl_dir/$_sl_key" || exit 1
            rm "$_sl_dir/$_sl_key" || exit 1
        fi
    done
    [ "$_sl_ok" = 1 ] || exit 1
    printf 'CLEANUP namespaces-absent keys-removed\n'
)

# Controller calls this while holding the project mutex, before backend stop.
# Interrupted runs with no namespace remaining still have exact keys removed.
spoof_lab_cleanup_all() (
    case $- in *x*) set +x; _spoof_fail 'xtrace is forbidden'; exit 1;; esac
    _spoof_safe_dir /etc/wgmvp && _spoof_safe_file /etc/wgmvp/owner || exit 1
    [ "$(cat /etc/wgmvp/owner)" = wgmvp-r1 ] || exit 1
    _sl_all_ok=1
    for _sl_candidate in /etc/wgmvp/spoof-lab-*; do
        [ -e "$_sl_candidate" ] || [ -L "$_sl_candidate" ] || continue
        spoof_lab_cleanup "$_sl_candidate" || _sl_all_ok=0
    done
    [ "$_sl_all_ok" = 1 ]
)

_spoof_ready() {
    _sl_wait=0
    until grep -q 'listening on ' "$1"; do
        _sl_wait=$((_sl_wait+1))
        [ "$_sl_wait" -lt 5 ] || return 1
        sleep 1
    done
}

_spoof_capture_phase() {
    _sl_phase=$1; _sl_source=$2
    # Only synthetic requests and nonempty encrypted data A -> B are captured.
    timeout -s INT -k 2 8 ip netns exec "$_sl_t" tcpdump -U -nn -i lo -w "$_sl_dir/$_sl_phase.outer.pcap" \
        'udp src port 52381 and udp dst port 52382 and udp[8:4] = 0x04000000 and udp[4:2] > 40' \
        > /dev/null 2> "$_sl_dir/$_sl_phase.outer.log" &
    _sl_outer_pid=$!; _sl_jobs="$_sl_jobs $_sl_outer_pid"
    timeout -s INT -k 2 8 ip netns exec "$_sl_b" tcpdump -U -nn -i wgs-b -w "$_sl_dir/$_sl_phase.inner.pcap" \
        "icmp and src host $_sl_source and dst host 10.203.77.3 and icmp[0] = 8" \
        > /dev/null 2> "$_sl_dir/$_sl_phase.inner.log" &
    _sl_inner_pid=$!; _sl_jobs="$_sl_jobs $_sl_inner_pid"
    _spoof_ready "$_sl_dir/$_sl_phase.outer.log" && _spoof_ready "$_sl_dir/$_sl_phase.inner.log" || return 1
    _sl_ping_rc=0
    timeout -k 2 7 ip netns exec "$_sl_a" ping -n -I "$_sl_source" -c 3 -W 1 10.203.77.3 \
        > "$_sl_dir/$_sl_phase.ping" 2>&1 || _sl_ping_rc=$?
    _sl_outer_rc=0; wait "$_sl_outer_pid" || _sl_outer_rc=$?
    _sl_inner_rc=0; wait "$_sl_inner_pid" || _sl_inner_rc=$?
    _sl_jobs=''
    # Timeout 124 is expected; other failure (including a forced kill) blocks.
    case "$_sl_outer_rc:$_sl_inner_rc" in 124:124) ;; *) return 1;; esac
    tcpdump -nn -r "$_sl_dir/$_sl_phase.outer.pcap" > "$_sl_dir/$_sl_phase.outer.txt" 2> "$_sl_dir/$_sl_phase.outer.read.log" || return 1
    tcpdump -nn -r "$_sl_dir/$_sl_phase.inner.pcap" > "$_sl_dir/$_sl_phase.inner.txt" 2> "$_sl_dir/$_sl_phase.inner.read.log" || return 1
    _sl_outer=$(wc -l < "$_sl_dir/$_sl_phase.outer.txt" | tr -d ' ')
    _sl_inner=$(wc -l < "$_sl_dir/$_sl_phase.inner.txt" | tr -d ' ')
    printf '%s ping_rc=%s encrypted_requests=%s delivered_requests=%s\n' \
        "$_sl_phase" "$_sl_ping_rc" "$_sl_outer" "$_sl_inner" | tee -a "$_sl_dir/result.txt"
    [ "$_sl_outer" -ge 3 ] || return 1
    if [ "$_sl_phase" = spoof ]; then
        [ "$_sl_ping_rc" = 1 ] && [ "$_sl_inner" = 0 ] &&
            grep -Eq '3 packets transmitted, 0 (packets )?received' "$_sl_dir/$_sl_phase.ping"
    else
        [ "$_sl_ping_rc" = 0 ] && [ "$_sl_inner" = 3 ] &&
            grep -Eq '3 packets transmitted, 3 (packets )?received' "$_sl_dir/$_sl_phase.ping"
    fi
}

_spoof_lab_run() (
    case $- in *x*) set +x; _spoof_fail 'xtrace is forbidden'; exit 1;; esac
    set -eu
    umask 077
    ROOT=/etc/wgmvp
    [ "$(id -u)" = 0 ] && _spoof_safe_dir "$ROOT"
    for _sl_cmd in ip wg tcpdump timeout flock stat awk grep cut tr wc tee; do command -v "$_sl_cmd" >/dev/null; done
    _spoof_safe_file "$ROOT/owner" && [ "$(cat "$ROOT/owner")" = wgmvp-r1 ]
    _spoof_safe_file "$ROOT/config.env"
    . "$ROOT/config.env"
    [ "$ROOT:$ROLE:$OWNER:$NS:$IFACE" = /etc/wgmvp:gz:wgmvp-r1:wgmvp:wgmvp ]
    _spoof_safe_dir "$ROOT/state" && [ ! -L "$ROOT/state/mutex" ]
    exec 8>"$ROOT/state/mutex"
    flock -x -n 8
    _spoof_safe_file "$ROOT/state/pending"
    [ "$(sed -n '1p' "$ROOT/state/pending")" = "$OWNER" ]
    [ "$(sed -n '2p' "$ROOT/state/pending")" = "$(cat /proc/sys/kernel/random/boot_id)" ]
    _sl_deadline=$(sed -n '4p' "$ROOT/state/pending")
    case "$_sl_deadline" in ''|*[!0-9]*) exit 1;; esac
    _sl_now=$(cut -d. -f1 /proc/uptime)
    [ "$_sl_deadline" -gt "$((_sl_now+90))" ] || { _spoof_fail 'renew lease before the lab'; exit 1; }
    _sl_token=$(cat /proc/sys/kernel/random/uuid)
    case "$_sl_token" in ''|*[!a-f0-9-]*) exit 1;; esac
    [ "${#_sl_token}" = 36 ]
    _sl_short=$(printf '%s' "$_sl_token" | cut -c1-8)
    _sl_mark=wgmvp-r1:spoof:$_sl_token
    _sl_a=wgs-a-$_sl_short; _sl_b=wgs-b-$_sl_short; _sl_t=wgs-t-$_sl_short
    _sl_dir=$ROOT/spoof-lab-$_sl_token
    for _sl_ns in "$_sl_a" "$_sl_b" "$_sl_t"; do [ ! -e "/run/netns/$_sl_ns" ]; done
    mkdir -m 700 "$_sl_dir"
    printf '%s\n' "$_sl_token" "$_sl_a $_sl_b $_sl_t" > "$_sl_dir/scope"
    _sl_jobs=''
    trap '_sl_exit=$?; trap - EXIT HUP INT TERM; for _sl_job in $_sl_jobs; do wait "$_sl_job" || :; done; spoof_lab_cleanup "$_sl_dir" || _sl_exit=1; exit "$_sl_exit"' EXIT
    trap 'exit 1' HUP INT TERM
    printf 'LAB evidence=%s; route via isolated WG, spoof source must fail before inner delivery\n' "$_sl_dir"
    for _sl_ns in "$_sl_t" "$_sl_a" "$_sl_b"; do
        ip netns add "$_sl_ns"
        stat -Lc '%d:%i' "/run/netns/$_sl_ns" > "$_sl_dir/$_sl_ns.identity"
        ip -n "$_sl_ns" link set lo up
    done
    wg genkey > "$_sl_dir/a.key"; wg pubkey < "$_sl_dir/a.key" > "$_sl_dir/a.pub"
    wg genkey > "$_sl_dir/b.key"; wg pubkey < "$_sl_dir/b.key" > "$_sl_dir/b.pub"
    # Both UDP sockets are born in this isolated transport namespace, listening
    # only on its loopback network. Configure before movement to prove birth.
    ip -n "$_sl_t" link add wgs-a alias "$_sl_mark" type wireguard
    ip -n "$_sl_t" link add wgs-b alias "$_sl_mark" type wireguard
    ip netns exec "$_sl_t" wg set wgs-a private-key "$_sl_dir/a.key" listen-port 52381 \
        peer "$(cat "$_sl_dir/b.pub")" allowed-ips 10.203.77.3/32 endpoint 127.0.0.1:52382
    ip netns exec "$_sl_t" wg set wgs-b private-key "$_sl_dir/b.key" listen-port 52382 \
        peer "$(cat "$_sl_dir/a.pub")" allowed-ips 10.203.77.2/32 endpoint 127.0.0.1:52381
    for _sl_end in a b; do
        if [ "$_sl_end" = a ]; then _sl_target=$_sl_a; else _sl_target=$_sl_b; fi
        _sl_before=$(ip -n "$_sl_t" -o link show dev "wgs-$_sl_end")
        _sl_index=$(printf '%s\n' "$_sl_before" | awk -F: 'NR==1 {print $1}')
        case "$_sl_index" in ''|*[!0-9]*) exit 1;; esac
        printf '%s\n' "$_sl_index" "$_sl_target" "$(cat /proc/sys/kernel/random/boot_id)" \
            "$(cat "$_sl_dir/$_sl_end.pub")" > "$_sl_dir/wgs-$_sl_end.move"
        ip -n "$_sl_t" link set "wgs-$_sl_end" netns "$_sl_target"
        ip -n "$_sl_target" link set "wgs-$_sl_end" alias "$_sl_mark"
    done
    ip -n "$_sl_a" address add 10.203.77.2/32 dev wgs-a
    ip -n "$_sl_b" address add 10.203.77.3/32 dev wgs-b
    ip -n "$_sl_a" link set wgs-a mtu 1380 up
    ip -n "$_sl_b" link set wgs-b mtu 1380 up
    ip -n "$_sl_a" route add 10.203.77.3/32 dev wgs-a
    ip -n "$_sl_b" route add 10.203.77.2/32 dev wgs-b
    for _sl_ns in "$_sl_t" "$_sl_a" "$_sl_b"; do
        ip -n "$_sl_ns" -d link show > "$_sl_dir/$_sl_ns.links"
        ip -n "$_sl_ns" route show table all > "$_sl_dir/$_sl_ns.routes"
    done
    ip netns exec "$_sl_b" wg show wgs-b allowed-ips > "$_sl_dir/b.allowed-ips"
    _spoof_capture_phase positive 10.203.77.2
    ip -n "$_sl_a" address add 10.203.77.3/32 dev wgs-a
    # Only this disposable source namespace: avoid a false local ping to .3.
    ip -n "$_sl_a" route del local 10.203.77.3/32 dev wgs-a table local
    # Linux bind() consults the local route table. Permit this deliberately
    # nonlocal source only in the disposable sender namespace after deleting
    # its local route; otherwise ping fails before emitting a spoofed packet.
    ip netns exec "$_sl_a" sysctl -qw net.ipv4.ip_nonlocal_bind=1
    ip -n "$_sl_a" route get 10.203.77.3 from 10.203.77.3 > "$_sl_dir/spoof.route"
    awk '{for(i=1;i<NF;i++) if($i=="dev" && $(i+1)=="wgs-a") good=1; if($1=="local") bad=1} END {exit (!good || bad)}' "$_sl_dir/spoof.route"
    _spoof_capture_phase spoof 10.203.77.3
    ip -n "$_sl_a" address del 10.203.77.3/32 dev wgs-a
    _spoof_capture_phase recovery 10.203.77.2
    spoof_lab_cleanup "$_sl_dir"
    trap - EXIT HUP INT TERM
    printf 'S05 PASS equivalent WireGuard source authorization; production peers unchanged\n' | tee -a "$_sl_dir/result.txt"
)

spoof_lab_run() (
    case $- in *x*) set +x; _spoof_fail 'xtrace is forbidden'; exit 1;; esac
    # Source-only installation is mode 0600. The fresh shell gives timeout a
    # bounded process group and does not inherit caller-defined shell functions.
    _spoof_safe_file /etc/wgmvp/spoof-lab.sh || exit 1
    timeout -s TERM -k 10 65 sh -c '. /etc/wgmvp/spoof-lab.sh; _spoof_lab_run'
)
