#!/bin/sh
# Sender/transit exceptions for bounded negative tests; never opens a receiver.
# The coordinator holds its own lock, validates current fingerprints, and arms
# the persistent controller lease before invoking this file.
probe_nft() { if [ "$ROLE" = gz ]; then ip netns exec "$NS" nft "$@"; else nft "$@"; fi; }
probe_assert() {
    if [ "$ROLE" = gz ]; then
        . "$ROOT/hub.sh"
        _hub_config && _hub_load_state && _hub_assert_namespace || return 1
        probe_nft list table inet wgmvp | _hub_assert_table
    else
        . "$ROOT/router.sh"
        router_check || return 1
        nft list table inet wgmvp_guard | awk 'NR==2 {good=($0 ~ /comment "wgmvp-r1"/)} END {exit !good}'
    fi
}
probe_close_locked() (
    set -eu
    [ -f "$ROOT/probe.active" ] || return 0
    [ "$(sed -n '1p' "$ROOT/probe.active")" = "$OWNER" ] || exit 1
    token=$(sed -n '2p' "$ROOT/probe.active") || exit 1
    case "$token" in ''|*[!a-f0-9-]*) exit 1;; esac
    [ "${#token}" = 36 ] || exit 1
    mark="$OWNER:probe:$token"
    if [ "$ROLE" = gz ]; then
        if [ ! -e "/run/netns/$NS" ]; then rm "$ROOT/probe.active" || exit 1; exit 0; fi
        table=wgmvp; chains='output forward'
    else table=wgmvp_guard; chains=tx; fi
    probe_assert || exit 1
    if probe_nft list set inet "$table" wgmvp_probe_gate >/dev/null 2>&1; then
        probe_nft list set inet "$table" wgmvp_probe_gate | grep -Fq "comment \"$mark\"" || exit 1
        probe_nft flush set inet "$table" wgmvp_probe_gate || exit 1
    fi
    for chain in $chains; do
        handles=$(probe_nft -a list chain inet "$table" "$chain" | awk -v m="\"$mark\"" 'index($0,m) {print $NF}')
        for h in $handles; do
            case "$h" in ''|*[!0-9]*) exit 1;; esac
            probe_nft delete rule inet "$table" "$chain" handle "$h" || exit 1
        done
    done
    if [ "$ROLE" != gz ]; then
        handles=$(nft -a list chain inet fw4 output | awk -v m="\"$mark\"" 'index($0,m) {print $NF}')
        for h in $handles; do
            case "$h" in ''|*[!0-9]*) exit 1;; esac
            nft delete rule inet fw4 output handle "$h" || exit 1
        done
    fi
    if probe_nft list set inet "$table" wgmvp_probe_gate >/dev/null 2>&1; then
        probe_nft delete set inet "$table" wgmvp_probe_gate || exit 1
    fi
    rm "$ROOT/probe.active" || exit 1
)
probe_open_locked() (
    set -eu
    src=${1:?source}; dst=${2:?destination}
    case "$src:$dst" in
      "$G:$V"|"$G:$C"|"$V:$C"|"$C:$V") ;; *) exit 1;;
    esac
    case "$ROLE" in
      gz) table=wgmvp; if [ "$src" = "$G" ]; then chain=output; else chain=forward; fi;;
      villa) [ "$src" = "$V" ]; table=wgmvp_guard; chain=tx;;
      cave) [ "$src" = "$C" ]; table=wgmvp_guard; chain=tx;;
      *) exit 1;;
    esac
    [ ! -e "$ROOT/probe.active" ]
    probe_assert
    ! probe_nft list set inet "$table" wgmvp_probe_gate >/dev/null 2>&1
    token=$(cat /proc/sys/kernel/random/uuid)
    mark="$OWNER:probe:$token"
    # Record ownership before the first firewall mutation for interrupted cleanup.
    tick=$(cut -d. -f1 /proc/uptime)
    printf '%s\n' "$OWNER" "$token" "$tick" "$(cat /proc/sys/kernel/random/boot_id)" > "$ROOT/probe.active"
    probe_nft -f - <<EOF
add set inet $table wgmvp_probe_gate { type ipv4_addr; flags timeout; timeout 60s; comment "$mark"; }
add element inet $table wgmvp_probe_gate { $src timeout 60s }
insert rule inet $table $chain ip saddr @wgmvp_probe_gate ip daddr $dst tcp dport { 22, 80, 443, 53, 9090 } counter accept comment "$mark"
EOF
    if [ "$ROLE" != gz ]; then
        # This exception alone cannot bypass the earlier independent guard.
        nft insert rule inet fw4 output oifname wgmvp ip saddr "$src" ip daddr "$dst" tcp dport '{ 22, 80, 443, 53, 9090 }' counter accept comment "\"$mark\""
    fi
    printf 'PROBE sender/transit only; destination INPUT unchanged; expires=60s\n'
)
probe_main() (
    set -eu
    umask 077
    ROOT=/etc/wgmvp
    [ "$(id -u)" = 0 ] && [ ! -L "$ROOT" ]
    [ "$(cat "$ROOT/owner")" = wgmvp-r1 ]
    . "$ROOT/config.env"
    [ "$ROOT:$OWNER:$IFACE:$NS" = /etc/wgmvp:wgmvp-r1:wgmvp:wgmvp ]
    if [ "${1:-}" = expire ] && [ ! -f "$ROOT/probe.active" ]; then exit 0; fi
    exec 9>"$ROOT/state/mutex"
    flock -x -n 9
    case "${1:-}" in
      open)
        [ -f "$ROOT/state/pending" ]
        [ "$(sed -n '2p' "$ROOT/state/pending")" = "$(cat /proc/sys/kernel/random/boot_id)" ]
        tick=$(cut -d. -f1 /proc/uptime)
        deadline=$(sed -n '4p' "$ROOT/state/pending")
        [ "$deadline" -gt "$((tick+65))" ]
        probe_open_locked "${2:?}" "${3:?}";;
      close) probe_close_locked;;
      expire)
        began=$(sed -n '3p' "$ROOT/probe.active")
        tick=$(cut -d. -f1 /proc/uptime)
        if [ "$(sed -n '4p' "$ROOT/probe.active")" != "$(cat /proc/sys/kernel/random/boot_id)" ] ||
          [ "$tick" -lt "$began" ] || [ "$tick" -ge "$((began+60))" ]; then probe_close_locked; fi;;
      *) exit 1;;
    esac
)
if [ "${WGMVP_PROBE_SOURCE_ONLY:-0}" != 1 ]; then probe_main "$@"; fi
