#!/bin/sh
# REVIEW PROPOSAL ONLY. Not installed, rendered or sourced by production code.
# Integration needed: watchdog calls expire at most every 3s; controller role
# cleanup calls restore before stop/start; coordinator registers bounded capture
# and iperf workers. Existing pending lease remains the independent fallback.
# Source-only functions. Caller holds the existing /etc/wgmvp/state/mutex FD9.

_mtu_safe() {
    [ -f "$1" ] && [ ! -L "$1" ] && ls -ldn "$1" |
        awk '$1=="-rw-------" && $2==1 && $3==0 {good=1} END {exit !good}'
}
_mtu_uint() { case "$1" in ''|*[!0-9]*) return 1;; esac; }
_mtu_context() {
    ROOT=/etc/wgmvp
    [ "$(id -u)" = 0 ] && [ ! -L "$ROOT" ] || return 1
    _mtu_safe "$ROOT/owner" && [ "$(cat "$ROOT/owner")" = wgmvp-r1 ] || return 1
    _mtu_safe "$ROOT/config.env" || return 1
    . "$ROOT/config.env"
    [ "$ROOT:$OWNER:$IFACE" = /etc/wgmvp:wgmvp-r1:wgmvp ] || return 1
    case "$ROLE" in gz|cave|villa) ;; *) return 1;; esac
    _mtu_record=$ROOT/mtu-probe.pending
    _mtu_boot=$(cat /proc/sys/kernel/random/boot_id) || return 1
    _mtu_now=$(cut -d. -f1 /proc/uptime) || return 1
    _mtu_uint "$_mtu_now" || return 1
    _mtu_config_hash=$(sha256sum "$ROOT/config.env") || return 1
    _mtu_config_hash=${_mtu_config_hash%% *}
}
_mtu_lock_assert() {
    [ "$(readlink /proc/$$/fd/9)" = "$ROOT/state/mutex" ] && flock -x -n 9
}
_mtu_exec() {
    if [ "$ROLE" = gz ]; then ip netns exec wgmvp "$@"; else "$@"; fi
}
_mtu_identity() {
    if [ "$ROLE" = gz ]; then
        . "$ROOT/hub.sh"
        _hub_config && _hub_load_state && _hub_assert_namespace || return 1
        _mtu_expected_alias=$_hub_mark
    else _mtu_expected_alias=$OWNER; fi
    _mtu_ns=$(_mtu_exec readlink /proc/self/ns/net) || return 1
    _mtu_index=$(_mtu_exec cat /sys/class/net/wgmvp/ifindex) || return 1
    _mtu_alias=$(_mtu_exec cat /sys/class/net/wgmvp/ifalias) || return 1
    _mtu_public=$(_mtu_exec wg show wgmvp public-key) || return 1
    _mtu_current=$(_mtu_exec cat /sys/class/net/wgmvp/mtu) || return 1
    _mtu_uint "$_mtu_index" && _mtu_uint "$_mtu_current" || return 1
    [ "$_mtu_alias" = "$_mtu_expected_alias" ] && [ "$_mtu_public" = "$(cat "$ROOT/public.$ROLE")" ] || return 1
}
_mtu_read_record() {
    _mtu_safe "$_mtu_record" || return 1
    [ "$(wc -l < "$_mtu_record" | tr -d ' ')" = 10 ] || return 1
    [ "$(sed -n '1p' "$_mtu_record")" = "$OWNER" ] || return 1
    _mtu_saved_boot=$(sed -n '2p' "$_mtu_record") || return 1
    _mtu_deadline=$(sed -n '3p' "$_mtu_record") || return 1
    _mtu_old=$(sed -n '4p' "$_mtu_record") || return 1
    _mtu_target=$(sed -n '5p' "$_mtu_record") || return 1
    _mtu_uint "$_mtu_deadline" && _mtu_uint "$_mtu_old" && _mtu_uint "$_mtu_target" || return 1
    [ "$_mtu_old" -ge 1280 ] && [ "$_mtu_old" -le 1420 ] &&
        [ "$_mtu_target" -ge 1280 ] && [ "$_mtu_target" -le 1420 ]
}
mtu_probe_restore_locked() (
    _mtu_context && _mtu_lock_assert || exit 1
    [ -e "$_mtu_record" ] || exit 0
    _mtu_read_record || exit 1
    # A boot change destroys the old runtime interface. Never modify a new one.
    if [ "$_mtu_saved_boot" != "$_mtu_boot" ]; then rm "$_mtu_record"; exit $?; fi
    [ "$(sed -n '6p' "$_mtu_record")" = "$_mtu_config_hash" ] || exit 1
    _mtu_identity || exit 1
    [ "$(sed -n '7,10p' "$_mtu_record")" = "$(printf '%s\n' "$_mtu_ns" "$_mtu_index" "$_mtu_alias" "$_mtu_public")" ] || exit 1
    case "$_mtu_current" in "$_mtu_old"|"$_mtu_target") ;; *)
        # The known-owned device changed unexpectedly; quiesce it and preserve
        # the journal rather than overwrite an unexplained third MTU.
        _mtu_exec ip link set dev wgmvp down || exit 1
        exit 1;;
    esac
    _mtu_exec ip link set dev wgmvp mtu "$_mtu_old" || exit 1
    [ "$(_mtu_exec cat /sys/class/net/wgmvp/mtu)" = "$_mtu_old" ] || exit 1
    rm "$_mtu_record" || exit 1
)
mtu_probe_expire_locked() (
    _mtu_context && _mtu_lock_assert || exit 1
    [ -e "$_mtu_record" ] || exit 0
    _mtu_read_record || exit 1
    [ "$_mtu_saved_boot" = "$_mtu_boot" ] && [ "$_mtu_now" -lt "$_mtu_deadline" ] && exit 0
    mtu_probe_restore_locked
)
mtu_probe_begin_locked() (
    umask 077
    _mtu_context && _mtu_lock_assert || exit 1
    _mtu_target=${1:-}
    _mtu_uint "$_mtu_target" && [ "$_mtu_target" -ge 1280 ] && [ "$_mtu_target" -le 1420 ] || exit 1
    [ ! -e "$_mtu_record" ] && [ ! -e "$_mtu_record.new" ] || exit 1
    _mtu_safe "$ROOT/state/pending" || exit 1
    [ "$(sed -n '1p' "$ROOT/state/pending")" = "$OWNER" ] &&
        [ "$(sed -n '2p' "$ROOT/state/pending")" = "$_mtu_boot" ] || exit 1
    _mtu_lease_deadline=$(sed -n '4p' "$ROOT/state/pending") || exit 1
    _mtu_uint "$_mtu_lease_deadline" && [ "$_mtu_lease_deadline" -gt "$((_mtu_now+150))" ] || exit 1
    _mtu_identity || exit 1
    [ "$_mtu_current" = "$MTU" ] || exit 1
    # The coordinator checks permanent status BEFORE opening benchmark rules,
    # then verifies the exact approved snapshot before this call. Rechecking
    # permanent nft equality here would reject the owned temporary benchmark ACL.
    if [ "$ROLE" != gz ]; then . "$ROOT/router.sh"; router_check || exit 1; fi
    # Durable intent precedes the only runtime mutation. A killed coordinator
    # leaves a complete record for the independently managed watcher's expiry.
    (set -C; printf '%s\n' "$OWNER" "$_mtu_boot" "$((_mtu_now+120))" "$_mtu_current" "$_mtu_target" \
        "$_mtu_config_hash" "$_mtu_ns" "$_mtu_index" "$_mtu_alias" "$_mtu_public" > "$_mtu_record.new") || exit 1
    mv "$_mtu_record.new" "$_mtu_record" || exit 1
    if ! _mtu_exec ip link set dev wgmvp mtu "$_mtu_target"; then
        mtu_probe_restore_locked || :
        exit 1
    fi
    [ "$(_mtu_exec cat /sys/class/net/wgmvp/mtu)" = "$_mtu_target" ] || {
        mtu_probe_restore_locked || :; exit 1;
    }
)
