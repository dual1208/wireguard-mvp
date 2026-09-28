#!/bin/sh
# Project-local lease supervisor. No private keys are read by this controller.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
ROOT=${WGMVP_ROOT:-/etc/wgmvp}
PROC=${WGMVP_PROC_ROOT:-/proc}
SELF=$ROOT/controller.sh
STATE=$ROOT/state
LOCK=$STATE/lock
EXPECTED_OWNER=wgmvp-r1
LOCK_HELD=0
LOCK_TOKEN=

fail() { printf 'wgmvp: %s\n' "$*" >&2; exit 1; }
uint() { case "$1" in ''|*[!0-9]*) return 1;; esac; }
field() { sed -n "${2}p" "$1"; }
now() {
    read -r uptime unused < "$PROC/uptime"
    uptime=${uptime%%.*}
    uint "$uptime" || fail 'invalid monotonic clock'
    printf '%s\n' "$uptime"
}
boot() {
    read -r boot_id < "$PROC/sys/kernel/random/boot_id"
    case "$boot_id" in ''|*[!a-fA-F0-9-]*) fail 'invalid boot identity';; esac
    printf '%s\n' "$boot_id"
}
process_start() {
    uint "$1" || return 1
    [ -r "$PROC/$1/stat" ] || return 1
    stat_line=$(cat "$PROC/$1/stat") || return 1
    # comm may itself contain spaces or parentheses. Start time is field 22.
    printf '%s\n' "${stat_line##*) }" | awk '$1 != "Z" && NF >= 20 { print $20 }'
}
alive() {
    [ "$1" = "$BOOT" ] || return 1
    actual=$(process_start "$2") || return 1
    [ -n "$actual" ] && [ "$actual" = "$3" ]
}
publish() {
    name=$1; shift
    printf '%s\n' "$@" > "$STATE/.$name.$$"
    mv -f "$STATE/.$name.$$" "$STATE/$name"
}
record_owner() {
    [ -f "$1" ] && [ "$(field "$1" 1)" = "$EXPECTED_OWNER" ]
}
release() {
    if [ "$LOCK_HELD" = 1 ]; then
        if [ -f "$LOCK/identity" ] && [ "$(cat "$LOCK/identity")" = "$LOCK_TOKEN" ]; then
            rm -f "$LOCK/identity"
            rmdir "$LOCK" || :
        fi
        # Closing our copy preserves exclusion while any role child retains FD 9.
        exec 9>&-
    fi
    LOCK_HELD=0
}
acquire() {
    command -v flock >/dev/null 2>&1 || fail 'flock is required before network changes'
    [ ! -L "$STATE/mutex" ] || fail 'mutex must not be a symlink'
    exec 9>"$STATE/mutex"
    lock_wait_started=$(now)
    while ! flock -x -n 9; do
        lock_wait_now=$(now)
        [ "$lock_wait_now" -ge "$lock_wait_started" ] &&
            [ $((lock_wait_now - lock_wait_started)) -lt 45 ] || fail 'another project operation still holds the kernel lock'
        sleep 1
    done
    LOCK_HELD=1
    trap release EXIT
    trap 'exit 1' HUP INT TERM
    # The inherited kernel lock proves no previous role worker is still running.
    # mkdir metadata remains useful for identity audit and detecting foreign state.
    if [ -d "$LOCK" ]; then
        if [ -f "$LOCK/identity" ]; then
            record_owner "$LOCK/identity" || fail 'lock ownership is foreign'
            lock_boot=$(field "$LOCK/identity" 2)
            lock_pid=$(field "$LOCK/identity" 3)
            lock_start=$(field "$LOCK/identity" 4)
            uint "$lock_pid" && uint "$lock_start" || fail 'invalid lock identity'
            alive "$lock_boot" "$lock_pid" "$lock_start" && fail 'live lock identity exists without kernel ownership'
            rm "$LOCK/identity"
        fi
        # An empty directory is an interrupted mkdir after kernel-lock acquisition.
        rmdir "$LOCK" || fail 'unexpected contents in project lock'
    fi
    mkdir "$LOCK"
    LOCK_TOKEN=$(printf '%s\n' "$EXPECTED_OWNER" "$BOOT" "$$" "$START")
    printf '%s\n' "$LOCK_TOKEN" > "$STATE/.lock-identity.$$"
    mv "$STATE/.lock-identity.$$" "$LOCK/identity"
}
watch_live() {
    record_owner "$STATE/watch" || return 1
    watch_boot=$(field "$STATE/watch" 2)
    watch_pid=$(field "$STATE/watch" 3)
    watch_start=$(field "$STATE/watch" 4)
    watch_time=$(field "$STATE/watch" 5)
    uint "$watch_time" || return 1
    alive "$watch_boot" "$watch_pid" "$watch_start" || return 1
    current=$(now)
    [ "$current" -ge "$watch_time" ] && [ $((current - watch_time)) -le 12 ]
}
load_pending() {
    record_owner "$STATE/pending" || return 2
    PBOOT=$(field "$STATE/pending" 2)
    PBEGIN=$(field "$STATE/pending" 3)
    PDEADLINE=$(field "$STATE/pending" 4)
    PMAX=$(field "$STATE/pending" 5)
    uint "$PBEGIN" && uint "$PDEADLINE" && uint "$PMAX" || return 2
    [ "$PBEGIN" -le "$PDEADLINE" ] && [ "$PDEADLINE" -le "$PMAX" ] &&
       [ $((PMAX - PBEGIN)) -eq 3600 ] || return 2
}
pending_live() {
    load_pending || return $?
    current=$(now)
    [ "$PBOOT" = "$BOOT" ] && [ "$current" -ge "$PBEGIN" ] && [ "$current" -lt "$PDEADLINE" ]
}
role() {
    # timeout is a bootstrap prerequisite. Role functions must not background writers.
    command -v timeout >/dev/null 2>&1 || fail 'timeout is required before network changes'
    WGMVP_LOCK_TOKEN=$LOCK_TOKEN WGMVP_ROOT=$ROOT WGMVP_PROC_ROOT=$PROC \
        timeout -s TERM -k 5 35 "$SELF" _role "$1"
}
rollback_locked() {
    reason=$1
    # Leave pending intact if stopping fails, so a later watch/reconcile retries.
    role stop || fail 'role stop failed; rollback remains pending'
    publish rolledback "$EXPECTED_OWNER" "$BOOT" "$(now)" "$reason"
    rm -f "$STATE/pending" "$STATE/committed"
}
pending_failed() {
    if [ "$1" = 2 ]; then
        role stop || fail 'invalid pending record and role stop failed; inspect host-local state'
        fail 'invalid pending record; project stopped and state preserved for inspection'
    fi
    rollback_locked "$2"
}
reconcile_locked() {
    [ -f "$STATE/pending" ] || return 0
    if pending_live; then :; else
        pending_failed "$?" lease-expired-or-boot-changed
    fi
}

[ -f "$ROOT/config.env" ] || fail 'missing host-local config.env'
config_root=$ROOT
. "$ROOT/config.env"
[ "$ROOT" = "$config_root" ] || fail 'config.env must not replace ROOT'
[ "${OWNER:-}" = "$EXPECTED_OWNER" ] || fail 'configuration ownership mismatch'
case "${ROLE:-}" in gz) prefix=hub;; villa|cave) prefix=router;; *) fail 'invalid ROLE';; esac
[ -f "$ROOT/$prefix.sh" ] || fail 'role implementation is not installed'
BOOT=$(boot)
START=$(process_start $$)
uint "$START" || fail 'cannot establish process identity'

action=${1:-status}
if [ "$action" = _role ]; then
    case "${2:-}" in start|stop|status|remove) ;; *) fail 'invalid role action';; esac
    if [ "$2" != status ]; then
        [ -n "${WGMVP_LOCK_TOKEN:-}" ] && [ -f "$LOCK/identity" ] &&
            [ "$(cat "$LOCK/identity")" = "$WGMVP_LOCK_TOKEN" ] || fail 'role invocation requires the current lock token'
    fi
    . "$ROOT/$prefix.sh"
    cleanup_failed=0
    if [ "$2" != status ]; then
        # A fresh shell keeps conditional error handling from suppressing
        # errexit inside helpers. Failed auxiliary cleanup must not prevent
        # shutdown of the production interface on an expired lease.
        if timeout -s TERM -k 1 12 sh -c '
            set -eu
            ROOT=$1; . "$ROOT/config.env"
            if [ -f "$ROOT/unknown-key.sh" ]; then WGMVP_UNKNOWN_SOURCE_ONLY=1; . "$ROOT/unknown-key.sh"; unknown_cleanup_locked; fi
            if [ -f "$ROOT/security-probe.sh" ]; then WGMVP_PROBE_SOURCE_ONLY=1; . "$ROOT/security-probe.sh"; probe_close_locked; fi
            if [ -f "$ROOT/benchmark.sh" ]; then . "$ROOT/benchmark.sh"; benchmark_cleanup_locked; fi
            if [ -f "$ROOT/spoof-lab.sh" ]; then . "$ROOT/spoof-lab.sh"; spoof_lab_cleanup_all; fi
        ' wgmvp-cleanup "$ROOT"; then :; else
            cleanup_failed=1
            printf 'wgmvp: auxiliary cleanup failed; preserving evidence\n' >&2
            [ "$2" = stop ] || exit 1
        fi
    fi
    if [ "$2" = start ] && [ "$prefix" = router ]; then
        wait_count=0
        until ubus -S call network.interface dump >/dev/null 2>&1; do
            wait_count=$((wait_count + 1))
            [ "$wait_count" -lt 25 ] || exit 75
            sleep 1
        done
    fi
    if [ "$2" = remove ] && [ "$prefix" = hub ]; then hub_stop;
    else "${prefix}_$2"; fi
    [ "$cleanup_failed" = 0 ] || exit 1
    exit
fi

case "$action" in start|stop|status|arm|renew|commit|rollback|reconcile|watch|remove) ;; *) fail 'usage: controller.sh start|stop|status|arm|renew|commit|rollback|reconcile|watch|remove';; esac
if [ "$action" = status ]; then
        if watch_live; then printf 'WATCH healthy\n'; else printf 'WATCH unavailable\n'; fi
        if [ -f "$STATE/pending" ]; then
            if pending_live; then printf 'LEASE pending deadline=%s now=%s\n' "$PDEADLINE" "$current";
            else printf 'LEASE expired-or-boot-changed\n'; fi
        elif record_owner "$STATE/committed"; then printf 'STATE committed\n';
        elif record_owner "$STATE/rolledback"; then printf 'STATE rolledback\n';
        else printf 'STATE unarmed\n'; fi
        role status
    exit
fi
mkdir -p "$STATE"
if [ "$action" = watch ]; then
    acquire
    if watch_live; then fail 'a verified project watcher is already running'; fi
    reconcile_locked
    publish watch "$EXPECTED_OWNER" "$BOOT" "$$" "$START" "$(now)"
    if [ ! -f "$STATE/pending" ] && [ -f "$STATE/committed" ]; then
        record_owner "$STATE/committed" || fail 'committed revision has invalid ownership'
        if role start; then :; else
            start_status=$?
            case "$start_status" in
                75|124|137) role stop || :; fail 'startup readiness timed out; committed intent retained';;
                *) rollback_locked committed-start-failed; fail 'committed role failed integrity/startup checks';;
            esac
        fi
    fi
    release
    trap 'exit 0' HUP INT TERM
    while :; do
        publish watch "$EXPECTED_OWNER" "$BOOT" "$$" "$START" "$(now)"
        # Reconciliation failure remains visible in service logs and is retried.
        "$SELF" reconcile || printf 'wgmvp: reconciliation failed; will retry\n' >&2
        if [ -x "$ROOT/security-probe.sh" ]; then "$ROOT/security-probe.sh" expire || :; fi
        if [ -x "$ROOT/benchmark.sh" ]; then "$ROOT/benchmark.sh" expire || :; fi
        sleep 3
    done
fi

acquire
case "$action" in
    arm)
        [ ! -e "$STATE/pending" ] || fail 'pending revision already exists; renew or roll it back'
        watch_live || fail 'a live service-managed watcher is required before arming'
        current=$(now)
        publish pending "$EXPECTED_OWNER" "$BOOT" "$current" "$((current + 300))" "$((current + 3600))"
        printf 'ARMED lease=300 maximum=3600\n'
        ;;
    renew)
        watch_live || fail 'watcher is not healthy'
        if pending_live; then :; else pending_failed "$?" lease-expired-before-renew; fail 'expired lease rolled back'; fi
        next=$((current + 300))
        [ "$next" -le "$PMAX" ] || next=$PMAX
        [ "$next" -gt "$current" ] || fail 'maximum lease deadline reached'
        publish pending "$EXPECTED_OWNER" "$PBOOT" "$PBEGIN" "$next" "$PMAX"
        printf 'RENEWED\n'
        ;;
    commit)
        watch_live || fail 'watcher is not healthy'
        if pending_live; then :; else pending_failed "$?" lease-expired-before-commit; fail 'expired lease rolled back'; fi
        publish committed "$EXPECTED_OWNER" "$BOOT" "$(now)"
        rm "$STATE/pending"
        printf 'COMMITTED\n'
        ;;
    start)
        watch_live || fail 'watcher is not healthy'
        if [ -f "$STATE/pending" ]; then
            if pending_live; then :; else pending_failed "$?" lease-expired-before-start; fail 'expired lease rolled back'; fi
            [ $((PDEADLINE - current)) -ge 45 ] || fail 'renew the lease before starting a bounded role operation'
        else
            record_owner "$STATE/committed" || fail 'arm a guarded revision before starting'
        fi
        role start || { rollback_locked start-failed; fail 'role failed to start and was stopped'; }
        # A slow successful start may have consumed the lease; check again.
        reconcile_locked
        ;;
    stop) role stop;;
    rollback) rollback_locked explicit-rollback;;
    remove)
        role remove
        publish rolledback "$EXPECTED_OWNER" "$BOOT" "$(now)" explicit-removal
        rm -f "$STATE/pending" "$STATE/committed"
        ;;
    reconcile) reconcile_locked;;

esac
