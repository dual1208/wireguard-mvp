#!/bin/sh
# Independent lease for a compatible, new-package-only installation.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
STATE=${WGMVP_PACKAGE_STATE:-/root/wgmvp-packages-before}
PROC=${WGMVP_PROC_ROOT:-/proc}
LOCK=${WGMVP_PACKAGE_LOCK:-/var/lock/wgmvp-bootstrap.lock}
EXPECTED=wgmvp-packages-r1
HELD=0
fail() { printf 'wgmvp-packages: %s\n' "$*" >&2; exit 1; }
uint() { case "$1" in ''|*[!0-9]*) return 1;; esac; }
field() { sed -n "${2}p" "$1"; }
secure() {
    [ ! -L "$1" ] && [ -e "$1" ] || fail 'missing or symlinked package guard input'
    # BusyBox on Villa has no stat applet; numeric ls ownership is available.
    set -- $(ls -ldn "$1")
    [ "$3" = 0 ] || fail 'package guard inputs must belong to root'
    case "$1" in drwx------|dr-x------|-rwx------|-rw-------|-r-x------|-r--------) ;;
        *) fail 'package guard inputs must be root-only';; esac
}
now() { read -r stamp rest < "$PROC/uptime"; stamp=${stamp%%.*}; uint "$stamp" || fail 'invalid monotonic clock'; printf '%s\n' "$stamp"; }
process_start() {
    uint "$1" && [ -r "$PROC/$1/stat" ] || return 1
    line=$(cat "$PROC/$1/stat") || return 1
    printf '%s\n' "${line##*) }" | awk '$1 != "Z" && NF >= 20 { print $20 }'
}
publish() { name=$1; shift; printf '%s\n' "$@" > "$STATE/.$name.$$"; mv -f "$STATE/.$name.$$" "$STATE/$name"; }
release() { if [ "$HELD" = 1 ]; then exec 9>&-; HELD=0; fi; }
take_lock() {
    command -v flock >/dev/null 2>&1 || fail 'flock is required'
    if [ "${WGMVP_PACKAGE_LOCK_FD:-}" = 9 ]; then
        [ "$PROC/$$/fd/9" -ef "$LOCK" ] || fail 'inherited installer lock is not the project lock'
    else
        [ ! -L "$LOCK" ] || fail 'package lock must not be a symlink'
        exec 9>"$LOCK"
    fi
    flock -x -n 9 || { exec 9>&-; return 1; }
    HELD=1
    trap release EXIT
    trap 'exit 1' HUP INT TERM
}
watch_live() {
    [ -f "$STATE/watch" ] && [ "$(field "$STATE/watch" 1)" = "$EXPECTED" ] || return 1
    [ "$(field "$STATE/watch" 2)" = "$BOOT" ] || return 1
    pid=$(field "$STATE/watch" 3); start=$(field "$STATE/watch" 4); tick=$(field "$STATE/watch" 5)
    uint "$tick" || return 1
    actual=$(process_start "$pid") || return 1
    [ -n "$actual" ] && [ "$actual" = "$start" ] || return 1
    current=$(now)
    [ "$current" -ge "$tick" ] && [ $((current - tick)) -le 12 ]
}
lease_live() {
    [ -f "$STATE/pending" ] && [ "$(field "$STATE/pending" 1)" = "$EXPECTED" ] || return 1
    [ "$(field "$STATE/pending" 2)" = "$BOOT" ] || return 1
    began=$(field "$STATE/pending" 3); deadline=$(field "$STATE/pending" 4)
    uint "$began" && uint "$deadline" || return 1
    [ $((deadline - began)) -eq 300 ] || return 1
    current=$(now)
    [ "$current" -ge "$began" ] && [ "$current" -lt "$deadline" ]
}
rollback_locked() {
    plan="$STATE/rollback-plan.$$"
    "$STATE/rollback.sh" plan > "$plan" || { publish result "$EXPECTED" rollback-plan-failed "$BOOT" "$(now)"; return 1; }
    while IFS= read -r package || [ -n "$package" ]; do
        case "$package" in ''|*[!a-zA-Z0-9.+:_-]*) fail 'rollback plan contains an invalid package name';; esac
        grep -Fxq "$package" "$STATE/new-packages.txt" || fail 'rollback proposes an unapproved package'
        if grep -Fxq "$package" "$STATE/baseline.txt"; then fail 'rollback proposes a baseline package'; fi
    done < "$plan"
    # apply receives the checked plan, not arbitrary manager output or arguments.
    "$STATE/rollback.sh" apply "$plan" || { publish result "$EXPECTED" rollback-apply-failed "$BOOT" "$(now)"; return 1; }
    publish result "$EXPECTED" rolledback "$BOOT" "$(now)"
    rm -f "$STATE/pending"
}

secure "$STATE"
for input in role.env baseline.txt baseline.ready new-packages.txt rollback.sh; do secure "$STATE/$input"; done
[ -s "$STATE/baseline.txt" ] && [ -x "$STATE/rollback.sh" ] || fail 'baseline or rollback handler is not ready'
[ "$(cat "$STATE/baseline.ready")" = "$EXPECTED" ] || fail 'baseline backup was not attested ready'
saved_state=$STATE
. "$STATE/role.env"
[ "$STATE" = "$saved_state" ] && [ "${OWNER:-}" = "$EXPECTED" ] || fail 'package state ownership mismatch'
case "${MANAGER:-}" in opkg|apk|apt) ;; *) fail 'invalid package manager';; esac
while IFS= read -r package || [ -n "$package" ]; do
    case "$package" in ''|*[!a-zA-Z0-9.+:_-]*) fail 'invalid approved package name';; esac
    if grep -Fxq "$package" "$STATE/baseline.txt"; then fail 'approved new package was already installed in baseline'; fi
done < "$STATE/new-packages.txt"
[ -s "$STATE/new-packages.txt" ] || fail 'no approved new packages'
read -r BOOT < "$PROC/sys/kernel/random/boot_id"
case "$BOOT" in ''|*[!a-fA-F0-9-]*) fail 'invalid boot identity';; esac
START=$(process_start $$); uint "$START" || fail 'cannot establish process identity'
action=${1:-status}
case "$action" in
    check) watch_live && lease_live || fail 'live watcher and unexpired pending lease required'; printf 'LEASE active\n'; exit;;
    status)
        if watch_live; then printf 'WATCH healthy\n'; else printf 'WATCH unavailable\n'; fi
        if lease_live; then printf 'LEASE active\n'; elif [ -f "$STATE/pending" ]; then printf 'LEASE expired-or-boot-changed\n'; else printf 'LEASE absent\n'; fi
        exit;;
    arm|commit|watch|rollback) ;;
    *) fail 'usage: package-guard.sh arm|commit|watch|rollback|status|check';;
esac

if [ "$action" = watch ]; then
    take_lock || fail 'installer currently holds package lock; service should retry'
    watch_live && fail 'a package watcher is already running'
    publish watch "$EXPECTED" "$BOOT" "$$" "$START" "$(now)"
    release
    trap 'exit 0' HUP INT TERM
    while :; do
        publish watch "$EXPECTED" "$BOOT" "$$" "$START" "$(now)"
        if [ -f "$STATE/pending" ] && ! lease_live; then
            if take_lock; then
                # Commit may have won the race while the watcher acquired the lock.
                if [ -f "$STATE/pending" ] && ! lease_live; then
                    rollback_locked || printf 'wgmvp-packages: rollback failed; pending retained for retry\n' >&2
                fi
                release
                trap 'exit 0' HUP INT TERM
            fi
        fi
        sleep 3
    done
fi

take_lock || fail 'installer currently holds package lock'
case "$action" in
    arm)
        [ ! -e "$STATE/pending" ] || fail 'a package transaction is already pending'
        watch_live || fail 'verify the independent watcher service before arming'
        tick=$(now)
        publish pending "$EXPECTED" "$BOOT" "$tick" "$((tick + 300))"
        printf 'ARMED package lease=300\n';;
    commit)
        watch_live && lease_live || fail 'cannot commit without a healthy watcher and live lease'
        publish result "$EXPECTED" committed "$BOOT" "$(now)"
        rm "$STATE/pending"
        printf 'COMMITTED\n';;
    rollback) rollback_locked;;
esac
