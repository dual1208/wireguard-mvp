#!/bin/sh
# Functions only. The coordinator verifies identity, fingerprints, recovery and
# package readiness before calling. write_payload writes nonsecret files to STAGE.
bootstrap_watch() {
    count=0
    while :; do
        pid=$(sed -n '3p' "$ROOT/state/watch" 2>/dev/null || true)
        case "$pid" in ''|*[!0-9]*) managed=;; *)
            if [ "$ROLE" = gz ]; then
                managed=$(systemctl show wgmvp.service -p MainPID --value)
            else
                managed=$(ubus call service list '{"name":"wgmvp"}' | jsonfilter -e '@.wgmvp.instances.*.pid')
            fi;;
        esac
        [ -n "$pid" ] && [ "$pid" = "$managed" ] && return 0
        count=$((count+1)); [ "$count" -lt 15 ] || return 1; sleep 1
    done
}
bootstrap_main() (
    set -eu
    umask 077
    ROLE=${1:?role}; ROOT=/etc/wgmvp; OWNER=wgmvp-r1
    case "$ROLE" in gz|villa|cave) ;; *) exit 1;; esac
    [ "$(id -u)" = 0 ]
    for cmd in wg ip nft sha256sum cmp flock timeout; do command -v "$cmd" >/dev/null; done
    timeout -s TERM -k 1 2 true
    # Stable lock inode is kept until explicit project removal.
    exec 8>/var/lock/wgmvp-bootstrap.lock
    flock -x -n 8 || { echo 'BLOCKED: another bootstrap owns the host lock' >&2; exit 1; }
    STAGE=$(mktemp -d /etc/wgmvp-bootstrap.XXXXXX)
    chmod 700 "$STAGE"
    write_payload
    find "$STAGE" -type f -exec chmod 600 '{}' \;
    [ "$(cat "$STAGE/owner")" = "$OWNER" ]
    [ -f "$STAGE/controller.sh" ] && [ -f "$STAGE/config.env" ]
    if [ -e "$ROOT" ]; then
        [ -d "$ROOT" ] && [ ! -L "$ROOT" ] && [ "$(cat "$ROOT/owner")" = "$OWNER" ]
        for f in "$STAGE"/*; do
            [ -f "$f" ] && cmp -s "$f" "$ROOT/${f##*/}" || {
                echo "BLOCKED: installed source differs: ${f##*/}" >&2; exit 1;
            }
        done
        # Remove only files this invocation just generated in its fresh stage.
        for f in "$STAGE"/*; do rm "$f"; done
        rmdir "$STAGE"
        bootstrap_watch || { echo 'BLOCKED: watcher does not match service manager' >&2; exit 1; }
        echo 'BOOTSTRAP unchanged'
        return 0
    fi
    if [ "$ROLE" = gz ]; then
        [ ! -e /etc/systemd/system/wgmvp.service ]
        [ ! -e /run/netns/wgmvp ]
        ! ip link show dev wgmvp >/dev/null 2>&1
        ! nft list table inet wgmvp_outer >/dev/null 2>&1
    else
        [ ! -e /etc/init.d/wgmvp ]
        ! ip link show dev wgmvp >/dev/null 2>&1
        ! nft list table inet wgmvp_guard >/dev/null 2>&1
        for section in network.wgmvp network.wgmvp_peer firewall.wgmvp firewall.wgmvp_diag_in firewall.wgmvp_diag_out; do
            ! uci -q show "$section" >/dev/null 2>&1
        done
        [ -z "$(uci changes network)$(uci changes firewall)" ]
    fi
    mkdir "$STAGE/backups"
    if [ "$ROLE" != gz ]; then
        cp -p /etc/config/network "$STAGE/backups/network.bootstrap"
        cp -p /etc/config/firewall "$STAGE/backups/firewall.bootstrap"
        chmod 600 "$STAGE/backups/"*
    fi
    wg genkey > "$STAGE/private.key"
    wg pubkey < "$STAGE/private.key" > "$STAGE/public.$ROLE"
    chmod 600 "$STAGE/private.key" "$STAGE/public.$ROLE"
    chmod 700 "$STAGE/controller.sh" "$STAGE/benchmark.sh" "$STAGE/security-probe.sh" "$STAGE/unknown-key.sh"
    mv "$STAGE" "$ROOT"
    # A failure here leaves no interface/routes; retain the owned directory for
    # diagnosis. Service startup runs a watcher, not an unarmed project interface.
    if [ "$ROLE" = gz ]; then
        cp "$ROOT/wgmvp.service" /etc/systemd/system/wgmvp.service
        chmod 644 /etc/systemd/system/wgmvp.service
        systemctl daemon-reload
        systemctl enable --now wgmvp.service
    else
        cp "$ROOT/wgmvp.init" /etc/init.d/wgmvp
        chmod 755 /etc/init.d/wgmvp
        /etc/init.d/wgmvp enable
        /etc/init.d/wgmvp start
    fi
    bootstrap_watch
    # Exercise the installed rollback handler before creating any network state.
    "$ROOT/controller.sh" arm
    "$ROOT/controller.sh" rollback
    [ -f "$ROOT/state/rolledback" ]
    echo 'BOOTSTRAP installed; host-local rollback exercised with no data path'
)

bootstrap_remove() (
    set -eu
    umask 077
    ROLE=${1:?role}; ROOT=/etc/wgmvp; OWNER=wgmvp-r1
    exec 8>/var/lock/wgmvp-bootstrap.lock
    flock -x -n 8 || exit 1
    [ -e "$ROOT" ] || { echo 'REMOVE already absent'; return 0; }
    [ ! -L "$ROOT" ] && [ "$(cat "$ROOT/owner")" = "$OWNER" ]
    "$ROOT/controller.sh" remove
    if [ "$ROLE" = gz ]; then
        cmp -s "$ROOT/wgmvp.service" /etc/systemd/system/wgmvp.service
        systemctl disable --now wgmvp.service
        rm /etc/systemd/system/wgmvp.service
        systemctl daemon-reload
    else
        cmp -s "$ROOT/wgmvp.init" /etc/init.d/wgmvp
        /etc/init.d/wgmvp disable
        /etc/init.d/wgmvp stop
        rm /etc/init.d/wgmvp
    fi
    mkdir -p /var/lib/wgmvp-archive
    chmod 700 /var/lib/wgmvp-archive
    archive=/var/lib/wgmvp-archive/$(date -u +%Y%m%dT%H%M%SZ)-$$
    [ ! -e "$archive" ]
    mv "$ROOT" "$archive"
    echo 'REMOVE complete; original backups and owner keys retained in root-only archive'
)
