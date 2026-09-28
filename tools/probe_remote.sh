#!/bin/sh
# Read-only inventory. No package installation, writes, restarts, or secret dumps.
# Output still contains private topology and public-key identities; keep it private.
set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH
LC_ALL=C
export LC_ALL
role=${1:-unknown}

section() { printf '\n===== %s =====\n' "$1"; }
run() {
    printf '\nCOMMAND'
    for arg in "$@"; do printf ' [%s]' "$arg"; done
    printf '\n'
    "$@" 2>&1
    rc=$?
    printf '\nEXIT_STATUS %s\n' "$rc"
    return 0
}

section "IDENTITY ($role)"
run date -u
run id
run hostname
run uname -a
printf 'SSH_CONNECTION=%s\n' "${SSH_CONNECTION:-unavailable}"
[ ! -r /etc/os-release ] || run cat /etc/os-release
if command -v ubus >/dev/null 2>&1; then run ubus call system board; fi

section 'NETWORK STATE'
if command -v ip >/dev/null 2>&1; then
    run ip -d link show
    # BusyBox ip on some routers rejects -d; preserve a basic link observation.
    run ip link show
    run ip -4 address show
    run ip -6 address show
    run ip -4 route show table all
    run ip -6 route show table all
    run ip -4 rule show
    run ip -6 rule show
    run ip netns list
else
    printf 'MISSING ip: routes and namespace state are unknown\n'
fi

section 'LISTENING SOCKETS (NO PROCESS ARGUMENTS)'
if command -v ss >/dev/null 2>&1; then
    run ss -lntu
elif command -v netstat >/dev/null 2>&1; then
    run netstat -lntu
else
    printf 'MISSING ss and netstat: listeners are unknown\n'
fi

section 'CAPABILITIES AND VERSIONS'
for cmd in wg nft fw4 uci opkg apk iperf3 systemctl; do
    if command -v "$cmd" >/dev/null 2>&1; then
        printf 'AVAILABLE %s: ' "$cmd"
        command -v "$cmd"
    else
        printf 'UNAVAILABLE %s\n' "$cmd"
    fi
done
[ ! -d /sys/module/wireguard ] || printf 'WIREGUARD_MODULE_PRESENT\n'
if command -v wg >/dev/null 2>&1; then run wg --version; fi
if command -v nft >/dev/null 2>&1; then run nft --version; fi
if command -v iperf3 >/dev/null 2>&1; then run iperf3 --version; fi

section 'WIREGUARD NONSECRET SELECTORS (CURRENT NAMESPACE ONLY)'
if command -v wg >/dev/null 2>&1; then
    run wg show interfaces
    for field in public-key listen-port peers endpoints allowed-ips latest-handshakes transfer persistent-keepalive; do
        run wg show all "$field"
    done
fi

section 'FORWARDING AND RESOURCES'
if command -v sysctl >/dev/null 2>&1; then
    run sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter
fi
for f in /proc/net/dev /proc/stat /proc/meminfo; do
    [ ! -r "$f" ] || run cat "$f"
done

if [ "$role" = gpu ]; then
    section 'GPU-LOCAL rt ALIAS: SELECTED NONSECRET FIELDS'
    if command -v ssh >/dev/null 2>&1; then
        # Do not log ProxyCommand text: a user-defined command could include a token.
        # The nested Cave probe independently tests whether this alias actually works.
        ssh -G rt 2>/dev/null | awk '
          $1 == "hostname" || $1 == "user" || $1 == "port" { print }
          $1 == "proxycommand" || $1 == "proxyjump" {
            if ($2 != "none") print $1 " configured (value withheld)"
          }
        '
    fi
fi
section 'END OF READ-ONLY PROBE'
printf 'Full firewall policy, cloud policy, other namespaces, and secret-bearing config were NOT collected.\n'
