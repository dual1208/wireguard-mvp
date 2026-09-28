#!/bin/sh
# Read-only supplemental discovery. Never prints raw network/proxy configuration.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
export PATH
role=${1:?role}
run() { printf '\nCOMMAND'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; "$@" 2>&1; printf '\nEXIT_STATUS %s\n' "$?"; }
run id
run sha256sum /etc/machine-id /etc/ssh/ssh_host_ed25519_key.pub /etc/dropbear/dropbear_ed25519_host_key /etc/config/network /etc/config/firewall
run df -h
run cat /proc/loadavg
run free -m
run sh -c 'cat /proc/cpuinfo | sed -n "1,30p"'
run sh -c 'cat /proc/modules | cut -d " " -f 1'
run ls /sys/class/net
if [ "$role" = gpu ]; then
 run sudo -n nft list ruleset
 run sudo -n ip -n daens -4 addr
 run sudo -n ip -n daens -4 route show table all
 run sudo -n ip -n daens -4 rule
 run sudo -n lsns -t net -o NS,TYPE,NPROCS,PID
else
 run nft -a list ruleset
 run sh -c 'command -v iptables-save >/dev/null && iptables-save'
 run sh -c 'command -v ip6tables-save >/dev/null && ip6tables-save'
 run sh -c 'ls /proc/[0-9]*/ns/net 2>/dev/null | while read p; do readlink "$p"; done | sort -u'
fi
if [ "$role" = villa ] || [ "$role" = cave ]; then
 run uci show firewall
 run sh -c 'uci changes | wc -l'
 run ls -l /lib/netifd/proto/wireguard.sh
 run cat /lib/netifd/proto/wireguard.sh
 run ls /etc/init.d
 run ls /etc/nftables.d
 run ls /usr/share/nftables.d
 run sh -c 'find /etc /usr/share/nftables.d -maxdepth 3 -type f \( -name "*e8450*" -o -name "*mihomo*" -o -name "*frp*" -o -name "*passwall*" \) 2>/dev/null'
 run sh -c 'for p in /proc/[0-9]*/comm; do n=$(cat "$p" 2>/dev/null); case "$n" in *mihomo*|*e8450*|*frp*) printf "%s %s\n" "$p" "$n";; esac; done'
 run ip -4 route get 10.203.77.1
 run ip -4 route get 8.163.2.191
 if command -v opkg >/dev/null; then
  run opkg list-installed
  run opkg info iperf3
 else
  run apk info
  run apk policy kmod-wireguard wireguard-tools ip-full tcpdump
  run apk info kernel
 fi
else
 run sh -c 'command -v systemctl >/dev/null && systemctl list-units --type=service --state=running --no-pager'
 run sh -c 'command -v lsns >/dev/null && lsns -t net -o NS,TYPE,NPROCS,PID'
 if [ "$role" = gz ]; then
  run modinfo wireguard
  run sh -c 'grep "CONFIG_NET_NS\|CONFIG_WIREGUARD" /boot/config-$(uname -r)'
  run apt-cache policy wireguard-tools iperf3 tcpdump
  run apt-get --simulate --no-install-recommends install wireguard-tools iperf3 tcpdump
  run ss -lntup
  run docker ps --format '{{.Names}} {{.Ports}}'
  run curl --noproxy '*' --silent --show-error --max-time 5 http://100.100.100.200/latest/meta-data/eipv4
  run curl --noproxy '*' --silent --show-error --max-time 5 http://100.100.100.200/latest/meta-data/public-ipv4
 fi
fi
