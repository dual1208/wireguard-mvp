# Primary references

Consulted 2026-09-27. These explain mechanisms; they do not certify this proposed deployment. Online main/master branches may differ from the installed release: the implementation agent must inspect and record the actual versions and relevant behavior.

[S1] WireGuard, conceptual overview and cryptokey routing:
https://www.wireguard.com/

[S2] WireGuard upstream `wg(8)`: AllowedIPs, endpoint learning, keepalive, public/private selectors, and secret-bearing dump format:
https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8

[S3] WireGuard, Protocol & Cryptography: handshake/session separation, UDP data format, replay protection, authenticated encryption:
https://www.wireguard.com/protocol/

[S4] WireGuard, Quick Start: interface setup and NAT keepalive:
https://www.wireguard.com/quickstart/

[S5] WireGuard, Routing & Network Namespace Integration: birthplace UDP socket and moved interface:
https://www.wireguard.com/netns/

[S6] WireGuard, Known Limitations: no native TCP transport, no built-in obfuscation, denial-of-service limitations:
https://www.wireguard.com/known-limitations/

[S7] OpenWrt, WireGuard server guide. Use for supported UCI concepts, NOT its broad LAN-zone trust policy in this project:
https://openwrt.org/docs/guide-user/services/vpn/wireguard/server

[S8] OpenWrt firewall4 source, generated input/forward/output rules and zone handling:
https://github.com/openwrt/firewall4/blob/master/root/usr/share/firewall4/templates/ruleset.uc

[S9] ESnet, iperf3 invocation and measurement options:
https://software.es.net/iperf/invoking.html

[S10] Netfilter nftables wiki, Configuring chains, including ACCEPT vs DROP across base chains:
https://wiki.iptables.org/wiki-nftables/index.php/Configuring_chains

[S11] WireGuard upstream `wg-quick(8)`: automatic routes, MTU, DNS options, and route ownership pitfalls:
https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8

The proposed namespace placement, policy whitelist, development workflow, and acceptance thresholds/measurement procedure are this project's design, not a vendor-provided ready-made configuration. Review and test them against the actual hosts.
