# Eight lectures on your WireGuard tunnel

**Current state:** after the working demonstration, you asked for gz's WireGuard socket to be closed. The hub interface was removed and the project cloud UDP allowance revoked. The tunnel is disconnected. These lectures explain the implemented architecture and its **earlier** observations, rather than claiming a currently working connection. [Closure evidence](.local/runs/20260927T143742Z-g6ids_la/); [deployment report](REPORT.md).

## 1. An overlay gives each router another address

Your administration paths remain separate from the tunnel:

```text
Administration                         Tunnel data when enabled
local -- SSH ------------> Villa        Villa V === gz G === Cave C
local -- SSH gpuxtcp --> GPU -- SSH rt --> Cave
local -- SSH gz ----------> gz
```

| Symbol | Machine | Overlay address |
|---|---|---|
| V | Villa | `10.203.77.2/32` |
| G | gz | `10.203.77.1/32` |
| C | Cave | `10.203.77.3/32` |

The reserved pool is `10.203.77.0/29`, but each interface receives a `/32`: one exact address. Explicit host routes connect these addresses. The pool supplies an allocation boundary, not an automatically connected subnet.

Villa's administration address remains `192.168.1.93` on its WAN. Its LAN is `10.9.0.0/24`; Cave's LAN is `10.8.0.0/24`. Neither LAN is advertised through WireGuard. Adding V and C does not move those networks or change the Internet gateway. An overlay address is another destination at which the same router can receive a packet, subject to its own ingress policy.

## 2. One inner packet travels in two successive outer packets

Suppose Villa originates an ICMP echo request to Cave:

```text
Inner packet:           [ IP V -> C | ICMP echo request ]
Villa-to-gz transport:  [ outer IP | UDP | WG-encrypted inner packet ]
                                      |
                                gz decrypts,
                                then forwards
                                      |
gz-to-Cave transport:   [ outer IP | UDP | WG-encrypted inner packet ]
```

The inner addresses describe the conversation. The outer addresses deliver encrypted UDP across the Internet. The first outer destination is gz's public IPv4 address, UDP `51820`. For the second leg, gz uses Cave's endpoint learned from authenticated packets. NAT can make that endpoint different from Cave's own WAN address.

Villa encrypts for gz. gz authenticates and decrypts, forwards the inner packet, then encrypts for Cave. Source V and destination C remain; ordinary forwarding changes the TTL. There is no inner NAT. These are serial encryptions: each Internet leg has one WireGuard encapsulation, not two nested ones.

The handshake establishes session keys; data uses symmetric authenticated encryption. Userspace tools configure interfaces, peers, routes, and policy. The Linux kernel processes the packets and performs encryption. [Protocol reference](https://www.wireguard.com/protocol/).

## 3. Routing, AllowedIPs, and firewall policy answer different questions

An operating-system route selects an interface for a destination. WireGuard's `AllowedIPs` then selects a peer using the **inner destination**. Firewall policy decides whether the particular traffic is permitted.

| Configuration on | Peer | Allowed inner addresses |
|---|---|---|
| Villa | gz | G/32, C/32 |
| Cave | gz | G/32, V/32 |
| gz | Villa | V/32 |
| gz | Cave | C/32 |

On reception, `AllowedIPs` instead checks whether the **inner source** belongs to the authenticated peer. If Villa sends an encrypted packet claiming source C, gz rejects it: Villa's key owns only V.

At Cave, source V is valid from gz because gz relays Villa's traffic. Cave authenticates gz on this link; it does not independently authenticate Villa's original packet.

Neither a route nor `AllowedIPs` means “TCP port 22 is permitted.” They establish forwarding choices and source ownership. Service restrictions belong to the firewall. A successful handshake therefore can coexist with deliberately denied SSH. [Cryptokey routing](https://www.wireguard.com/) and [wg(8)](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8).

## 4. gz's socket stays where it was born

A network namespace has its own interfaces, routes, sockets, and network policy. The implemented arrangement was:

```text
gz ordinary host namespace             namespace wgmvp
--------------------------             ----------------
public NIC + Internet routes           lo + wgmvp interface
existing SSH/web services              G, routes to V and C
encrypted UDP socket :51820  <------->  decrypted IP packets
host ingress policy                    exact ICMP policy
```

The WireGuard interface was created in gz's ordinary host namespace, then moved into `wgmvp`. Linux WireGuard retains its UDP socket in its birthplace namespace. Outer packets therefore use the host's Internet routes, while decrypted packets enter the isolated namespace. [Namespace documentation](https://www.wireguard.com/netns/).

The UDP socket belongs to kernel WireGuard, so no userspace server PID is required. Before closure, `ss` showed port `51820` without a `users:(...)` owner. That does not mean the listener was absent. Its reported `ssh.service` cgroup reflected creation through SSH; accounting attribution does not make sshd the WireGuard packet-processing server.

Inside `wgmvp`, there was no physical NIC, veth, default route, or management daemon. gz forwarded V-to-C packets through the same interface using different peers. Host forwarding settings remained unchanged. This separation prevents accidental ordinary network paths into gz's services; gz root still controls both contexts.

After closure, both IPv4 and IPv6 socket listings were empty for `51820`. The rollback supervisor can remain healthy while the endpoint is absent: supervision and packet transport have different lifetimes.

## 5. INPUT, OUTPUT, and FORWARD depend on the destination

An incoming packet destined for this machine takes INPUT. A packet generated here takes OUTPUT. A packet passing through takes FORWARD. For the inner echo exchange:

```text
request: Villa OUTPUT -> gz namespace FORWARD -> Cave INPUT
reply:   Cave OUTPUT  -> gz namespace FORWARD -> Villa INPUT
```

An echo addressed to G instead terminates in namespace INPUT. The outer UDP packet terminating at gz belongs to the host's input path. Keep outer and inner decisions separate.

The permanent policy permits exact overlay ICMP diagnostics and narrowly necessary related traffic. It denies administration arriving through `wgmvp` to **every router-local destination**, including existing WAN/LAN addresses. Blocking only SSH to C would leave other local destinations conceptually uncovered.

LAN access is a separate forwarding decision. Traffic crossing between the tunnel and a router's existing networks is denied in both directions. Disabling forwarding alone would not protect SSH on the router, because that packet terminates locally. The dedicated project zone and early ingress guard enforce those separate decisions. [Firewall chains](https://wiki.iptables.org/wiki-nftables/index.php/Configuring_chains).

## 6. The outer packet needs its own route around Mihomo

Cave already runs Mihomo. A correct inner route to V accomplishes nothing if the newly encrypted UDP packet is intercepted or sent down an unsuitable path.

The WireGuard socket uses mark `0x77203`. The deployed priority-1002 rule matches that mark **and the gz endpoint**, selecting the existing WAN route. The mark is local kernel metadata used for routing, not a header sent to gz or a cryptographic identity.

Separate priority-1000/1001 rules select local/main routing for the overlay pool. Early project guards precede proxy redirection. These targeted rules preserve existing proxy settings, ordinary Internet routing, and DNS. The recorded outer-route observation selected the existing gateway on `wan` for gz's public endpoint with mark `0x77203`.

## 7. A failed tunnel must not fall back to plaintext

Live `/32` routes are more specific than the persistent pool blackhole:

```text
live C/32 route present -> wgmvp -> encrypted transport
live C/32 route absent  -> pool blackhole -> discard
```

Without that fallback, removing a route could let the ordinary default route win. Project egress drops and policy/proxy handling complement the blackhole: a route in one table cannot control every other routing decision. The guard concerns the overlay pool, preserving ordinary networking. If a router interface remains up while the hub is gone, its route can still select WireGuard; that does not establish a functioning remote path.

Reaching public UDP `51820` also differs from entering the tunnel. An ordinary scanner lacks an authorized peer's private key and cannot turn arbitrary UDP into accepted inner traffic. This authentication does not make WireGuard look like HTTPS. Native WireGuard has no built-in HTTPS camouflage; the existing authenticated HTTPS/WebSocket recovery gateway is a separate service and never carried this tunnel. [Known limitations](https://www.wireguard.com/known-limitations/).

The hub is nevertheless trusted. gz sees plaintext between the two encryptions and can originate traffic claiming a source permitted from gz. Router policy restricts that traffic, but does not create end-to-end encryption excluding gz.

## 8. Six replies establish prior connectivity, not capacity

The earlier measurement sent three small ICMP packets each way, and all six received replies. The recorded ping summaries reported mean RTTs of **17.404 ms Villa → Cave** and **21.641 ms Cave → Villa**. These observations establish that both links carried traffic then. They do not establish stable loss rates, loaded latency, or throughput.

Configured MTU was **1380 bytes**, a conservative choice rather than a measured path maximum. Each Internet leg needs room for its outer IP, UDP, and WireGuard headers. Oversized packets can encounter path-MTU problems; small packets devote more bandwidth to overhead.

Capacity depends on the slower relevant link and the processing budget: Villa's upload, Cave's download, gz's bandwidth limits, CPU, RTT, and loss can all matter. Reversing direction changes that balance. No throughput, sustained-load, or MTU sweep was run, and no benchmark service remains active. Kernel packet processing explains the implementation; it does not supply a speed result.

## Inspect without sending test traffic

These commands read selected non-secret state. Namespace inspection on gz requires root privileges:

```sh
ssh root@192.168.1.93 'ip -4 route get 10.203.77.3'
ssh gpuxtcp 'ssh rt "ip -4 route get 10.203.77.2"'
ssh gz 'ss -lunp "sport = :51820"'
ssh gz 'ip netns list'
```

`ip route get` requests a routing decision without emitting a ping. Cave's nested command uses GPU's existing `rt` alias. After the requested closure, gz should have no `51820` listener or project namespace. These commands inspect configuration; they do not replace the earlier connectivity evidence.

## Concept check

If ICMP worked but overlay SSH was denied, was the tunnel broken? No: routing, authentication, and allowed ICMP could work while service policy rejected SSH. Did the missing PID mean no UDP listener existed? No: kernel WireGuard owned it. Should a missing overlay route send C through the default gateway? The pool guard should discard it. Could gz read carried packets? Yes: it terminated both encrypted links. Does a healthy rollback supervisor mean the tunnel is connected now? No: the requested endpoint closure is the current state.
