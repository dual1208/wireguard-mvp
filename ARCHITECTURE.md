# Selected architecture

## Decision: trusted hub, isolated forwarding on gz

```text
Independent administration, NOT the new data path:

local ---- SSH ----------------------------> Villa
local ---- SSH gpuxtcp ----> GPU ---- SSH rt -> Cave
local ---- SSH gz -------------------------> gz

New data path:

Villa ===== WireGuard link V-G ===== gz ===== WireGuard link G-C ===== Cave
                                     |
                              decrypt, route,
                                re-encrypt
```

Both routers initiate outbound UDP to the verified public gz endpoint. Each router has one peer, gz. gz has two peers, one for each router. The routers do not have a direct cryptographic session with one another in this design. Normal per-link session keys are maintained by WireGuard. [S1, S3]

This choice avoids a new relay protocol and nested encryption. gz remains trusted with inner traffic. A future requirement that even gz root cannot inspect or originate valid inner traffic requires a different/end-to-end design, not an optimistic firewall comment.

## Keep ordinary gz networking separate

```text
gz host namespace                         gz namespace: wgmvp
-----------------                         --------------------
physical NIC, existing routes             lo + wgmvp only
existing sshd and other services           three overlay host addresses/routes
WireGuard encrypted UDP socket  <-------> WireGuard decrypted interface
host firewall: selected UDP port          namespace firewall: narrow whitelist
host forwarding settings UNCHANGED        IPv4 forwarding enabled only here
```

Linux WireGuard retains its UDP socket in the namespace where the interface was created, even after the interface is moved. Use that documented property. [S5]

Required construction order, expressed as an implementation recipe rather than a blind live script:

1. Verify `wgmvp` names are unused and the host supports the necessary capabilities.
2. Create the namespace with only its loopback interface.
3. Prepare namespace-local policy, IPv4 forwarding, and fail-closed routes while no traffic is admitted. Disable unnecessary redirect acceptance/sending in this namespace; do not change host-namespace sysctls.
4. Create the WireGuard interface in the **ordinary gz host namespace**; keep it down initially.
5. Move only that newly created interface into `wgmvp`.
6. Configure keys, peers, addresses, routes, and firewall inside `wgmvp`.
7. Permit the selected outer UDP listener through the existing host firewall manager.
8. Bring the project interface up and verify both namespace and host observations.

Do not run `wg-quick up` inside a network-isolated namespace and expect its newly created UDP socket to find the Internet. Do not add a veth, bridge, namespace default route, general NAT, or a new SSH daemon there. Do not copy the unrelated “move all physical interfaces” example from the WireGuard namespaces page. [S5]

This namespace is an accidental-connectivity boundary, not a VM or protection against privileged gz access or a host-kernel vulnerability. Its temporary diagnostic processes share the host filesystem unless additional isolation is explicitly provided; never call it a full sandbox.

## Candidate addressing, subject to discovery

```text
Reserved project pool: 10.203.77.0/29
G = gz hub:             10.203.77.1/32
V = Villa:              10.203.77.2/32
C = Cave:               10.203.77.3/32
```

Reserve the pool only after checking local, GPU, both routers, gz, existing namespaces, all relevant routing tables, proxy policies, and VPNs. Assign `/32`s, not a connected `/29`. Actual host routes are explicit; the unused pool can support a less-specific blackhole guard.

Peer membership and AllowedIPs:

| Location | Peer key | Allowed inner addresses |
|---|---|---|
| Villa | gz public key | G/32, C/32 |
| Cave | gz public key | G/32, V/32 |
| gz namespace | Villa public key | V/32 |
| gz namespace | Cave public key | C/32 |

On sending, AllowedIPs chooses a peer by inner destination. On receiving, it validates the inner source against the authenticated peer. OS routes still determine whether the packet reaches the WireGuard interface. [S1, S2]

Add OS host routes corresponding to the remote AllowedIPs on each router and both peer host routes in the gz namespace. Use a single clearly identified configuration owner for those routes; do not mix netifd, wg-quick, and independent scripts owning the same route.

## One packet: Villa pings Cave

```text
Villa creates:  [IP V -> C | ICMP echo request]
  OS route: C/32 -> wgmvp
  WireGuard: destination C -> peer key gz
  Internet: [outer IP Villa-current-endpoint -> gz | UDP | encrypted inner]

gz host namespace receives the outer UDP packet
  WireGuard authenticates Villa and decrypts into namespace wgmvp
  check: inner source V belongs to Villa's public key
  namespace route: C/32 -> wgmvp
  namespace FORWARD: V -> C ICMP is permitted
  WireGuard: destination C -> peer key Cave
  Internet: [outer IP gz -> Cave-current-endpoint | UDP | encrypted inner]

Cave authenticates gz
  check: inner source V is allowed from gz
  destination C is local, so use INPUT, not FORWARD
  router INPUT: V -> C ICMP is permitted
  ICMP echo reply takes the reverse path
```

There is no inner-address translation between V and C. The forwarding gz kernel performs ordinary IP forwarding, including the usual TTL change. The two encryptions are serial on different links, not nested on the same packet on one link. [S1, S3, S5]

## Routes must fail closed

Install a project-specific blackhole/unreachable route for the reserved pool that remains when the live `/32` WireGuard routes are removed. Also prevent project-destination packets from leaving via non-project interfaces, accounting for policy routing, local OUTPUT, forwarded traffic, and proxy redirection. A blackhole in the main table alone is not sufficient when another routing table or transparent proxy can bypass it.

Do not install a global Internet kill switch. Ordinary Internet, DNS, and recovery traffic must keep their original path. The gz namespace has no non-WireGuard egress; gz's host namespace must not acquire routes to the overlay as part of this project.

## Reachability and restart

Use `PersistentKeepalive = 25` on each router's peer to gz as an initial NAT-maintenance setting. gz normally learns the routers' current endpoints from authenticated packets; do not hardcode their transient NAT port mappings. [S2, S4]

Verify that router-to-gz UDP works independently on both legs. Working SSH, including the `gpuxtcp` route, does not establish that native UDP works. Native WireGuard is not HTTPS/QUIC obfuscation. A blocked UDP leg is a reachability blocker, not a reason to weaken key checks. [S6]

Prefer a verified literal public IPv4 endpoint for this IPv4 MVP. Record how it was verified. An SSH alias may resolve through a proxy or localhost forward; its effective HostName is not automatically the correct WireGuard public endpoint.
