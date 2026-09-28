# Security contract

## Required guarantee and boundary

An unauthenticated Internet sender must not gain usable inner connectivity through the new service. A scanner may reach the outer UDP listener and consume some link/CPU resources; “no router access” does not mean no packet can reach a cryptographic parser or that denial of service is impossible. WireGuard uses peer authentication and replay protection, but this project makes no universal software-security claim. [S3, S6]

The hub is trusted. Both routers authenticate gz, not each other, on their respective links. gz root can read inner packets, change hub policy, and impersonate inner source addresses that the routers permit from gz. Router-local firewall restrictions therefore remain essential, but they do not turn this into end-to-end authentication excluding gz.

## Default permanent policy

Here G, V, and C mean the verified overlay addresses. “Management” means every router-local administrative destination address and port, not only TCP 22 on the overlay address.

| Place | Allow | Reject/drop |
|---|---|---|
| gz public/host networking | Existing approved services unchanged; selected WireGuard UDP port | No newly added public router TCP/UDP forwards; no overlay route into the host namespace |
| gz namespace INPUT | ICMP echo diagnostics from V/C to G; narrowly related ICMP needed for operation | All other new traffic to gz in this namespace |
| gz namespace OUTPUT | Corresponding ICMP traffic from G to V/C; narrowly related errors | Other generated traffic, except temporary benchmark rules |
| gz namespace FORWARD | Exact V -> C and C -> V ICMP tuples | All other forwarding, including another source/destination pair |
| Villa project ingress INPUT | G/C -> V ICMP diagnostics and necessary related ICMP | All other router-local traffic arriving on the project interface, regardless of destination address |
| Cave project ingress INPUT | G/V -> C ICMP diagnostics and necessary related ICMP | Same prohibition for Cave |
| Router project FORWARD | Nothing in the initial MVP | Every path between the new tunnel and existing networks |
| Router project OUTPUT | Exact overlay ICMP diagnostics and necessary replies/errors | Other overlay traffic except time-limited benchmarks |

Use appropriate narrowly scoped return-state handling. Do not let a broad pre-existing established/related rule, offload path, or proxy rule defeat project-specific prohibitions. Validate the resulting compiled policy, not just UCI text. Verify how existing connections are handled when temporary permissions expire; remove only project-owned conntrack entries if needed, never flush the whole table.

TCP/UDP iperf tests are temporary exceptions with source, destination, protocol, and port constraints. They do not authorize router administration. Bind the server to its overlay address, not `0.0.0.0` or `::`; iperf3 uses TCP control traffic even for UDP tests. [S9]

## Defense in depth

1. Peer private-key possession gates decrypted traffic. Do not register a catch-all/test peer in the live hub.
2. gz peers get one source `/32` each. A legitimate Villa peer cannot claim Cave's source address at gz.
3. Namespace isolation prevents accidental links to gz's regular networking. No veth/default route/port-forward back door.
4. The namespace firewall permits only specific traffic between the authorized overlay endpoints.
5. Each router independently denies administrative and LAN access from its new interface. A hub firewall mistake must not grant router administration.
6. Project-destination traffic is dropped when the tunnel is unavailable, not rerouted in plaintext through an ordinary default gateway.

WireGuard AllowedIPs is not a TCP/UDP service ACL. A peer's successful handshake is not permission to access its SSH server. [S1, S2]

## Firewall integration traps

Create a dedicated OpenWrt zone for `wgmvp`, never reuse `lan`. Review the actual firmware's netifd/firewall4 behavior. The official generic WireGuard server tutorial includes deliberately permissive LAN-zone setup that is unsuitable for this threat model. Do not copy that setup. [S7, S8]

On gz, integrate the public UDP allowance with its existing firewall owner. A separate nftables chain issuing ACCEPT cannot override a DROP in another base chain. A DROP is terminal at that hook; ACCEPT is not necessarily final. Inspect chain priorities, Docker/firewalld/UFW policies, and cloud firewall rules before relying on an allow rule. [S10]

The project must not rewrite unrelated firewall state. A project-owned guard must survive supported firewall reloads, or interface startup must remain blocked until the guard exists. Include both address families in isolation policy, despite IPv4-only payload scope. The new outer listener is authorized only for IPv4 in this MVP; verify that an IPv6 UDP bind does not accidentally receive a broader public allowance. Do not change unrelated IPv6 services.

## Key handling

Generate one private key on each owning node using restrictive permissions. Store and configure it there. Transfer only public keys through existing verified SSH sessions. No key in process arguments, chat, source control, or the discovery evidence. Avoid optional PSKs in the first MVP unless there is a specific requirement; they do not remove the hub trust boundary.

Log only explicit non-secret `wg show` selectors: interfaces, public-key, listen-port, peers, endpoints, allowed-ips, latest-handshakes, transfer, and persistent-keepalive. `wg show all dump` and `wg showconf` can reveal keys. [S2]

## Existing exposure audit

Inspect existing public listeners, reverse proxies/tunnels, port-forward rules, and cloud ingress. The `gpuxtcp` recovery mechanism may use gz or another service; do not assume its security or modify it silently. Flag any pre-existing route from public services to router management or a LAN.

If such a path exists, report the whole-system safety goal as blocked even if the new WireGuard component is correctly restricted. Explain a narrow remediation separately. Do not claim “scanners can never reach the routers” based only on the new UDP port's behavior.
