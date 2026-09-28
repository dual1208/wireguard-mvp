# Reviewed deployment plan — 2026-09-27

This is a concrete proposed change, not a deployment result. Read `REPORT.md` and
`results.json` for current evidence. No full router reboot is authorized.

## Inventory from read-only SSH discovery

| Node | Observed system | Administrative path | Existing IPv4 networks |
|---|---|---|---|
| Villa | Linksys E8450 UBI, OpenWrt 24.10.5, kernel 6.6.119 | `ssh root@192.168.1.93` | WAN `192.168.1.93/24`; LAN `10.9.0.1/24` |
| Cave | OpenWrt 25.12.2, kernel 6.12.74 | local `ssh gpuxtcp`, then GPU user's `ssh rt` | WAN `192.168.1.70/24`; LAN `10.8.0.1/24`; Mihomo `198.18.0.1/30` |
| gz | Debian 13.4, kernel 6.12.74+deb13+1-amd64 | `ssh gz` | Private cloud NIC `/20`; Docker bridges `/16` |
| GPU | Arch Linux, kernel 6.18.51-1-lts | `ssh gpuxtcp` | WAN-side `192.168.1.100/24`; Docker; `daens` |
| local | macOS; user states `192.168.0.0/16` | unchanged | Address/interface observations retained privately |

Villa already had a loaded WireGuard kernel module and userspace tools. The
reviewed compatible packages are now installed and committed on all three
hosts: four new packages on gz, six on Villa, and sixteen on Cave. Native signed
metadata and exact payload hashes were checked; no installed package or kernel
was upgraded. The installed rollback watchdog was exercised before each package
transaction. Router free overlay
storage is approximately 50/53 MiB. gz has approximately 212 MiB available RAM,
unused 2 GiB swap, and 27 GiB free storage; preserve Docker/Matrix and use bounded
benchmarks. Exact package manifests, protected baselines, and installation
evidence are retained in private `.local/packages/` and on each owning host.

gz's literal IPv4 endpoint is verified by its provider metadata, not inferred
only from the SSH alias. The literal endpoint and sensitive identity hashes are
in `inventory.local.json` and private `.local/` evidence.

## Findings and gates

* Villa's address used for administration belongs to WAN, not LAN.
* Villa's TC classifier is attached to LAN ingress. Its marked proxy traffic
  uses priorities 1844/1845 before its local-table lookup at 1846.
* Cave's ordinary route to gz currently selects Mihomo. Its TCP OUTPUT redirect
  follows the selected interface. Project outer UDP needs a narrowly scoped
  mark rule to use the main WAN route.
* Both routers have globally scoped IPv6 addresses; this MVP does not alter
  those addresses or their existing IPv6 policies.
* gz host forwarding is already 1, used by Docker. It must remain 1; the new
  namespace has its own forwarding sysctl and no links to ordinary gz networking.
* GPU's privileged firewall and namespace audit is complete. Its `daens` has
  link-local addressing; all four process namespaces and the named namespace
  were checked. No overlap with the proposed overlay was found. gz's ten
  process namespaces and Cave's sole network namespace were also checked.
* Existing gz Docker DNATs serve Matrix/related applications. Existing FRP binds
  loopback and uses token authentication behind a separate secret-authenticated
  transport. These observations do not constitute a complete audit of those apps.
* The authenticated Alibaba CLI confirms that gz is the sole member of its
  security group. Read-only ingress inspection found no UDP 51820 allowance.
  This explains a missing prerequisite for the initial failed handshake tests;
  packet delivery must still be measured after adding the single project rule.
  Preserve all existing rules, including independent SSH/recovery and Matrix.

## Proposed object delta

Conflict review permits reserving `10.203.77.0/29`. Assign gz `.1/32`,
Villa `.2/32`, Cave `.3/32`. Start at provisional MTU 1380; validate both legs
before calling it final. Use UDP 51820, subject to a fresh bind/conflict check.

Each router gets owned UCI sections `network.wgmvp`, one peer, and a dedicated
firewall zone plus exact ICMP rules. Netifd owns live remote `/32` routes. The
project controller owns the persistent `blackhole 10.203.77.0/29` route, protocol
186, metric 32760; rule 1000 looks up local for that pool, rule 1001 looks up main
for that pool, and rule 1002 looks up main only for the gz public `/32` with WG
socket mark `0x77203`. Existing priorities/objects must be free before install.
The local-table rule preserves delivery to the router's own overlay address.

`inet wgmvp_guard` has early ingress and OUTPUT guards before proxy redirection,
exact ICMP INPUT/OUTPUT, and unconditional project FORWARD denial. IPv6 on this
interface is denied; existing IPv6 elsewhere stays unchanged. Each peer has
only the hub and other router `/32` in AllowedIPs. Keepalive is 25 seconds.

gz gets `/etc/wgmvp`, one systemd service, one `wgmvp` network namespace, and one
WireGuard interface born in the host namespace then moved down into `wgmvp`.
Only loopback and that new interface exist inside. There is no veth, default
route, inner NAT, public TCP forward, or administration listener. gz peers each
have only their own source `/32`. Namespace nft INPUT/OUTPUT/FORWARD default to
drop, allowing exact ICMP diagnostics. A project host nft table rejects the new
listener's IPv6 traffic. Its IPv4 allowance is subject to all existing firewall
and cloud policy; no existing DROP can be bypassed by that ACCEPT.

The cloud delta is one owned IPv4 UDP 51820/51820 ingress allowance for gz,
with an exact rule identifier, private original-rule snapshot, and guarded
revoke operation. There is no TCP allowance or change to existing rules.
Host-local rollback deletes the WireGuard listener even if the local cloud
control connection disappears; complete removal also revokes the owned rule.

## Recovery and rollback

The local coordinator and each remote host have a mutation lock. Before a write,
compare host identity, stable config fingerprints, fresh SSH recovery, and the
planned delta. Save root-only host-local backups/hashes; never export raw UCI
network configuration or private keys. Initial bootstrap creates no network
objects until the independently supervised rollback handler is active and tested.

A pending revision records boot identity and a monotonic lease, initially 300
seconds with a bounded overall lifetime. Startup reconciles pending state before
starting the interface; changed boot identity rolls it back. Router UCI autostart
stays disabled: the early guard/controller explicitly brings up only this
interface. A lost coordinator or failed test allows the host watcher to stop the
project interface. Guards remain while it is stopped. Full removal verifies
ownership and removes only project objects; backups are retained for audit.

No operation restores an entire old firewall/network file over subsequent
unrelated edits. A conflicting object stops its own teardown step and is reported.
No operation restarts the whole network or reboots any machine implicitly.

## Test sequence and expected packets

1. Validate host identity/recovery, conflicts, package compatibility and rollback.
2. Install gz, then Villa, then Cave under leases; check each native WAN UDP leg.
3. Ping both ways using explicit overlay sources. Villa's kernel routes V→C to
   WireGuard; its gz peer encrypts it. gz authenticates Villa, validates source V,
   decrypts in the namespace, forwards under exact ICMP policy, then encrypts for
   Cave. Cave authenticates gz, accepts source V, and applies INPUT for local C.
4. Test unknown-key, management/LAN denial, equivalent-policy source spoofing,
   IPv6/reload isolation, and disappearing-interface plaintext prevention.
5. Verify idempotence, each interface/service restart, and rollback/removal.
6. Only after security checks, open finite exact-tuple benchmark exceptions and
   bind servers to overlay IPs. Test per-leg and cross-router TCP/UDP, idle/load
   RTT, MTU, loss/retransmits, and contemporaneous CPU/recovery. Finally stop every
   benchmark process and expire/remove every temporary rule.
7. Commit only after mandatory checks. Router reboot remains NOT_RUN without
   the explicit launcher flag and separate tested boot-recovery gates.

Every test records PASS, FAIL, NOT_RUN, or BLOCKED. Offline tests cannot establish
live security or performance. gz remains able to inspect and originate inner
traffic: this is a trusted hub, not encryption excluding gz.
