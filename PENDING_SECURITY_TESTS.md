# Pending coordinated security probes

This is a test plan, not a record of live results. The read-only runner
`python3 tools/acceptance.py` collects structural evidence and at most three
explicit-source ICMP requests in each direction. `--no-ping` collects without
synthetic traffic; `--baseline PATH/observations.json` compares gz host routing,
forwarding and unrelated nft policy against an earlier collection. Raw evidence
is restricted under `.local/acceptance/`. Exit 1 means an observed failure;
exit 2 means incomplete acceptance. All 27 IDs are retained in `results.json`.
An ordinary post-deployment collection cannot become a pre-deployment baseline.

Only the deployment coordinator may perform the changes below, after refreshed
identity, reviewed-state fingerprint, independent recovery and a tested local
rollback lease. Use verified owned destinations, bounded timeouts and narrow
synthetic capture filters. Record before/after policy counters and the positive
control; a failed connection without a listener or authenticated route proves
little. Never widen production peer identities for a test.

| ID | Bounded probe and required evidence |
|---|---|
| S01 | A temporary owner-local fresh key on an owned external vantage sends at most three overlay pings toward gz's verified UDP endpoint. Do not register it at gz. Capture only that outer tuple and synthetic inner ICMP for at most 12 seconds. Require observed outer arrival, no new accepted peer/inner packets, and a successful authorized control afterward. |
| S02 | Against the verified gz public address, test only individually reviewed existing TCP ports and the chosen UDP listener, with a 15-second process bound and one retry. Compare actual DNAT/forward policy and narrowly filtered captures. UDP `open|filtered` is not an authentication result. Existing reverse exposures require separate documentation. |
| S03 | From both the hub namespace and the opposite authorized router, attempt selected management TCP ports with a 3-second bound. The present OUTPUT/FORWARD policies reject TCP upstream; a root-coordinated temporary exact source/destination/port allowance is needed to exercise the receiving router INPUT denial itself. Keep its INPUT guard intact. Match its deny counters and use its known working ordinary management listener as a control. Cover all router-local destination addresses by compiled policy review; do not advertise LAN prefixes to obtain a test path. |
| S04 | Check absent LAN AllowedIPs/routes and project ingress FORWARD denial. Traffic rejected by upstream AllowedIPs alone does not prove router forwarding denial. Exercise equivalent rules in an isolated lab or use a separately reviewed narrow authenticated probe and matching router FORWARD counters. |
| S05 | Run the disposable equivalent-policy source-spoof lab only after review: isolated loopback transport, two native WireGuard interfaces moved into isolated payload namespaces, one allowed source /32. Show valid-source success, encrypted spoof arrival and no delivered inner spoof packet. Keep production namespaces and peers unchanged. |
| S06 | Compare gz host nft policy to the real pre-deployment baseline excluding the single owned outer table. Inspect service/reverse-proxy and cloud ingress separately; missing access remains BLOCKED. No namespace veth/default route/NAT is allowed. |
| S07 | Under each owner's lease, take down only its project interface. Run `ping -I OVERLAY_SOURCE -c 3 -W 2 OTHER_OVERLAY` while bounded captures inspect only synthetic plaintext overlay ICMP on the reviewed physical and proxy paths. Verify the guard and blackhole/rule decision, no plaintext packet, fresh ordinary SSH and HTTPS; restore and verify before testing the next owner. A source-address error by itself does not exercise fallback, so also make a bounded ordinary-source route/probe observation with the down interface. |
| S08 | Under lease, reload only the supported firewall owner and validate unchanged project guards before restarting traffic. Inspect IPv6 AllowedIPs/routes/listeners and nft family coverage. Use only owned IPv6 destinations if available; unsupported probes remain BLOCKED. Do not disable global IPv6. |
| S09 | Audit process arguments and known evidence for secret-bearing command patterns without printing matched secrets. Check root-only owner keys/config/backups and local evidence permissions. Never read `wg showconf`, `wg ... dump`, raw UCI network config or private keys into evidence. |
| S10 | Exercise temporary benchmark lease cleanup after normal exit, interruption, service restart and expiry. Verify exact listeners, ACLs and relevant project conntrack state are absent; preserve unrelated state. |

O01/O02/O04 need coordinated idempotence, individual interface/service restart
and ownership-aware rollback observations. O03 remains NOT_RUN without the
explicit router-reboot opt-in. No reboot is part of either the read-only runner
or the source-spoof lab. Performance P01–P08 need the separate bounded benchmark
workflow and cannot be inferred from ping success.

## Guarded live-check adapter

`tools/live_checks.py` provides `management`, `restart`, `tunnel-down` and
`firewall-reload` actions. Each invocation is a no-connection dry run unless
the sole deployment coordinator supplies `--apply`. It uses the existing
`wgmvp.Launcher` reviewed snapshots, fresh recovery checks, local coordinator
lock and pending host leases. It never stages new backend scripts or commits a
revision. Guarded mutations remember intentional stopped states before restart.
Use `--targets gz cave` to exclude Villa from every project read, renewal,
capture, mutation and positive control while it is unavailable. Existing GPU
and HTTPS recovery checks still run. Subset results expose `scope_status` for
the selected checks, but their global acceptance status remains BLOCKED until
the omitted host and paths are tested; a successful selected scope exits zero.

The management action tests four authenticated paths and five selected TCP
ports. Besides unchanged receiver policy and drop/accept counter deltas, it
requires exact-source receiver SYN evidence for every port. The audited router
BusyBox netcat uses a plain connect under `timeout`; an unqualified route lookup
must first show the intended overlay source. Hub netcat binds its overlay source
inside the project namespace. Receiver permissions are never opened. Sender and
transit exceptions close in `finally`, before waiting for capture completion.

The tunnel-down action uses unbound router pings so an absent source address
cannot trivialize the test. With gz stopped, its payload namespace is absent;
probes originate on both routers and must reach gz as encrypted data while its
host capture sees no plaintext overlay ICMP. It never sends ordinary gz host
traffic toward the overlay through the unrelated default route. Captures cover
all interfaces in the respective host namespace, remain active across probes,
and must report zero capture drops. Each stopped component is restored in
`finally`, followed by positive controls and independent management checks.

The restart action also restarts only gz's new `wgmvp.service`; no existing
network service or full router is restarted. Firewall reload delegates to
`tools/reload_check.py`, reloads routers separately and compares exact independent
guard policies. IPv6 assertions are structural; generated IPv6 payload testing
remains explicitly NOT_RUN.

All results and synthetic header traces stay under the launcher's private run
directory. Capture workers have finite timeouts and remote files are root-only;
normal collection removes their exact files. Unexpected fingerprint drift
blocks further writes instead of adopting new state. A failed partial mutation
or cleanup remains BLOCKED and leaves the existing supervisor authoritative.
No result in this document states that these actions have run live.

## Isolated source authorization lab invocation

After the coordinator reviews and stages `remote/spoof-lab.sh` as the root-owned
mode-0600 `/etc/wgmvp/spoof-lab.sh` on gz, renew the existing pending host lease.
Then source the file and call `spoof_lab_run`. It takes the existing host mutex,
requires more than 90 seconds of the same-boot lease, and bounds the worker to
65 seconds with a 10-second termination grace. It never executes on sourcing.

The lab creates an isolated loopback transport namespace and two payload
namespaces. Two native WireGuard interfaces retain UDP sockets in the transport
namespace after movement; its ports cannot reach the host network. Only the
synthetic `.2 -> .3` request/reply traffic and `.3 -> .3` spoof request are used.
The spoof source's automatically created local destination route is removed
inside that disposable namespace so the attempt actually reaches WireGuard.
There are no lab firewall drops obscuring the WireGuard source-authorization
test. This reproduces the peer /32 gate; it is not a test of the production
router firewall, production keys or Internet path.

PASS requires three positive inner requests, at least three encrypted arrivals
but zero inner requests in the spoof phase, three recovery requests, and
successful cleanup. The root-only `/etc/wgmvp/spoof-lab-UUID` directory retains
synthetic captures, public identities and results; its two private keys are
removed. Copy only the intended synthetic evidence, never key files. If killed
without a cleanup trap or if ownership changed, report BLOCKED and inspect the
retained namespaces. The coordinator can retry `spoof_lab_cleanup` with that
exact directory while holding the project lock. Cleanup checks stored namespace
identity, owned link aliases and absence of processes; it does not adopt unknown
objects or kill unrelated processes. It downs and deletes the owned WireGuard
devices before removing namespace names, avoiding retained birth-namespace
references. The controller can call `spoof_lab_cleanup_all` while holding its
existing mutex before backend teardown. A reboot destroys the disposable network
namespaces, but retained private key files still require owner-local cleanup.
