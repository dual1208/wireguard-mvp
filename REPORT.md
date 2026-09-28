# Deployed WireGuard MVP

> **Current state — closed at the user’s request (2026-09-27 14:37 UTC):** gz’s WireGuard interface/namespace was rolled back, both UDP 51820 sockets are absent, and the exact cloud allowance was revoked. The supervisor remains in rolled-back state and will not reopen the endpoint. The router-to-router tunnel is disconnected. The deployment and measurements below describe the earlier working state.

Updated 2026-09-27T14:32:56.711520+00:00. The earlier deployment had all three revisions committed before the later user-requested closure. Villa and Cave exchange IPv4 ICMP through gz using native kernel WireGuard. The user selected native UDP, explicitly omitted HTTPS camouflage, and then requested delivery instead of extended testing. Authentication and restrictive policy remain in force; this report does not claim full acceptance.

## Delivered connection

| Node | Overlay | Observed platform and administration |
|---|---|---|
| Villa | `10.203.77.2/32` | E8450, OpenWrt24.10.5, kernel6.6.119; `ssh root@192.168.1.93` |
| Cave | `10.203.77.3/32` | OpenWrt25.12.2, kernel6.12.74; `ssh gpuxtcp`, then GPU user's `ssh rt` |
| gz | `10.203.77.1/32` | Debian13.4, kernel6.12.74; `ssh gz`; decrypted interface in namespace `wgmvp` |

Villa's administration address is on WAN192.168.1.93/24; its LAN is10.9.0.0/24. Cave's WAN is192.168.1.70/24; its LAN is10.8.0.0/24. These are observed assignments. Neither LAN is advertised. The chosen10.203.77.0/29 pool was checked against local/GPU/router/gz routes, namespaces and proxy policy.

Permanent traffic is exact overlay ICMP diagnostics. Router administration, DNS, LAN forwarding and all other new inner traffic are denied. No default route, DNS setting, existing proxy configuration, public TCP forward, bridge or veth was added. Keepalive25s; configured MTU1380 is conservative and **not a validated path maximum**.

## Measured working result

| Direction | Received | RTT min / mean / max | Median |
|---|---|---|---|
| Villa → Cave |3/3,0% loss|16.349 /17.404 /19.107ms|16.758ms|
| Cave → Villa |3/3,0% loss|16.592 /21.642 /31.146ms|17.187ms|

These are three small ICMP samples per direction, not a throughput or loaded-latency benchmark. Throughput, UDP loss sweeps, CPU-under-load and path-MTU optimization were deliberately not run after the user's instruction. No benchmark service or permission is active.

Actual sanitized output:

```text
Villa: 3 packets transmitted, 3 packets received, 0% packet loss
Cave:  3 packets transmitted, 3 packets received, 0% packet loss
marked outer route: gz-public-IP via existing gateway dev wan mark0x77203
```

Commit evidence: [.local/runs/20260927T143118Z-t2br2iek](.local/runs/20260927T143118Z-t2br2iek/).

[Working connection evidence](.local/runs/20260927T142643Z-lewv6jmf/acceptance/20260927T142824Z-ygk0a_0q/results.json). Earlier failed handshakes were caused by a missing cloud UDP prerequisite; they are preserved as historical failures and superseded by this successful connection. An earlier local TCP-connect diagnostic was intercepted by the local proxy and had no matching gz packet capture; it was not proof of a public service or router exposure.

## Actual packet path

```text
inner: Villa10.203.77.2 → Cave10.203.77.3, ICMP
  Villa /32 route → wgmvp → encrypt for gz public key
    outer UDP: Villa WAN/NAT → gz-public-IPv4:51820
  gz ordinary host namespace receives encrypted UDP
    authenticate Villa key + permitted source.2
  decrypt into gz namespace wgmvp
    /32 route to.3 → exact ICMP FORWARD allow → encrypt for Cave key
    outer UDP: gz → Cave's authenticated, learned WAN/NAT endpoint
  Cave authenticates gz; source.2 is allowed from that peer
    early project ingress guard → dedicated INPUT ICMP allow → local.3
```

The reply follows the reverse path. Userspace configures peers/routes/firewalls; the Linux kernel processes and encrypts packets. The gz interface was created in the ordinary host namespace before moving it, preserving the outer socket's ordinary Internet route. Only loopback and WireGuard exist inside its namespace; no default route, host management daemon, inner NAT or link to Docker/LAN networks exists there.

Router priorities1000/1001 select local/main only for the overlay pool. Priority1002 selects the existing WAN route only for the gz endpoint with WireGuard socket mark0x77203, avoiding Cave's Mihomo interception. Early guards precede proxy redirection. A persistent pool blackhole and egress drops prevent plaintext fallback when the interface is stopped.

WireGuard private keys stay on their owning machines. On gz each router's authenticated key may source only its own /32. Each router authenticates gz and permits only the hub and other router /32. The independent router guard rejects management traffic to **every router-local destination**, and denies project forwarding in both directions.

## Changes and persistence

- One native interface per router, dedicated firewall zone, exact /32 routes, pool guards and narrow policy rules.
- One gz namespace/interface and service. Host routes and forwarding sysctls unchanged.
- One cloud IPv4 UDP51820 rule targeted to gz's private /32. Its exact-ID add/revoke/add cycle succeeded; all12 pre-existing ingress rules were preserved. No new TCP/IPv6 rule.
- Compatible packages installed:4 on gz,6 on Villa,16 on Cave; no existing package/kernel/firmware upgraded. Root-only owner-local backups and package manifests retained.
- The single explicitly approved Cave network-service restart loaded its new netifd WireGuard handler. The existing Mihomo service was restarted to restore its runtime policy rules after that restart; saved proxy settings were preserved. No router reboot or gz/GPU/local reboot occurred.
- Service-managed rollback watchers retain guarded startup and same-boot lease handling. The working revision is committed only after carried traffic, canonical restrictive policy, original recovery and absent benchmark services were confirmed. Boot services are enabled; physical reboot recovery remains untested.

A host-local rollback closes the WireGuard endpoint without cloud credentials. The local `rollback`/`remove` operations additionally revoke the exact owned cloud rule. If the cloud API is unavailable, that rule can remain while the listener is closed; unfinished cleanup is reported, not hidden.

## Acceptance ledger

`PASS` below is scoped to the stated evidence. `NOT_RUN` records intentionally deferred work; it is never an inferred pass.

| ID | Status | Evidence / limit |
|---|---|---|
| A01 | PASS | Original SSH paths and independent HTTPS remain available. |
| A02 | PASS | Privileged discovery reviewed all host/process namespaces, route tables and proxy policies; current routes match the non-overlapping pool. |
| A03 | PASS | Both native kernel WireGuard links authenticate and carry the successful bidirectional router traffic. The single cloud UDP allowance corrected the missing ingress prerequisite. |
| A04 | PASS | Isolated gz namespace and unchanged host routes/forwarding. |
| A05 | PASS | Exact peers, increasing counters,3/3 pings each direction. |
| S01 | NOT_RUN | Deferred by the latest user instruction. |
| S02 | NOT_RUN | Deferred by the latest user instruction. |
| S03 | NOT_RUN | Deferred by the latest user instruction. |
| S04 | PASS | Structural enforcement: no LAN/default AllowedIPs; dedicated router zone; unconditional project FORWARD drops and early all-destination ingress guard verified by each native backend. No synthetic LAN probe was run. |
| S05 | PASS | Earlier isolated equivalent-policy lab: authorized3/3 delivered; spoof3 encrypted arrivals/0 delivered; recovery3/3. Production peer mappings unchanged. |
| S06 | PASS | Scoped listener/NAT/proxy/cloud review found no project public administration/LAN forward. Existing FRP backend is loopback behind authenticated camouflage and FRP authentication; unrelated public Matrix/web services remain unchanged. This is not an audit of every application vulnerability. |
| S07 | NOT_RUN | Deferred by the latest user instruction. |
| S08 | NOT_RUN | Deferred by the latest user instruction. |
| S09 | PASS | Owner-local private keys/backups and permissions verified; local source/evidence scan found no leaked private/PSK material; audit-file permission remediation completed. |
| S10 | NOT_RUN | Deferred by the latest user instruction. |
| O01 | NOT_RUN | Deferred by the latest user instruction. |
| O02 | NOT_RUN | Deferred by the latest user instruction. |
| O03 | NOT_RUN | Deferred by the latest user instruction. |
| O04 | PASS | Owned-interface rollback occurred on all three hosts and retained restrictive guards/unrelated settings; cloud exact-ID add/revoke/add succeeded. Full remove was not exercised live. |
| P01 | NOT_RUN | Deferred by the latest user instruction. |
| P02 | NOT_RUN | Deferred by the latest user instruction. |
| P03 | NOT_RUN | Deferred by the latest user instruction. |
| P04 | NOT_RUN | Deferred by the latest user instruction. |
| P05 | NOT_RUN | Deferred by the latest user instruction. |
| P06 | NOT_RUN | Deferred by the latest user instruction. |
| P07 | NOT_RUN | Deferred by the latest user instruction. |
| P08 | NOT_RUN | Deferred by the latest user instruction. |

Machine-readable detail: [results.json](results.json). Full discovery, configuration delta and rollback rationale: [PLAN.md](PLAN.md). Secret-handling evidence: [SECRET_AUDIT.md](SECRET_AUDIT.md). Operations: [RUNBOOK.md](RUNBOOK.md).

## Remaining trust boundary

The existing camouflage process is an authenticated HTTPS/WebSocket gateway for loopback FRP; it is unchanged and does not carry this UDP tunnel. Existing public web/Matrix applications and authenticated recovery transports are preserved. Their entire application security is outside this project's audit.

**gz can read, modify and originate permitted inner traffic. This is a trusted-hub MVP, not end-to-end encryption excluding gz.** WireGuard authentication and source authorization plus namespace/router policy protect the project boundary; no finite observation promises immunity to implementation vulnerabilities, stolen keys, privileged compromise or denial of service.
