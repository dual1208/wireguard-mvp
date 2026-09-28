# Acceptance tests

Record each test as `PASS`, `FAIL`, `NOT_RUN`, or `BLOCKED`. Include evidence paths and why the observation establishes the claim. No test outcome in this file is a result already obtained.

## Core and safety

| ID | Test | Required observation |
|---|---|---|
| A01 | Baseline identity/recovery | Correct four SSH targets, GPU-local alias resolution, independent Internet check recorded; unknown identity blocks writes. |
| A02 | Address/route conflict check | Chosen pool does not capture existing subnets, host addresses, non-default routes, proxy policies, or any recovery destination. |
| A03 | Native support and UDP path | Compatible kernel WireGuard and namespace support; both router-to-gz UDP legs actually work. SSH success alone is insufficient. |
| A04 | Namespace structure | Only loopback and project WG interface in gz project namespace; no veth, default route, NAT escape, or management daemon. Host routes/forwarding unchanged. |
| A05 | Correct peers and packets | Exact intended public keys/AllowedIPs, both links transfer data, bidirectional router-to-router pings use the project path. |
| S01 | Unknown-key sender | A fresh, unregistered key sends a bounded test to gz's public listener; no accepted peer or inner packet appears; the authorized path still works. |
| S02 | Ordinary external probing | From an external vantage without a configured WG key, selected public TCP/UDP probes do not expose a new route/forward to either router. Inspect rule/capture evidence, not just scanner labels. |
| S03 | Management denial | From the hub namespace and the other authorized router, TCP attempts to overlay SSH/LuCI/HTTP/etc. fail with matching deny evidence. Policies cover ALL router-local destination addresses on project ingress. |
| S04 | LAN forwarding denial | No LAN prefix routes/AllowedIPs; router project FORWARD counters/policy demonstrate rejection rather than a trusted-zone shortcut. |
| S05 | Source spoof rejection | In a disposable equivalent-policy lab, a valid peer using another peer's source /32 is rejected. Do not alter production peer identity mappings just to make a spoof test possible. |
| S06 | No public-forward/back door | No new public DNAT, reverse TCP exposure, namespace veth/default route, or tunnel-to-host-services path. Report existing unrelated exposures separately. |
| S07 | Tunnel-down behavior | With each project interface down/deleted in a controlled test, synthetic overlay packets do not leave a physical/proxy interface in plaintext. Ordinary Internet/recovery survives. |
| S08 | IPv6 and reload behavior | No accidental IPv6 tunnel/admin exposure; policy survives supported firewall reload; no global IPv6 shutdown used as a shortcut. |
| S09 | Secret hygiene | No private/preshared keys in logs, repository, command arguments, local evidence, or wrong hosts; host-local configs/backups are restricted. |
| S10 | Benchmark expiry | Listeners, temporary permissions, and relevant permitted state are gone after normal exit, interruption, restart, and lease expiry. |
| O01 | Idempotence | Second apply leaves no duplicate peers, routes, zones, units, rules, or keys. |
| O02 | Interface/service restart | Each router WG interface and gz project service recover separately with independent management intact. |
| O03 | Router reboot, opt-in | Reboot one router at a time; original SSH returns; persistent firewall/guard policy exists before tunnel traffic; pending uncommitted changes recover safely. |
| O04 | Rollback/removal | A known revision can be undone without damage to unrelated routing, firewall, SSH, keys, or services. |

A `nmap` UDP result of `open|filtered` does not prove either secure authentication or insecurity. A TCP connection failure can be caused by no listener rather than the firewall: combine the result with counters/trace and a known-positive test where possible. No finite scan proves “never” for all packets. The assurance comes from a scoped threat model, reviewed gates, and tests supporting those gates.

For S03, test router administration from a context that really has an authenticated path to the router's overlay address. A test from the ordinary gz host namespace with no overlay route is useful for isolation, but does not prove router INPUT restrictions. Test both contexts and label them correctly.

Use low-rate negative probes against owned, verified addresses only. Do not attack unrelated public services, brute-force SSH, or load-test authentication. Simulate adversarial source addressing only in the controlled lab or tightly bounded owned-overlay tests; preserve live peer mappings.

## Performance methodology

P01: Record pre-test load, CPU model/core counts, CPU frequency when available, kernel/tool versions, interface link rates, MTU, path type, and active offload/proxy policies. Wired router-generated tests measure router-to-router performance, not Wi-Fi performance. Preserve existing global offload settings unless a narrowly justified change is separately approved.

P02: Measure router <-> gz on each leg in both directions using temporary namespace-bound servers and source/destination-specific permissions. Those encrypted per-leg baselines are not raw physical-link capacity. A path that cannot be safely baselined is reported as unmeasured, not guessed.

P03: Measure Villa <-> Cave sequentially in both directions, TCP one stream and four streams. Use three finite repeats per direction/setting, initially about 10–15 measured seconds each with a short omitted warm-up supported by the installed version. Capture iperf3 JSON, receiver goodput, retransmissions, and simultaneous CPU/softirq/load observations. A near-line-rate test can cause transient congestion; keep SSH monitoring active and abort on degraded recovery.

P04: Run bounded UDP tests in each direction at explicit increasing bitrates, starting low and stopping at material loss or management degradation. Never use an unlimited bitrate setting. Record offered load, received bitrate, jitter, and loss. Set a UDP payload length compatible with the tested MTU. Remember the TCP control connection in the temporary ACL. [S9]

P05: Measure idle RTT/loss and latency under a bounded bulk transfer, using the same path and payload size. Report sample counts, median and p95, min/max where useful. Do not substitute an average for a tail-latency measurement. Compare with the network's contemporaneous baseline rather than inventing a universal ping target.

P06: Verify path MTU using available DF/size probes and actual data transfer on both legs. Start conservatively, for example 1380 only as a provisional value, then choose the largest validated safe common setting. IPv4 transport has 60 bytes of fixed outer IP/UDP/WireGuard data overhead before padding; IPv6 transport has 80 before extra headers/padding. Account for real underlay encapsulations. Do not subtract two WireGuard headers for two serial, non-nested links. [S3]

P07: Correlate bottlenecks with each direction. For Villa -> Cave, a useful bound is:

```text
goodput <= min(Villa upload path,
               gz receiving/forwarding/sending capacity,
               Cave download path,
               participating CPU/packet-processing capacity)
```

Reverse the path for the other direction. Shared VPS NIC/provider quotas may count both reception and retransmission; report the provider's actual accounting if known. Do not assert the bound is achievable or that multi-stream throughput predicts single-stream application performance.

P08: Change at most one justified parameter at a time, repeat relevant tests, and rerun security/recovery checks afterward. Do not remove ACLs, add nested protocols, switch to a userspace relay, disable checks, or globally tune the router to manufacture a benchmark improvement.

## Results format

Create a `results.json` with one entry for every ID above, plus P01–P08. Suggested entry:

```json
{
  "id": "S01",
  "status": "NOT_RUN",
  "observed_at": null,
  "host_namespace": "gz / host and wgmvp",
  "expected": "unregistered key yields no accepted inner traffic",
  "observed": null,
  "evidence_files": [],
  "limitations": []
}
```

The final report must keep live test results separate from offline helper tests. Offline tests of this handoff kit cannot establish that either router or gz is configured safely.
