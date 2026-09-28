# Goal and definition of done

## Required outcome

Establish a persistent, explicitly restricted IPv4 network path between the two routers via gz, using maintained native WireGuard implementations. Minimize changes and overhead. Demonstrate correct behavior under normal traffic, invalid authentication, interface restart, and tunnel failure.

The optimization order is:

1. Preserve independent management and prevent unauthorized access.
2. Obtain stable connectivity and a safe rollback.
3. Measure and improve useful throughput and latency without relaxing the first two.

These are project design requirements, not claims that deployment has already passed.

## Threat interpretation

“An Internet scanner of gz must never access my routers” means: knowing the public gz address, port, or public key, sending arbitrary packets, and lacking a configured peer's private key must not grant the scanner a usable decrypted IP path to either router, any router management service, or either LAN through this project. Source-IP allowlisting is not authentication. WireGuard authenticates peers before accepting their carried traffic; source authorization and firewall authorization are separate gates. [S1, S2, S3]

This is not a promise against unknown implementation vulnerabilities, stolen authorized keys, a malicious privileged administrator, physical compromise, or denial of service. The trusted-hub design does not keep inner packets confidential from gz. Pre-existing public reverse proxies, port forwards, or compromised services can defeat a whole-machine security goal independently of this project. Discover and report them; do not silently reconfigure unrelated services.

## Scope of the first working MVP

- Three new overlay host addresses, assigned as `/32`s after conflict checks.
- Villa <-> Cave ICMP diagnostics through gz; narrow gz <-> router diagnostics.
- Temporary, scoped TCP/UDP throughput tests between overlay addresses.
- No persistent SSH, LuCI, HTTP, DNS, RPC, or other application access through the overlay.
- No LAN prefix advertised or routed through the overlay.
- No Internet exit service, subnet bridging, default-route capture, DNS changes, or NAT for inner site-to-site traffic.
- IPv4 payload only. Audit IPv6 exposure; do not globally disable existing IPv6.
- Native kernel path where compatible kernel support exists. No silent userspace replacement, TCP wrapper, firmware replacement, or packet-relay daemon.

Full LAN interconnection is a later policy and addressing task, not something to smuggle into this milestone. A usable router-to-router tunnel and reproducible speed tests are the MVP here.

## Required deliverables from the implementation agent

Provide runnable code/configuration for the lifecycle operations, a sanitized discovered inventory, host-local restricted backups, a changed-object manifest, persistent rollback/teardown instructions, and per-test evidence.

`REPORT.md` must separate:

- What was observed on each host.
- What changed, including exact routes, interfaces, and firewall policies.
- What passed, failed, was not run, or is blocked.
- Actual throughput, latency, loss, CPU load, MTU, and recovery measurements.
- Pre-existing exposures and the residual trust in gz.

## Completion gates

Normal tunnel establishment is necessary but not sufficient. Completion requires bidirectional carried traffic, rejected unknown-key attempts, denied management and LAN traffic, no plaintext fallback when the project interface disappears, intact recovery paths, successful idempotent reapplication, safe persistence, and cleanup of benchmarks.

Full router reboot validation is separately reported and remains `NOT_RUN` without the reboot opt-in. Do not label it tested merely because a WireGuard interface restart passed. `wg show` handshake age by itself is not an end-to-end health test. [S2, S4]

No arbitrary Mbps target is predeclared: the available paths and CPU capacity are unknown. Establish baselines, identify the limiting resource, and state what is measured rather than promising line rate.
