# Paste this into the requested 6 Astra Ultra session

You are implementing the project in this directory on my own machines. Read `AGENTS.md`, `GOAL.md`, `ARCHITECTURE.md`, `SECURITY.md`, `IMPLEMENTATION.md`, and `ACCEPTANCE.md` before changes.

**Goal:** Build and deploy a minimal, reversible, fast WireGuard connection between my Villa and Cave routers through my public gz VPS. An unauthenticated Internet scanner of gz must not gain a decrypted network path, router administration access, or LAN access through this project. Keep my independent Internet and SSH recovery working. Deliver measured results and teach me the actual packet path as you work.

My current facts are:

```text
This local machine is on 192.168.0.0/16.
Local -> Villa:  ssh root@192.168.1.93
Local -> GPU:    ssh gpuxtcp
GPU   -> Cave:   ssh rt
Local -> VPS:    ssh gz
```

`rt` is resolved using the GPU user's SSH configuration, not mine. Use nested SSH; do not assume a local `rt` alias or silently replace this with a local ProxyJump. `gpuxtcp` is an existing recovery transport, not a name you may redefine.

My local Internet and `ssh gpuxtcp` remain usable when either router reboots or changes links. The router itself can be temporarily unreachable during its own reboot. Preserve the paths; do not confuse that with a guarantee of no downtime on the router being rebooted.

Discover the actual subnet assignments, router versions, kernel support, active interfaces/zones, gz public endpoint, existing firewall/proxy rules, and route conflicts. The candidate overlay addresses in this package are proposals, not observations. Do not assume 192.168.1.93 is Villa's LAN interface just because it is an administrative address. Do not reuse subnet addresses from previous teaching examples.

Implement the selected design: one native WireGuard interface per router, a two-peer WireGuard hub on gz, with the decrypted gz interface in an isolated Linux network namespace. Create that gz WireGuard interface in the ordinary host namespace before moving it, so its outer UDP socket retains the normal Internet path. No veth, bridge, public TCP forwarding, LAN forwarding, default-route changes, custom VPN protocol, or nested tunnel in this MVP.

Treat this launch instruction as authorization for additive, reversible project configuration, compatible package installation, finite tests on these owned hosts, and restarting the new project interfaces. Use the apply/rollback gates in the documents. Full router reboot tests require an explicit `--allow-router-reboot` opt-in; do not reboot gz, GPU, or the local machine. Do not flash firmware or upgrade the kernel.

Start with read-only discovery. Then write a concrete inventory, risk findings, planned diff, local rollback procedure, and test plan. Proceed with ordinary reversible steps without asking me to resolve facts you can discover. Stop only the unsafe or genuinely blocked step; finish all other useful work and say exactly what remains blocked. Never weaken authentication, broaden a firewall, or claim success to get around a blocker.

Use the requested model for all reasoning agents if the runtime supports it. Do not invent a model ID or configuration switch, or silently use a different model. If matching subagents are unavailable, work serially in the requested main session. Only one actor may mutate live network configuration at a time.

Produce idempotent `plan`, `apply`, `status`, `verify`, `benchmark`, `rollback`, and `remove` operations. Keep keys on their owning machines, preserve original configuration, test rejected traffic as well as allowed traffic, record real measurements, and leave benchmark services stopped. Report `PASS`, `FAIL`, `NOT_RUN`, or `BLOCKED` for each acceptance test.

At each milestone, explain: what packet exists, its inner source/destination, its outer endpoint when encrypted, which machine and namespace handle it, which route selects it, which key authenticates it, and which firewall rule admits or rejects it. Show short ASCII diagrams and actual sanitized output. End with a complete report, a reproducible runbook, and the remaining trust boundary: gz can read inner traffic because this is a trusted-hub MVP, not end-to-end encryption excluding gz.
