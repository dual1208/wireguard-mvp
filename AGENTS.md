# Agent operating contract

## Facts and precedence

The user's current SSH paths and current 192.168.0.0/16 statement override older examples. They do not establish the actual masks or zone membership of router interfaces. Preserve `root@192.168.1.93`, local alias `gpuxtcp`, GPU-local alias `rt`, and local alias `gz`.

Run the requested model. Do not fabricate model identifiers, claim a runtime setting was enforced when it was not, or fall back to another model silently. Parallel review is fine; simultaneous live network writes are not. Use a per-host lock plus a single deployment coordinator.

## Allowed without another routine confirmation

Read-only discovery; local implementation and tests; host-local backups; compatible package installation that does not upgrade the OS/kernel; new project-owned interfaces, namespace, addresses, narrow rules, routes, and service units; temporary bounded benchmarks; restart of the new project interface; project rollback and removal.

Before each remote write, verify host identity, current configuration fingerprint, fresh recovery access, and a tested host-local rollback mechanism. Log the planned delta before applying it. A different live state from the reviewed plan requires reconciliation, not blind overwrite.

## Explicitly outside routine authorization

Firmware flashing, kernel or distribution upgrades, gz/GPU/local-machine reboot, existing bridge or WAN reconstruction, changes to SSH authentication or authorized_keys, removal of proxy software, broad firewall replacement, globally disabling IPv6, or changing the user's Internet gateway/DNS.

A full router reboot is allowed only with the launcher's explicit `--allow-router-reboot` flag, after persistent recovery has been implemented and reviewed. Reboot one router at a time; never both together.

## Non-negotiable rules

- Never run `nft flush ruleset`, `iptables -F`, or replace unrelated UCI configuration.
- Never put the project interface into the existing trusted LAN zone.
- Never enable `0.0.0.0/0`, `::/0`, or either real LAN prefix in MVP peer AllowedIPs.
- Never add a public TCP port forward or expose SSH/LuCI through the tunnel.
- Never change the host-namespace forwarding sysctls on gz for this design.
- Never move gz's physical NICs or existing interfaces into a namespace.
- Never solve a failed test by setting INPUT/FORWARD to ACCEPT globally.
- Never disable host-key verification or forward the local SSH agent into gz or GPU.
- Never copy a router's private WireGuard key to gz, the local repository, chat, or another router. Exchange public keys through the existing trusted SSH paths.
- Never log `wg show ... dump`, `wg showconf`, raw UCI network configuration, `set -x` around secrets, secret-bearing process arguments, or raw key files. The machine-readable dump contains private/preshared keys. [S2]
- Never use broad CPU-intensive scanning, password attempts, flooding, or tests against third parties. Bound negative tests to the user's confirmed hosts and selected ports.

## Evidence and secrets

Use private `.local/` storage for host identifiers and raw diagnostics. Keep host-local backups root-readable only; UCI network backups can contain unrelated credentials. A public template may contain a clearly marked key placeholder; a rendered config containing a private key must remain on its owner.

The supplied discovery helper avoids known secret-bearing configuration commands. Its output still contains sensitive topology and public-key identities. Inspect/sanitize it before sharing. Missing commands or permission failures are unknowns, not evidence of absence.

## Teaching loop

Before a change: predict one route decision and one security decision.
After a change: show a sanitized observation and compare with the prediction.
Use link/network/transport/application terminology, rather than unexplained layer numbers. Distinguish a userspace configuration operation from the kernel's packet processing. No need for a GUI, new framework, or custom crypto.
