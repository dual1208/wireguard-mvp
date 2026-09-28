# Implementation and operations

## Phase A: discover without changing the network

Run the supplied offline tests, inspect the helper, then run `tools/discover.py`. Supplement it with targeted read-only observations. It intentionally does not collect secret-bearing raw configuration or make itself a full network auditor.

Record current facts for local, GPU, both routers, and gz: identity, effective management path, OS/kernel, privileges, networking managers, interface addresses/masks/MTUs, all relevant routes and rules, global IPv6 addresses, namespaces, existing tunnel interfaces, listening ports, firewall ownership, cloud ingress if accessible, proxy interception, offload, forwarding, and package/kernel compatibility.

On GPU, resolve `rt` there and identify the interface/path used to reach Cave. Do not install anything or alter routing on GPU. `ssh -G` and `/proc`/network observations are hints, not proof of a publicly routable WireGuard endpoint. Preserve literal access facts even if the alias uses FRP or another proxy.

Establish baseline independent access from fresh SSH connections and at least one existing, known-working local Internet check. Reuse the user's established Internet test or choose a harmless HTTPS check; do not conflate ICMP blocking with loss of Internet. Record the exact test destination.

Verify candidate overlay non-overlap against interfaces, VPNs, routes in all relevant tables, namespace addressing, and interception policies. A default route overlaps every address mathematically and is not itself a conflict; a non-default overlapping policy route still requires review. Fill and preflight-validate `inventory.local.json`. For the initial guarded deployment, select a conservative provisional MTU, but leave `outer_udp_paths_verified` and `mtu_validated` false until they are actually tested. `tools/check_inventory.py --phase final inventory.local.json` requires those later attestations; this avoids pretending that a not-yet-created path was already tested.

## Phase B: build before applying

Implement a small local orchestrator using the exact SSH paths. Keep remote scripts POSIX-shell compatible with the discovered routers. Use netifd/UCI for router persistence and one service owned by the discovered init manager for the gz namespace lifecycle. Prefer existing packaged tools and avoid a new framework.

Required interface:

```text
plan       -> read-only inventory validation, proposed delta, risks
apply      -> backups, rollback lease, additive guarded deployment
status     -> read-only state and fresh end-to-end probes
verify     -> explicit acceptance tests and structured results
benchmark  -> temporary scoped rules/server, finite tests, finally cleanup
rollback   -> undo a specific applied revision safely
remove     -> remove only project-owned objects and restore prior state
```

Default all mutation operations to dry-run until an explicit apply flag is supplied. Resolve usernames, route devices, interfaces, package commands, privilege escalation, and manager behavior from evidence. Never interpolate unvalidated user-configured strings into an unquoted shell command.

Every generated object must have a stable project name and ownership metadata. Never take ownership of an existing `wgmvp` interface, namespace, UCI section, route, unit, or file just because the name matches.

## Phase C: rollback before deployment

Back up affected configuration locally on each host with restrictive permissions and hashes. Save an object manifest and relevant prior firewall/sysctl state. Do not export private configuration to the repository.

Arm a host-local rollback lease before each live change. It must not depend on the just-created tunnel or an open SSH session. A bare background `sleep` is not a reboot-persistent rollback mechanism. Persist a pending-change marker and install startup reconciliation before enabling automatic startup or doing any full reboot test.

Suggested initial lease: 300 seconds per apply stage, renewable only after health checks, with an explicit bounded deadline. Use a monotonic timer during an uninterrupted boot. After a reboot, conservatively roll back an uncommitted pending revision unless a reviewed boot-safe rule says otherwise. A recorded wall-clock deadline by itself is unreliable when time synchronization changes the clock.

Test the rollback handler in a disposable namespace/local environment first. It must remove only owned state and detect conflicting concurrent changes; restoring the entire old firewall over newer unrelated changes is not safe.

## Phase D: deploy incrementally

1. Establish guards and host-local recovery.
2. Deploy gz's isolated namespace and interface, then its one required outer UDP allowance. Leave all ordinary gz routes and forwarding sysctls unchanged.
3. Deploy Villa's dedicated interface/zone and narrow routes. Verify its peer link and the independent access paths.
4. Deploy Cave through GPU-local `ssh rt`. Verify the second link, then Villa <-> Cave traffic.
5. Validate negative/security tests before opening temporary benchmark permissions.
6. Test an idempotent reapply and targeted interface restart.
7. Enable persistent startup with firewall-before-interface ordering; re-check.
8. Run approved bounded benchmarks and remove every temporary listener/rule/process.
9. Commit the revision only after required health/security checks pass.

A project setup failure must stop/undo the partially configured component, not leave a permissive namespace/interface running. Keep namespace policy in place until its WireGuard interface is down/deleted during teardown. Delete project processes before deleting the namespace; `ip netns del` alone is not a guarantee that a namespace with remaining processes is destroyed.

OpenWrt may need a coordinated firewall reload to install its rules. That is not permission for `service network restart` or reconstruction of unrelated bridges. Observe the compiled rules before and after; retain emergency access.

## Phase E: restart/recovery

At minimum, bounce each new WireGuard interface independently and restart the gz project service. A gz project-service restart is not a VPS reboot.

Full router reboot tests are opt-in. Test Villa and Cave separately, monitor local Internet and GPU access during the reboot, and verify that the router eventually returns through its original SSH path. Wait for ordinary uplink restoration before measuring WireGuard reconnection. Do not call a router SSH connection failing during its own reboot a failure of the independent GPU path.

Link-change testing must be narrow and scoped to the discovered topology. Do not rename or recreate a physical interface merely to simulate a change. Never change both ends simultaneously.

## Output and live evidence

Store sanitized evidence for each acceptance ID, including timestamp, host/namespace, exact command, exit status, key counters, and expected-versus-observed result. Full packet captures can contain private payloads; capture only synthetic test traffic, restrict access/retention, and publish a summary rather than raw user traffic.

A missing capability must produce `BLOCKED` or `NOT_RUN`, not a fabricated success. When cloud firewall access or external scan provenance is unavailable, state that explicitly.
