# WireGuard MVP operations

Run from `/Users/ielts/wireguard-mvp`. Live operations require `--apply`; without
it, mutation commands print a plan. Read `REPORT.md` and `results.json` for actual
acceptance results. These instructions do not imply that an untested gate passed.

The connection was deployed and committed, then gz’s endpoint and cloud UDP allowance were closed at the user’s request. It is currently disconnected. `apply --apply` would reopen the endpoint; run it only when that is intended. The user explicitly
deferred extended tests and benchmarks in favor of delivering this educational
MVP. Routine operation does not require rerunning the acceptance suite.

Use the overlay from the routers themselves:

```sh
ssh root@192.168.1.93 'ping -I 10.203.77.2 -c 3 10.203.77.3'
ssh gpuxtcp "ssh rt 'ping -I 10.203.77.3 -c 3 10.203.77.2'"
```

Only diagnostic ICMP is permanently admitted. LAN traffic and administrative
connections are intentionally outside this MVP.

## Administration and recovery

```sh
ssh root@192.168.1.93
ssh gpuxtcp
# On GPU, using that user's SSH configuration:
ssh rt
# From the local machine:
ssh gz
```

Do not redefine `gpuxtcp`, resolve `rt` locally, add ProxyJump, forward an SSH
agent, or change SSH authentication. A router can disappear during its own link
change; local Internet and the independent GPU transport must remain usable.

## Review and prepare

```sh
python3 tools/wgmvp.py plan --refresh
```

Review candidate snapshots against the inventory and current diagnostics. A
refresh never approves a changed host. Reconcile any unrelated drift before
updating `inventory.local.json` or a reviewed `.local/state/<role>.json`.
Private topology and evidence remain in `.local/`; never copy private keys or
raw router network configuration there.

The reviewed missing packages are staged under `.local/packages/<role>`. Package
installation has its own persistent rollback guard and never upgrades existing
packages. Execute serially, inspecting each result before proceeding:

```sh
python3 tools/install_packages.py gz --apply
python3 tools/install_packages.py villa --apply
python3 tools/install_packages.py cave --apply
```

The package installer is for the recorded initial package delta; it refuses a
second unrelated transaction over its protected baseline. Committed packages
may remain after removing the tunnel. Villa's two new essential runtime
libraries are retained rather than forcibly removing essential packages.

After package evidence is reconciled, prepare the project without starting any
network object:

```sh
python3 tools/wgmvp.py apply --prepare --apply
```

Preparation generates each private key on its owner, creates restricted local
backups, starts the systemd/procd lease watcher, and exercises installed rollback.
Only then can `checks.rollback_ready` be recorded as true with its evidence.

## Start and inspect

```sh
python3 tools/wgmvp.py apply --apply
python3 tools/wgmvp.py status
python3 tools/wgmvp.py verify
```

Initial apply proceeds gz → Villa → Cave under 300-second leases. A watcher
rolls back an expired lease or a pending revision from a previous boot. The
maximum pending period is 3,600 seconds. Renew only after checking project and
recovery health; do not use an unattended endless renewal loop. Initial apply
does not claim acceptance or automatically commit an unverified revision.
Reapplying an unchanged committed deployment preserves its committed state.

On an owning host, inspect the controller without exposing secrets:

```sh
/etc/wgmvp/controller.sh status
/etc/wgmvp/controller.sh renew
```

After the mandatory live security/recovery checks pass, the deployment
coordinator records the evidence and commits each pending host revision:

```sh
/etc/wgmvp/controller.sh commit
```

Do not use `wg showconf`, `wg show ... dump`, raw UCI network output, or shell
tracing. Safe WG fields include `public-key`, `peers`, `allowed-ips`,
`latest-handshakes`, `endpoints`, and `transfer`.

## Benchmarks and rollback

```sh
python3 tools/wgmvp.py benchmark             # inspect dry-run first
python3 tools/wgmvp.py benchmark --apply
python3 tools/wgmvp.py rollback --apply
python3 tools/wgmvp.py remove --apply
```

Benchmarks require current security evidence. Permissions are exact overlay
tuples, expire in the kernel, and use finite listeners bound to overlay
addresses. No benchmark service should remain after testing.

Rollback stops only the project data path. Router drop routes and independent
guards remain to prevent plaintext fallback. Removal verifies ownership and
deletes only project objects, preserving original configuration and root-only
backup/key archives. It refuses conflicting objects rather than overwriting
unrelated changes. No command restores a whole historical firewall over newer
configuration.

If local orchestration is interrupted, use the original SSH paths and run the
owner-local `/etc/wgmvp/controller.sh rollback`. The autonomous watcher also
performs this when the pending lease expires. Never repair this project by
flushing a ruleset or setting global INPUT/FORWARD policy to ACCEPT.

## Packet path and trust

```text
V .2 → C .3 inner ICMP
Villa kernel → WG authentication/encryption for gz
  outer UDP: Villa's current WAN/NAT endpoint → gz:51820
gz host UDP socket → decrypt in namespace wgmvp
  verify Villa key/source .2 → /32 route → narrow FORWARD policy
  encrypt for Cave → outer UDP to Cave's learned endpoint
Cave WG → authenticate gz/source .2 → local INPUT → ICMP reply
```

gz has only `lo` and `wgmvp` in the new namespace, no veth or default route.
Router LAN prefixes and default routes are absent from AllowedIPs. The three
overlay addresses use `/32`; a less-specific blackhole and early firewall
guards prevent fallback when a project interface is absent.

gz can read, modify, and originate permitted inner traffic. This is a trusted
hub MVP, not end-to-end encryption excluding gz. Full router reboot testing
remains `NOT_RUN` unless explicitly requested with `--allow-router-reboot` and
its separate recovery gates. Never reboot gz, GPU, or the local machine.

## Cloud UDP allowance

The user confirmed native WireGuard UDP with strict authentication/isolation and explicitly omitted HTTPS camouflage after reviewing the live TCP/WebSocket gateway. The single UDP cloud allowance is integrated into apply, status, rollback, and remove when the reviewed `.local/cloud-plan.json` exists. Its first real add and exact-ID revoke succeeded with WireGuard stopped; see private cloud operation evidence for the current state.

The helper exposes `CloudGate(launcher).plan()`, `.status()`, `.apply()`, `.rollback()` and `.remove()`. Planning reads the reviewed private instance, group-membership and security-group snapshots under `.local/audit` and writes `.local/cloud-plan.json`; status queries the existing `tyson` OAuth profile in `cn-guangzhou`. It never reads or copies profile credentials. Apply/rollback/remove default to a no-connection dry run unless their explicit mutation flag is provided.

The prepared rule is IPv4 UDP destination port `51820/51820`, source `0.0.0.0/0`, restricted further to the reviewed gz private address `/32`. It adds no TCP or IPv6 rule. Every write rechecks the sole-instance group membership, exact instance mapping, existing permissions and gz identity/recovery. An addition requires same-boot rollback evidence and a stopped project endpoint. Ownership combines a random description marker with the cloud-assigned rule ID; deletion names only that ID. All other permissions must still match the preserved baseline. Ambiguous failures retain private state for exact readback reconciliation.

Integration uses the launcher's existing coordinator lock. Apply checks the cloud prerequisite before starting gz. Rollback/removal attempt every host cleanup and exact owned cloud-rule deletion, and report any unfinished cleanup. A host-local lease closes the project listener but cannot autonomously revoke a persistent cloud rule without cloud credentials; those credentials remain local. Read-only cloud queries have at most three bounded attempts; writes are never blindly retried.
