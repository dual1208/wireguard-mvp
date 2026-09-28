# WireGuard MVP

**Current state: gz’s public WireGuard endpoint is closed at the user’s request; the cloud UDP allowance is removed and the tunnel is disconnected.** Reapplying would reopen it; do not run apply unless that is intended.

Native Villa ↔ gz ↔ Cave WireGuard, restricted to overlay ICMP diagnostics. Router administration and LAN forwarding remain denied. Read the [packet-path lectures](MENTAL_MODELS.md). See [REPORT.md](REPORT.md) for the deployed state and measurements, and [RUNBOOK.md](RUNBOOK.md) for operation and rollback.

```sh
python3 tools/wgmvp.py status
python3 tools/wgmvp.py plan
python3 tools/wgmvp.py apply --apply
python3 tools/wgmvp.py verify
python3 tools/wgmvp.py benchmark             # dry run; extra evidence gate applies
python3 tools/wgmvp.py rollback --apply
python3 tools/wgmvp.py remove --apply
```

Mutation commands are dry runs without `--apply`. Preserve the populated private `inventory.local.json` and `.local/` ownership/evidence records; do not overwrite them with the example inventory. Use the original SSH paths in the runbook.

The user deferred extended testing and benchmarks. The complete acceptance suite is not claimed. No router reboot occurred. gz terminates both links and can read inner traffic.
