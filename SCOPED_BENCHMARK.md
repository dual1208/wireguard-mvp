# Cave-leg benchmark gate

The `cave-leg` scope tests only Cave ↔ gz. It does not establish Villa paths,
router-to-router performance, or full MVP acceptance. No benchmark may begin
until the selected leg's security and recovery checks have passed and its
current snapshots match the separately reviewed scoped gate.

```sh
# No connections or remote changes:
python3 tools/wgmvp.py benchmark --benchmark-scope cave-leg

# Sole coordinator, after reviewing the private gate and current recovery:
python3 tools/wgmvp.py benchmark --benchmark-scope cave-leg --apply

# Optional bounded UDP sweeps, after both TCP directions in the same run:
python3 tools/wgmvp.py benchmark --benchmark-scope cave-leg --cave-leg-udp --apply
```

The default is two single-stream TCP runs, Cave → gz and gz → Cave. Each uses
the existing 10-second measurement, 2-second warmup, exact overlay binding,
port 52080 restrictions, 120-second kernel permission expiry and finite process
timeouts. The UDP option adds 1, 5, 10 and 20 Mbps offered rates in each
direction, stopping that direction's remaining sweep above 1% measured loss.
Normal cleanup and failure cleanup remain unchanged.

The private `.local/security-gate-cave-leg.json` has a distinct schema from the
existing full-network `.local/security-gate.json`:

```json
{
  "owner": "wgmvp-r1",
  "kind": "scoped-security-gate",
  "selected_scope": ["gz", "cave"],
  "full_acceptance": false,
  "scope_tests": {
    "A01": {
      "status": "NOT_RUN",
      "selected_scope": ["gz", "cave"],
      "evidence_files": [
        {
          "path": "runs/REVIEWED-RUN/scoped-results.json",
          "sha256": "REPLACE_WITH_REVIEWED_FILE_SHA256"
        }
      ]
    }
  },
  "snapshots": {
    "gz": "REPLACE_WITH_CURRENT_REVIEWED_SNAPSHOT_OBJECT",
    "cave": "REPLACE_WITH_CURRENT_REVIEWED_SNAPSHOT_OBJECT"
  }
}
```

This illustrative object intentionally cannot pass. Supply one explicit scoped
PASS record for every A01–A05 and S01–S09 only after reviewing its selected-leg
evidence. Every record must have the exact selected scope and at least one
existing private evidence file with its SHA-256. Relative paths resolve under
`.local`; outside paths, symlinks, multiple hard links, public permissions,
changed evidence and stale snapshots are rejected.

A global `BLOCKED` result cannot substitute for a scoped PASS record. A report
containing global `status: BLOCKED` and selected `scope_status: PASS` may support
a manually reviewed scoped record; this is an explicit scope decision, not an
automatic conversion. The launcher never rewrites global acceptance statuses
or creates either gate from test output. The original full-network gate still
requires all three host snapshots and all its original PASS declarations.

All live health reads, pings, benchmark permissions, samplers, servers, clients
and lease renewals in this scope target only gz and Cave. Existing independent
GPU/HTTPS recovery checks remain mandatory. Each measured run is followed by
cleanup, both directed leg pings and recovery checks before renewing those two
leases. Results include `benchmark-scope.json` with `full_acceptance: false`.
No revision is committed automatically. Existing inventory contract checks
remain in force; a scoped gate does not authorize bypassing an unresolved
inventory safety blocker or an unapproved service restart.
