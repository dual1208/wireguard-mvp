# S09 scoped source and evidence audit

Audit snapshot: **2026-09-27 14:03:21 UTC**. No remote commands were run for this audit. No private key was requested, copied or printed.

**No exported WireGuard private key or preshared key was found in the audited snapshot.** This is a scoped source/evidence finding, not a claim about every file or process on the machines. The existing acceptance result is preserved; its overall S09 status was `BLOCKED`, although all five recorded owner-file permission checks passed.

## Scope and evidence

The scan covered 529 files: project sources, documentation, tests and local inventory, plus the files present in `.local/runs`, `.local/audit`, `.local/discovery` and `.local/acceptance` when enumerated. Vendored packages, upstream checkouts, dependency/cache directories and other `.local` directories were excluded. Symlinks were not followed.

The private manifest [secret-audit-scan.json](.local/audit/secret-audit-scan.json) records each scanned file's SHA-256, scan time, classified matches and permission findings. It contains no matched key values. There were 11,162 text entries, including decoded JSON strings and identifiable base64-encoded shell payloads. No file changed during its individual read, and no binary file was skipped in this enumeration. This was not an atomic snapshot of the active deployment; files written later are outside its scope.

| Check | Observation |
| --- | --- |
| WireGuard-shaped base64 values | 180 occurrences; every occurrence matched one of three public identities established by `public-keys.json`, owner-public observations or explicit public WireGuard selectors. Zero unrecognized values. |
| Private/preshared key assignments | Zero literal key-shaped private/preshared assignments. |
| Private PEM material | Zero private-key PEM headers. |
| Raw private key files | No `private.key`, `a.key`, `b.key`, `.key` or `.pem` file in the enumerated scope. |
| Secret-bearing WireGuard output commands | Matches were documented prohibitions or negative tests. No captured invocation of private-key/preshared-key output, configuration output or machine-readable secret dumps was found. |
| Shell tracing | Enabling-trace matches were the operating prohibition and a negative test. No traced private-key command appeared in the scanned evidence. |
| Local evidence ownership | All audited evidence files and their 41 parent directories belonged to the current user. All 41 directories were private. The coordinator corrected sixteen audit files from `0644` to `0600`; independent local verification passed. |

The scanner classified values without printing them. Public identities were obtained from the scoped evidence itself; key shape alone was never treated as proof that a value was public. Fresh unknown-key public markers were recognized as a permitted source, but this snapshot introduced no additional distinct public identity from that test.

## Source review

- [bootstrap.sh](remote/bootstrap.sh) generates the private key on its owner with restrictive creation permissions. Only the derived public key is exchanged. Backups stay owner-local and are restricted to root.
- [hub.sh](remote/hub.sh), [unknown-key.sh](remote/unknown-key.sh) and [spoof-lab.sh](remote/spoof-lab.sh) pass private-key **file paths** to WireGuard. They do not pass private-key contents as process arguments. Temporary lab keys remain on their creating host and have ownership-checked cleanup.
- [router.sh](remote/router.sh) supplies the private value through a shell builtin and a pipe into UCI. The generated batch is not returned to the coordinator. Section/removal fingerprints hash private-bearing UCI locally; only the digest is emitted.
- [wgmvp.py](tools/wgmvp.py) captures UCI exports into owner-local shell variables to calculate the unrelated-configuration fingerprint. The exported configuration is not emitted: only its SHA-256 is returned. This explains the one non-test raw-network-command pattern. The launcher saves the remote script's hash rather than its expanded contents.
- [probe_remote.sh](tools/probe_remote.sh) and [acceptance.py](tools/acceptance.py) enumerate explicit nonsecret WireGuard fields. Discovery filters SSH configuration before persistence; it does not retain raw `ProxyCommand` text. Project service commands do not enable shell tracing.

These are source-path observations. They do not establish the contents of arbitrary process arguments or logs outside this collection, and they do not make manually enabling shell tracing safe.

## Owner-file permissions and completed hygiene correction

The existing [13:46 acceptance evidence](.local/acceptance/20260927T134651Z-8ok4dhuy/results.json) records PASS for gz, Villa and Cave owner key/config permissions and both routers' host-local backup permissions. The captured directory mode is `0700`; owner key/config and reported backups are root-owned `0600`. This audit reused that evidence and did not refresh remote permissions.

The initial scan found sixteen files under `.local/audit` with mode `0644`; their containing directories were private. The deployment coordinator subsequently restricted exactly those files to `0600`. A separate read-only verification confirmed that all sixteen are regular, nonsymlink files owned by the current user with mode `0600`. The correction is complete for the enumerated findings; no modes were changed by this auditor. The initial manifest is preserved, and [secret-audit-permissions-remediation.json](.local/audit/secret-audit-permissions-remediation.json) records the verification time and per-file results.

## Limits

This audit does not cover all machine files, remote process environments/arguments, shell history, system journals, memory, external backups, arbitrary encrypted/encoded archives, package payloads, or evidence created after enumeration. Pattern matching and public-key comparison establish no general absence-of-secrets theorem. Existing topology and public identities remain sensitive even when no private key is present. No acceptance JSON or security gate was promoted by this audit.
