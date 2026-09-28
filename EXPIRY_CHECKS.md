# Benchmark cleanup checks

`tools/expiry_checks.py` is a coordinator adapter for S10. It uses the installed
benchmark and controller backends, the local coordinator lock, exact host
fingerprints, independent recovery checks, and the existing host mutex. It
installs no helper and never writes a lease record or signals a PID directly.

Preview, then run one host before selecting the full matrix:

```sh
python3 tools/expiry_checks.py --targets gz
python3 tools/expiry_checks.py --targets gz --apply
python3 tools/expiry_checks.py --targets villa cave --apply
python3 tools/expiry_checks.py --apply
```

All three live roles are maintained by default, even when only one host is
selected for testing. `--active-roles gz cave` explicitly excludes Villa from
reads and writes. Selected targets must be included in active roles. A partial
target or case selection can report `scope_status: PASS`; full S10 stays
`BLOCKED` until all four cases pass on all three hosts in one campaign. Separate
campaigns retain their own evidence and are not automatically merged.

Prerequisites are the exact reviewed installed benchmark source, current
reviewed snapshots, healthy project interfaces, fresh independent recovery,
and pending supervised leases. The runner does not create a performance
security gate or bypass an unresolved network failure. Backend hash checking
means the installed source must match the current local source before use.

The four cases on each selected host are:

1. Open one exact overlay permission and a one-off port52080 listener, then use
   normal backend close and prove the listener, registered process, temporary
   rules, timeout set, and active record are absent.
2. Simulate coordinator interruption by withholding close. Observe the server
   gone after its45s bound while temporary permissions remain, then the120s
   gate deadline and watcher cleanup. No target renewal or benchmark mutation
   is issued during this observation. Other active hosts keep their ordinary
   pending leases.
3. Restart only the new `wgmvp` service through its existing service manager.
   Verify normal stop cleanup and the expected stopped state, then restore the
   project interface under a pending lease.
4. Renew through the controller's public API, allow the actual300s deadline to
   pass, and check the watcher's automatic rollback record. Open the benchmark
   near the end and launch its45s server no earlier than30s before the deadline,
   so it overlaps lease expiry. Never alter lease timestamps. Restore through
   normal `arm` and `start` afterward.

A clean stopped fingerprint is measured before each host's cases. Autonomous
cleanup is accepted only if the new fingerprint equals that measured stopped
state or the corresponding clean running state. Any other drift blocks
restoration rather than being adopted. Cleanup/restoration is attempted in
`finally`; unresolved recovery errors are recorded and stop subsequent cases.

SSH operations are capped at55s. Clock polling uses at most15s local sleeps,
prints progress, and does not hold the host mutex while waiting. Expect several
minutes per host because120s and300s intervals are real.

Evidence is private under `.local/runs/…/expiry-check-results.json` and the
associated Launcher evidence files. The report separates the configured
kernel timeout, server expiry, and physical cleanup. If the watcher already
removed the set, the kernel-only runtime observation is explicitly
`NOT_OBSERVED_WATCHER_ALREADY_CLEANED`. JSON timeouts use seconds, as specified
by the upstream [libnftables-json manual distributed by Debian](https://manpages.debian.org/unstable/libnftables1/libnftables-json.5.en.html).

This runner creates no throughput load or established test connection. It does
not claim an established-flow/conntrack expiry probe, real SSH disconnection,
router reboot, or full network-service restart. Those limits remain in every
result. Offline simulator tests establish adapter behavior, not live S10
acceptance.
