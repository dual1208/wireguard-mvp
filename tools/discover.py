#!/usr/bin/env python3
"""Read-only inventory using the owner's exact SSH management paths.

Python 3 is needed only on the local machine. Remote commands are POSIX shell.
No SSH/network action occurs with --dry-run. Existing SSH configuration and
ProxyCommand/ProxyJump are trusted user configuration and are not rewritten.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
from typing import Any

TARGETS = ("villa", "gpu", "cave", "gz")
SSH_OPTIONS = [
    "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
    "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
    "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
    "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
    "-o", "ControlMaster=no", "-o", "ControlPath=none",
    "-o", "RemoteCommand=none",
]


def command_for(target: str) -> list[str]:
    """Do not evaluate the GPU's `rt` alias using local SSH configuration."""
    if target not in TARGETS:
        raise ValueError(f"Unknown target: {target!r}")
    remote = f"sh -s -- {shlex.quote(target)}"
    if target == "cave":
        nested = ["ssh", *SSH_OPTIONS, "rt", remote]
        return ["ssh", *SSH_OPTIONS, "gpuxtcp", shlex.join(nested)]
    destination = {"villa": "root@192.168.1.93", "gpu": "gpuxtcp", "gz": "gz"}[target]
    return ["ssh", *SSH_OPTIONS, destination, remote]


def run_bounded(command: list[str], *, stdin: str | None = None,
                timeout: int = 90) -> dict[str, Any]:
    """Bound each probe and terminate only the process group we created."""
    started = datetime.now(timezone.utc).isoformat()
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", start_new_session=(os.name == "posix"),
        )
    except OSError as exc:
        return {"started_at": started, "returncode": None, "timeout": False,
                "stdout": "", "stderr": str(exc)}
    timed_out = False
    try:
        stdout, stderr = process.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
    return {"started_at": started, "returncode": process.returncode,
            "timeout": timed_out, "stdout": stdout, "stderr": stderr}


def selected_ssh_fields(output: str) -> dict[str, str]:
    """Never persist potentially credential-bearing ProxyCommand text."""
    selected = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts
        key = key.lower()
        if key in {"hostname", "user", "port"}:
            selected[key] = value
        elif key in {"proxycommand", "proxyjump"}:
            selected[key] = "none" if value == "none" else "configured (value withheld)"
    return selected


def write_private(path: Path, value: str) -> None:
    # New run directories prevent overwriting earlier evidence or following files.
    with path.open("x", encoding="utf-8") as handle:
        handle.write(value)
    path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print commands without executing anything")
    parser.add_argument("--targets", nargs="+", choices=TARGETS, default=list(TARGETS))
    parser.add_argument("--output-dir", type=Path, default=Path(".local/discovery"))
    parser.add_argument("--timeout", type=int, default=90, help="seconds per target (10..300)")
    args = parser.parse_args()
    args.targets = list(dict.fromkeys(args.targets))
    if not 10 <= args.timeout <= 300:
        parser.error("--timeout must be in 10..300")
    if args.dry_run:
        for target in args.targets:
            print(f"{target}: {shlex.join(command_for(target))} < tools/probe_remote.sh")
        print("No connections made. rt will be resolved on GPU, not locally.")
        return 0

    script_path = Path(__file__).with_name("probe_remote.sh")
    try:
        script = script_path.read_text(encoding="utf-8")
    except OSError as exc:
        parser.error(f"Cannot read remote probe: {exc}")
    os.umask(0o077)
    args.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path(tempfile.mkdtemp(prefix=f"{timestamp}-", dir=str(args.output_dir)))
    summary: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "kind": "read-only discovery, not live acceptance testing",
        "cave_transport": "local SSH gpuxtcp -> GPU-local SSH rt",
        "ssh_alias_hints": {}, "targets": {},
        "limitations": [
            "Missing commands and permission failures are unknowns, not absence.",
            "Full firewall/cloud policy, proxy policy, and other namespaces need further inspection.",
            "SSH alias HostName is not necessarily the public WireGuard endpoint.",
            "No independent Internet or UDP reachability test is included in this collector.",
            "Existing SSH clients, configs, and ProxyCommands are trusted prerequisites.",
        ],
    }
    # These are local configuration observations only. Raw output is never persisted.
    for alias in ("root@192.168.1.93", "gpuxtcp", "gz"):
        hint = run_bounded(["ssh", "-G", alias], timeout=15)
        summary["ssh_alias_hints"][alias] = {
            "returncode": hint["returncode"], "timeout": hint["timeout"],
            "fields": selected_ssh_fields(hint["stdout"]),
        }

    local_commands = [["uname", "-a"]]
    if sys.platform == "darwin":
        local_commands += [["sw_vers"], ["/sbin/ifconfig"],
                           ["/usr/sbin/netstat", "-rn"], ["/sbin/route", "-n", "get", "default"]]
    elif sys.platform.startswith("linux"):
        local_commands += [["ip", "-4", "address", "show"], ["ip", "-6", "address", "show"],
                           ["ip", "-4", "route", "show", "table", "all"],
                           ["ip", "-6", "route", "show", "table", "all"],
                           ["ip", "-4", "rule", "show"], ["ip", "-6", "rule", "show"]]
    local_observations = [{"command": cmd, **run_bounded(cmd, timeout=15)} for cmd in local_commands]
    write_private(run_dir / "local.json", json.dumps(local_observations, indent=2) + "\n")

    failed = False
    for target in args.targets:
        print(f"Reading {target}...", flush=True)
        command = command_for(target)
        result = run_bounded(command, stdin=script, timeout=args.timeout)
        write_private(run_dir / f"{target}.txt", result["stdout"])
        write_private(run_dir / f"{target}.stderr.txt", result["stderr"])
        transport_ok = result["returncode"] == 0 and not result["timeout"]
        summary["targets"][target] = {
            "command": command, "started_at": result["started_at"],
            "transport_ok": transport_ok, "returncode": result["returncode"],
            "timeout": result["timeout"], "evidence_file": f"{target}.txt",
            "note": "Transport success does not mean all individual probes succeeded; inspect EXIT_STATUS markers.",
        }
        failed |= not transport_ok
        print(f"  {'READ' if transport_ok else 'FAILED'}; check per-command exit markers.", flush=True)
    write_private(run_dir / "summary.json", json.dumps(summary, indent=2) + "\n")
    print(f"Private evidence: {run_dir}")
    print("No deployment was performed. Review evidence before filling inventory.local.json.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
