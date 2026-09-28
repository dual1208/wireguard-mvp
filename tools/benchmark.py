#!/usr/bin/env python3
"""Finite benchmark plan and coordinator adapter. Standalone execution is a dry run.

The main launcher must validate current security/recovery evidence before calling
run_suite(). This module routes every mutation through that launcher's guarded
mutate(), using its exact SSH paths, reviewed fingerprints and recovery checks.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
from pathlib import Path
import re
import shlex
import time
from typing import Any, Callable

from wgmvp import Blocked, ROLES, json_write, utcnow

PAIRS = (("villa", "gz"), ("gz", "villa"), ("cave", "gz"), ("gz", "cave"),
         ("villa", "cave"), ("cave", "villa"))
ADDRESSES = {"gz": "10.203.77.1", "villa": "10.203.77.2", "cave": "10.203.77.3"}


@dataclass(frozen=True)
class Scenario:
    client: str
    server: str
    protocol: str
    setting: int
    repeat: int = 1

    def __post_init__(self) -> None:
        if (self.client, self.server) not in PAIRS:
            raise ValueError("only the six owned overlay directions are allowed")
        if self.protocol == "tcp" and self.setting not in {1, 4}:
            raise ValueError("TCP stream count must be 1 or 4")
        if self.protocol == "udp" and self.setting not in {1, 5, 10, 20}:
            raise ValueError("UDP offered rate must be 1, 5, 10 or 20 Mbps")
        if self.protocol not in {"tcp", "udp"} or self.repeat not in {1, 2, 3}:
            raise ValueError("invalid bounded scenario")

    @property
    def label(self) -> str:
        return f"{self.client}-to-{self.server}-{self.protocol}-{self.setting}-r{self.repeat}"

    @property
    def participants(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(("gz", self.server, self.client)))


def scenarios(scope: str = "all", *, include_udp: bool = False) -> list[Scenario]:
    if scope not in {"all", "per-leg", "cross-tcp", "cross-udp", "cave-leg"}:
        raise ValueError("unknown benchmark scope")
    if include_udp and scope != "cave-leg":
        raise ValueError("optional UDP selection applies only to cave-leg")
    if scope == "cave-leg":
        pairs = (("cave", "gz"), ("gz", "cave"))
        jobs = [Scenario(client, server, "tcp", 1) for client, server in pairs]
        if include_udp:
            jobs.extend(Scenario(client, server, "udp", rate) for client, server in pairs for rate in (1, 5, 10, 20))
        return jobs
    jobs = [Scenario(client, server, "tcp", 1) for client, server in PAIRS[:4]] if scope in {"all", "per-leg"} else []
    for client, server in PAIRS[4:]:
        if scope in {"all", "cross-tcp"}:
            for streams in (1, 4):
                jobs.extend(Scenario(client, server, "tcp", streams, repeat) for repeat in (1, 2, 3))
        if scope in {"all", "cross-udp"}:
            jobs.extend(Scenario(client, server, "udp", rate) for rate in (1, 5, 10, 20))
    return jobs


def command(*args: str) -> str:
    return shlex.join(["/etc/wgmvp/benchmark.sh", *args]) + "\n"


def number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise Blocked(f"missing or invalid measured field: {field}")
    return float(value)


def measurement(client: dict[str, Any], server: dict[str, Any], protocol: str) -> dict[str, Any]:
    if client.get("error") or server.get("error"):
        raise Blocked("iperf reported an application error")
    client_end, server_end = client.get("end", {}), server.get("end", {})
    receiver = client_end.get("sum_received") or server_end.get("sum_received")
    if protocol == "udp" and not receiver:
        # No reverse option is used: the server's sum is its received UDP data.
        receiver = server_end.get("sum")
    if not isinstance(receiver, dict):
        raise Blocked("iperf JSON has no identifiable receiver aggregate")
    result = {"receiver_mbps": number(receiver.get("bits_per_second"), "receiver bits_per_second") / 1e6,
              "receiver_seconds": number(receiver.get("seconds"), "receiver seconds"),
              "receiver_bytes": number(receiver.get("bytes"), "receiver bytes")}
    if protocol == "tcp":
        result["sender_retransmits"] = number(client_end.get("sum_sent", {}).get("retransmits"), "retransmits")
    else:
        result["loss_percent"] = number(receiver.get("lost_percent"), "receiver lost_percent")
        if result["loss_percent"] > 100:
            raise Blocked("invalid UDP loss percentage")
        result["jitter_ms"] = number(receiver.get("jitter_ms"), "receiver jitter_ms")
        result["received_packets"] = number(receiver.get("packets"), "receiver packets")
    return result


def latency(text: str) -> dict[str, Any]:
    observed = re.findall(r"time([=<])([0-9.]+)\s*ms", text)
    exact = sorted(float(value) for comparator, value in observed if comparator == "=")
    censored = sum(comparator == "<" for comparator, _ in observed)
    counts = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text)
    result: dict[str, Any] = {"samples": len(observed), "censored_samples": censored,
                              "transmitted": int(counts[1]) if counts else None,
                              "received": int(counts[2]) if counts else None}
    if exact and not censored:
        count = len(exact)
        result.update(median_ms=(exact[(count - 1) // 2] + exact[count // 2]) / 2,
                      p95_ms=exact[math.ceil(0.95 * count) - 1], min_ms=exact[0], max_ms=exact[-1])
    else:
        result["limitation"] = "Exact quantiles unavailable for absent or censored ping samples"
    return result


def run_one(launcher: Any, scenario: Scenario) -> dict[str, Any]:
    """Requires the caller's current security gate; always attempts owned cleanup.

    The server is one-off, bound to its overlay IP and limited to 45 seconds.
    Client load is 10 seconds after a 2-second warmup, bounded by 20 seconds.
    CPU and ping samplers are independently finite. No kernel timeout is renewed.
    """
    opened: list[str] = []
    record: dict[str, Any] = {"scenario": asdict(scenario), "started_at": utcnow(),
                              "status": "BLOCKED", "evidence_files": [], "cleanup": {}}
    collection = launcher.run_dir / scenario.label
    collection.mkdir(mode=0o700)

    def mutate(role: str, args: tuple[str, ...], description: str, *, network: bool = False) -> None:
        launcher.mutate(role, command(*args), f"bench-{args[0]}", description, changes_network=network)

    def read(role: str, kind: str) -> str:
        result = launcher.remote(role, command("result", kind), f"bench-{kind}")
        record["evidence_files"].append(result["evidence_file"])
        if result["returncode"] != 0 or result["timeout"]:
            raise Blocked(f"{role}: benchmark {kind} evidence is unavailable")
        return result["stdout"]

    try:
        for role in scenario.participants:
            # Include a role even when open itself fails: its kernel transaction
            # may have succeeded before the SSH response was lost.
            opened.append(role)
            mutate(role, ("open", ADDRESSES[scenario.client], ADDRESSES[scenario.server]),
                   "open exact TCP/UDP overlay tuples on port52080, gated by a 120-second kernel element", network=True)
        mutate(scenario.client, ("idle",), "capture ten finite idle overlay ping samples")
        idle_text = read(scenario.client, "idle")
        for role in scenario.participants:
            mutate(role, ("sample",), "start a bounded CPU/softirq/load sampler on this participating host")
        mutate(scenario.server, ("server",), "start a one-off overlay-bound iperf3 server with a 45-second timeout")
        mutate(scenario.client, ("client", scenario.protocol, str(scenario.setting)),
               "run finite iperf3 and load ping; TCP1/4 streams or explicit capped UDP offered rate")
        client = json.loads(read(scenario.client, "client"))
        server = json.loads(read(scenario.server, "server"))
        record["measurement"] = measurement(client, server, scenario.protocol)
        record["latency_idle"] = latency(idle_text)
        record["latency_during_load"] = latency(read(scenario.client, "load"))
        for role in scenario.participants:
            raw = read(role, "cpu")
            # Counter data stays private; the report must derive utilization from
            # timestamped deltas, not mistake cumulative counters for percentages.
            path = collection / f"{role}-cpu.txt"
            with path.open("x") as stream:
                stream.write(raw)
            path.chmod(0o600)
            record["evidence_files"].append(str(path))
        record["status"] = "MEASURED"
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        record["error"] = str(exc)
    finally:
        for role in reversed(opened):
            try:
                mutate(role, ("close",), "revoke timeout gate, stop only registered diagnostics, remove own temporary rules", network=True)
                record["cleanup"][role] = "removed"
            except (RuntimeError, OSError, ValueError, KeyError) as exc:
                record["cleanup"][role] = f"BLOCKED: {exc}"
                record["status"] = "BLOCKED"
                record["expiry_boundary"] = "Kernel gate expires after120s; server/samplers after45s; client after20s. Physical rule cleanup still needs confirmation."
        record["finished_at"] = utcnow()
        json_write(collection / "measurement.json", record)
    return record


def run_suite(launcher: Any, require_current_security_evidence: Callable[[], None],
              jobs: list[Scenario] | None = None, *,
              after_measured: Callable[[], None] | None = None) -> list[dict[str, Any]]:
    """Root launcher supplies a real evidence gate; a raising gate stops all work."""
    require_current_security_evidence()
    results, stopped_udp = [], set()
    for scenario in jobs if jobs is not None else scenarios():
        deadline = getattr(launcher, "operation_deadline", None)
        if deadline is not None and time.monotonic() + 180 >= deadline:
            results.append({"scenario": asdict(scenario), "status": "BLOCKED",
                            "reason": "Suite time budget leaves insufficient time for another bounded run and cleanup"})
            break
        direction = (scenario.client, scenario.server)
        if scenario.protocol == "udp" and direction in stopped_udp:
            results.append({"scenario": asdict(scenario), "status": "NOT_RUN",
                            "reason": "UDP sweep stopped after measured loss exceeded1%"})
            continue
        result = run_one(launcher, scenario)
        results.append(result)
        if result["status"] != "MEASURED":
            break  # No more offered load after failed recovery, setup or cleanup.
        if after_measured is not None:
            try:
                after_measured()
            except (RuntimeError, OSError, ValueError, KeyError) as exc:
                result["post_run_health"] = f"BLOCKED: {exc}"
                result["status"] = "BLOCKED"
                json_write(launcher.run_dir / scenario.label / "measurement.json", result, replace=True)
                break
            result["post_run_health"] = "healthy; pending leases renewed"
            json_write(launcher.run_dir / scenario.label / "measurement.json", result, replace=True)
        if scenario.protocol == "udp" and result["measurement"]["loss_percent"] > 1.0:
            stopped_udp.add(direction)
    json_write(launcher.run_dir / "benchmark-results.json", {"created_at": utcnow(), "runs": results})
    return results


if __name__ == "__main__":
    print(json.dumps({"mode": "DRY_RUN", "note": "Integrate through wgmvp.py after current security gates; no SSH is performed.",
                      "port": 52080, "kernel_permission_seconds": 120, "measured_seconds": 10,
                      "warmup_seconds": 2, "udp_payload_bytes": 1200,
                      "scenarios": [asdict(item) for item in scenarios()]}, indent=2))
