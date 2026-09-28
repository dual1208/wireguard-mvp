#!/usr/bin/env python3
"""Measure the current configured MTU; dry run unless --apply is supplied.

No runtime MTU or persistent configuration changes are implemented. Full-size
UDP uses the existing bounded benchmark ACL and registered diagnostic worker.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
import socket
import struct
import sys
import time

import acceptance
import benchmark
import wgmvp

ADDRESSES = {"gz": "10.203.77.1", "villa": "10.203.77.2", "cave": "10.203.77.3"}
REVIEWED_MAX = 1420


def checked_mtu(mtu: int) -> int:
    if type(mtu) is not int or not 1280 <= mtu <= REVIEWED_MAX:
        raise ValueError("candidate must remain inside the reviewed 1280..1420 range")
    return mtu


def next_candidate(passed: int, rejected: int | None = None) -> int | None:
    """Only explicit size/fragment evidence may establish a rejected upper bound.

    Timeouts, nonzero loss, missing captures and unavailable recovery are unknowns;
    the caller must stop rather than pass them as a proven MTU rejection.
    """
    checked_mtu(passed)
    if rejected is None:
        return REVIEWED_MAX if passed < REVIEWED_MAX else None
    checked_mtu(rejected)
    if rejected <= passed:
        raise ValueError("rejected candidate must exceed the validated candidate")
    return (passed + rejected) // 2 if rejected - passed > 1 else None


def candidate_plan(mtu: int = 1380, scope: str = "cave") -> dict:
    checked_mtu(mtu)
    if scope not in {"cave", "villa", "all"}:
        raise ValueError("unknown leg scope")
    routers = ("cave", "villa") if scope == "all" else (scope,)
    payload = mtu - 20 - 8
    legs = []
    for router in routers:
        ping = ["timeout", "-s", "TERM", "-k", "2", "10", "ip", "netns", "exec", "wgmvp",
                "ping", "-4", "-n", "-I", ADDRESSES["gz"], "-M", "do", "-c", "3", "-w", "8",
                "-s", str(payload), ADDRESSES[router]]
        directions = []
        for source, destination in (("gz", router), (router, "gz")):
            prefix = ["ip", "netns", "exec", "wgmvp"] if source == "gz" else []
            directions.append({"source": source, "destination": destination,
                               "client_argv": ["timeout", "-s", "TERM", "-k", "2", "20", *prefix,
                                               "iperf3", "-4", "-c", ADDRESSES[destination], "-B", ADDRESSES[source],
                                               "-p", "52080", "-u", "--dont-fragment", "-b", "1M", "-l", str(payload),
                                               "-t", "10", "-O", "0", "-J"],
                               "required_receiver": {"bind": ADDRESSES[destination], "port": 52080,
                                                     "one_off": True, "timeout_seconds": 45},
                               "required_capture": "both ends: inner exact size/DF plus outer IPv4 fragments and wire length; finite registered captures"})
        legs.append({"router": router, "gz_icmp_argv": ping, "udp_directions": directions})
    return {"id": "P06", "mode": "PLAN_ONLY", "status": "NOT_RUN", "scope": scope,
            "candidate_mtu": mtu, "ipv4_icmp_or_udp_payload": payload,
            "expected_outer_ipv4_bytes_at_exact_mtu": mtu + 60, "reviewed_ceiling": REVIEWED_MAX,
            "legs": legs, "runtime_mtu_changes": False, "requires_configured_mtu": mtu,
            "execution_ready": False,
            "blockers": ["Live execution measures only inventory/current configured MTU; never changes it to the requested candidate.",
                         "Verify installed benchmark worker hash and iperf3 --help includes --dont-fragment on each sender.",
                         "Capture confirmed outer endpoints and interfaces; noninitial IPv4 fragments lack UDP ports."],
            "success_requires": ["Every required source/destination sends and receives exact-size inner DF packets.",
                                  "Complete bounded captures show no matching inner/outer fragmentation; capture failure or drops are unknown.",
                                  "Low-rate UDP receiver data succeeds in both leg directions.",
                                  "Captures and temporary rules are removed; canonical status and independent recovery remain healthy."],
            "claim_limit": "Current configured MTU on selected paths only; no larger maximum is inferred."}


def require(condition, reason):
    if not condition:
        raise wgmvp.Blocked(reason)


class Failed(wgmvp.Blocked):
    pass


def decode_mtu_packets(data):
    """Bounded classic-pcap decoder preserving fragments, DF and total IP size."""
    orders = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    require(len(data) >= 24 and data[:4] in orders, "unsupported pcap header")
    order = orders[data[:4]]
    _, _, _, _, snaplen, link = struct.unpack(order + "HHIIII", data[4:24])
    require(64 <= snaplen <= 128 and link in (1, 101, 113, 228, 276), "unsupported bounded capture format")
    offset, result = 24, []
    while offset < len(data):
        require(len(data) - offset >= 16, "truncated pcap record")
        seconds, fraction, captured, original = struct.unpack(order + "IIII", data[offset:offset + 16])
        offset += 16
        require(captured <= snaplen and captured <= original and offset + captured <= len(data), "truncated captured packet")
        frame = data[offset:offset + captured]
        offset += captured
        start = 0
        direction = None
        if link in (1, 113, 276):
            start, field = {1: (14, 12), 113: (16, 14), 276: (20, 0)}[link]
            require(len(frame) >= start and struct.unpack("!H", frame[field:field + 2])[0] == 0x0800, "non-IPv4 capture")
            if link in (113, 276):
                kind = struct.unpack("!H", frame[:2])[0] if link == 113 else frame[10]
                direction = "out" if kind == 4 else "in"
        header = frame[start:]
        require(len(header) >= 20 and header[0] >> 4 == 4, "invalid IPv4 header")
        ihl = (header[0] & 15) * 4
        require(20 <= ihl <= len(header), "invalid IPv4 header length")
        total, ident, flags = struct.unpack("!HHH", header[2:8])
        require(ihl <= total <= original - start, "invalid total IPv4 length")
        item = {"src": socket.inet_ntoa(header[12:16]), "dst": socket.inet_ntoa(header[16:20]),
                "protocol": header[9], "total_length": total, "id": ident,
                "df": bool(flags & 0x4000), "mf": bool(flags & 0x2000), "offset": (flags & 0x1fff) * 8,
                "direction": direction, "timestamp": [seconds, fraction]}
        transport = header[ihl:]
        if item["protocol"] == 17 and item["offset"] == 0:
            require(len(transport) >= 8, "truncated UDP header")
            item["sport"], item["dport"], item["udp_length"] = struct.unpack("!HHH", transport[:6])
            item["wireguard_data"] = transport[8:12] == b"\x04\0\0\0"
        result.append(item)
        require(len(result) <= 2048, "packet capture bound exceeded")
    return result


def assess_direction(traces, source, destination, mtu):
    """Neither an empty capture nor a small UDP control exchange is a pass."""
    result = {}
    for role in (source, destination):
        inner = [item for item in traces[role]["inner"]
                 if item["src"] == ADDRESSES[source] and item["dst"] == ADDRESSES[destination]]
        if any(item["mf"] or item["offset"] for item in inner):
            raise Failed(f"{role}: captured fragmented inner UDP probe")
        full = [item for item in inner if item.get("dport") == 52080 and item["total_length"] >= 1280]
        require(len(full) >= 3, f"{role}: no repeated full-size UDP payload evidence")
        if any(item["total_length"] != mtu or not item["df"] for item in full):
            raise Failed(f"{role}: UDP payload size/DF differs from configured MTU probe")
        outer = traces[role]["outer"]
        first_fragments = {(item["src"], item["dst"], item["id"]) for item in outer
                           if item["offset"] == 0 and item["mf"]
                           and 51820 in (item.get("sport"), item.get("dport"))}
        if first_fragments:
            raise Failed(f"{role}: captured fragmented outer WireGuard UDP datagram")
        require(not any(item["mf"] or item["offset"] for item in outer),
                f"{role}: unattributed outer fragments make no-fragmentation evidence incomplete")
        data = [item for item in outer if item.get("wireguard_data")
                and 51820 in (item.get("sport"), item.get("dport")) and item["total_length"] >= mtu + 60]
        require(len(data) >= 3, f"{role}: no repeated full-size outer WireGuard data evidence")
        require(all(item["total_length"] == mtu + 60 for item in data),
                f"{role}: larger outer packets require offload/encapsulation reconciliation")
        result[role] = {"inner_full_size_df_packets": len(full), "outer_exact_size_packets": len(data),
                        "inner_ip_bytes": mtu, "outer_ipv4_bytes": mtu + 60, "fragments": 0}
    return result


def run_current(launcher, scope="cave"):
    """Caller holds coordinator lock. All writes pass through Launcher.mutate."""
    from outer_checks import OuterChecks
    require(scope in {"cave", "all"}, "live MTU scope must be cave or all")
    routers = ("cave",) if scope == "cave" else ("cave", "villa")
    roles = ("gz", *routers)
    mtu = checked_mtu(launcher.inventory["plan"]["mtu"])
    require(launcher.inventory["plan"]["outer_udp_port"] == 51820, "unreviewed outer port")
    launcher.operation_deadline = time.monotonic() + 1500
    result = {"id": "P06", "status": "BLOCKED", "scope_status": "BLOCKED", "selected_scope": list(roles),
              "configured_mtu": mtu, "runtime_mtu_changed": False, "maximum_mtu_established": False,
              "pings": [], "directions": [], "started_at": wgmvp.utcnow(),
              "limitations": ["Only the current configured MTU is tested; no larger MTU is inferred."]}
    capture = OuterChecks(launcher, routers)
    digest = hashlib.sha256((wgmvp.REPO / "remote/benchmark.sh").read_bytes()).hexdigest()

    def mutate(role, args, action, *, network=False):
        body = f'[ "$(sha256sum "$ROOT/benchmark.sh" | cut -d" " -f1)" = {digest} ]\n' + benchmark.command(*args)
        launcher.mutate(role, body, "mtu-" + action, "bounded current-MTU diagnostic: " + action,
                        changes_network=network)

    def read(role, script, label):
        return capture.read(role, script, "mtu-" + label)

    try:
        gate = launcher.load_cave_leg_security_gate() if scope == "cave" else launcher.load_security_gate()
        launcher.benchmark_health(gate, active_roles=roles)
        for role in roles:
            prefix = "ip netns exec wgmvp " if role == "gz" else ""
            text = read(role, 'ROOT=/etc/wgmvp\n. "$ROOT/config.env"\nprintf "CONFIG %s\\n" "$MTU"\n'
                        + "printf 'ACTUAL '; " + prefix + "cat /sys/class/net/wgmvp/mtu\n"
                        + 'printf "WORKER "; sha256sum "$ROOT/benchmark.sh" | cut -d" " -f1\n'
                        + "iperf3 --help | grep -- --dont-fragment >/dev/null\n", "prerequisites")
            require(text.splitlines() == [f"CONFIG {mtu}", f"ACTUAL {mtu}", f"WORKER {digest}"],
                    f"{role}: configured/live MTU or reviewed diagnostic worker differs")
            launcher.mutate(role, 'if [ -f "$ROOT/state/pending" ]; then "$ROOT/controller.sh" renew; '
                            'else [ "$(sed -n \'1p\' "$ROOT/state/committed")" = "$OWNER" ] || exit 1; "$ROOT/controller.sh" arm; fi\n',
                            "mtu-arm", "arm/renew bounded pending revision after current policy and recovery checks")
        for router in routers:
            plan = candidate_plan(mtu, router)["legs"][0]
            text = read("gz", shlex.join(plan["gz_icmp_argv"]) + "\n", "df-ping-" + router)
            require(re.search(r"(?m)^3 packets transmitted, 3 (?:packets )?received(?:,|\s)", text)
                    and acceptance.zero_loss(text), f"gz to {router}: full-size DF echo failed")
            result["pings"].append({"router": router, "status": "PASS", "bytes": mtu, "reply_df_inferred": False})
            peer = read("gz", f"cat /etc/wgmvp/public.{router}\n", "peer-public").strip()
            endpoints = read("gz", "ip netns exec wgmvp wg show wgmvp endpoints\n", "outer-endpoint")
            matches = [line.split()[1] for line in endpoints.splitlines() if len(line.split()) == 2 and line.split()[0] == peer]
            require(len(matches) == 1, "selected peer endpoint is absent or ambiguous")
            endpoint = matches[0].rsplit(":", 1)
            require(len(endpoint) == 2 and endpoint[1].isdigit(), "selected outer endpoint is not IPv4 UDP")
            remote_ip = str(ipaddress.IPv4Address(endpoint[0]))
            for source, destination in (("gz", router), (router, "gz")):
                detail = {"source": source, "destination": destination, "status": "BLOCKED", "cleanup": {}}
                opened, captures, traces, error = [], [], {}, None
                try:
                    for role in ("gz", router):
                        opened.append(role)
                        mutate(role, ("open", ADDRESSES[source], ADDRESSES[destination]), "open", network=True)
                    for role in ("gz", router):
                        other = remote_ip if role == "gz" else launcher.inventory["plan"]["gz_public_ipv4"]
                        outer = f"ip and host {other} and ip proto 17 and (udp port 51820 or (ip[6:2] & 0x3fff != 0))"
                        inner = (f"ip and src host {ADDRESSES[source]} and dst host {ADDRESSES[destination]} and ip proto 17 "
                                 "and (udp dst port 52080 or (ip[6:2] & 0x3fff != 0))")
                        descriptor = capture.capture_descriptor(role, {"outer": ("host", outer),
                            "inner": ("wgmvp" if role == "gz" else "host", inner)}, packet_limit=2048, duration=60)
                        captures.append(descriptor)
                        capture.start_outer_capture(descriptor)
                    mutate(destination, ("server",), "server")
                    for descriptor in captures:
                        capture.capture_covering(descriptor)
                    mutate(source, ("client", "udp-df", "1"), "udp-df")
                    for descriptor in captures:
                        capture.capture_covering(descriptor)
                    client = json.loads(read(source, benchmark.command("result", "client"), "client-result"))
                    server = json.loads(read(destination, benchmark.command("result", "server"), "server-result"))
                    detail["measurement"] = benchmark.measurement(client, server, "udp")
                    require(detail["measurement"]["receiver_bytes"] > 0 and detail["measurement"]["receiver_seconds"] >= 8,
                            "full-duration receiver data unavailable")
                    if detail["measurement"]["loss_percent"] != 0:
                        raise wgmvp.Blocked("UDP loss makes current-MTU validation inconclusive")
                except (RuntimeError, OSError, ValueError, KeyError) as exc:
                    error = exc
                finally:
                    for descriptor in captures:
                        try:
                            traces[descriptor["role"]] = capture.finish_outer_capture(descriptor, decode=decode_mtu_packets)
                            detail["cleanup"][descriptor["role"] + "-capture"] = "removed"
                        except (RuntimeError, OSError, ValueError, KeyError) as exc:
                            detail["cleanup"][descriptor["role"] + "-capture"] = str(exc)
                            error = error or exc
                    for role in reversed(opened):
                        try:
                            mutate(role, ("close",), "close", network=True)
                            detail["cleanup"][role + "-rules"] = "removed"
                        except (RuntimeError, OSError, ValueError, KeyError) as exc:
                            detail["cleanup"][role + "-rules"] = str(exc)
                            error = error or exc
                if error is None:
                    try:
                        detail["packet_evidence"] = assess_direction(traces, source, destination, mtu)
                        launcher.benchmark_health(gate, active_roles=roles)
                        for role in roles:
                            launcher.mutate(role, '"$ROOT/controller.sh" renew\n', "mtu-renew",
                                            "renew after current-MTU data, capture/rule cleanup, health and recovery")
                    except (RuntimeError, OSError, ValueError, KeyError) as exc:
                        error = exc
                detail["status"] = "FAIL" if isinstance(error, Failed) else "BLOCKED" if error else "PASS"
                if error:
                    detail["reason"] = str(error)
                result["directions"].append(detail)
                if error:
                    raise error
        result.update(scope_status="PASS", validated_current_mtu=mtu,
                      status="MEASURED" if scope == "all" else "BLOCKED")
        if scope != "all":
            result["limitations"].append("Villa was not contacted; full P06 remains incomplete.")
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        result["status"] = "FAIL" if isinstance(exc, Failed) else "BLOCKED"
        result["reason"] = str(exc)
    result["finished_at"] = wgmvp.utcnow()
    wgmvp.json_write(launcher.run_dir / "mtu-results.json", result, replace=True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mtu", type=int, help="dry-run candidate only; live execution must match inventory/current MTU")
    parser.add_argument("--scope", choices=("cave", "all"), default="cave")
    parser.add_argument("--inventory", type=Path, default=wgmvp.REPO / "inventory.local.json")
    parser.add_argument("--local-dir", type=Path, default=wgmvp.REPO / ".local")
    parser.add_argument("--apply", action="store_true", help="run guarded probes at current MTU; never change MTU")
    args = parser.parse_args(argv)
    try:
        if not args.apply:
            print(json.dumps(candidate_plan(args.mtu if args.mtu is not None else 1380, args.scope), indent=2))
            return 0
        inventory = json.loads(args.inventory.read_text())
        require(args.mtu is None or args.mtu == inventory["plan"]["mtu"], "live requested MTU must equal current inventory MTU")
        with wgmvp.coordinator_lock(args.local_dir):
            launcher = wgmvp.Launcher(inventory, args.local_dir)
            result = run_current(launcher, args.scope)
        print(f"P06 {args.scope}: scope={result['scope_status']}, overall={result['status']}; maximum not inferred.")
        print(f"Private evidence: {launcher.run_dir}")
        return 0 if result["scope_status"] == "PASS" else 2
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
