#!/usr/bin/env python3
"""Validate the handoff inventory's narrow invariants, not the live network.

A successful exit checks only supplied data and explicit human/agent attestations.
It does not authenticate evidence, inspect firewalls, or authorize unsafe changes.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
from typing import Any

REQUIRED_CHECKS = (
    "identities_verified", "inventory_complete", "all_route_tables_and_namespaces_reviewed",
    "overlay_conflicts_reviewed", "proxy_interception_reviewed", "existing_public_exposure_reviewed",
    "host_namespace_forwarding_unchanged_planned", "kernel_and_package_compatibility_verified",
    "namespace_support_verified", "outer_udp_paths_verified", "port_available_or_project_owned",
    "independent_management_verified", "rollback_ready", "mtu_validated",
)
FALSE_POLICIES = (
    "router_management_over_tunnel", "lan_forwarding", "default_route_changes",
    "host_gz_forwarding_changes", "public_tcp_forwarding",
)
RFC1918 = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def validate(data: Any, *, final: bool = False, prepare: bool = False) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["inventory must be a JSON object"]
    for field in ("management_facts", "policy", "plan", "observed", "checks"):
        if not isinstance(data.get(field), dict):
            errors.append(f"{field} must be an object")
    if errors:
        return errors
    if type(data.get("schema_version")) is not int or data.get("schema_version") != 1:
        errors.append("schema_version must be integer 1")
    if data.get("project") != "wgmvp":
        errors.append("project must be wgmvp; do not silently take over another deployment")
    if data.get("architecture") != "trusted-hub-isolated-netns":
        errors.append("architecture must explicitly remain trusted-hub-isolated-netns")
    facts = data["management_facts"]
    expected = {
        "local_subnet": "192.168.0.0/16", "villa_ssh": "root@192.168.1.93",
        "gpu_ssh_local_alias": "gpuxtcp", "cave_ssh_alias_on_gpu": "rt", "gz_ssh_local_alias": "gz",
    }
    for key, value in expected.items():
        if facts.get(key) != value:
            errors.append(f"management_facts.{key} must preserve {value!r}")
    if facts.get("independent_local_internet_and_gpu_access_user_stated") is not True:
        errors.append("preserve the user's stated independent recovery paths")
    policy = data["policy"]
    for key in FALSE_POLICIES:
        if policy.get(key) is not False:
            errors.append(f"policy.{key} must be false for this MVP")
    for key in ("trusted_gz_hub", "payload_ipv4_only"):
        if policy.get(key) is not True:
            errors.append(f"policy.{key} must be true")
    if not isinstance(policy.get("allow_router_reboot"), bool):
        errors.append("policy.allow_router_reboot must be an explicit boolean")
    for key in REQUIRED_CHECKS:
        if key == "rollback_ready" and prepare and not final:
            if not isinstance(data["checks"].get(key), bool):
                errors.append(f"checks.{key} must be an explicit boolean")
            continue
        if key in {"outer_udp_paths_verified", "mtu_validated"} and not final:
            if not isinstance(data["checks"].get(key), bool):
                errors.append(f"checks.{key} must be an explicit boolean")
            continue
        if data["checks"].get(key) is not True:
            errors.append(f"checks.{key} is not verified")

    plan = data["plan"]
    pool = None
    try:
        pool = ipaddress.IPv4Network(plan.get("overlay_pool"), strict=True)
        if pool.prefixlen != 29:
            errors.append("overlay_pool must be an explicitly reserved /29 for this design")
        if not any(pool.subnet_of(private) for private in RFC1918):
            errors.append("overlay_pool must be inside RFC1918 space")
    except (ValueError, TypeError, AttributeError):
        errors.append("overlay_pool must be a canonical IPv4 network")
    addresses = plan.get("overlay_addresses")
    parsed: list[ipaddress.IPv4Address] = []
    if not isinstance(addresses, dict) or set(addresses) != {"gz", "villa", "cave"}:
        errors.append("overlay_addresses must contain exactly gz, villa, cave")
    else:
        for name, address in addresses.items():
            try:
                interface = ipaddress.IPv4Interface(address)
                if interface.network.prefixlen != 32:
                    errors.append(f"{name} address must use /32")
                if pool is not None and (interface.ip not in pool or interface.ip in (pool.network_address, pool.broadcast_address)):
                    errors.append(f"{name} address must be a usable host within the reserved pool")
                parsed.append(interface.ip)
            except (ValueError, TypeError, AttributeError):
                errors.append(f"{name} address is invalid")
        if len(parsed) != len(set(parsed)):
            errors.append("overlay host addresses must be distinct")

    observed = data["observed"]
    prefixes = observed.get("existing_ipv4_prefixes")
    if not isinstance(prefixes, list) or not prefixes:
        errors.append("existing_ipv4_prefixes must be a nonempty observed list")
    else:
        if "192.168.0.0/16" not in prefixes:
            errors.append("existing prefixes must include the user's current 192.168.0.0/16")
        for prefix in prefixes:
            try:
                network = ipaddress.IPv4Network(prefix, strict=False)
                if pool is not None and network.prefixlen != 0 and network.overlaps(pool):
                    errors.append(f"overlay pool overlaps existing non-default prefix {network}")
            except (ValueError, TypeError, AttributeError):
                errors.append(f"invalid observed prefix: {prefix!r}")
    for key in ("villa_version", "cave_version", "gz_os", "gz_public_endpoint_evidence"):
        if not isinstance(observed.get(key), str) or not observed[key].strip():
            errors.append(f"observed.{key} is missing")

    try:
        endpoint = ipaddress.IPv4Address(plan.get("gz_public_ipv4"))
        if not endpoint.is_global or endpoint.is_multicast or endpoint.is_unspecified or endpoint.is_reserved:
            errors.append("gz_public_ipv4 must be a verified global unicast IPv4 endpoint")
        if pool is not None and endpoint in pool:
            errors.append("outer endpoint must not be inside the overlay")
    except (ValueError, TypeError, AttributeError):
        errors.append("gz_public_ipv4 is unresolved or invalid")

    for key in ("interface", "gz_namespace"):
        value = plan.get(key)
        if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,14}", value) is None:
            errors.append(f"{key} must be a safe, short lowercase identifier")
    for key, low, high in (
        ("outer_udp_port", 1024, 65535), ("mtu", 1280, 9000),
        ("persistent_keepalive_seconds", 1, 120), ("rollback_lease_seconds", 60, 900),
    ):
        value = plan.get(key)
        if type(value) is not int or not low <= value <= high:
            errors.append(f"{key} must be an observed/selected integer in {low}..{high}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--phase", choices=("preflight", "final"), default="preflight",
                        help="final additionally requires live UDP and MTU checks")
    args = parser.parse_args()
    try:
        data = json.loads(args.inventory.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"INVALID: cannot read inventory: {exc}")
        return 2
    errors = validate(data, final=args.phase == "final")
    if errors:
        print("NOT READY: inventory is incomplete or violates the MVP contract.")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("INVENTORY CHECKS PASS. This validates supplied data, not live firewall behavior or actual safety.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
