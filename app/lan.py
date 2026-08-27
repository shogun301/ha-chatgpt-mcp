from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import time
from collections.abc import Iterable
from typing import Any

HOME_NETWORK = ipaddress.ip_network(
    os.environ.get("LAN_SUBNET", "192.0.2.0/24").strip() or "192.0.2.0/24"
)
if HOME_NETWORK.version != 4 or HOME_NETWORK.prefixlen != 24:
    raise RuntimeError("LAN_SUBNET must be one fixed IPv4 /24")
ROUTER_NODE = "node-001"
NODE_RE = re.compile(r"^node-(\d{3})$")
MAX_CONCURRENT_PROBES = 64
DEFAULT_TIMEOUT_SECONDS = 0.25
MAX_SCAN_RESULTS = 100

# This is deliberately a closed diagnostic surface. Adding a service requires a
# code change and tests; callers cannot supply arbitrary ports or destinations.
SERVICE_PORTS: dict[str, int] = {
    "dns": 53,
    "http": 80,
    "https": 443,
    "rtsp": 554,
    "ipp": 631,
    "mqtt": 1883,
    "router_ssh": 22,
    "cast_http": 8008,
    "cast_tls": 8009,
    "jetdirect": 9100,
}
DEFAULT_DISCOVERY_SERVICES = tuple(SERVICE_PORTS)


class LanDiagnosticError(ValueError):
    """Raised when a LAN diagnostic request is outside the fixed safe surface."""


def node_address(node_id: str) -> str:
    """Resolve an opaque node ID to one host inside the fixed home /24."""
    match = NODE_RE.fullmatch(node_id)
    if match is None:
        raise LanDiagnosticError("node_id must use the form node-001 through node-254")
    host_number = int(match.group(1))
    if not 1 <= host_number <= 254:
        raise LanDiagnosticError("node_id must use the form node-001 through node-254")
    return str(HOME_NETWORK.network_address + host_number)


def node_id_for(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    if parsed not in HOME_NETWORK or parsed in {
        HOME_NETWORK.network_address,
        HOME_NETWORK.broadcast_address,
    }:
        raise LanDiagnosticError("address is outside the fixed home LAN")
    return f"node-{int(str(parsed).rsplit('.', 1)[1]):03d}"


def normalize_services(services: Iterable[str] | None) -> tuple[str, ...]:
    if services is None:
        return DEFAULT_DISCOVERY_SERVICES
    normalized = tuple(dict.fromkeys(str(item).strip() for item in services))
    if not normalized:
        raise LanDiagnosticError("at least one fixed service is required")
    unknown = [name for name in normalized if name not in SERVICE_PORTS]
    if unknown:
        raise LanDiagnosticError("unsupported LAN service")
    return normalized


class LanDiagnostics:
    """Bounded TCP-connect diagnostics for the fixed routed home LAN."""

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_concurrent_probes: int = MAX_CONCURRENT_PROBES,
    ) -> None:
        if not 0.05 <= timeout_seconds <= 2.0:
            raise LanDiagnosticError("timeout must be between 0.05 and 2 seconds")
        if not 1 <= max_concurrent_probes <= MAX_CONCURRENT_PROBES:
            raise LanDiagnosticError("probe concurrency is outside the safe bound")
        self.timeout_seconds = timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrent_probes)

    async def _probe(self, address: str, port: int) -> dict[str, Any]:
        async with self._semaphore:
            started = time.monotonic()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port),
                    timeout=self.timeout_seconds,
                )
            except (TimeoutError, OSError):
                return {"open": False, "latency_ms": None}

            latency_ms = round((time.monotonic() - started) * 1000, 1)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
            except (TimeoutError, OSError):
                pass
            return {"open": True, "latency_ms": latency_ms}

    async def probe_node(
        self, node_id: str, services: Iterable[str] | None = None
    ) -> dict[str, Any]:
        address = node_address(node_id)
        selected = normalize_services(services)
        checks = await asyncio.gather(
            *(self._probe(address, SERVICE_PORTS[name]) for name in selected)
        )
        service_status = {
            name: {
                "reachable": check["open"],
                "latency_ms": check["latency_ms"],
            }
            for name, check in zip(selected, checks, strict=True)
        }
        return {
            "node_id": node_id,
            "reachable": any(item["reachable"] for item in service_status.values()),
            "services": service_status,
            "probe_type": "tcp_connect_only",
        }

    async def scan(
        self,
        services: Iterable[str] | None = None,
        *,
        max_results: int = MAX_SCAN_RESULTS,
    ) -> dict[str, Any]:
        if isinstance(max_results, bool) or not 1 <= max_results <= MAX_SCAN_RESULTS:
            raise LanDiagnosticError(
                f"max_results must be between 1 and {MAX_SCAN_RESULTS}"
            )
        selected = normalize_services(services)

        async def inspect(host_number: int) -> dict[str, Any] | None:
            node_id = f"node-{host_number:03d}"
            result = await self.probe_node(node_id, selected)
            if not result["reachable"]:
                return None
            open_services = [
                name
                for name, status in result["services"].items()
                if status["reachable"]
            ]
            return {"node_id": node_id, "services": open_services}

        discovered = [
            item
            for item in await asyncio.gather(*(inspect(host) for host in range(1, 255)))
            if item is not None
        ]
        truncated = len(discovered) > max_results
        return {
            "nodes": discovered[:max_results],
            "count": min(len(discovered), max_results),
            "truncated": truncated,
            "services_checked": list(selected),
            "coverage": "fixed_home_ipv4_subnet",
            "limitations": (
                "Only fixed TCP services are tested. A node with no checked open service "
                "will not appear, and no packets beyond the TCP handshake are sent."
            ),
        }

    async def gateway_status(self) -> dict[str, Any]:
        router = await self.probe_node(
            ROUTER_NODE, ("dns", "http", "https", "router_ssh")
        )
        return {
            "home_lan_route_reachable": router["reachable"],
            "router_node": router,
            "allowed_services": list(SERVICE_PORTS),
            "target_policy": "fixed_home_subnet_node_ids_only",
            "control_capability": False,
        }
