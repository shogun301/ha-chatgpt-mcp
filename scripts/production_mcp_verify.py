from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import time
import uuid
from typing import Any

import httpx2
import jwt
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from app import config


def _transport_streams(transport: Any) -> tuple[Any, Any]:
    """Accept the two- and three-item MCP SDK transport contracts."""
    if not isinstance(transport, tuple) or len(transport) not in (2, 3):
        raise RuntimeError("unexpected MCP transport contract")
    return transport[0], transport[1]


DIAGNOSTIC_TOOLS = (
    "get_host_runtime_health",
    "get_restart_outage_diagnostics",
    "list_diagnostic_events",
    "get_fixed_route_health",
    "get_lan_gateway_status",
    "list_lan_nodes",
    "probe_lan_node",
)
LAN_PROBE_SERVICES = ("dns", "router_ssh")
EXPECTED_VERSION = "2.6.2"
EXPECTED_TOOL_COUNT = 99
NEW_CAPABILITY_TOOLS = {
    "get_capability_sync_status",
    "get_calendar_events",
    "create_calendar_event",
    "get_schedule",
    "set_time_value",
    "list_sprinkler_zones",
    "get_sprinkler_configuration",
    "get_sprinkler_history",
    "refresh_sprinkler",
    "run_sprinkler_sequence",
}

_TOKEN_RE = re.compile(
    r"(?i)(?:bearer\s+[A-Za-z0-9._~+\-/=]{8,}|basic\s+[A-Za-z0-9+/=]{8,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[=:])"
)
_AWS_RE = re.compile(
    r"(?:\bAKIA[0-9A-Z]{16}\b|\barn:aws(?:-[a-z]+)?:|"
    r"\b(?:i|subnet|sg|vpc)-[0-9a-f]{8,17}\b|(?<!\d)\d{12}(?!\d))",
    re.I,
)
_HOME_RE = re.compile(r"(?i)(?:\b[A-Z]:\\Users\\|/(?:home|Users)/[^/\s]+)")


def _access_token(scope: str) -> str:
    now = int(time.time())
    claims = {
        "iss": config.PUBLIC_BASE_URL,
        "sub": "production-diagnostics-verifier",
        "aud": config.MCP_RESOURCE,
        "iat": now,
        "nbf": now - 5,
        "exp": now + 120,
        "jti": uuid.uuid4().hex,
        "client_id": "production-diagnostics-verifier",
        "scope": scope,
    }
    return jwt.encode(claims, config.JWT_SECRET, algorithm="HS256")


def _serialized_result(result: Any) -> str:
    if hasattr(result, "model_dump"):
        value = result.model_dump(mode="json")
    else:
        value = result
    return json.dumps(value, sort_keys=True, default=str)


def _assert_sanitized(value: str) -> None:
    if _TOKEN_RE.search(value) or _AWS_RE.search(value) or _HOME_RE.search(value):
        raise AssertionError("diagnostic output contains a forbidden identifier class")
    for candidate in re.findall(
        r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])", value
    ):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        raise AssertionError("diagnostic output contains an IPv6 address")
    for candidate in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", value):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        raise AssertionError("diagnostic output contains an IPv4 address")


async def _raw_auth_checks(url: str) -> None:
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "production-verifier", "version": "1"},
        },
    }
    async with httpx2.AsyncClient(timeout=15, follow_redirects=False) as client:
        for headers in ({}, {"Authorization": "Bearer invalid"}):
            response = await client.post(url, json=initialize, headers=headers)
            if response.status_code != 401:
                raise AssertionError(f"expected 401, received {response.status_code}")
            challenge = response.headers.get("www-authenticate", "")
            if not challenge.lower().startswith("bearer"):
                raise AssertionError("missing Bearer authentication challenge")


async def _session(scope: str, *, diagnostics_allowed: bool) -> dict[str, Any]:
    token = _access_token(scope)
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx2.AsyncClient(
        headers=headers, timeout=30, follow_redirects=False
    ) as client:
        async with streamable_http_client(
            f"{config.PUBLIC_BASE_URL}/mcp", http_client=client
        ) as transport:
            read_stream, write_stream = _transport_streams(transport)
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()
                tool_names = {item.name for item in tools.tools}
                if initialized.server_info.version != EXPECTED_VERSION:
                    raise AssertionError("unexpected server version")
                if len(tools.tools) != EXPECTED_TOOL_COUNT:
                    raise AssertionError("unexpected tool count")
                if not set(DIAGNOSTIC_TOOLS).issubset(tool_names):
                    raise AssertionError("diagnostic tool registry is incomplete")
                if not NEW_CAPABILITY_TOOLS.issubset(tool_names):
                    raise AssertionError(
                        "capability synchronization tool registry is incomplete"
                    )

                sync_result = await session.call_tool(
                    "get_capability_sync_status", {"refresh": True}
                )
                if bool(getattr(sync_result, "is_error", False)):
                    raise AssertionError("capability synchronization status failed")
                sync_payload = _serialized_result(sync_result)
                _assert_sanitized(sync_payload)
                if "in_sync" not in sync_payload:
                    raise AssertionError(
                        "capability synchronization baseline has drift"
                    )

                results: dict[str, bool] = {}
                for name in DIAGNOSTIC_TOOLS:
                    arguments: dict[str, Any] = {}
                    if name == "get_restart_outage_diagnostics":
                        arguments = {"since_hours": 24, "limit": 50}
                    elif name == "list_diagnostic_events":
                        arguments = {"since_hours": 24, "limit": 50}
                    elif name == "list_lan_nodes":
                        arguments = {
                            "services": ["dns", "https", "ipp"],
                            "max_results": 20,
                        }
                    elif name == "probe_lan_node":
                        arguments = {
                            "node_id": "node-001",
                            "services": list(LAN_PROBE_SERVICES),
                        }
                    result = await session.call_tool(name, arguments)
                    is_error = bool(getattr(result, "is_error", False))
                    if diagnostics_allowed and is_error:
                        raise AssertionError(
                            f"{name} unexpectedly rejected authorized call"
                        )
                    if not diagnostics_allowed and not is_error:
                        raise AssertionError(f"{name} accepted an insufficient scope")
                    if diagnostics_allowed:
                        _assert_sanitized(_serialized_result(result))
                    results[name] = not is_error

                sprinkler_safe_calls: dict[str, bool] = {}
                if "mcp:write" in scope.split():
                    for name in (
                        "list_sprinkler_zones",
                        "get_sprinkler_configuration",
                        "get_sprinkler_summary",
                        "refresh_sprinkler",
                    ):
                        result = await session.call_tool(name, {})
                        is_error = bool(getattr(result, "is_error", False))
                        if is_error:
                            raise AssertionError(f"{name} failed safe production acceptance")
                        _assert_sanitized(_serialized_result(result))
                        sprinkler_safe_calls[name] = True
                return {
                    "version": initialized.server_info.version,
                    "tool_count": len(tools.tools),
                    "diagnostic_calls": results,
                    "capability_sync": "in_sync",
                    "sprinkler_safe_calls": sprinkler_safe_calls,
                }


async def main() -> None:
    endpoint = f"{config.PUBLIC_BASE_URL}/mcp"
    await _raw_auth_checks(endpoint)
    read_only = await _session("mcp:read", diagnostics_allowed=False)
    least_privileged = await _session(
        "mcp:read mcp:diagnostics", diagnostics_allowed=True
    )
    legacy = await _session("mcp:read mcp:write", diagnostics_allowed=True)
    print(
        json.dumps(
            {
                "public_authentication": "verified",
                "insufficient_scope_rejected": all(
                    not allowed for allowed in read_only["diagnostic_calls"].values()
                ),
                "least_privileged_scope": least_privileged,
                "legacy_scope": legacy,
                "sanitization_scan": "passed",
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
