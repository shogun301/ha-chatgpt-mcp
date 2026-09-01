from __future__ import annotations

import asyncio
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

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
EXPECTED_VERSION = "2.7.8"
EXPECTED_TOOL_COUNT = 110
CONTRACT_PATH = Path("/app/tests/fixtures/server-contract-2.7.8.json")
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
    "get_sprinkler_capabilities",
    "get_sprinkler_command_status",
    "list_sprinkler_schedules",
    "get_sprinkler_upcoming_runs",
    "get_sprinkler_weather_and_decisions",
    "get_sprinkler_controller_diagnostics",
    "run_sprinkler_zone_exact",
    "run_sprinkler_sequence_exact",
    "pause_sprinklers",
    "resume_sprinklers",
    "skip_sprinkler_zone",
}
DIAGNOSTIC_REQUESTS: dict[str, dict[str, Any]] = {
    "get_host_runtime_health": {},
    "get_restart_outage_diagnostics": {"since_hours": 24, "limit": 50},
    "list_diagnostic_events": {"since_hours": 24, "limit": 50},
    "get_fixed_route_health": {},
    "get_lan_gateway_status": {},
    "list_lan_nodes": {
        "services": ["dns", "https", "ipp"],
        "max_results": 20,
    },
    "probe_lan_node": {
        "node_id": "node-001",
        "services": list(LAN_PROBE_SERVICES),
    },
}
SPRINKLER_READ_REQUESTS: dict[str, dict[str, Any]] = {
    "list_sprinkler_zones": {},
    "get_sprinkler_configuration": {},
    "get_sprinkler_summary": {},
    "get_sprinkler_history": {"limit": 100, "hours": 48},
    "get_sprinkler_capabilities": {},
    "get_sprinkler_command_status": {},
    "list_sprinkler_schedules": {},
    "get_sprinkler_upcoming_runs": {},
    "get_sprinkler_weather_and_decisions": {},
    "get_sprinkler_controller_diagnostics": {},
}
SPRINKLER_COMMAND_TOOLS = {
    "refresh_sprinkler",
    "run_sprinkler_zone",
    "run_sprinkler_sequence",
    "run_sprinkler_zone_exact",
    "run_sprinkler_sequence_exact",
    "pause_sprinklers",
    "resume_sprinklers",
    "skip_sprinkler_zone",
    "stop_sprinklers",
}
SPRINKLER_CONFIRMATION_TOOLS = {
    "pause_sprinklers",
    "resume_sprinklers",
    "skip_sprinkler_zone",
}
STATE_EVIDENCE = {
    "commanded",
    "controller-reported",
    "calculated",
    "inferred",
    "physically-measured",
}
HISTORY_EVIDENCE = {"physical", "controller-reported", "reconstructed"}

_TOKEN_RE = re.compile(
    r"(?i)(?:bearer\s+[A-Za-z0-9._~+\-/=]{8,}|basic\s+[A-Za-z0-9+/=]{8,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[=:])"
)
_AWS_RE = re.compile(
    r"(?:\bAKIA[0-9A-Z]{16}\b|\barn:aws(?:-[a-z]+)?:|"
    r"\b(?:i|subnet|sg|vpc)-[0-9a-f]{8,17}\b|"
    r"\baws[_ -]?account(?:[_ -]?id)?[\"']?\s*[=:]\s*[\"']?\d{12}(?!\d))",
    re.I,
)
_HOME_RE = re.compile(r"(?i)(?:\b[A-Z]:\\Users\\|/(?:home|Users)/[^/\s]+)")


def _verification_base_url() -> str:
    value = os.environ.get("PRODUCTION_VERIFY_BASE_URL", "").strip().rstrip("/")
    if not value:
        return config.PUBLIC_BASE_URL
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.port is None
    ):
        raise RuntimeError(
            "PRODUCTION_VERIFY_BASE_URL must be an explicit loopback HTTP origin"
        )
    return value


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


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _structured_result(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    if hasattr(result, "model_dump"):
        dumped = result.model_dump(mode="json")
        for key in ("structuredContent", "structured_content"):
            if isinstance(dumped.get(key), dict):
                return dumped[key]
    for content in getattr(result, "content", []) or []:
        text = getattr(content, "text", None)
        if not isinstance(text, str):
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise AssertionError("tool result did not include structured JSON output")


def _assert_aware_timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str):
        raise AssertionError(f"{label} is not a timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AssertionError(f"{label} is not RFC 3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AssertionError(f"{label} is not time-zone-aware")


def _assert_evidence_labels(value: Any, *, path: str = "result") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            current = f"{path}.{key}"
            if key == "evidence" or (
                key.endswith("_evidence") and key != "upstream_evidence"
            ):
                if child is not None and child not in STATE_EVIDENCE:
                    raise AssertionError(f"{current} has an invalid evidence label")
            if key == "evidence_type" and child not in HISTORY_EVIDENCE:
                raise AssertionError(f"{current} has an invalid history evidence label")
            _assert_evidence_labels(child, path=current)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_evidence_labels(child, path=f"{path}[{index}]")


def _assert_unsupported(value: Any, label: str) -> None:
    if not isinstance(value, dict) or value.get("supported") is not False:
        raise AssertionError(f"{label} is not explicitly unsupported")
    if not value.get("reason") or not value.get("upstream_evidence"):
        raise AssertionError(f"{label} does not explain its upstream limitation")


def _find_snapshot_payload(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        if isinstance(value.get("zones"), list) and (
            "watering_state" in value or "controller_health" in value
        ):
            return value
        for child in value.values():
            found = _find_snapshot_payload(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_snapshot_payload(child)
            if found is not None:
                return found
    return None


async def _ha_sprinkler_snapshot(device_id: str) -> dict[str, Any]:
    if not device_id:
        raise AssertionError("MCP sprinkler capabilities omitted the native controller ID")
    url = (
        f"{config.HA_BASE_URL.rstrip('/')}"
        "/api/services/wyzeapi/get_sprinkler_snapshot?return_response"
    )
    async with httpx2.AsyncClient(timeout=30, follow_redirects=False) as client:
        response = await client.post(
            url,
            headers={"Authorization": f"Bearer {config.HA_TOKEN}"},
            json={"device_id": [device_id]},
        )
        if response.status_code != 200:
            raise AssertionError(
                f"read-only integration snapshot failed with HTTP {response.status_code}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise AssertionError("read-only integration snapshot was not JSON") from exc
    snapshot = _find_snapshot_payload(body)
    if snapshot is None:
        raise AssertionError("read-only integration snapshot omitted zone metadata")
    return snapshot


def _assert_zone_inventory(
    mcp_payload: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    configured_count: int,
) -> dict[str, Any]:
    mcp_zones = mcp_payload.get("zones")
    upstream_zones = snapshot.get("zones")
    if not isinstance(mcp_zones, list) or mcp_payload.get("count") != len(mcp_zones):
        raise AssertionError("MCP sprinkler zone count does not match its zone inventory")
    if not isinstance(upstream_zones, list):
        raise AssertionError("integration snapshot zone inventory is missing")
    if len(mcp_zones) != configured_count:
        raise AssertionError(
            f"MCP exposes {len(mcp_zones)} zones but SPRINKLER_ZONE_COUNT={configured_count}"
        )
    upstream_by_id: dict[str, dict[str, Any]] = {}
    for zone in upstream_zones:
        if not isinstance(zone, dict):
            raise AssertionError("integration snapshot contains an invalid zone record")
        number = zone.get("zone_number")
        if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 8:
            raise AssertionError("integration snapshot contains an invalid zone number")
        normalized = f"zone-{number}"
        if normalized in upstream_by_id:
            raise AssertionError("integration snapshot contains duplicate zones")
        upstream_by_id[normalized] = zone
    mcp_by_id: dict[str, dict[str, Any]] = {}
    for zone in mcp_zones:
        if not isinstance(zone, dict) or not isinstance(zone.get("zone_id"), str):
            raise AssertionError("MCP zone inventory contains an invalid normalized ID")
        normalized = zone["zone_id"]
        if normalized in mcp_by_id:
            raise AssertionError("MCP zone inventory contains duplicate normalized IDs")
        mcp_by_id[normalized] = zone
    if set(mcp_by_id) != set(upstream_by_id):
        raise AssertionError("MCP zone inventory does not exactly match live integration zones")
    for normalized, upstream in upstream_by_id.items():
        native = upstream.get("zone_id")
        if native is not None and str(native) != str(mcp_by_id[normalized].get("native_zone_id")):
            raise AssertionError(f"MCP native zone ID differs for {normalized}")
    return {
        "configured_zone_count": configured_count,
        "integration_zone_count": len(upstream_by_id),
        "normalized_zone_ids": sorted(upstream_by_id),
    }


def _validate_sprinkler_result(name: str, payload: dict[str, Any]) -> None:
    _assert_evidence_labels(payload)
    if name == "get_sprinkler_history":
        _assert_aware_timestamp(payload.get("window_started_at"), "history window start")
        _assert_aware_timestamp(payload.get("window_ended_at"), "history window end")
        intervals = payload.get("intervals")
        if not isinstance(intervals, list) or payload.get("count") != len(intervals):
            raise AssertionError("history interval count does not match")
        omitted = payload.get("omitted_ambiguous_timestamp_count")
        if not isinstance(omitted, int) or isinstance(omitted, bool) or omitted < 0:
            raise AssertionError("history ambiguity omission count is missing or invalid")
        if omitted and "timezone-ambiguous" not in str(payload.get("limitation", "")).lower():
            raise AssertionError("history ambiguity omissions lack an explicit limitation")
        required = {
            "zone_id", "zone_name", "started_at", "ended_at",
            "duration_seconds", "duration_supported", "duration_evidence",
            "commanded_duration_seconds", "commanded_duration_evidence",
            "source", "source_supported", "source_evidence",
            "outcome", "outcome_supported", "outcome_evidence",
            "interrupted", "interruption_supported", "interruption_evidence",
            "run_id", "program_id", "evidence_type",
        }
        for interval in intervals:
            if not isinstance(interval, dict) or not required <= set(interval):
                raise AssertionError("history interval is not Gantt-ready")
            _assert_aware_timestamp(interval["started_at"], "interval start")
            if interval["ended_at"] is not None:
                _assert_aware_timestamp(interval["ended_at"], "interval end")
            if interval["evidence_type"] not in HISTORY_EVIDENCE:
                raise AssertionError("history interval evidence type is invalid")
            duration_supported = interval["duration_supported"]
            if not isinstance(duration_supported, bool):
                raise AssertionError("history duration support flag is invalid")
            if duration_supported != (interval["duration_seconds"] is not None):
                raise AssertionError("history duration support conflicts with its value")
            if duration_supported != (interval["duration_evidence"] is not None):
                raise AssertionError("history duration support conflicts with its evidence")
            commanded = interval["commanded_duration_seconds"]
            if (commanded is None) != (interval["commanded_duration_evidence"] is None):
                raise AssertionError("commanded duration and evidence must appear together")
            source_supported = interval["source_supported"]
            if not isinstance(source_supported, bool):
                raise AssertionError("history source support flag is invalid")
            if source_supported == (interval["source"] == "unknown"):
                raise AssertionError("history source must be unknown exactly when unsupported")
            if source_supported != (interval["source_evidence"] is not None):
                raise AssertionError("history source support conflicts with its evidence")
            outcome_supported = interval["outcome_supported"]
            if not isinstance(outcome_supported, bool):
                raise AssertionError("history outcome support flag is invalid")
            if outcome_supported:
                if interval["outcome_evidence"] is None:
                    raise AssertionError("supported outcome lacks evidence")
            elif interval["outcome"] != "unknown" or interval["outcome_evidence"] is not None:
                raise AssertionError("unsupported outcome must be explicit unknown without evidence")
            interruption_supported = interval["interruption_supported"]
            if not isinstance(interruption_supported, bool):
                raise AssertionError("history interruption support flag is invalid")
            if interruption_supported:
                if not isinstance(interval["interrupted"], bool) or interval["interruption_evidence"] is None:
                    raise AssertionError("supported interruption lacks a boolean value or evidence")
            elif interval["interrupted"] is not None or interval["interruption_evidence"] is not None:
                raise AssertionError("unsupported interruption must be explicit null without evidence")
    elif name == "get_sprinkler_capabilities":
        capabilities = payload.get("capabilities")
        if not isinstance(capabilities, list) or not capabilities:
            raise AssertionError("sprinkler capability contract is empty")
        unsupported = [item for item in capabilities if item.get("supported") is False]
        if not unsupported or any(not item.get("limitation") for item in unsupported):
            raise AssertionError("unsupported sprinkler capabilities lack limitations")
    elif name == "get_sprinkler_command_status":
        logical = payload.get("logical_run")
        if not isinstance(logical, dict):
            raise AssertionError("logical sprinkler run status is missing")
        for field in ("can_pause", "can_resume", "can_skip", "can_stop"):
            if not isinstance(logical.get(field), bool):
                raise AssertionError(f"logical sprinkler status lacks boolean {field}")
        if logical.get("physical_state_verified") is not False:
            raise AssertionError("logical sprinkler status claims physical verification")
        if logical.get("can_skip") is True and not (
            logical.get("state") == "running"
            and logical.get("source") == "dashboard_manual"
            and isinstance(logical.get("remaining_queued_zones"), list)
            and bool(logical["remaining_queued_zones"])
        ):
            raise AssertionError("logical sprinkler skip eligibility is not fail-closed")
    elif name == "list_sprinkler_schedules":
        _assert_unsupported(payload.get("mutations"), "schedule mutations")
    elif name == "get_sprinkler_weather_and_decisions":
        _assert_unsupported(payload.get("wyze_weather_data"), "raw Wyze weather")
        _assert_unsupported(
            payload.get("sprinkler_plus_calculation"), "Sprinkler Plus calculation"
        )
    elif name == "get_sprinkler_controller_diagnostics":
        for key in ("physical_feedback", "measured_flow", "electrical_load", "valve_faults"):
            _assert_unsupported(payload.get(key), key)


def _assert_registry_contract(tools: list[Any]) -> None:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    by_name = {item.name: item for item in tools}
    if contract.get("version") != EXPECTED_VERSION:
        raise AssertionError("bundled registry contract version is stale")
    if contract.get("tool_count") != EXPECTED_TOOL_COUNT:
        raise AssertionError("bundled registry contract tool count is stale")
    if set(contract.get("tool_names", [])) != set(by_name):
        raise AssertionError("live registry tool names differ from the release contract")
    input_schemas = {name: tool.input_schema for name, tool in by_name.items()}
    output_schemas = {name: tool.output_schema for name, tool in by_name.items()}
    annotations = {
        name: tool.annotations.model_dump(mode="json") if tool.annotations else None
        for name, tool in by_name.items()
    }
    metadata = {
        name: {
            "title": tool.title,
            "description": tool.description,
        }
        for name, tool in by_name.items()
    }
    expected = {
        "tool_schema_sha256": _canonical_hash(input_schemas),
        "tool_output_schema_sha256": _canonical_hash(output_schemas),
        "tool_annotations_sha256": _canonical_hash(annotations),
        "tool_metadata_sha256": _canonical_hash(metadata),
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            raise AssertionError(f"live registry differs from release contract: {key}")


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
            f"{_verification_base_url()}/mcp", http_client=client
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
                if not SPRINKLER_COMMAND_TOOLS.issubset(tool_names):
                    raise AssertionError("sprinkler command registry is incomplete")
                by_name = {item.name: item for item in tools.tools}
                for name in SPRINKLER_CONFIRMATION_TOOLS:
                    tool = by_name[name]
                    properties = tool.input_schema.get("properties", {})
                    if set(properties) != {"confirmed"}:
                        raise AssertionError(f"{name} exposes unexpected command inputs")
                    confirmed = properties["confirmed"]
                    if confirmed.get("type") != "boolean" or confirmed.get("default") is not False:
                        raise AssertionError(f"{name} confirmation schema is unsafe")
                    annotations = tool.annotations
                    if (
                        annotations is None
                        or annotations.destructive_hint is not True
                        or annotations.idempotent_hint is not False
                        or annotations.open_world_hint is not False
                    ):
                        raise AssertionError(f"{name} safety annotations are unsafe")
                _assert_registry_contract(tools.tools)

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
                    arguments = DIAGNOSTIC_REQUESTS[name]
                    result = await session.call_tool(name, arguments)
                    is_error = bool(getattr(result, "is_error", False))
                    if diagnostics_allowed and is_error:
                        raise AssertionError(
                            f"{name} unexpectedly rejected authorized call"
                        )
                    if not diagnostics_allowed and not is_error:
                        raise AssertionError(f"{name} accepted an insufficient scope")
                    if diagnostics_allowed:
                        try:
                            _assert_sanitized(_serialized_result(result))
                        except AssertionError as exc:
                            raise AssertionError(
                                f"{name} returned unsafe diagnostic output: {exc}"
                            ) from exc
                    results[name] = not is_error

                sprinkler_read_calls: dict[str, bool] = {}
                sprinkler_payloads: dict[str, dict[str, Any]] = {}
                sprinkler_inventory: dict[str, Any] | None = None
                if scope.split() == ["mcp:read"]:
                    for name, arguments in SPRINKLER_READ_REQUESTS.items():
                        result = await session.call_tool(name, arguments)
                        is_error = bool(getattr(result, "is_error", False))
                        if is_error:
                            raise AssertionError(f"{name} failed read-only production acceptance")
                        try:
                            _assert_sanitized(_serialized_result(result))
                        except AssertionError as exc:
                            raise AssertionError(
                                f"{name} returned unsafe read output: {exc}"
                            ) from exc
                        payload = _structured_result(result)
                        _validate_sprinkler_result(name, payload)
                        sprinkler_payloads[name] = payload
                        sprinkler_read_calls[name] = True
                    capabilities = sprinkler_payloads["get_sprinkler_capabilities"]
                    integration_snapshot = await _ha_sprinkler_snapshot(
                        str(capabilities.get("controller_id") or "")
                    )
                    sprinkler_inventory = _assert_zone_inventory(
                        sprinkler_payloads["list_sprinkler_zones"],
                        integration_snapshot,
                        configured_count=config.SPRINKLER_ZONE_COUNT,
                    )
                return {
                    "version": initialized.server_info.version,
                    "tool_count": len(tools.tools),
                    "diagnostic_calls": results,
                    "capability_sync": "in_sync",
                    "sprinkler_read_calls": sprinkler_read_calls,
                    "sprinkler_inventory": sprinkler_inventory,
                    "sprinkler_command_schemas_inspected": sorted(SPRINKLER_COMMAND_TOOLS),
                }


def _verification_report(
    read_only: dict[str, Any],
    least_privileged: dict[str, Any],
    legacy: dict[str, Any],
) -> dict[str, Any]:
    sprinkler_calls = read_only.get("sprinkler_read_calls")
    if not isinstance(sprinkler_calls, dict):
        raise AssertionError("read-only sprinkler acceptance results are missing")
    if set(sprinkler_calls) != set(SPRINKLER_READ_REQUESTS) or not all(
        value is True for value in sprinkler_calls.values()
    ):
        raise AssertionError("read-only sprinkler acceptance did not execute every read")
    inventory = read_only.get("sprinkler_inventory")
    if not isinstance(inventory, dict):
        raise AssertionError("read-only sprinkler inventory evidence is missing")
    configured = inventory.get("configured_zone_count")
    integration = inventory.get("integration_zone_count")
    zone_ids = inventory.get("normalized_zone_ids")
    if (
        not isinstance(configured, int)
        or isinstance(configured, bool)
        or configured < 1
        or integration != configured
        or not isinstance(zone_ids, list)
        or len(zone_ids) != configured
    ):
        raise AssertionError("read-only sprinkler inventory evidence is inconsistent")
    if set(read_only.get("sprinkler_command_schemas_inspected") or ()) != (
        SPRINKLER_COMMAND_TOOLS
    ):
        raise AssertionError("sprinkler command schema inspection is incomplete")
    return {
        "public_authentication": "verified",
        "insufficient_scope_rejected": all(
            not allowed for allowed in read_only["diagnostic_calls"].values()
        ),
        "read_only_scope": read_only,
        "least_privileged_scope": least_privileged,
        "legacy_scope": legacy,
        "sanitization_scan": "passed",
    }


async def main() -> None:
    endpoint = f"{_verification_base_url()}/mcp"
    await _raw_auth_checks(endpoint)
    read_only = await _session("mcp:read", diagnostics_allowed=False)
    least_privileged = await _session(
        "mcp:read mcp:diagnostics", diagnostics_allowed=True
    )
    legacy = await _session("mcp:read mcp:write", diagnostics_allowed=True)
    print(
        json.dumps(
            _verification_report(read_only, least_privileged, legacy),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
