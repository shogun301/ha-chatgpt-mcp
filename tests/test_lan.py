from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import get_args
from unittest.mock import AsyncMock, patch

_temporary_root = tempfile.TemporaryDirectory()
_root = Path(_temporary_root.name)
for _name, _value in {
    "ha_token": "test-home-assistant-token",
    "oauth_password_hash": "$argon2id$v=19$m=65536,t=3,p=4$dGVzdA$dGVzdA",
    "jwt_secret": "test-jwt-secret-that-is-long-enough-for-unit-tests",
    "origin_shared_secret": "test-origin-shared-secret",
}.items():
    (_root / _name).write_text(_value, encoding="utf-8")

os.environ.update(
    {
        "PUBLIC_BASE_URL": "https://example.invalid",
        "FRONTEND_PUBLIC_URL": "https://ha.example.invalid",
        "HA_BASE_URL": "http://127.0.0.1:8123",
        "HA_TOKEN_FILE": str(_root / "ha_token"),
        "OAUTH_PASSWORD_HASH_FILE": str(_root / "oauth_password_hash"),
        "JWT_SECRET_FILE": str(_root / "jwt_secret"),
        "ORIGIN_SHARED_SECRET_FILE": str(_root / "origin_shared_secret"),
        "DATABASE_PATH": str(_root / "oauth.sqlite3"),
        "AUDIT_LOG_PATH": str(_root / "audit.jsonl"),
        "HA_CONFIG_PATH": str(_root / "ha-config"),
        "BACKUP_PATH": str(_root / "backups"),
        "HOST_DIAGNOSTICS_PATH": str(_root / "host-diagnostics"),
    }
)
(_root / "ha-config").mkdir()
(_root / "backups").mkdir()
(_root / "host-diagnostics").mkdir()

from app.lan import (
    SERVICE_PORTS,
    LanDiagnosticError,
    LanDiagnostics,
    node_address,
    node_id_for,
    normalize_services,
)
from app.server import (
    LanService,
    claims_context,
    get_lan_gateway_status,
    lan_diagnostics,
    list_lan_nodes,
    mcp,
    probe_lan_node,
)


class LanValidationTests(unittest.TestCase):
    def test_only_opaque_fixed_subnet_node_ids_are_accepted(self) -> None:
        self.assertEqual(node_address("node-001"), "192.0.2.1")
        self.assertEqual(node_address("node-254"), "192.0.2.254")
        self.assertEqual(node_id_for("192.0.2.67"), "node-067")
        for value in (
            "node-000",
            "node-255",
            "192.0.2.1",
            "router.local",
            "node-1",
            "node-001;whoami",
        ):
            with self.subTest(value=value), self.assertRaises(LanDiagnosticError):
                node_address(value)

    def test_service_list_is_closed_and_deduplicated(self) -> None:
        self.assertEqual(normalize_services(["https", "https", "ipp"]), ("https", "ipp"))
        self.assertEqual(set(normalize_services(None)), set(SERVICE_PORTS))
        for value in ([], ["ssh"], ["12345"], ["http", "telnet"]):
            with self.subTest(value=value), self.assertRaises(LanDiagnosticError):
                normalize_services(value)

    def test_constructor_and_result_bounds_fail_closed(self) -> None:
        with self.assertRaises(LanDiagnosticError):
            LanDiagnostics(timeout_seconds=10)
        with self.assertRaises(LanDiagnosticError):
            LanDiagnostics(max_concurrent_probes=65)


class LanProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_targeted_probe_returns_no_raw_address(self) -> None:
        reader = LanDiagnostics()

        async def fake_probe(address: str, port: int) -> dict[str, object]:
            return {"open": port in {443, 9100}, "latency_ms": 2.5 if port in {443, 9100} else None}

        with patch.object(reader, "_probe", side_effect=fake_probe):
            result = await reader.probe_node("node-067", ["https", "ipp", "jetdirect"])

        self.assertTrue(result["reachable"])
        self.assertTrue(result["services"]["https"]["reachable"])
        self.assertFalse(result["services"]["ipp"]["reachable"])
        self.assertNotIn("192.0.2.", json.dumps(result))

    async def test_scan_is_fixed_to_254_nodes_and_truncates_output(self) -> None:
        reader = LanDiagnostics()
        seen: set[str] = set()

        async def fake_probe(address: str, port: int) -> dict[str, object]:
            seen.add(address)
            host = int(address.rsplit(".", 1)[1])
            return {
                "open": (host == 1 and port == 53) or (host == 67 and port == 9100),
                "latency_ms": 1.0,
            }

        with patch.object(reader, "_probe", side_effect=fake_probe):
            result = await reader.scan(["dns", "jetdirect"], max_results=1)

        self.assertEqual(len(seen), 254)
        self.assertEqual(result["nodes"], [{"node_id": "node-001", "services": ["dns"]}])
        self.assertEqual(result["count"], 1)
        self.assertTrue(result["truncated"])
        self.assertNotIn("192.0.2.", json.dumps(result))

    async def test_scan_rejects_invalid_result_caps(self) -> None:
        reader = LanDiagnostics()
        for value in (0, 101, True):
            with self.subTest(value=value), self.assertRaises(LanDiagnosticError):
                await reader.scan(["http"], max_results=value)  # type: ignore[arg-type]


class LanToolSurfaceTests(unittest.IsolatedAsyncioTestCase):
    def test_schema_service_names_match_the_closed_backend_allowlist(self) -> None:
        self.assertEqual(set(get_args(LanService)), set(SERVICE_PORTS))

    async def test_tools_require_diagnostics_scope_and_audit_safe_fields(self) -> None:
        token = claims_context.set({"scope": "mcp:read"})
        try:
            with self.assertRaises(PermissionError):
                await get_lan_gateway_status()
        finally:
            claims_context.reset(token)

        token = claims_context.set({"scope": "mcp:read mcp:diagnostics"})
        try:
            with (
                patch.object(
                    lan_diagnostics,
                    "gateway_status",
                    new=AsyncMock(return_value={"home_lan_route_reachable": True}),
                ),
                patch.object(
                    lan_diagnostics,
                    "scan",
                    new=AsyncMock(return_value={"count": 0, "truncated": False, "nodes": []}),
                ),
                patch.object(
                    lan_diagnostics,
                    "probe_node",
                    new=AsyncMock(return_value={"reachable": True, "services": {}}),
                ),
            ):
                self.assertTrue((await get_lan_gateway_status())["home_lan_route_reachable"])
                self.assertEqual((await list_lan_nodes(["https"], 5))["count"], 0)
                self.assertTrue((await probe_lan_node("node-001", ["dns"]))["reachable"])
        finally:
            claims_context.reset(token)

    async def test_schemas_expose_no_arbitrary_destination_or_port(self) -> None:
        tools = {tool.name: tool for tool in await mcp.list_tools()}
        for name in ("get_lan_gateway_status", "list_lan_nodes", "probe_lan_node"):
            tool = tools[name]
            rendered = json.dumps(tool.input_schema, sort_keys=True)
            self.assertNotIn('"port"', rendered)
            self.assertNotIn('"address"', rendered)
            self.assertTrue(tool.annotations.read_only_hint)
            self.assertFalse(tool.annotations.open_world_hint)


if __name__ == "__main__":
    unittest.main()
