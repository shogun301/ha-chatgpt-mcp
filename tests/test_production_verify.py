from __future__ import annotations

import os
import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jwt

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
        "FRONTEND_PUBLIC_URL": "https://frontend.example.invalid",
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
for _directory in ("ha-config", "backups", "host-diagnostics"):
    (_root / _directory).mkdir()

from app.lan import SERVICE_PORTS
from app.server import ALLOWED_SERVICES, SERVER_VERSION, mcp
from scripts.production_mcp_verify import (
    DIAGNOSTIC_REQUESTS,
    DIAGNOSTIC_TOOLS,
    EXPECTED_TOOL_COUNT,
    EXPECTED_VERSION,
    LAN_PROBE_SERVICES,
    NEW_CAPABILITY_TOOLS,
    SPRINKLER_SAFE_REQUESTS,
    _access_token,
    _transport_streams,
)


class ProductionVerifierCompatibilityTests(unittest.TestCase):
    def test_accepts_current_two_stream_transport(self) -> None:
        self.assertEqual(_transport_streams(("read", "write")), ("read", "write"))

    def test_accepts_legacy_three_item_transport(self) -> None:
        self.assertEqual(
            _transport_streams(("read", "write", "session")), ("read", "write")
        )

    def test_rejects_unknown_transport_contract(self) -> None:
        with self.assertRaises(RuntimeError):
            _transport_streams(("read",))

    def test_verifier_token_targets_mcp_resource(self) -> None:
        with (
            patch("scripts.production_mcp_verify.config.PUBLIC_BASE_URL", "https://example.invalid"),
            patch("scripts.production_mcp_verify.config.MCP_RESOURCE", "https://example.invalid/mcp"),
            patch(
                "scripts.production_mcp_verify.config.JWT_SECRET",
                "test-verifier-secret-at-least-32-bytes",
            ),
        ):
            token = _access_token("mcp:read")
        claims = jwt.decode(
            token,
            "test-verifier-secret-at-least-32-bytes",
            algorithms=["HS256"],
            audience="https://example.invalid/mcp",
            issuer="https://example.invalid",
        )
        self.assertEqual(claims["aud"], "https://example.invalid/mcp")

    def test_verifier_only_mutates_sprinkler_via_safe_refresh(self) -> None:
        source = Path("scripts/production_mcp_verify.py").read_text(encoding="utf-8")
        self.assertIn('"refresh_sprinkler",', source)
        self.assertNotIn('session.call_tool("run_sprinkler_zone"', source)
        self.assertNotIn('session.call_tool("run_sprinkler_sequence"', source)
        self.assertNotIn('session.call_tool("stop_sprinklers"', source)

    def test_verifier_uses_only_canonical_lan_services(self) -> None:
        self.assertTrue(set(LAN_PROBE_SERVICES).issubset(SERVICE_PORTS))


class ProductionVerifierSchemaTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _assert_value_matches_schema(value: object, schema: dict[str, object]) -> None:
        expected = schema.get("type")
        if expected == "boolean":
            assert isinstance(value, bool)
        elif expected == "integer":
            assert isinstance(value, int) and not isinstance(value, bool)
        elif expected == "number":
            assert isinstance(value, (int, float)) and not isinstance(value, bool)
        elif expected == "string":
            assert isinstance(value, str)
        elif expected == "array":
            assert isinstance(value, list)
            item_schema = schema.get("items")
            if isinstance(item_schema, dict):
                for item in value:
                    ProductionVerifierSchemaTests._assert_value_matches_schema(
                        item, item_schema
                    )
        if "enum" in schema:
            assert value in schema["enum"]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema:
                assert value >= schema["minimum"]
            if "maximum" in schema:
                assert value <= schema["maximum"]
        if isinstance(value, str) and "pattern" in schema:
            import re

            assert re.fullmatch(str(schema["pattern"]), value)

    async def test_all_production_verifier_requests_match_advertised_schemas(self) -> None:
        tools = {tool.name: tool for tool in await mcp.list_tools()}
        contract = json.loads(
            Path("tests/fixtures/server-contract-2.6.3.json").read_text(encoding="utf-8")
        )
        self.assertEqual(EXPECTED_VERSION, SERVER_VERSION)
        self.assertEqual(EXPECTED_TOOL_COUNT, len(tools))
        self.assertEqual(contract["version"], SERVER_VERSION)
        self.assertEqual(contract["tool_count"], len(tools))
        self.assertEqual(set(contract["tool_names"]), set(tools))
        canonical = lambda value: hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(
            contract["tool_schema_sha256"],
            canonical({name: tool.input_schema for name, tool in tools.items()}),
        )
        self.assertEqual(
            contract["tool_annotations_sha256"],
            canonical(
                {
                    name: (
                        tool.annotations.model_dump(mode="json")
                        if tool.annotations is not None
                        else None
                    )
                    for name, tool in tools.items()
                }
            ),
        )
        self.assertEqual(
            contract["generic_service_allowlist"],
            {domain: sorted(services) for domain, services in ALLOWED_SERVICES.items()},
        )
        self.assertTrue(NEW_CAPABILITY_TOOLS.issubset(tools))
        self.assertEqual(set(DIAGNOSTIC_TOOLS), set(DIAGNOSTIC_REQUESTS))
        requests = {
            "get_capability_sync_status": {"refresh": True},
            **DIAGNOSTIC_REQUESTS,
            **SPRINKLER_SAFE_REQUESTS,
        }
        for name, arguments in requests.items():
            with self.subTest(tool=name):
                schema = tools[name].input_schema
                properties = schema.get("properties", {})
                self.assertTrue(set(arguments).issubset(properties))
                self.assertTrue(set(schema.get("required", [])).issubset(arguments))
                for key, value in arguments.items():
                    self._assert_value_matches_schema(value, properties[key])
