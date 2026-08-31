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
    SPRINKLER_COMMAND_TOOLS,
    SPRINKLER_READ_REQUESTS,
    _access_token,
    _assert_sanitized,
    _assert_zone_inventory,
    _transport_streams,
    _validate_sprinkler_result,
    _verification_report,
    _verification_base_url,
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

    def test_verifier_never_executes_any_sprinkler_command(self) -> None:
        source = Path("scripts/production_mcp_verify.py").read_text(encoding="utf-8")
        self.assertNotIn("refresh_sprinkler", SPRINKLER_READ_REQUESTS)
        self.assertTrue(SPRINKLER_COMMAND_TOOLS.isdisjoint(SPRINKLER_READ_REQUESTS))
        for name in SPRINKLER_COMMAND_TOOLS:
            self.assertNotIn(f'session.call_tool("{name}"', source)

    def test_report_requires_every_sprinkler_read_and_live_inventory(self) -> None:
        read_only = {
            "diagnostic_calls": {name: False for name in DIAGNOSTIC_TOOLS},
            "sprinkler_read_calls": {
                name: True for name in SPRINKLER_READ_REQUESTS
            },
            "sprinkler_inventory": {
                "configured_zone_count": 3,
                "integration_zone_count": 3,
                "normalized_zone_ids": ["zone-1", "zone-2", "zone-3"],
            },
            "sprinkler_command_schemas_inspected": sorted(SPRINKLER_COMMAND_TOOLS),
        }
        report = _verification_report(read_only, {}, {})
        self.assertIs(report["read_only_scope"], read_only)
        self.assertTrue(report["insufficient_scope_rejected"])

        missing_read = dict(read_only)
        missing_read["sprinkler_read_calls"] = dict(
            read_only["sprinkler_read_calls"]
        )
        missing_read["sprinkler_read_calls"].pop("get_sprinkler_summary")
        with self.assertRaisesRegex(AssertionError, "every read"):
            _verification_report(missing_read, {}, {})

        missing_inventory = dict(read_only)
        missing_inventory["sprinkler_inventory"] = None
        with self.assertRaisesRegex(AssertionError, "inventory evidence is missing"):
            _verification_report(missing_inventory, {}, {})

    def test_verifier_uses_only_canonical_lan_services(self) -> None:
        self.assertTrue(set(LAN_PROBE_SERVICES).issubset(SERVICE_PORTS))

    def test_preflight_transport_override_is_loopback_only(self) -> None:
        with patch.dict(
            os.environ,
            {"PRODUCTION_VERIFY_BASE_URL": "http://127.0.0.1:8001"},
        ):
            self.assertEqual(_verification_base_url(), "http://127.0.0.1:8001")
        for unsafe in (
            "https://example.invalid",
            "http://192.0.2.1:8001",
            "http://127.0.0.1:8001/path",
        ):
            with (
                patch.dict(os.environ, {"PRODUCTION_VERIFY_BASE_URL": unsafe}),
                self.assertRaisesRegex(RuntimeError, "loopback"),
            ):
                _verification_base_url()

    def test_sanitizer_allows_native_twelve_digit_device_identifiers(self) -> None:
        _assert_sanitized('{"native_zone_id":"123456789012"}')

    def test_sanitizer_rejects_contextual_aws_account_identifiers(self) -> None:
        with self.assertRaisesRegex(AssertionError, "forbidden identifier"):
            _assert_sanitized('{"aws_account_id":"123456789012"}')

    def test_gantt_acceptance_requires_aware_timestamps_and_evidence(self) -> None:
        payload = {
            "window_started_at": "2026-08-29T00:00:00+00:00",
            "window_ended_at": "2026-08-31T00:00:00+00:00",
            "count": 1,
            "omitted_ambiguous_timestamp_count": 0,
            "intervals": [{
                "zone_id": "zone-1", "zone_name": "Zone 1",
                "started_at": "2026-08-29T01:00:00+00:00",
                "ended_at": "2026-08-29T01:05:00+00:00",
                "duration_seconds": 300, "duration_supported": True,
                "duration_evidence": "calculated",
                "commanded_duration_seconds": 300,
                "commanded_duration_evidence": "commanded",
                "source": "quick_run", "source_supported": True,
                "source_evidence": "controller-reported", "outcome": "completed",
                "outcome_supported": True,
                "outcome_evidence": "controller-reported",
                "interrupted": False, "interruption_supported": True,
                "interruption_evidence": "inferred", "run_id": "run-1",
                "program_id": "program-1",
                "evidence_type": "controller-reported",
            }],
        }
        _validate_sprinkler_result("get_sprinkler_history", payload)
        payload["intervals"][0]["started_at"] = "2026-08-29T01:00:00"
        with self.assertRaisesRegex(AssertionError, "time-zone-aware"):
            _validate_sprinkler_result("get_sprinkler_history", payload)
        interval = payload["intervals"][0]
        interval["started_at"] = "2026-08-29T01:00:00+00:00"
        interval.update({
            "outcome": "unknown", "outcome_supported": False,
            "outcome_evidence": None, "interrupted": None,
            "interruption_supported": False, "interruption_evidence": None,
        })
        _validate_sprinkler_result("get_sprinkler_history", payload)
        interval["outcome"] = "completed"
        with self.assertRaisesRegex(AssertionError, "unsupported outcome"):
            _validate_sprinkler_result("get_sprinkler_history", payload)

    def test_acceptance_requires_explicit_unsupported_upstream_evidence(self) -> None:
        unsupported = {
            "supported": False,
            "reason": "No verified upstream signal.",
            "upstream_evidence": "Captured payload and installed library omit it.",
        }
        payload = {
            "physical_feedback": unsupported,
            "measured_flow": unsupported,
            "electrical_load": unsupported,
            "valve_faults": unsupported,
        }
        _validate_sprinkler_result("get_sprinkler_controller_diagnostics", payload)
        payload["measured_flow"] = {"supported": False}
        with self.assertRaisesRegex(AssertionError, "upstream limitation"):
            _validate_sprinkler_result("get_sprinkler_controller_diagnostics", payload)

    def test_zone_inventory_must_exactly_match_live_integration_snapshot(self) -> None:
        mcp_payload = {
            "count": 2,
            "zones": [
                {"zone_id": "zone-1", "native_zone_id": "native-a"},
                {"zone_id": "zone-2", "native_zone_id": "native-b"},
            ],
        }
        snapshot = {
            "zones": [
                {"zone_number": 1, "zone_id": "native-a"},
                {"zone_number": 2, "zone_id": "native-b"},
            ]
        }
        result = _assert_zone_inventory(mcp_payload, snapshot, configured_count=2)
        self.assertEqual(result["integration_zone_count"], 2)
        self.assertEqual(result["normalized_zone_ids"], ["zone-1", "zone-2"])
        snapshot["zones"].append({"zone_number": 3, "zone_id": "native-c"})
        with self.assertRaisesRegex(AssertionError, "exactly match"):
            _assert_zone_inventory(mcp_payload, snapshot, configured_count=2)

    def test_verifier_reads_snapshot_but_has_no_integration_command_endpoint(self) -> None:
        source = Path("scripts/production_mcp_verify.py").read_text(encoding="utf-8")
        self.assertIn("/api/services/wyzeapi/get_sprinkler_snapshot?return_response", source)
        for command in (
            "run_sprinkler_zone", "run_sprinkler_sequence", "stop_sprinkler",
            "refresh_sprinkler",
        ):
            self.assertNotIn(f"/api/services/wyzeapi/{command}", source)


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
            Path("tests/fixtures/server-contract-2.7.7.json").read_text(encoding="utf-8")
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
            contract["tool_output_schema_sha256"],
            canonical({name: tool.output_schema for name, tool in tools.items()}),
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
        for name in ("list_vacuum_rooms", "clean_vacuum_rooms"):
            self.assertIsNone(
                tools[name].input_schema["properties"]["entity_id"].get("default"),
                f"{name} must not expose an environment-specific entity default",
            )
        self.assertTrue(NEW_CAPABILITY_TOOLS.issubset(tools))
        self.assertEqual(set(DIAGNOSTIC_TOOLS), set(DIAGNOSTIC_REQUESTS))
        requests = {
            "get_capability_sync_status": {"refresh": True},
            **DIAGNOSTIC_REQUESTS,
            **SPRINKLER_READ_REQUESTS,
        }
        for name, arguments in requests.items():
            with self.subTest(tool=name):
                schema = tools[name].input_schema
                properties = schema.get("properties", {})
                self.assertTrue(set(arguments).issubset(properties))
                self.assertTrue(set(schema.get("required", [])).issubset(arguments))
                for key, value in arguments.items():
                    self._assert_value_matches_schema(value, properties[key])
