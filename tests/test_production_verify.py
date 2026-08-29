from __future__ import annotations

import os
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
from scripts.production_mcp_verify import (
    LAN_PROBE_SERVICES,
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
