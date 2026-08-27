from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from app.capability_sync import CapabilitySync, _normalize_services


def services(*entries: tuple[str, str, dict]) -> list[dict]:
    domains: dict[str, dict] = {}
    for domain, service, fields in entries:
        domains.setdefault(domain, {})[service] = {"fields": fields}
    return [
        {"domain": domain, "services": domain_services}
        for domain, domain_services in domains.items()
    ]


class CapabilityNormalizationTests(unittest.TestCase):
    def test_normalization_keeps_only_schema_compatibility_fields(self) -> None:
        raw = services(
            (
                "calendar",
                "create_event",
                {
                    "summary": {"required": True, "example": "Private title"},
                    "description": {"required": False},
                },
            )
        )
        self.assertEqual(
            _normalize_services(raw),
            [
                {
                    "domain": "calendar",
                    "service": "create_event",
                    "fields": ["description", "summary"],
                    "required_fields": ["summary"],
                }
            ],
        )


class CapabilitySyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_drift_persists_across_restart_until_release_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "capability-sync.json"
            ha = AsyncMock()
            ha.services.return_value = services(("light", "turn_on", {}))
            sync = CapabilitySync(state_path, "2.6.0", interval_seconds=60)
            first = await sync.refresh(ha)
            self.assertEqual(first["status"], "in_sync")

            ha.services.return_value = services(
                ("light", "turn_on", {}),
                ("wyzeapi", "new_function", {"zone": {"required": True}}),
            )
            changed = await sync.refresh(ha)
            self.assertEqual(changed["status"], "drift_detected")
            self.assertEqual(changed["drift"]["added"], ["wyzeapi.new_function"])

            restarted = CapabilitySync(state_path, "2.6.0", interval_seconds=60)
            persisted = await restarted.refresh(ha)
            self.assertEqual(persisted["drift"]["added"], ["wyzeapi.new_function"])

            next_release = CapabilitySync(state_path, "2.6.1", interval_seconds=60)
            acknowledged = await next_release.refresh(ha)
            self.assertEqual(acknowledged["status"], "in_sync")
            self.assertFalse(any(acknowledged["drift"].values()))

    async def test_field_contract_changes_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "capability-sync.json"
            ha = AsyncMock()
            ha.services.return_value = services(
                ("time", "set_value", {"time": {"required": True}})
            )
            sync = CapabilitySync(state_path, "2.6.0", interval_seconds=60)
            await sync.refresh(ha)
            ha.services.return_value = services(
                (
                    "time",
                    "set_value",
                    {"time": {"required": True}, "timezone": {"required": False}},
                )
            )
            result = await sync.refresh(ha)
            self.assertEqual(result["status"], "drift_detected")
            self.assertEqual(result["drift"]["changed"][0]["service"], "time.set_value")
            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["schema_version"], 1)
            self.assertIn("baseline_fingerprint", persisted)
