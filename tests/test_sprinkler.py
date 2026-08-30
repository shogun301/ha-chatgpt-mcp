from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from pydantic import BaseModel, ConfigDict

_temporary_root = tempfile.TemporaryDirectory()
_root = Path(_temporary_root.name)
for _name, _value in {
    "ha_token": "test-home-assistant-token",
    "oauth_password_hash": "$argon2id$v=19$m=65536,t=3,p=4$dGVzdA$dGVzdA",
    "jwt_secret": "test-jwt-secret-that-is-long-enough-for-unit-tests",
    "origin_shared_secret": "test-origin-shared-secret",
}.items():
    (_root / _name).write_text(_value, encoding="utf-8")
os.environ.setdefault("PUBLIC_BASE_URL", "https://example.invalid")
os.environ.setdefault("FRONTEND_PUBLIC_URL", "https://ha.example.invalid")
os.environ.setdefault("HA_BASE_URL", "http://127.0.0.1:8123")
os.environ.setdefault("HA_TOKEN_FILE", str(_root / "ha_token"))
os.environ.setdefault("OAUTH_PASSWORD_HASH_FILE", str(_root / "oauth_password_hash"))
os.environ.setdefault("JWT_SECRET_FILE", str(_root / "jwt_secret"))
os.environ.setdefault("ORIGIN_SHARED_SECRET_FILE", str(_root / "origin_shared_secret"))
os.environ.setdefault("DATABASE_PATH", str(_root / "oauth.sqlite3"))
os.environ.setdefault("AUDIT_LOG_PATH", str(_root / "audit.jsonl"))
os.environ.setdefault("HA_CONFIG_PATH", str(_root / "ha-config"))
os.environ.setdefault("BACKUP_PATH", str(_root / "backups"))
os.environ.setdefault("HOST_DIAGNOSTICS_PATH", str(_root / "host-diagnostics"))
(_root / "ha-config").mkdir(exist_ok=True)
(_root / "backups").mkdir(exist_ok=True)
(_root / "host-diagnostics").mkdir(exist_ok=True)

from app.server import (
    RedactingMCPServer,
    SprinklerSequenceEntry,
    SprinklerExactSequenceEntry,
    _controller_from_snapshot,
    _run_intervals,
    _zone_model,
    claims_context,
    get_sprinkler_capabilities,
    get_sprinkler_command_status,
    get_sprinkler_controller_diagnostics,
    get_sprinkler_history,
    get_sprinkler_summary,
    get_sprinkler_upcoming_runs,
    get_sprinkler_weather_and_decisions,
    list_sprinkler_schedules,
    mcp,
    press_button,
    run_sprinkler_sequence,
    run_sprinkler_sequence_exact,
    run_sprinkler_zone,
    run_sprinkler_zone_exact,
    set_number_value,
    stop_sprinklers,
)
from app.sprinkler import ConfigurationValue, SprinklerConfiguration


class _SensitiveTypedOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip_address: str | None = None
    ssid: str | None = None
    access_token: str | None = None
    ip_address_redacted: bool
    ssid_redacted: bool


class SprinklerContractTests(unittest.TestCase):
    def test_empty_zone_event_placeholders_are_omitted_defensively(self) -> None:
        zone = _zone_model(
            {
                "zone": 1,
                "enabled": True,
                "recent_events": [
                    {},
                    {"evidence_type": "controller-reported"},
                    {"event_id": "real-event", "event_type": "watering"},
                ],
            }
        )

        self.assertEqual(len(zone.recent_events), 1)
        self.assertEqual(zone.recent_events[0].event_id, "real-event")

    def test_new_tools_advertise_structured_output_schemas(self) -> None:
        tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
        expected = {
            "get_sprinkler_capabilities",
            "get_sprinkler_summary",
            "list_sprinkler_zones",
            "get_sprinkler_configuration",
            "get_sprinkler_history",
            "get_sprinkler_command_status",
            "list_sprinkler_schedules",
            "get_sprinkler_upcoming_runs",
            "get_sprinkler_weather_and_decisions",
            "get_sprinkler_controller_diagnostics",
            "refresh_sprinkler",
            "run_sprinkler_zone",
            "run_sprinkler_sequence",
            "run_sprinkler_zone_exact",
            "run_sprinkler_sequence_exact",
            "stop_sprinklers",
        }
        self.assertTrue(expected.issubset(tools))
        for name in expected:
            schema = tools[name].output_schema
            self.assertIsInstance(schema, dict, name)
            self.assertEqual(schema.get("type"), "object", name)
            self.assertTrue(schema.get("properties"), name)
            self.assertFalse(schema.get("additionalProperties", True), name)
            for definition_name, definition in schema.get("$defs", {}).items():
                if definition.get("type") == "object":
                    self.assertFalse(
                        definition.get("additionalProperties", True),
                        f"{name}.{definition_name}",
                    )

        history_schema = tools["get_sprinkler_history"].output_schema
        interval = history_schema["$defs"]["SprinklerHistoryInterval"]
        self.assertEqual(
            history_schema["properties"]["window_started_at"]["format"],
            "date-time",
        )
        self.assertEqual(interval["properties"]["started_at"]["format"], "date-time")
        self.assertIn("source_supported", interval["required"])
        self.assertIn("duration_supported", interval["required"])
        self.assertIn("omitted_ambiguous_timestamp_count", history_schema["required"])
        self.assertIn("interruption_supported", interval["required"])
        self.assertEqual(
            interval["properties"]["duration_seconds"]["anyOf"][0]["type"],
            "integer",
        )

        command_schema = tools["run_sprinkler_zone_exact"].output_schema
        command_zone = command_schema["$defs"]["SprinklerCommandZone"]
        self.assertEqual(command_zone["type"], "object")
        self.assertFalse(command_zone["additionalProperties"])
        self.assertEqual(
            command_zone["properties"]["duration_seconds"]["anyOf"][0]["type"],
            "integer",
        )
        exact_input = tools["run_sprinkler_zone_exact"].input_schema
        self.assertEqual(
            exact_input["properties"]["duration_seconds"]["minimum"], 1
        )

    def test_exact_zone_command_constructs_native_integer_seconds(self) -> None:
        token = claims_context.set({"scope": "mcp:read mcp:write"})
        try:
            with (
                patch(
                    "app.server._sprinkler_zone_records",
                    new=AsyncMock(
                        return_value=[
                            {
                                "zone": 1,
                                "enabled": True,
                                "native_zone_id": "native-zone-a",
                            }
                        ]
                    ),
                ),
                patch(
                    "app.server._sprinkler_device_id",
                    new=AsyncMock(return_value="device-registry-id"),
                ),
                patch(
                    "app.server.ha.call_service", new=AsyncMock(return_value=[])
                ) as service,
            ):
                result = asyncio.run(run_sprinkler_zone_exact("zone-1", 20, True))
        finally:
            claims_context.reset(token)
        service_data = service.await_args.args[2]
        self.assertEqual(service.await_args.args[:2], ("wyzeapi", "run_sprinkler_zone"))
        self.assertEqual(service_data["device_id"], ["device-registry-id"])
        self.assertEqual(service_data["zone"], 1)
        self.assertEqual(service_data["duration_seconds"], 20)
        self.assertEqual(service_data["command_id"], result.command_id)
        self.assertEqual(result.evidence, "commanded")
        self.assertFalse(result.physical_state_verified)
        self.assertEqual(result.zones[0].duration_seconds, 20)

    def test_exact_sequence_constructs_ordered_unique_seconds(self) -> None:
        token = claims_context.set({"scope": "mcp:read mcp:write"})
        entries = [
            SprinklerExactSequenceEntry(zone_id="zone-2", duration_seconds=121),
            SprinklerExactSequenceEntry(zone_id="zone-1", duration_seconds=60),
        ]
        try:
            with (
                patch(
                    "app.server._sprinkler_zone_records",
                    new=AsyncMock(
                        return_value=[
                            {"zone": 1, "enabled": True, "native_zone_id": "a"},
                            {"zone": 2, "enabled": True, "native_zone_id": "b"},
                        ]
                    ),
                ),
                patch(
                    "app.server._sprinkler_device_id",
                    new=AsyncMock(return_value="device-registry-id"),
                ),
                patch(
                    "app.server.ha.call_service", new=AsyncMock(return_value=[])
                ) as service,
            ):
                result = asyncio.run(run_sprinkler_sequence_exact(entries, True))
        finally:
            claims_context.reset(token)
        self.assertEqual(
            service.await_args.args[2]["zones"],
            [
                {"zone": 2, "duration_seconds": 121},
                {"zone": 1, "duration_seconds": 60},
            ],
        )
        self.assertEqual(service.await_args.args[2]["command_id"], result.command_id)
        self.assertEqual([item.zone_id for item in result.zones], ["zone-2", "zone-1"])

    def test_legacy_zone_sequence_and_stop_correlate_command_ids(self) -> None:
        token = claims_context.set({"scope": "mcp:read mcp:write"})
        zone_records = [
            {"zone": 1, "enabled": True, "native_zone_id": "native-a"},
            {"zone": 2, "enabled": True, "native_zone_id": "native-b"},
        ]
        try:
            with (
                patch(
                    "app.server._sprinkler_zone_records",
                    new=AsyncMock(return_value=zone_records),
                ),
                patch(
                    "app.server._sprinkler_device_id",
                    new=AsyncMock(return_value="device-registry-id"),
                ),
                patch(
                    "app.server.ha.call_service", new=AsyncMock(return_value=[])
                ) as service,
            ):
                zone_result = asyncio.run(run_sprinkler_zone(1, 2.05, True))
                sequence_result = asyncio.run(
                    run_sprinkler_sequence(
                        [SprinklerSequenceEntry(zone=2, duration_minutes=1.5)],
                        True,
                    )
                )
                stop_result = asyncio.run(stop_sprinklers())
        finally:
            claims_context.reset(token)

        zone_call, sequence_call, stop_call = service.await_args_list
        self.assertEqual(zone_call.args[2]["command_id"], zone_result.command_id)
        self.assertEqual(zone_call.args[2]["duration_minutes"], 2.05)
        self.assertEqual(zone_result.zones[0].duration_seconds, 123)
        self.assertEqual(
            sequence_call.args[2]["command_id"], sequence_result.command_id
        )
        self.assertEqual(
            sequence_call.args[2]["zones"],
            [{"zone": 2, "duration_minutes": 1.5}],
        )
        self.assertEqual(stop_call.args[2]["command_id"], stop_result.command_id)
        self.assertEqual(stop_call.args[2]["device_id"], ["device-registry-id"])

    def test_history_unions_recorder_dedupes_and_includes_overlap(self) -> None:
        now = datetime.now(UTC)
        provider_run = {
            "run_id": "run-provider",
            "program_id": "program-1",
            "source": "quick_run",
            "outcome": "completed",
            "zone_runs": [
                {
                    "zone_number": 1,
                    "zone_id": "native-zone-a",
                    "zone_name": "Front",
                    "started_at": (now - timedelta(minutes=55)).isoformat(),
                    "ended_at": (now - timedelta(minutes=50)).isoformat(),
                    "duration_seconds": 300,
                    "duration_evidence_type": "controller-reported",
                    "commanded_duration_seconds": 1200,
                    "commanded_duration_evidence_type": "controller-reported",
                    "source": "quick_run",
                    "source_evidence_type": "controller-reported",
                }
            ],
        }
        recorder_provider_copy = {
            "run_id": "different-recorder-id",
            "zone_runs": [
                {
                    "zone_number": 1,
                    "zone_name": "Front",
                    "started_at": (
                        now - timedelta(minutes=55) + timedelta(seconds=1)
                    ).isoformat(),
                    "ended_at": (now - timedelta(minutes=49, seconds=30)).isoformat(),
                }
            ],
        }
        recorder_provider_open = {
            "zone_runs": [
                {
                    "zone_number": 1,
                    "zone_name": "Front",
                    "started_at": (
                        now - timedelta(minutes=55) + timedelta(seconds=1)
                    ).isoformat(),
                }
            ]
        }
        recorder_run = {
            "state": "cancelled",
            "zone_runs": [
                {
                    "zone_number": 1,
                    "zone_name": "Front",
                    "started_at": (now - timedelta(minutes=30)).isoformat(),
                    "ended_at": (now - timedelta(minutes=25)).isoformat(),
                }
            ],
        }
        recorder = [
            [
                {"attributes": {"recent_runs": [recorder_provider_open, recorder_run]}},
                {"attributes": {"recent_runs": [recorder_provider_copy, recorder_run]}},
            ]
        ]
        with (
            patch(
                "app.server._sprinkler_zone_records",
                new=AsyncMock(
                    return_value=[{"zone": 1, "name": "Front", "enabled": True}]
                ),
            ),
            patch(
                "app.server._sprinkler_response",
                new=AsyncMock(return_value={"runs": [provider_run]}),
            ),
            patch("app.server.ha.history", new=AsyncMock(return_value=recorder)),
        ):
            result = asyncio.run(get_sprinkler_history(limit=100, hours=1))
        self.assertEqual(result.count, 2)
        self.assertEqual(result.intervals[0].evidence_type, "controller-reported")
        self.assertEqual(result.intervals[0].duration_seconds, 300)
        self.assertEqual(result.intervals[0].commanded_duration_seconds, 1200)
        self.assertEqual(result.intervals[0].source, "quick_run")
        self.assertIsNone(result.intervals[0].interrupted)
        self.assertFalse(result.intervals[0].interruption_supported)
        self.assertEqual(result.intervals[1].evidence_type, "reconstructed")
        self.assertTrue(result.intervals[1].interrupted)
        self.assertIsNone(result.intervals[1].run_id)
        self.assertEqual(result.native_run_count, 1)
        self.assertEqual(result.native_interval_count, 1)
        self.assertEqual(result.recorder_snapshot_count, 2)
        self.assertEqual(result.recorder_interval_count, 4)
        self.assertEqual(result.deduplicated_interval_count, 3)
        self.assertEqual(result.omitted_ambiguous_timestamp_count, 0)
        self.assertFalse(result.upstream_complete)

    def test_command_status_retains_last_audited_sequence_details(self) -> None:
        with (
            patch(
                "app.server._sprinkler_response",
                new=AsyncMock(
                    return_value={
                        "snapshot": {
                            "watering_state": {
                                "state": "idle",
                                "evidence_type": "controller-reported",
                            },
                            "command_pending": False,
                        }
                    }
                ),
            ),
            patch(
                "app.server.audit.latest_tool_call",
                return_value={
                    "tool": "run_sprinkler_sequence_exact",
                    "command_id": "sequence-command-1",
                    "operation": "run_sequence",
                    "timestamp": "2026-08-29T19:00:00Z",
                    "zones": [
                        {
                            "zone_id": "zone-2",
                            "native_zone_id": "native-b",
                            "duration_seconds": 121,
                        },
                        {
                            "zone_id": "zone-1",
                            "native_zone_id": "native-a",
                            "duration_seconds": 60,
                        },
                    ],
                },
            ),
        ):
            status = asyncio.run(get_sprinkler_command_status())
        self.assertEqual(status.last_mcp_command.command_id, "sequence-command-1")
        self.assertEqual(status.last_mcp_command.action, "run_sequence")
        self.assertIsNone(status.last_mcp_command.zone_id)
        self.assertEqual(
            [zone.zone_id for zone in status.last_mcp_command.zones],
            ["zone-2", "zone-1"],
        )
        self.assertEqual(
            [zone.duration_seconds for zone in status.last_mcp_command.zones],
            [121, 60],
        )
        self.assertEqual(status.last_mcp_command.zones[0].native_zone_id, "native-b")

    def test_history_reports_timezone_ambiguous_omissions(self) -> None:
        with (
            patch(
                "app.server._sprinkler_zone_records",
                new=AsyncMock(
                    return_value=[{"zone": 1, "name": "Front", "enabled": True}]
                ),
            ),
            patch(
                "app.server._sprinkler_response",
                new=AsyncMock(
                    return_value={
                        "runs": [
                            {
                                "zone_runs": [
                                    {
                                        "zone_number": 1,
                                        "started_at": "2026-08-29T12:00:00",
                                        "timestamp_ambiguity": {
                                            "supported": False,
                                            "reason": "naive local timestamp",
                                        },
                                    }
                                ]
                            },
                            {
                                "zone_runs": [
                                    {
                                        "zone_number": 1,
                                        "started_at": "2026-08-29T12:00:00Z",
                                        "start_time": "2026-08-29T12:00:00",
                                        "ended_at": "2026-08-29T12:05:00Z",
                                        "timestamp_ambiguity": {
                                            "supported": False,
                                            "reason": "secondary alias is naive",
                                        },
                                    }
                                ]
                            },
                        ]
                    }
                ),
            ),
            patch("app.server.ha.history", new=AsyncMock(return_value=[])),
        ):
            result = asyncio.run(get_sprinkler_history(limit=100, hours=48))
        self.assertEqual(result.count, 1)
        self.assertEqual(result.omitted_ambiguous_timestamp_count, 1)
        self.assertIn("Timezone-ambiguous", result.limitation)

    def test_history_preserves_provenance_unknowns_and_strict_false(self) -> None:
        now = datetime.now(UTC)
        intervals = _run_intervals(
            [
                {
                    "zone_runs": [
                        {
                            "zone_number": 1,
                            "started_at": (now - timedelta(minutes=5)).isoformat(),
                            "ended_at": (now - timedelta(minutes=3)).isoformat(),
                            "duration_seconds": 120,
                            "duration_evidence_type": "calculated",
                            "commanded_duration_seconds": 180,
                            "commanded_duration_evidence_type": "controller-reported",
                            "source": "manual",
                            "source_evidence_type": "inferred",
                            "outcome": "aborted",
                            "outcome_evidence_type": "inferred",
                            "interrupted": "false",
                            "interruption_evidence_type": "inferred",
                            "evidence_type": "reconstructed",
                        }
                    ]
                },
                {
                    "zone_runs": [
                        {
                            "zone_number": 2,
                            "started_at": (now - timedelta(minutes=2)).isoformat(),
                            "source": "unknown",
                            "source_evidence_type": "controller-reported",
                        }
                    ]
                },
                {
                    "zone_runs": [
                        {
                            "zone_number": 3,
                            "started_at": now.isoformat(),
                            "ended_at": (now - timedelta(minutes=1)).isoformat(),
                        }
                    ]
                },
            ],
            window_start=now - timedelta(hours=1),
            window_end=now,
            evidence_type="controller-reported",
            zone_names={1: "Front", 2: "Back"},
        )
        derived, unknown = intervals
        self.assertEqual(derived.evidence_type, "reconstructed")
        self.assertEqual(derived.duration_evidence, "calculated")
        self.assertEqual(derived.commanded_duration_seconds, 180)
        self.assertEqual(derived.commanded_duration_evidence, "controller-reported")
        self.assertEqual(derived.source_evidence, "inferred")
        self.assertEqual(derived.outcome_evidence, "inferred")
        self.assertFalse(derived.interrupted)
        self.assertEqual(derived.interruption_evidence, "inferred")

        self.assertIsNone(unknown.run_id)
        self.assertEqual(unknown.source, "unknown")
        self.assertFalse(unknown.source_supported)
        self.assertIsNone(unknown.source_evidence)
        self.assertEqual(unknown.outcome, "unknown")
        self.assertFalse(unknown.outcome_supported)
        self.assertIsNone(unknown.outcome_evidence)
        self.assertIsNone(unknown.interrupted)
        self.assertFalse(unknown.interruption_supported)
        self.assertIsNone(unknown.interruption_evidence)
        self.assertIsNone(unknown.duration_seconds)
        self.assertFalse(unknown.duration_supported)
        self.assertIsNone(unknown.duration_evidence)

        synthetic_command_end = _run_intervals(
            [
                {
                    "zone_runs": [
                        {
                            "zone_number": 1,
                            "started_at": (now - timedelta(minutes=20)).isoformat(),
                            "ended_at": (now - timedelta(minutes=10)).isoformat(),
                            "commanded_duration_seconds": 600,
                            "duration_evidence_type": "unsupported",
                            "evidence_type": "reconstructed",
                        }
                    ]
                }
            ],
            window_start=now - timedelta(hours=1),
            window_end=now,
            evidence_type="controller-reported",
            zone_names={1: "Front"},
        )[0]
        self.assertIsNone(synthetic_command_end.ended_at)
        self.assertIsNone(synthetic_command_end.duration_seconds)
        self.assertFalse(synthetic_command_end.duration_supported)
        self.assertEqual(synthetic_command_end.commanded_duration_seconds, 600)

        native_timing = _run_intervals(
            [
                {
                    "zone_runs": [
                        {
                            "zone_number": 1,
                            "started_at": (now - timedelta(minutes=10)).isoformat(),
                            "ended_at": (now - timedelta(minutes=8)).isoformat(),
                            "source": "manual",
                            "source_evidence_type": "inferred",
                            "outcome": "completed",
                            "outcome_evidence_type": "inferred",
                        }
                    ]
                }
            ],
            window_start=now - timedelta(hours=1),
            window_end=now,
            evidence_type="controller-reported",
            zone_names={1: "Front"},
        )[0]
        self.assertEqual(native_timing.evidence_type, "controller-reported")
        self.assertEqual(native_timing.duration_evidence, "calculated")
        self.assertEqual(native_timing.source_evidence, "inferred")
        self.assertEqual(native_timing.outcome_evidence, "inferred")

        delayed = _run_intervals(
            [
                {
                    "zone_runs": [
                        {
                            "zone_number": 1,
                            "started_at": (now - timedelta(minutes=15)).isoformat(),
                            "ended_at": (now - timedelta(minutes=14)).isoformat(),
                            "skip_state": "rain_delay",
                        }
                    ]
                }
            ],
            window_start=now - timedelta(hours=1),
            window_end=now,
            evidence_type="controller-reported",
            zone_names={1: "Front"},
        )[0]
        self.assertEqual(delayed.outcome, "rain_delay")
        self.assertTrue(delayed.outcome_supported)
        self.assertEqual(delayed.outcome_evidence, "controller-reported")

        parent_only_multizone = _run_intervals(
            [
                {
                    "started_at": (now - timedelta(minutes=20)).isoformat(),
                    "ended_at": (now - timedelta(minutes=10)).isoformat(),
                    "zone_runs": [{"zone_number": 1}, {"zone_number": 2}],
                }
            ],
            window_start=now - timedelta(hours=1),
            window_end=now,
            evidence_type="controller-reported",
            zone_names={1: "Front", 2: "Back"},
        )
        self.assertEqual(parent_only_multizone, [])

    def test_capabilities_are_explicit_about_upstream_absence(self) -> None:
        with (
            patch(
                "app.server._sprinkler_device_id",
                new=AsyncMock(return_value="device-registry-id"),
            ),
            patch(
                "app.server._sprinkler_zone_records",
                new=AsyncMock(
                    return_value=[{"zone": 1, "name": "Front", "enabled": True}]
                ),
            ),
        ):
            result = asyncio.run(get_sprinkler_capabilities())
        capabilities = {item.capability: item for item in result.capabilities}
        self.assertFalse(capabilities["schedule_mutations"].supported)
        self.assertFalse(
            capabilities["physical_valve_flow_electrical_fault_feedback"].supported
        )
        self.assertEqual(capabilities["zone_moisture_estimate"].evidence, "calculated")

    def test_read_tools_normalize_integration_response_services(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        with patch(
            "app.server._sprinkler_response",
            new=AsyncMock(
                return_value={
                    "snapshot": {
                        "connected": True,
                        "watering_state": {
                            "state": "watering",
                            "evidence_type": "inferred",
                        },
                        "active_zone_number": 1,
                        "active_zone_id": "native-zone-a",
                        "remaining_seconds": 90,
                        "remaining_evidence_type": "controller-reported",
                        "expected_end_at": "2026-08-29T19:01:30Z",
                        "expected_end_evidence_type": "calculated",
                        "zones": [
                            {
                                "zone_number": 1,
                                "zone_id": "native-zone-a",
                            }
                        ],
                        "command_pending": True,
                        "command_status": {
                            "command_id": "mcp-command-1",
                            "action": "start_zone",
                            "state": "pending",
                            "zone_number": 1,
                            "zone_id": "native-zone-a",
                            "duration_seconds": 90,
                            "issued_at": "2026-08-29T19:00:00Z",
                            "evidence_type": "commanded",
                            "physical_state_verified": True,
                        },
                    }
                }
            ),
        ):
            command = asyncio.run(get_sprinkler_command_status())
        self.assertEqual(command.pending_command.evidence, "commanded")
        self.assertEqual(command.pending_command.command_id, "mcp-command-1")
        self.assertEqual(command.pending_command.action, "start_zone")
        self.assertEqual(command.pending_command.zone_id, "zone-1")
        self.assertEqual(command.pending_command.requested_duration_seconds, 90)
        self.assertFalse(command.pending_command.physical_state_verified)
        self.assertEqual(command.controller_state.evidence, "inferred")
        self.assertEqual(command.controller_state.active_zone_id, "zone-1")
        self.assertEqual(
            command.controller_state.active_native_zone_id, "native-zone-a"
        )
        self.assertEqual(
            command.controller_state.remaining_runtime_evidence,
            "controller-reported",
        )
        self.assertEqual(command.controller_state.expected_end_evidence, "calculated")

        schedule_payload = {
            "schedules": [
                {
                    "schedule_id": "program-1",
                    "name": "Morning",
                    "enabled": True,
                    "schedule_type": "fixed",
                    "zone_runs": [
                        {
                            "zone_number": 1,
                            "zone_id": "native-zone-a",
                            "duration_seconds": 300,
                        }
                    ],
                }
            ]
        }
        with patch(
            "app.server._sprinkler_response",
            new=AsyncMock(return_value=schedule_payload),
        ):
            schedules = asyncio.run(list_sprinkler_schedules())
        self.assertTrue(schedules.read_supported)
        self.assertEqual(schedules.schedules[0].zone_ids, ["zone-1"])
        self.assertEqual(schedules.schedules[0].zone_runs[0].duration_seconds, 300)
        self.assertFalse(schedules.mutations.supported)

        with patch(
            "app.server._sprinkler_response",
            new=AsyncMock(
                side_effect=[
                    {
                        "runs": [
                            {
                                "run_id": "future-run",
                                "schedule_id": "program-1",
                                "next_run_at": future,
                                "zone_runs": [{"zone_number": 1}],
                            }
                        ]
                    },
                    {"schedules": []},
                ]
            ),
        ):
            upcoming = asyncio.run(get_sprinkler_upcoming_runs())
        self.assertTrue(upcoming.supported)
        self.assertEqual(upcoming.runs[0].zone_ids, ["zone-1"])
        self.assertEqual(upcoming.runs[0].source, "unknown")
        self.assertFalse(upcoming.runs[0].source_supported)
        self.assertIsNone(upcoming.runs[0].evidence)

        configuration = SprinklerConfiguration(
            entity_id="sensor.sprinkler_controller_configuration",
            state="configured",
            values=[
                ConfigurationValue(name="rain_skip_threshold", value=0.5),
                ConfigurationValue(name="notification_watering_is_skipped", value=True),
            ],
        )
        with (
            patch(
                "app.server.get_sprinkler_configuration",
                new=AsyncMock(return_value=configuration),
            ),
            patch(
                "app.server._sprinkler_response",
                new=AsyncMock(
                    return_value={
                        "runs": [
                            {
                                "run_id": "skipped-run",
                                "skipped": True,
                                "skipped_reason": "rain",
                            },
                            {
                                "run_id": "delayed-run",
                                "skip_state": "rain_delay",
                                "skip_reason": "forecast rain",
                            },
                        ]
                    }
                ),
            ),
        ):
            weather = asyncio.run(get_sprinkler_weather_and_decisions())
        self.assertEqual(
            {item.name: item.value for item in weather.thresholds},
            {"rain_skip_threshold": 0.5},
        )
        self.assertEqual(weather.decisions[0].decision, "skipped")
        self.assertEqual(weather.decisions[1].decision, "rain_delay")
        self.assertFalse(weather.wyze_weather_data.supported)

        with (
            patch(
                "app.server._sprinkler_response",
                new=AsyncMock(
                    return_value={
                        "snapshot": {
                            "controller_health": {
                                "connected": True,
                                "evidence_type": "controller-reported",
                                "firmware": "1.2.3",
                                "signal_strength_native_value": -55,
                                "ip_address": "192.0.2.1",
                                "ssid": "private-wifi",
                            },
                            "endpoint_errors": [],
                        }
                    }
                ),
            ),
            patch(
                "app.server.ha.state",
                new=AsyncMock(return_value={"state": "idle", "attributes": {}}),
            ),
        ):
            diagnostics = asyncio.run(get_sprinkler_controller_diagnostics())
            typed_diagnostics = asyncio.run(
                mcp.call_tool("get_sprinkler_controller_diagnostics", {})
            )
        self.assertEqual(diagnostics.firmware_version, "1.2.3")
        self.assertTrue(diagnostics.firmware_supported)
        self.assertEqual(diagnostics.firmware_evidence, "controller-reported")
        self.assertTrue(diagnostics.connectivity_supported)
        self.assertEqual(diagnostics.connectivity_evidence, "controller-reported")
        self.assertEqual(diagnostics.signal_strength_native_value, -55)
        self.assertTrue(diagnostics.signal_strength_supported)
        self.assertEqual(diagnostics.signal_strength_units, "upstream_unspecified")
        self.assertEqual(diagnostics.signal_strength_evidence, "controller-reported")
        self.assertEqual(diagnostics.endpoint_health_evidence, "inferred")
        self.assertIsNone(diagnostics.ip_address)
        self.assertTrue(diagnostics.ip_address_supported)
        self.assertEqual(diagnostics.ip_address_evidence, "controller-reported")
        self.assertTrue(diagnostics.ip_address_redacted)
        self.assertTrue(diagnostics.ssid_supported)
        self.assertEqual(diagnostics.ssid_evidence, "controller-reported")
        self.assertTrue(diagnostics.ssid_redacted)
        self.assertFalse(diagnostics.measured_flow.supported)
        self.assertIsNone(typed_diagnostics.structured_content["ip_address"])
        self.assertTrue(
            typed_diagnostics.structured_content["ip_address_supported"]
        )
        self.assertTrue(
            typed_diagnostics.structured_content["ip_address_redacted"]
        )
        self.assertTrue(typed_diagnostics.structured_content["ssid_redacted"])

        with (
            patch(
                "app.server._sprinkler_response",
                new=AsyncMock(
                    return_value={
                        "snapshot": {
                            "controller_health": {
                                "connected": None,
                                "evidence_type": "unsupported",
                            }
                        }
                    }
                ),
            ),
            patch(
                "app.server.ha.state",
                new=AsyncMock(return_value={"state": "unknown", "attributes": {}}),
            ),
        ):
            unknown_diagnostics = asyncio.run(get_sprinkler_controller_diagnostics())
            typed_unknown_diagnostics = asyncio.run(
                mcp.call_tool("get_sprinkler_controller_diagnostics", {})
            )
        self.assertIsNone(unknown_diagnostics.connected)
        self.assertFalse(unknown_diagnostics.connectivity_supported)
        self.assertIsNone(unknown_diagnostics.connectivity_evidence)
        self.assertFalse(unknown_diagnostics.firmware_supported)
        self.assertIsNone(unknown_diagnostics.firmware_evidence)
        self.assertFalse(unknown_diagnostics.signal_strength_supported)
        self.assertIsNone(unknown_diagnostics.signal_strength_evidence)
        self.assertFalse(unknown_diagnostics.ip_address_supported)
        self.assertIsNone(unknown_diagnostics.ip_address_evidence)
        self.assertFalse(unknown_diagnostics.ip_address_redacted)
        self.assertFalse(unknown_diagnostics.ssid_supported)
        self.assertIsNone(unknown_diagnostics.ssid_evidence)
        self.assertFalse(unknown_diagnostics.ssid_redacted)
        self.assertIsNone(
            typed_unknown_diagnostics.structured_content["ip_address"]
        )
        self.assertFalse(
            typed_unknown_diagnostics.structured_content["ip_address_redacted"]
        )
        self.assertFalse(
            typed_unknown_diagnostics.structured_content["ssid_redacted"]
        )

    def test_controller_unknown_and_upcoming_feed_are_explicitly_unsupported(
        self,
    ) -> None:
        controller = _controller_from_snapshot(
            {
                "watering": None,
                "watering_state": {
                    "state": "unknown",
                    "evidence_type": "unsupported",
                },
                "updated_at": "2026-08-29T19:00:00Z",
            }
        )
        self.assertEqual(controller.state, "unknown")
        self.assertFalse(controller.state_supported)
        self.assertIsNone(controller.evidence)

        explicit_idle = _controller_from_snapshot({"watering": False})
        self.assertEqual(explicit_idle.state, "idle")
        self.assertTrue(explicit_idle.state_supported)
        self.assertEqual(explicit_idle.evidence, "controller-reported")

        unavailable = _controller_from_snapshot({"watering_state": "unavailable"})
        self.assertEqual(unavailable.state, "unavailable")
        self.assertFalse(unavailable.state_supported)
        self.assertIsNone(unavailable.evidence)

        states = [
            {
                "entity_id": "sensor.sprinkler_status",
                "state": "unknown",
                "attributes": {
                    "watering_evidence_type": "unsupported",
                    "physical_state_verified": True,
                },
            },
            {
                "entity_id": "sensor.sprinkler_active_zone",
                "state": "unknown",
                "attributes": {},
            },
            {
                "entity_id": "sensor.sprinkler_remaining",
                "state": "unknown",
                "attributes": {},
            },
            {
                "entity_id": "sensor.sprinkler_last_watering",
                "state": "unknown",
                "attributes": {},
            },
        ]
        with (
            patch("app.server.ha.state", new=AsyncMock(side_effect=states)),
            patch(
                "app.server._sprinkler_zone_records",
                new=AsyncMock(return_value=[]),
            ),
        ):
            summary = asyncio.run(get_sprinkler_summary())
        self.assertFalse(summary.controller_state.state_supported)
        self.assertIsNone(summary.controller_state.evidence)
        self.assertFalse(summary.telemetry.live_running_state_available)
        self.assertFalse(summary.telemetry.physical_state_verified)

        unavailable_states = [
            {
                "entity_id": item["entity_id"],
                "state": "unavailable",
                "attributes": {},
            }
            for item in states
        ]
        with (
            patch(
                "app.server.ha.state", new=AsyncMock(side_effect=unavailable_states)
            ),
            patch(
                "app.server._sprinkler_zone_records",
                new=AsyncMock(return_value=[]),
            ),
        ):
            unavailable_summary = asyncio.run(get_sprinkler_summary())
        self.assertFalse(unavailable_summary.controller_state.state_supported)
        self.assertIsNone(unavailable_summary.controller_state.evidence)

        offline_states = [
            {
                "entity_id": item["entity_id"],
                "state": "offline" if index == 0 else "unknown",
                "attributes": {},
            }
            for index, item in enumerate(states)
        ]
        with (
            patch("app.server.ha.state", new=AsyncMock(side_effect=offline_states)),
            patch(
                "app.server._sprinkler_zone_records",
                new=AsyncMock(return_value=[]),
            ),
        ):
            offline_summary = asyncio.run(get_sprinkler_summary())
        self.assertEqual(offline_summary.controller_state.state, "offline")
        self.assertFalse(offline_summary.controller_state.state_supported)
        self.assertIsNone(offline_summary.controller_state.evidence)

        future = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        with patch(
            "app.server._sprinkler_response",
            new=AsyncMock(
                side_effect=[
                    {"runs": [{"next_run_at": future}]},
                    {"schedules": []},
                ]
            ),
        ):
            unsupported = asyncio.run(get_sprinkler_upcoming_runs())
        self.assertFalse(unsupported.supported)
        self.assertFalse(unsupported.feed_complete)
        self.assertEqual(unsupported.count, 0)

        with patch(
            "app.server._sprinkler_response",
            new=AsyncMock(
                side_effect=[
                    {
                        "runs": [
                            {
                                "schedule_id": "program-a",
                                "next_run_at": future,
                                "zone_runs": [{"zone_number": 1}],
                            },
                            {
                                "schedule_id": "program-b",
                                "next_run_at": future,
                                "zone_runs": [{"zone_number": 2}],
                            },
                        ]
                    },
                    {"schedules": []},
                ]
            ),
        ):
            distinct = asyncio.run(get_sprinkler_upcoming_runs())
        self.assertEqual(distinct.count, 2)
        self.assertEqual(
            {run.program_id for run in distinct.runs}, {"program-a", "program-b"}
        )
        self.assertTrue(all(run.run_id is None for run in distinct.runs))
        self.assertTrue(all(not run.source_supported for run in distinct.runs))

    def test_zone_native_moisture_and_configuration_evidence_are_typed(self) -> None:
        from app.server import _zone_model

        zone = _zone_model(
            {
                "zone": 1,
                "enabled": True,
                "flow_rate": 7.5,
                "area": 350,
                "modeled_soil_moisture_native_value": 247.25,
            }
        )
        self.assertEqual(zone.configuration_evidence, "controller-reported")
        self.assertEqual(zone.flow_rate_evidence, "controller-reported")
        self.assertFalse(zone.flow_rate_physically_measured)
        self.assertEqual(zone.flow_rate_unit, "upstream_unspecified")
        self.assertEqual(zone.area_unit, "upstream_unspecified")
        self.assertEqual(zone.modeled_soil_moisture_native_value, 247.25)
        self.assertEqual(zone.moisture_unit, "upstream_unspecified")
        self.assertEqual(zone.moisture_evidence, "calculated")

    def test_typed_mcp_outputs_cross_redaction_boundary(self) -> None:
        server = RedactingMCPServer("redaction-test")

        @server.tool()
        async def typed_sensitive_output(include: bool = True) -> _SensitiveTypedOutput:
            return _SensitiveTypedOutput(
                ip_address="192.0.2.10" if include else None,
                ssid="private-wifi" if include else None,
                access_token="must-never-leave-mcp" if include else None,
                ip_address_redacted=include,
                ssid_redacted=include,
            )

        result = asyncio.run(server.call_tool("typed_sensitive_output", {}))
        rendered = json.dumps(result.model_dump(mode="json"))
        self.assertNotIn("192.0.2.10", rendered)
        self.assertNotIn("private-wifi", rendered)
        self.assertNotIn("must-never-leave-mcp", rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertTrue(result.structured_content["ip_address_redacted"])
        self.assertTrue(result.structured_content["ssid_redacted"])
        absent = asyncio.run(server.call_tool("typed_sensitive_output", {"include": False}))
        self.assertIsNone(absent.structured_content["ip_address"])
        self.assertIsNone(absent.structured_content["ssid"])
        self.assertIsNone(absent.structured_content["access_token"])
        self.assertFalse(absent.structured_content["ip_address_redacted"])
        self.assertFalse(absent.structured_content["ssid_redacted"])

    def test_generic_entity_tools_cannot_bypass_sprinkler_authorization(self) -> None:
        token = claims_context.set({"scope": "mcp:read mcp:write"})
        try:
            with self.assertRaisesRegex(PermissionError, "dedicated sprinkler"):
                asyncio.run(set_number_value("number.sprinkler_controller_zone_1", 10))
            with self.assertRaisesRegex(PermissionError, "dedicated sprinkler"):
                asyncio.run(set_number_value("number.sprinkler_controller_zone_4", 10))
            with self.assertRaisesRegex(PermissionError, "dedicated sprinkler"):
                asyncio.run(
                    press_button("button.sprinkler_controller_zone_1", confirmed=True)
                )
            with self.assertRaisesRegex(PermissionError, "dedicated sprinkler"):
                asyncio.run(
                    press_button("button.sprinkler_controller_zone_4", confirmed=True)
                )
        finally:
            claims_context.reset(token)


if __name__ == "__main__":
    unittest.main()
