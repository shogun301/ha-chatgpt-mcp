"""Pure tests for the deterministic Wyze sprinkler integration overlay."""

from __future__ import annotations

import ast
import asyncio
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import time
import types


OVERLAY = (
    Path(__file__).parents[1]
    / "wyzeapi_overlay"
    / "custom_components"
    / "wyzeapi"
)


def _load_irrigation_data():
    spec = importlib.util.spec_from_file_location(
        "wyze_sprinkler_overlay_irrigation_data", OVERLAY / "irrigation_data.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


data = _load_irrigation_data()


def _evidence_values(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith("evidence_type"):
                yield item
            yield from _evidence_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _evidence_values(item)


def test_zone_normalization_preserves_advanced_allowlisted_configuration() -> None:
    zone = data.normalize_zone(
        {
            "zone_number": "3",
            "zone_id": "native-zone-771",
            "name": "Orchard",
            "enabled": "true",
            "smart_duration": "720",
            "wired": "true",
            "zone_area": "845.5",
            "available_water_capacity": "0.19",
            "kc": "0.72",
            "application_efficiency": "0.81",
            "flow_rate": "8.4",
            "sprinkler_head_count": "7",
            "root_depth_in": "10",
            "management_allowed_depletion": "0.45",
            "soil_moisture_level_at_end_of_day_pct": "0.34",
            "vegetation_type": "trees",
            "sun_exposure": "full_sun",
            "soil_type": "loam",
            "slope_type": "moderate",
            "nozzle_type": "rotary",
            "events": [
                {
                    "id": "event-1",
                    "type": "model_update",
                    "status": "complete",
                    "timestamp": 1_788_000_000_000,
                    "opaque_secret": "must-not-survive",
                }
            ],
            "access_token": "must-not-survive",
        }
    )

    assert zone["zone_number"] == 3
    assert zone["zone_id"] == "native-zone-771"
    assert zone["wired"] is True
    assert zone["area"] == 845.5
    assert zone["available_water"] == 0.19
    assert zone["crop_coefficient"] == 0.72
    assert zone["efficiency"] == 0.81
    assert zone["flow_rate"] == 8.4
    assert zone["flow_rate_evidence_type"] == "configuration"
    assert zone["flow_rate_physically_measured"] is False
    assert zone["head_count"] == 7.0
    assert zone["root_depth"] == 10.0
    assert zone["allowed_depletion"] == 0.45
    assert zone["modeled_soil_moisture_native_value"] == 0.34
    assert zone["modeled_soil_moisture_units"] == "unknown"
    assert zone["soil_moisture_evidence_type"] == "calculated"
    assert zone["latest_events"] == [
        {
            "event_id": "event-1",
            "event_type": "model_update",
            "state": "complete",
            "occurred_at": "2026-08-29T10:40:00+00:00",
            "evidence_type": "controller-reported",
        }
    ]
    assert "must-not-survive" not in repr(zone)


def test_zone_entity_attributes_expose_rich_fields_and_bound_events() -> None:
    normalized = data.normalize_zone(
        {
            "zone_number": 4,
            "zone_id": "native-4",
            "name": "Garden",
            "wired": True,
            "area": 400,
            "available_water": 0.18,
            "crop_coefficient": 0.7,
            "efficiency": 0.8,
            "flow_rate": 7.5,
            "head_count": 6,
            "root_depth": 8,
            "allowed_depletion": 0.4,
            "modeled_soil_moisture": 0.31,
            "latest_events": [
                {"id": f"event-{index}", "type": "model_update", "time": index}
                for index in range(12)
            ],
            "opaque": "must-not-survive",
        }
    )
    attributes = data.zone_entity_attributes(normalized)

    assert attributes["zone_id"] == "native-4"
    assert attributes["wired"] is True
    assert attributes["area"] == 400.0
    assert attributes["available_water"] == 0.18
    assert attributes["crop_coefficient"] == 0.7
    assert attributes["efficiency"] == 0.8
    assert attributes["flow_rate"] == 7.5
    assert attributes["flow_rate_evidence_type"] == "configuration"
    assert attributes["flow_rate_physically_measured"] is False
    assert attributes["head_count"] == 6.0
    assert attributes["root_depth"] == 8.0
    assert attributes["allowed_depletion"] == 0.4
    assert attributes["modeled_soil_moisture_native_value"] == 0.31
    assert attributes["modeled_soil_moisture_units"] == "unknown"
    assert attributes["soil_moisture_evidence_type"] == "calculated"
    assert len(attributes["latest_events"]) == 10
    assert "opaque" not in repr(attributes)


def test_empty_zone_event_placeholders_are_omitted() -> None:
    normalized = data.normalize_zone(
        {
            "zone_number": 1,
            "latest_events": [
                {},
                {"evidence_type": "controller-reported"},
                {"id": "real-event", "type": "watering"},
            ],
        }
    )

    assert normalized["latest_events"] == [
        {
            "event_id": "real-event",
            "event_type": "watering",
            "evidence_type": "controller-reported",
        }
    ]
    assert data.zone_entity_attributes({"latest_events": [{}, {}]}) == {}


def test_schedule_runs_preserve_rich_per_zone_semantics_and_utc() -> None:
    now = datetime(2026, 8, 29, 12, 30, tzinfo=timezone.utc)
    response = {
        "data": {
            "schedule_runs": [
                {
                    "run_id": "run-42",
                    "program_id": "program-7",
                    "schedule_id": "schedule-9",
                    "schedule_name": "Morning",
                    "schedule_type": "fixed",
                    "source": "native_schedule",
                    "schedule_state": "complete",
                    "outcome": "completed",
                    "skip_state": "not_skipped",
                    "zone_runs": [
                        {
                            "run_id": "zone-run-a",
                            "zone_number": 1,
                            "zone_id": "native-a",
                            "status": "complete",
                            "start_time": "2026-08-29T05:00:00-07:00",
                            "end_time": "2026-08-29T05:08:00-07:00",
                            "duration": 600,
                            "actual_duration": 480,
                            "outcome": "completed",
                            "interrupted": False,
                        },
                        {
                            "run_id": "zone-run-b",
                            "zone_number": 2,
                            "status": "stopped",
                            "start_ts": 1_787_999_280_000,
                            "end_ts": 1_787_999_460_000,
                            "planned_duration": 420,
                            "stop_reason": "manual_stop",
                        },
                    ],
                }
            ]
        }
    }
    zones = [
        {"zone_number": 1, "zone_id": "native-a", "name": "Lawn"},
        {"zone_number": 2, "zone_id": "native-b", "name": "Beds"},
    ]

    normalized = data.normalize_schedule_runs_response(
        response, zones, limit=48, now=now
    )
    run = normalized["runs"][0]
    first, second = run["zone_runs"]

    assert normalized["limit"] == 48
    assert run["run_id"] == "run-42"
    assert run["program_id"] == "program-7"
    assert run["schedule_id"] == "schedule-9"
    assert run["schedule_type"] == "fixed"
    assert run["source"] == "native_schedule"
    assert run["outcome"] == "completed"
    assert run["skip_state"] == "not_skipped"
    assert first["started_at"] == "2026-08-29T12:00:00+00:00"
    assert first["ended_at"] == "2026-08-29T12:08:00+00:00"
    assert first["duration_seconds"] == 480
    assert first["duration_evidence_type"] == "controller-reported"
    assert first["commanded_duration_seconds"] == 600
    assert first["commanded_duration_evidence_type"] == "controller-reported"
    assert first["interrupted"] is False
    assert first["run_id"] == "run-42"
    assert first["parent_run_id"] == "run-42"
    assert first["zone_run_id"] == "zone-run-a"
    assert first["record_scope"] == "zone_run"
    assert second["zone_id"] == "native-b"
    assert second["interrupted"] is True
    assert second["interruption_evidence_type"] == "inferred"
    assert second["interruption_reason"] == "manual_stop"
    assert normalized["physical_state_verified"] is False
    assert "physical" not in set(_evidence_values(normalized))


def test_planned_end_is_separate_from_actual_history_interval() -> None:
    now = datetime(2026, 8, 29, 12, 5, tzinfo=timezone.utc)
    run = data.normalize_schedule(
        {
            "schedule_run_id": "active-1",
            "zone_runs": [
                {
                    "zone_number": 1,
                    "started_at": "2026-08-29T12:00:00Z",
                    "duration": 900,
                }
            ],
        },
        [{"zone_number": 1, "name": "Lawn"}],
        now,
    )

    assert run["state"] == "running"
    assert run["state_evidence_type"] == "inferred"
    assert "ended_at" not in run
    assert run["expected_end_at"] == "2026-08-29T12:15:00+00:00"
    assert run["expected_end_evidence_type"] == "calculated"
    assert "duration_seconds" not in run
    assert run["duration_evidence_type"] == "unsupported"
    assert run["remaining_seconds"] == 600
    assert run["remaining_evidence_type"] == "calculated"
    assert "ended_at" not in run["zone_runs"][0]
    assert run["zone_runs"][0]["expected_end_at"] == "2026-08-29T12:15:00+00:00"
    assert run["zone_runs"][0]["expected_end_evidence_type"] == "calculated"
    assert run["zone_runs"][0]["evidence_type"] == "controller-reported"
    assert "duration_seconds" not in run["zone_runs"][0]
    assert run["zone_runs"][0]["duration_evidence_type"] == "unsupported"
    assert run["zone_runs"][0]["commanded_duration_seconds"] == 900
    assert "interrupted" not in run["zone_runs"][0]
    assert run["zone_runs"][0]["interruption_evidence_type"] == "unsupported"


def test_explicit_utc_fields_win_over_naive_local_aliases() -> None:
    run = data.normalize_schedule(
        {
            "run_id": "utc-run",
            "schedule_state": "complete",
            "zone_runs": [
                {
                    "zone_number": 1,
                    "start_time_utc": "2026-08-29T12:00:00Z",
                    "start_time": "2026-08-29T05:00:00",
                    "complete_time_utc": "2026-08-29T12:05:00+00:00",
                    "end_time": "2026-08-29T05:05:00",
                }
            ],
        },
        [{"zone_number": 1, "name": "Lawn"}],
        datetime(2026, 8, 29, 13, 0, tzinfo=timezone.utc),
    )

    interval = run["zone_runs"][0]
    assert interval["started_at"] == "2026-08-29T12:00:00+00:00"
    assert interval["ended_at"] == "2026-08-29T12:05:00+00:00"
    assert "timestamp_ambiguity" not in interval


def test_naive_local_timestamps_are_not_assumed_utc() -> None:
    run = data.normalize_schedule(
        {
            "run_id": "ambiguous-run",
            "schedule_state": "complete",
            "zone_runs": [
                {
                    "zone_number": 1,
                    "start_time": "2026-08-29T05:00:00",
                    "end_time": "2026-08-29T05:05:00",
                }
            ],
        },
        [{"zone_number": 1, "name": "Lawn"}],
        datetime(2026, 8, 29, 13, 0, tzinfo=timezone.utc),
    )

    interval = run["zone_runs"][0]
    assert "started_at" not in interval
    assert "ended_at" not in interval
    assert interval["timestamp_ambiguity"] == {
        "supported": False,
        "fields": ["end_time", "start_time"],
        "reason": "naive local timestamps have no UTC offset",
    }

    schedules = data.normalize_schedules_response(
        {
            "data": {
                "schedules": [
                    {
                        "id": "schedule-naive",
                        "next_run_time": "2026-08-30T05:00:00",
                    }
                ]
            }
        },
        [],
        datetime(2026, 8, 29, 13, 0, tzinfo=timezone.utc),
    )
    definition = schedules["schedules"][0]
    assert "next_run_at" not in definition
    assert definition["timestamp_ambiguity"]["supported"] is False
    assert definition["timestamp_ambiguity"]["fields"] == ["next_run_at"]


def test_snapshot_exposes_controller_health_and_command_latch_without_physical_claim() -> None:
    now = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
    snapshot = data.normalize_snapshot(
        {
            "data": {
                "props": {
                    "iot_state": "connected",
                    "iot_state_update_time": 1_787_996_800_000,
                    "RSSI": "-57",
                    "IP": "192.0.2.10",
                    "ssid": "example",
                    "app_version": "1.2.3",
                    "sn": "controller-serial",
                    "wifi_mac": "AA:BB:CC:DD:EE:FF",
                    "zone_state": [{"zone_number": 1, "state": "idle"}],
                }
            }
        },
        {"data": {"zones": [{"zone_number": 1, "name": "Lawn"}]}},
        {"data": {"enable_schedules": True}},
        {"data": {"schedule_runs": []}},
        now,
    )
    snapshot = data.apply_coordinator_state(
        snapshot,
        command_pending=True,
        partial=True,
        endpoint_errors=["schedule"],
    )

    assert snapshot["controller_health"] == {
        "connected": True,
        "iot_state": "connected",
        "iot_state_updated_at": "2026-08-29T09:46:40+00:00",
        "rssi": -57,
        "ip": "192.0.2.10",
        "ssid": "example",
        "firmware": "1.2.3",
        "serial_number": "controller-serial",
        "wifi_mac": "AA:BB:CC:DD:EE:FF",
        "evidence_type": "controller-reported",
        "partial": True,
        "endpoint_errors": ["schedule"],
        "endpoint_health_evidence_type": "calculated",
    }
    assert snapshot["command_pending"] is True
    assert snapshot["command_status"] == {
        "state": "pending",
        "evidence_type": "commanded",
        "physical_state_verified": False,
    }
    assert snapshot["watering_state"]["physical_state_verified"] is False
    assert "physical" not in set(_evidence_values(snapshot))


def test_snapshot_preserves_native_active_zone_and_state_evidence() -> None:
    snapshot = data.normalize_snapshot(
        {"data": {"props": {"iot_state": "connected"}}},
        {
            "data": {
                "zones": [
                    {"zone_number": 2, "zone_id": "native-zone-2", "name": "Beds"}
                ]
            }
        },
        {},
        {
            "data": {
                "schedule_runs": [
                    {
                        "run_id": "run-active",
                        "schedule_state": "running",
                        "zone_runs": [
                            {
                                "zone_number": 2,
                                "status": "running",
                                "start_time_utc": "2026-08-29T12:00:00Z",
                                "duration": 300,
                                "remaining_time": 120,
                            }
                        ],
                    }
                ]
            }
        },
        datetime(2026, 8, 29, 12, 1, tzinfo=timezone.utc),
    )
    assert snapshot["active_zone_number"] == 2
    assert snapshot["active_zone_id"] == "native-zone-2"
    assert snapshot["watering_state"]["evidence_type"] == "controller-reported"
    assert snapshot["remaining_evidence_type"] == "controller-reported"
    assert snapshot["expected_end"] == "2026-08-29T12:05:00+00:00"
    assert snapshot["expected_end_evidence_type"] == "calculated"


def test_snapshot_keeps_watering_unknown_without_explicit_controller_evidence() -> None:
    snapshot = data.normalize_snapshot(
        {"data": {"props": {"iot_state": "connected"}}},
        {"data": {"zones": [{"zone_number": 1, "name": "Lawn"}]}},
        {},
        {},
        datetime(2026, 8, 29, 12, 1, tzinfo=timezone.utc),
    )
    assert snapshot["connected"] is True
    assert snapshot["watering"] is None
    assert snapshot["watering_state"] == {
        "state": "unknown",
        "evidence_type": "unsupported",
        "physical_state_verified": False,
    }


def test_snapshot_treats_controller_past_schedule_as_finished() -> None:
    snapshot = data.normalize_snapshot(
        {"data": {"props": {"iot_state": "connected"}}},
        {"data": {"zones": [{"zone_number": 3, "name": "Front Yard 3"}]}},
        {},
        {
            "data": {
                "schedule_runs": [
                    {
                        "program_id": "App Quick Run",
                        "schedule_state": "past",
                        "zone_runs": [
                            {
                                "zone_number": 3,
                                "status": "past",
                                "start_time_utc": "2026-08-30T05:34:29Z",
                                "complete_time_utc": "2026-08-30T05:34:41Z",
                                "duration": 12,
                            }
                        ],
                    }
                ]
            }
        },
        datetime(2026, 8, 30, 5, 35, tzinfo=timezone.utc),
    )
    assert snapshot["watering"] is False
    assert snapshot["active_zone_number"] is None
    assert snapshot["watering_state"] == {
        "state": "idle",
        "evidence_type": "inferred",
        "physical_state_verified": False,
    }


def test_running_child_overrides_contradictory_past_parent_state() -> None:
    snapshot = data.normalize_snapshot(
        {"data": {"props": {"iot_state": "connected"}}},
        {"data": {"zones": [{"zone_number": 3, "name": "Front Yard 3"}]}},
        {},
        {
            "data": {
                "schedule_runs": [
                    {
                        "schedule_state": "past",
                        "zone_runs": [
                            {
                                "zone_number": 3,
                                "status": "running",
                                "start_time_utc": "2026-08-30T05:34:29Z",
                                "duration": 480,
                            }
                        ],
                    }
                ]
            }
        },
        datetime(2026, 8, 30, 5, 35, tzinfo=timezone.utc),
    )
    assert snapshot["watering"] is True
    assert snapshot["active_zone_number"] == 3
    assert snapshot["watering_state"]["evidence_type"] == "controller-reported"


def test_snapshot_keeps_connectivity_unknown_without_iot_state_evidence() -> None:
    snapshot = data.normalize_snapshot(
        {"data": {"props": {}}},
        {"data": {"zones": []}},
        {},
        {},
        datetime(2026, 8, 29, 12, 1, tzinfo=timezone.utc),
    )
    assert snapshot["connected"] is None
    snapshot = data.apply_coordinator_state(
        snapshot,
        partial=True,
        endpoint_errors=["iot"],
    )
    assert snapshot["controller_health"] == {
        "evidence_type": "unsupported",
        "partial": True,
        "endpoint_errors": ["iot"],
        "endpoint_health_evidence_type": "calculated",
    }


def test_multi_zone_parent_times_do_not_create_false_zone_intervals() -> None:
    run = data.normalize_schedule(
        {
            "run_id": "parent-run",
            "schedule_state": "complete",
            "start_time_utc": "2026-08-29T12:00:00Z",
            "complete_time_utc": "2026-08-29T12:10:00Z",
            "duration": 600,
            "zone_runs": [
                {"zone_number": 1, "status": "complete"},
                {"zone_number": 2, "status": "complete"},
            ],
        },
        [
            {"zone_number": 1, "name": "Lawn"},
            {"zone_number": 2, "name": "Beds"},
        ],
        datetime(2026, 8, 29, 13, 0, tzinfo=timezone.utc),
    )

    assert run["started_at"] == "2026-08-29T12:00:00+00:00"
    assert run["ended_at"] == "2026-08-29T12:10:00+00:00"
    assert run["duration_seconds"] == 600
    for zone_run in run["zone_runs"]:
        assert "started_at" not in zone_run
        assert "ended_at" not in zone_run
        assert "expected_end_at" not in zone_run
        assert "duration_seconds" not in zone_run
        assert "commanded_duration_seconds" not in zone_run
        assert zone_run["duration_evidence_type"] == "unsupported"


def test_snapshot_accepts_only_explicit_zone_idle_as_controller_reported() -> None:
    snapshot = data.normalize_snapshot(
        {
            "data": {
                "props": {
                    "iot_state": "connected",
                    "zone_state": [{"zone_number": 1, "state": "idle"}],
                }
            }
        },
        {"data": {"zones": [{"zone_number": 1, "name": "Lawn"}]}},
        {},
        {},
        datetime(2026, 8, 29, 12, 1, tzinfo=timezone.utc),
    )
    assert snapshot["watering"] is False
    assert snapshot["watering_state"]["state"] == "idle"
    assert snapshot["watering_state"]["evidence_type"] == "controller-reported"


def test_schedule_definition_normalization_is_allowlisted() -> None:
    response = {
        "data": {
            "schedules": [
                {
                    "id": "schedule-1",
                    "name": "Weekdays",
                    "enabled": 1,
                    "type": "fixed",
                    "time": "05:30",
                    "days_of_week": [1, 2, 3, 4, 5],
                    "next_run_time": "2026-08-31T05:30:00-07:00",
                    "zones": [
                        {"zone_number": 2, "duration": 720, "enabled": True}
                    ],
                    "credential": "must-not-survive",
                    "opaque_weather_blob": {"secret": "must-not-survive"},
                }
            ]
        }
    }
    result = data.normalize_schedules_response(
        response,
        [{"zone_number": 2, "zone_id": "native-2", "name": "Beds"}],
        datetime(2026, 8, 29, tzinfo=timezone.utc),
    )

    assert result["schedules"] == [
        {
            "schedule_id": "schedule-1",
            "name": "Weekdays",
            "enabled": True,
            "schedule_type": "fixed",
            "start_time": "05:30",
            "next_run_at": "2026-08-31T12:30:00+00:00",
            "days": [1, 2, 3, 4, 5],
            "zone_runs": [
                {
                    "zone_number": 2,
                    "zone_id": "native-2",
                    "zone_name": "Beds",
                    "duration_seconds": 720,
                    "enabled": True,
                }
            ],
            "evidence_type": "controller-reported",
        }
    ]
    assert "must-not-survive" not in repr(result)


def test_schedule_cycle_soak_and_recurrence_are_allowlisted() -> None:
    result = data.normalize_schedules_response(
        {
            "data": {
                "schedules": [
                    {
                        "id": "schedule-cycle",
                        "recurrence_rule": "weekly",
                        "repeat_interval": 2,
                        "day_parity": "odd",
                        "cycle_soak": {
                            "enabled": True,
                            "cycle_count": 3,
                            "cycle_duration": 240,
                            "soak_duration": 600,
                            "opaque": "must-not-survive",
                        },
                    }
                ]
            }
        },
        [],
        datetime(2026, 8, 29, tzinfo=timezone.utc),
    )
    schedule = result["schedules"][0]
    assert schedule["recurrence"] == "weekly"
    assert schedule["repeat_interval"] == 2
    assert schedule["odd_even"] == "odd"
    assert schedule["cycle_soak"] == {
        "enabled": True,
        "cycle_count": 3,
        "cycle_duration_seconds": 240,
        "soak_duration_seconds": 600,
    }
    assert "must-not-survive" not in repr(schedule)


def test_capability_contract_returns_explicit_unsupported_signals() -> None:
    contract = data.sprinkler_capabilities()
    supported = {item["capability"]: item for item in contract["supported"]}
    unsupported = {item["capability"]: item for item in contract["unsupported"]}

    for capability in (
        "physical_valve_feedback",
        "physically_measured_flow",
        "electrical_load_or_valve_fault",
        "physically_measured_zone_moisture",
        "schedule_create_update_delete_enable_disable",
        "native_schedule_manual_run",
        "wyze_weather_dataset",
    ):
        assert unsupported[capability]["supported"] is False
        assert unsupported[capability]["reason"]
    assert contract["physical_state_verified"] is False
    assert contract["integration_version"] == "0.1.43"
    assert "physically-measured" not in contract["evidence_labels"]
    assert "unknown native units" in supported["modeled_zone_moisture"]["semantics"]


def test_exact_seconds_and_legacy_decimal_minutes_construct_identical_runs() -> None:
    assert data.duration_seconds_from_fields({"duration_seconds": 123}) == 123
    assert data.duration_seconds_from_fields({"duration_minutes": 2.05}) == 123
    assert data.validate_sequence(
        [
            {"zone": 1, "duration_seconds": 123},
            {"zone": 2, "duration_minutes": 2.05},
        ],
        {1, 2},
    ) == [
        {"zone_number": 1, "duration": 123},
        {"zone_number": 2, "duration": 123},
    ]


def test_duration_construction_requires_one_exact_bounded_field() -> None:
    invalid = (
        {},
        {"duration_seconds": 123, "duration_minutes": 2.05},
        {"duration_seconds": 123.5},
        {"duration_seconds": True},
        {"duration_seconds": 0},
        {"duration_seconds": 10_801},
        {"duration_minutes": 0.99},
        {"duration_minutes": 180.01},
    )
    for fields in invalid:
        try:
            data.duration_seconds_from_fields(fields)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid duration accepted: {fields!r}")


def test_command_status_reconciliation_preserves_metadata_and_stop_pending() -> None:
    pending = {
        "command_id": "command-1",
        "action": "start_zone",
        "state": "pending",
        "zone_number": 2,
        "duration_seconds": 123,
        "issued_at": "2026-08-29T12:00:00+00:00",
        "expires_at": "2026-08-29T12:02:00+00:00",
        "evidence_type": "commanded",
        "physical_state_verified": False,
    }
    unchanged, still_pending = data.reconcile_command_status(
        pending, watering=False, active_zone_number=None, expired=False
    )
    assert still_pending is True
    assert unchanged == pending

    observed, still_pending = data.reconcile_command_status(
        pending, watering=True, active_zone_number=2, expired=False
    )
    assert still_pending is False
    assert observed["command_id"] == "command-1"
    assert observed["state"] == "controller_state_observed"
    assert observed["evidence_type"] == "inferred"
    assert observed["observed_active_zone_number"] == 2
    assert observed["physical_state_verified"] is False

    mismatch, still_pending = data.reconcile_command_status(
        pending, watering=True, active_zone_number=3, expired=False
    )
    assert still_pending is True
    assert mismatch["state"] == "pending"

    unknown_zone, still_pending = data.reconcile_command_status(
        pending, watering=True, active_zone_number=None, expired=False
    )
    assert still_pending is True
    assert unknown_zone["state"] == "pending"

    stop = {"command_id": "command-2", "action": "stop", "state": "pending"}
    stop_pending, is_pending = data.reconcile_command_status(
        stop, watering=True, active_zone_number=2, expired=False
    )
    assert is_pending is True
    assert stop_pending["state"] == "pending"
    stopped, is_pending = data.reconcile_command_status(
        stop, watering=False, active_zone_number=None, expired=False
    )
    assert is_pending is False
    assert stopped["state"] == "controller_state_observed"

    unknown, is_pending = data.reconcile_command_status(
        stop, watering=None, active_zone_number=None, expired=False
    )
    assert is_pending is True
    assert unknown["state"] == "pending"


def _load_init_service_functions():
    source_path = OVERLAY / "__init__.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    names = {
        "_single_device_id",
        "_strict_zone_number",
        "_bounded_duration",
        "_bounded_duration_seconds",
        "_require_one_duration",
        "_bounded_history_limit",
        "_bounded_command_id",
        "async_register_irrigation_services",
        "async_unload_entry",
    }
    selected = [
        node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names
    ]
    module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))

    class FakeVol:
        class Invalid(Exception):
            pass

        PREVENT_EXTRA = object()

        @staticmethod
        def Required(name):
            return name

        @staticmethod
        def Optional(name, default=None):
            return name

        @staticmethod
        def Schema(value, **kwargs):
            return value

        @staticmethod
        def All(*values):
            return values

        @staticmethod
        def Length(**kwargs):
            return kwargs

    namespace = {
        "Any": object,
        "ConfigEntry": object,
        "HomeAssistant": object,
        "HomeAssistantError": RuntimeError,
        "ServiceCall": object,
        "SupportsResponse": types.SimpleNamespace(ONLY="only"),
        "vol": FakeVol,
        "cv": types.SimpleNamespace(ensure_list=object(), string=object()),
        "math": math,
        "re": __import__("re"),
        "duration_seconds_from_fields": data.duration_seconds_from_fields,
        "ATTR_DEVICE_ID": "device_id",
        "DOMAIN": "wyzeapi",
        "PLATFORMS": ["sensor"],
        "SERVICE_RUN_SPRINKLER_ZONE": "run_sprinkler_zone",
        "SERVICE_RUN_SPRINKLER_SEQUENCE": "run_sprinkler_sequence",
        "SERVICE_STOP_SPRINKLER": "stop_sprinkler",
        "SERVICE_REFRESH_SPRINKLER": "refresh_sprinkler",
        "SERVICE_GET_SPRINKLER_SNAPSHOT": "get_sprinkler_snapshot",
        "SERVICE_GET_SPRINKLER_SCHEDULE_RUNS": "get_sprinkler_schedule_runs",
        "SERVICE_GET_SPRINKLER_SCHEDULES": "get_sprinkler_schedules",
        "SERVICE_GET_SPRINKLER_CAPABILITIES": "get_sprinkler_capabilities",
        "IRRIGATION_COORDINATORS": "irrigation_coordinators",
    }
    exec(compile(module, str(source_path), "exec"), namespace)
    return namespace


def test_mocked_ha_response_services_are_response_only_and_do_not_actuate() -> None:
    namespace = _load_init_service_functions()

    class FakeCoordinator:
        def __init__(self):
            self.commands = []
            self.reads = []

        async def async_start_zone(self, zone, duration, command_id=None):
            self.commands.append(("zone", zone, duration, command_id))

        async def async_start_sequence(self, zones, command_id=None):
            self.commands.append(("sequence", zones, command_id))

        async def async_stop(self, command_id=None):
            self.commands.append(("stop", command_id))

        async def async_force_full_refresh(self):
            self.commands.append(("refresh",))

        def sprinkler_snapshot(self):
            self.reads.append("snapshot")
            return {"supported": True, "network_request_performed": False}

        async def async_get_schedule_runs(self, limit):
            self.reads.append(("runs", limit))
            return {"supported": True, "runs": []}

        async def async_get_schedules(self):
            self.reads.append("schedules")
            return {"supported": True, "schedules": []}

        def sprinkler_capabilities(self):
            self.reads.append("capabilities")
            return {"supported": []}

    coordinator = FakeCoordinator()
    namespace["coordinator_for_device_id"] = lambda hass, device_id: coordinator

    class FakeServices:
        def __init__(self):
            self.registered = {}
            self.removed = []

        def has_service(self, domain, service):
            return False

        def async_register(self, domain, service, handler, **kwargs):
            self.registered[service] = (handler, kwargs)

        def async_remove(self, domain, service):
            self.removed.append(service)

    hass = types.SimpleNamespace(services=FakeServices())
    namespace["async_register_irrigation_services"](hass)
    assert set(hass.services.registered) == {
        "run_sprinkler_zone",
        "run_sprinkler_sequence",
        "stop_sprinkler",
        "refresh_sprinkler",
        "get_sprinkler_snapshot",
        "get_sprinkler_schedule_runs",
        "get_sprinkler_schedules",
        "get_sprinkler_capabilities",
    }
    for service in (
        "get_sprinkler_snapshot",
        "get_sprinkler_schedule_runs",
        "get_sprinkler_schedules",
        "get_sprinkler_capabilities",
    ):
        assert hass.services.registered[service][1]["supports_response"] == "only"

    async def exercise():
        call = lambda **data_fields: types.SimpleNamespace(data={"device_id": ["device-1"], **data_fields})
        await hass.services.registered["get_sprinkler_snapshot"][0](call())
        await hass.services.registered["get_sprinkler_schedule_runs"][0](call(limit=48))
        await hass.services.registered["get_sprinkler_schedules"][0](call())
        await hass.services.registered["get_sprinkler_capabilities"][0](call())
        assert coordinator.commands == []
        await hass.services.registered["run_sprinkler_zone"][0](
            call(zone=2, duration_seconds=123, command_id="mcp-command-1")
        )
        await hass.services.registered["run_sprinkler_sequence"][0](
            call(
                zones=[{"zone": 2, "duration_seconds": 180}],
                command_id="mcp-command-2",
            )
        )
        await hass.services.registered["stop_sprinkler"][0](
            call(command_id="mcp-command-3")
        )

    asyncio.run(exercise())
    assert coordinator.commands == [
        ("zone", 2, 123, "mcp-command-1"),
        (
            "sequence",
            [{"zone": 2, "duration_seconds": 180}],
            "mcp-command-2",
        ),
        ("stop", "mcp-command-3"),
    ]
    assert coordinator.reads == ["snapshot", ("runs", 48), "schedules", "capabilities"]


def test_command_id_validator_accepts_bounded_ids_and_rejects_opaque_values() -> None:
    namespace = _load_init_service_functions()
    validator = namespace["_bounded_command_id"]
    assert validator("mcp-command_123") == "mcp-command_123"
    for value in ("", "space is invalid", "x" * 65, "slash/invalid", None):
        try:
            validator(value)
        except Exception:
            pass
        else:
            raise AssertionError(f"invalid command ID accepted: {value!r}")


def test_mocked_ha_unload_removes_all_eight_services() -> None:
    namespace = _load_init_service_functions()

    class FakeServices:
        def __init__(self):
            self.removed = []

        def async_remove(self, domain, service):
            self.removed.append(service)

    class FakeEntries:
        async def async_unload_platforms(self, entry, platforms):
            return True

    hass = types.SimpleNamespace(
        services=FakeServices(),
        config_entries=FakeEntries(),
        data={"wyzeapi": {"entry-1": {}}},
    )
    entry = types.SimpleNamespace(entry_id="entry-1")
    assert asyncio.run(namespace["async_unload_entry"](hass, entry)) is True
    assert len(hass.services.removed) == 8


def test_mocked_native_sequence_http_payload_preserves_exact_seconds() -> None:
    source_path = OVERLAY / "irrigation.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    class_node = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "WyzeIrrigationCoordinator"
    )
    method = next(
        node for node in class_node.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "async_start_sequence"
    )
    function = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    namespace = {
        "Any": object,
        "HomeAssistantError": RuntimeError,
        "validate_sequence": data.validate_sequence,
        "time": time,
        "json": json,
        "OLIVE_APP_ID": "app",
        "APP_INFO": "info",
        "PHONE_ID": "phone",
        "QUICKRUN_URL": "https://example.invalid/quickrun",
        "olive_create_signature": lambda payload, token: "signature",
        "check_for_errors_iot": lambda service, response: None,
    }
    exec(compile(function, str(source_path), "exec"), namespace)

    class AsyncLock:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class Auth:
        def __init__(self):
            self.token = types.SimpleNamespace(access_token="token")
            self.posts = []

        async def refresh_if_should(self):
            return None

        async def post(self, url, **kwargs):
            self.posts.append((url, kwargs))
            return {"code": "1"}

    auth = Auth()
    fake = types.SimpleNamespace(
        _command_lock=AsyncLock(),
        _managed_run_task=None,
        last_update_success=True,
        data={"connected": True, "watering": False, "endpoint_errors": []},
        _command_pending_until=0.0,
        enabled_zone_numbers={1},
        device=types.SimpleNamespace(mac="controller-1"),
        service=types.SimpleNamespace(_auth_lib=auth),
    )
    async def no_op():
        return None
    fake.async_refresh = no_op
    fake.async_request_refresh = no_op
    fake._set_command_pending = lambda action, **details: setattr(fake, "pending", (action, details))
    fake._command_zone_identity = lambda zone_number: {
        "zone_number": zone_number,
        "zone_id": "native-1",
        "zone_name": "Lawn",
    }

    asyncio.run(
        namespace["async_start_sequence"](
            fake,
            [{"zone": 1, "duration_seconds": 123}],
            command_id="mcp-command-2",
        )
    )
    assert len(auth.posts) == 1
    url, kwargs = auth.posts[0]
    assert url == "https://example.invalid/quickrun"
    payload = json.loads(kwargs["data"])
    assert payload["zone_runs"] == [{"zone_number": 1, "duration": 123}]
    assert fake.pending == (
        "start_sequence",
        {
            "command_id": "mcp-command-2",
            "zones": [
                {
                    "zone_number": 1,
                    "zone_id": "native-1",
                    "zone_name": "Lawn",
                    "duration_seconds": 123,
                }
            ],
        },
    )

    fake.data["watering"] = None
    try:
        asyncio.run(
            namespace["async_start_sequence"](
                fake,
                [{"zone": 1, "duration_seconds": 123}],
                command_id="must-not-be-sent",
            )
        )
    except RuntimeError as err:
        assert "watering state is unavailable" in str(err)
    else:
        raise AssertionError("sequence command accepted an unknown watering state")
    assert len(auth.posts) == 1


def test_pending_ledger_preserves_caller_command_id_and_bounded_metadata() -> None:
    source_path = OVERLAY / "irrigation.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    class_node = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "WyzeIrrigationCoordinator"
    )
    method = next(
        node for node in class_node.body if isinstance(node, ast.FunctionDef) and node.name == "_set_command_pending"
    )
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    namespace = {
        "Any": object,
        "copy": __import__("copy"),
        "datetime": datetime,
        "timedelta": __import__("datetime").timedelta,
        "timezone": timezone,
        "time": time,
        "uuid": __import__("uuid"),
    }
    exec(compile(module, str(source_path), "exec"), namespace)
    fake = types.SimpleNamespace()
    namespace["_set_command_pending"](
        fake,
        "start_zone",
        command_id="mcp-command-3",
        zone_number=2,
        zone_id="native-zone-2",
        duration_seconds=123,
    )
    status = fake._command_status
    assert status["command_id"] == "mcp-command-3"
    assert status["action"] == "start_zone"
    assert status["zone_number"] == 2
    assert status["zone_id"] == "native-zone-2"
    assert status["duration_seconds"] == 123
    assert status["state"] == "pending"
    assert status["evidence_type"] == "commanded"
    assert status["physical_state_verified"] is False
    assert datetime.fromisoformat(status["expires_at"]) > datetime.fromisoformat(
        status["issued_at"]
    )


def test_failed_sprinkler_first_refresh_is_contained_per_controller() -> None:
    source_path = OVERLAY / "irrigation.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "async_setup_irrigation_coordinators"
    )

    warnings = []

    class FakeCoordinator:
        def __init__(self, hass, service, device, entry_id):
            self.device = device
            self._known_zone_numbers = None

        async def async_config_entry_first_refresh(self):
            if self.device.mac == "failed-controller":
                raise RuntimeError("synthetic refresh failure")

    class FakeService:
        async def get_irrigations(self):
            return [
                types.SimpleNamespace(
                    mac="failed-controller", nickname="Failed", available=True
                ),
                types.SimpleNamespace(
                    mac="healthy-controller", nickname="Healthy", available=True
                ),
            ]

    class FakeAuthError(Exception):
        pass

    namespace = {
        "Any": object,
        "HomeAssistant": object,
        "WyzeIrrigationCoordinator": FakeCoordinator,
        "AccessTokenError": FakeAuthError,
        "ConfigEntryAuthFailed": RuntimeError,
        "ConfigEntryNotReady": RuntimeError,
        "DOMAIN": "wyzeapi",
        "IRRIGATION_COORDINATORS": "irrigation_coordinators",
        "_LOGGER": types.SimpleNamespace(
            warning=lambda *args, **kwargs: warnings.append((args, kwargs))
        ),
    }
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
            str(source_path),
            "exec",
        ),
        namespace,
    )

    service = FakeService()

    async def service_value():
        return service

    hass = types.SimpleNamespace(data={"wyzeapi": {"entry-1": {}}})
    client = types.SimpleNamespace(irrigation_service=service_value())
    asyncio.run(
        namespace["async_setup_irrigation_coordinators"](
            hass, "entry-1", client
        )
    )

    coordinators = hass.data["wyzeapi"]["entry-1"]["irrigation_coordinators"]
    assert set(coordinators) == {"failed-controller", "healthy-controller"}
    assert coordinators["failed-controller"].device.available is False
    assert coordinators["failed-controller"]._known_zone_numbers == set()
    assert coordinators["healthy-controller"].device.available is True
    assert len(warnings) == 1


def test_direct_coordinator_commands_require_explicitly_enabled_zone() -> None:
    source_path = OVERLAY / "irrigation.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    class_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "WyzeIrrigationCoordinator"
    )
    enabled_getter = next(
        node
        for node in class_node.body
        if isinstance(node, ast.FunctionDef) and node.name == "enabled_zone_numbers"
    )
    enabled_getter.decorator_list = []
    start_method = next(
        node
        for node in class_node.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "async_start_zone"
    )
    namespace = {
        "HomeAssistantError": RuntimeError,
        "time": time,
    }
    exec(
        compile(
            ast.fix_missing_locations(
                ast.Module(body=[enabled_getter, start_method], type_ignores=[])
            ),
            str(source_path),
            "exec",
        ),
        namespace,
    )

    data_with_unknown_zone = {
        "zones": [
            {"zone_number": 1, "enabled": True},
            {"zone_number": 2},
            {"zone_number": 3, "enabled": False},
        ]
    }
    enabled = namespace["enabled_zone_numbers"](
        types.SimpleNamespace(data=data_with_unknown_zone)
    )
    assert enabled == {1}

    class AsyncLock:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    service_calls = []

    async def start_zone(*args):
        service_calls.append(args)

    async def no_op():
        return None

    fake = types.SimpleNamespace(
        _command_lock=AsyncLock(),
        last_update_success=True,
        data={
            **data_with_unknown_zone,
            "connected": True,
            "watering": False,
            "endpoint_errors": [],
        },
        _command_pending_until=0.0,
        enabled_zone_numbers=enabled,
        device=types.SimpleNamespace(nickname="Controller"),
        service=types.SimpleNamespace(start_zone=start_zone),
        async_refresh=no_op,
    )
    try:
        asyncio.run(namespace["async_start_zone"](fake, 2, 123))
    except RuntimeError as err:
        assert "not enabled" in str(err)
    else:
        raise AssertionError("direct coordinator accepted a zone without enabled=true")
    assert service_calls == []


def test_home_assistant_owns_subminute_sequence_timing_and_stops_each_zone() -> None:
    source_path = OVERLAY / "irrigation.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    class_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "WyzeIrrigationCoordinator"
    )
    method_names = {
        "async_start_sequence",
        "_async_complete_managed_runs",
        "_async_managed_stop",
        "_async_wait_for_idle",
    }
    methods = [
        node
        for node in class_node.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name in method_names
    ]
    namespace = {
        "Any": object,
        "HomeAssistantError": RuntimeError,
        "QUICKRUN_URL": "unused",
        "asyncio": asyncio,
        "datetime": datetime,
        "timedelta": __import__("datetime").timedelta,
        "timezone": timezone,
        "time": time,
        "json": json,
        "olive_create_signature": lambda *args: "unused",
        "check_for_errors_iot": lambda *args: None,
        "APP_INFO": "unused",
        "OLIVE_APP_ID": "unused",
        "PHONE_ID": "unused",
        "validate_sequence": data.validate_sequence,
        "_LOGGER": types.SimpleNamespace(error=lambda *args, **kwargs: None),
    }
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=methods, type_ignores=[])),
            str(source_path),
            "exec",
        ),
        namespace,
    )

    class AsyncLock:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    calls = []
    statuses = []
    controller = {"stop_requested": False, "fail_post_stop_refresh": False}

    async def start_zone(device, zone, seconds):
        calls.append(("start", zone, seconds))

    async def stop_running_schedule(device):
        calls.append(("stop",))
        controller["stop_requested"] = True

    async def refresh():
        if controller["stop_requested"]:
            if controller["fail_post_stop_refresh"]:
                fake.last_update_success = False
                return
            controller["stop_requested"] = False
            fake.data["watering"] = False
            fake.data["active_zone_number"] = None
        fake.last_update_success = True

    async def no_op():
        return None

    fake = types.SimpleNamespace(
        _command_lock=AsyncLock(),
        _command_pending_until=0.0,
        _managed_run_task=None,
        last_update_success=True,
        data={
            "connected": True,
            "watering": None,
            "active_zone_number": None,
            "endpoint_errors": [],
            "zones": [
                {"zone_number": 1, "enabled": True},
                {"zone_number": 2, "enabled": True},
                {"zone_number": 3, "enabled": True},
            ],
        },
        enabled_zone_numbers={1, 2, 3},
        device=types.SimpleNamespace(nickname="Controller"),
        service=types.SimpleNamespace(
            start_zone=start_zone,
            stop_running_schedule=stop_running_schedule,
        ),
        hass=types.SimpleNamespace(
            async_create_task=lambda coroutine, name: asyncio.create_task(
                coroutine, name=name
            )
        ),
        async_refresh=refresh,
        async_request_refresh=no_op,
        _command_zone_identity=lambda zone: {"zone_number": zone},
        _set_command_pending=lambda action, command_id=None, **details: statuses.append(
            (action, command_id, details)
        ),
    )
    for name in method_names:
        setattr(fake, name, types.MethodType(namespace[name], fake))

    original_sleep = namespace["asyncio"].sleep

    async def immediate_sleep(_seconds):
        return None

    async def exercise():
        namespace["asyncio"].sleep = immediate_sleep
        try:
            try:
                await fake.async_start_sequence(
                    [{"zone": 1, "duration_seconds": 20}],
                    command_id="must-not-mutate-while-unknown",
                )
            except RuntimeError as err:
                assert "watering state is unavailable" in str(err)
            else:
                raise AssertionError("sub-minute run accepted unknown watering state")
            assert calls == []
            fake.data["watering"] = False
            controller["fail_post_stop_refresh"] = True
            await fake.async_start_sequence(
                [
                    {"zone": 1, "duration_seconds": 20},
                    {"zone": 2, "duration_seconds": 20},
                ],
                command_id="must-not-advance-on-failed-refresh",
            )
            failed_task = fake._managed_run_task
            assert failed_task is not None
            await failed_task
            assert ("start", 2, 60) not in calls
            assert fake.last_update_success is False

            calls.clear()
            statuses.clear()
            controller["stop_requested"] = False
            controller["fail_post_stop_refresh"] = False
            fake.last_update_success = True
            fake.data["watering"] = False
            await fake.async_start_sequence(
                [
                    {"zone": 1, "duration_seconds": 20},
                    {"zone": 2, "duration_seconds": 20},
                    {"zone": 3, "duration_seconds": 20},
                ],
                command_id="mcp-command-subminute",
            )
            task = fake._managed_run_task
            assert task is not None
            await task
        finally:
            namespace["asyncio"].sleep = original_sleep

    asyncio.run(exercise())
    assert calls == [
        ("start", 1, 60),
        ("stop",),
        ("start", 2, 60),
        ("stop",),
        ("start", 3, 60),
        ("stop",),
    ]
    assert statuses[0][2]["managed_by_home_assistant"] is True
    assert statuses[0][2]["zones"][0]["duration_seconds"] == 20
    assert statuses[0][2]["zones"][0]["provider_duration_seconds"] == 60


def test_schedule_get_and_response_service_construction_are_read_only() -> None:
    irrigation_source = (OVERLAY / "irrigation.py").read_text(encoding="utf-8")
    init_source = (OVERLAY / "__init__.py").read_text(encoding="utf-8")
    sensor_source = (OVERLAY / "sensor.py").read_text(encoding="utf-8")
    services_source = (OVERLAY / "services.yaml").read_text(encoding="utf-8")

    assert (
        'SCHEDULES_URL = "https://wyze-lockwood-service.wyzecam.com/plugin/irrigation/schedule"'
        in irrigation_source
    )
    schedule_method = irrigation_source.split(
        "async def async_get_schedules", 1
    )[1].split("async def _async_update_data", 1)[0]
    assert '"device_id": self.device.mac' in schedule_method
    assert '"nonce": str(int(time.time() * 1000))' in schedule_method
    assert "self.service._auth_lib.get(" in schedule_method
    assert "SCHEDULES_URL, headers=headers, params=payload" in schedule_method
    assert "self.service._auth_lib.post(" not in schedule_method
    assert "SupportsResponse.ONLY" in init_source
    assert "duration_seconds = duration_seconds_from_fields(call.data)" in init_source
    assert 'vol.Optional("duration_seconds")' in init_source
    assert "from .irrigation_data import zone_entity_attributes" in sensor_source
    assert "return zone_entity_attributes(self._zone)" in sensor_source
    assert 'return f"{self._device.mac}-zone-{self._zone[\'zone_number\']}-metadata"' in sensor_source
    assert "network_request_performed" in irrigation_source
    for service_name in (
        "get_sprinkler_snapshot",
        "get_sprinkler_schedule_runs",
        "get_sprinkler_schedules",
        "get_sprinkler_capabilities",
    ):
        assert f"{service_name}:" in services_source


def test_overlay_manifest_and_base_guard_are_deterministic() -> None:
    manifest = json.loads((OVERLAY / "manifest.json").read_text(encoding="utf-8"))
    readme = (OVERLAY.parents[1] / "README.md").read_text(encoding="utf-8")

    assert manifest["domain"] == "wyzeapi"
    assert manifest["version"] == "0.1.43"
    for filename in (
        "manifest.json",
        "__init__.py",
        "const.py",
        "irrigation.py",
        "irrigation_data.py",
        "sensor.py",
        "services.yaml",
    ):
        assert filename in readme
    assert "stop-and-reinspect concurrency guard" in readme
    assert "C:\\Users\\" not in readme
    assert "UPSTREAM_LICENSE" in readme
    assert "NOTICE" in readme
    assert "full Home Assistant\nprocess/container restart" in readme
    assert "config-entry reload is not sufficient" in readme


def test_upstream_license_attribution_and_modification_notices_are_complete() -> None:
    overlay_root = OVERLAY.parents[1]
    license_bytes = (overlay_root / "UPSTREAM_LICENSE").read_bytes()
    notice_bytes = (overlay_root / "NOTICE").read_bytes()
    assert hashlib.sha256(license_bytes).hexdigest().upper() == (
        "074E6E32C86A4C0EF8B3ED25B721CA23ACA83DF277CD88106EF7177C354615FF"
    )
    assert hashlib.sha256(notice_bytes).hexdigest().upper() == (
        "9BF747BDE395E8090DAE15FAB014D3570578F6F0695A64D15389933ECED4BE8B"
    )
    assert b"Apache License" in license_bytes
    assert b"SecKatie/ha-wyzeapi" in notice_bytes
    for filename in (
        "__init__.py",
        "const.py",
        "irrigation.py",
        "irrigation_data.py",
        "sensor.py",
    ):
        source = (OVERLAY / filename).read_text(encoding="utf-8")
        assert "SPDX-License-Identifier: Apache-2.0" in source
        assert "Derived from SecKatie/ha-wyzeapi; modified" in source
    services = (OVERLAY / "services.yaml").read_text(encoding="utf-8")
    assert services.startswith("# SPDX-License-Identifier: Apache-2.0")
