"""Pure, allowlisted data helpers for Wyze sprinkler payloads."""
# SPDX-License-Identifier: Apache-2.0
# Derived from SecKatie/ha-wyzeapi; modified for evidence-labelled normalization.

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

MAX_HISTORY_ITEMS = 100
CONFIG_KEYS = {
    "wiring",
    "sensor",
    "enable_schedules",
    "notification_enable",
    "notification_watering_begins",
    "notification_watering_ends",
    "notification_watering_is_skipped",
    "skip_low_temp",
    "skip_wind",
    "skip_rain",
    "skip_saturation",
}


def _mapping(value: Any) -> dict[str, Any]:
    """Return a string-keyed mapping or an empty mapping."""
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return {}


def _list(value: Any) -> list[Any]:
    """Return a list while rejecting strings and mappings."""
    return value if isinstance(value, list) else []


def _data(response: Any) -> dict[str, Any]:
    """Unwrap a Wyze response data object."""
    response_map = _mapping(response)
    return _mapping(response_map.get("data", response_map))


def _first(source: dict[str, Any], *keys: str) -> Any:
    """Return the first present value, preserving false and zero."""
    for key in keys:
        if key in source and source[key] is not None:
            return source[key]
    return None


def _extract_known_values(value: Any, keys: set[str]) -> dict[str, Any]:
    """Find known properties across mapping, list, and key/value API shapes."""
    result: dict[str, Any] = {}
    if isinstance(value, list):
        for item in value:
            result.update(_extract_known_values(item, keys))
        return result
    if not isinstance(value, dict):
        return result
    source = _mapping(value)
    property_name = source.get("key", source.get("name", source.get("prop")))
    if property_name in keys:
        if "value" in source:
            result[str(property_name)] = source["value"]
        elif "val" in source:
            result[str(property_name)] = source["val"]
    for key, item in source.items():
        if key in keys:
            if isinstance(item, dict) and "value" in item:
                result[key] = item["value"]
            else:
                result[key] = item
        elif isinstance(item, (dict, list)):
            result.update(_extract_known_values(item, keys))
    return result


def _number(value: Any) -> float | None:
    """Coerce a value to a finite number."""
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    if result != result or result in (float("inf"), float("-inf")):
        return None
    return result


def _integer(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None else None


def _strict_integer(value: Any) -> int | None:
    """Return an integer without silently truncating a physical target."""
    if isinstance(value, bool):
        return None
    number = _number(value)
    if number is None or not number.is_integer():
        return None
    return int(number)


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "on", "yes", "enabled", "connected"}:
            return True
        if normalized in {"0", "false", "off", "no", "disabled", "disconnected"}:
            return False
    return None


def _timestamp(value: Any) -> str | None:
    """Return an ISO UTC timestamp from seconds, milliseconds, or ISO text."""
    if value in (None, ""):
        return None
    if isinstance(value, str) and not value.strip().replace(".", "", 1).isdigit():
        candidate = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    numeric = _number(value)
    if numeric is None:
        return None
    if numeric > 10_000_000_000:
        numeric /= 1000
    try:
        return datetime.fromtimestamp(numeric, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _naive_timestamp_text(value: Any) -> bool:
    """Return true only for a parseable ISO timestamp lacking an offset."""
    if not isinstance(value, str) or not value.strip():
        return False
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return parsed.tzinfo is None


def _epoch_seconds(value: Any) -> float | None:
    timestamp = _timestamp(value)
    if timestamp is None:
        return None
    return datetime.fromisoformat(timestamp).timestamp()


def _primitive(value: Any) -> Any:
    """Retain only JSON-safe scalar values."""
    return value if isinstance(value, (str, int, float, bool)) else None


def _alias_value(source: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    direct = _first(source, *aliases)
    if direct is not None:
        return direct
    nested = _extract_known_values(source, set(aliases))
    for alias in aliases:
        if alias in nested:
            return nested[alias]
    return None


def _normalize_event(event: Any) -> dict[str, Any]:
    """Normalize one bounded zone event without retaining opaque payload data."""
    source = _mapping(event)
    timestamp_fields = (
        "occurred_at_utc",
        "event_time_utc",
        "timestamp_utc",
        "occurred_at",
        "event_time",
        "timestamp",
        "time",
        "created_at",
    )
    raw_timestamp = _first(source, *timestamp_fields)
    result = {
        "event_id": _primitive(_first(source, "event_id", "id")),
        "event_type": _primitive(_first(source, "event_type", "type", "name")),
        "state": _primitive(_first(source, "state", "status", "result")),
        "reason": _primitive(_first(source, "reason", "message")),
        "occurred_at": _timestamp(raw_timestamp),
        "source": _primitive(_first(source, "source", "origin")),
        "evidence_type": "controller-reported",
    }
    if _naive_timestamp_text(raw_timestamp):
        result["timestamp_ambiguity"] = {
            "supported": False,
            "reason": "naive local timestamp has no UTC offset",
        }
    existing_ambiguity = _mapping(source.get("timestamp_ambiguity"))
    if existing_ambiguity.get("supported") is False:
        ambiguity = {
            "supported": False,
            "reason": _primitive(existing_ambiguity.get("reason"))
            or "timestamp is ambiguous",
        }
        fields = [
            item
            for item in _list(existing_ambiguity.get("fields"))[:10]
            if isinstance(item, str)
        ]
        if fields:
            ambiguity["fields"] = fields
        result["timestamp_ambiguity"] = ambiguity
    return {key: value for key, value in result.items() if value is not None}


def normalize_zone(zone: Any) -> dict[str, Any]:
    """Normalize an allowlisted zone configuration and modeled values."""
    source = _mapping(zone)
    result: dict[str, Any] = {
        "zone_number": _integer(_alias_value(source, ("zone_number", "zone_num"))),
        "zone_id": _primitive(_alias_value(source, ("zone_id", "id"))),
        "name": _primitive(_alias_value(source, ("name", "zone_name"))),
        "enabled": _bool(_alias_value(source, ("enabled", "is_enabled"))),
        "smart_duration": _integer(
            _alias_value(source, ("smart_duration", "smart_duration_seconds"))
        ),
        "wired": _bool(_alias_value(source, ("wired", "is_wired"))),
    }
    scalar_aliases = {
        "crop": ("crop",),
        "crop_type": ("crop_type", "vegetation", "vegetation_type"),
        "exposure": ("exposure",),
        "exposure_type": ("exposure_type", "sun", "sun_exposure"),
        "nozzle": ("nozzle",),
        "nozzle_type": ("nozzle_type", "sprinkler_head_type"),
        "slope": ("slope",),
        "slope_type": ("slope_type",),
        "soil": ("soil",),
        "soil_type": ("soil_type",),
    }
    for output_key, aliases in scalar_aliases.items():
        value = _primitive(_alias_value(source, aliases))
        if value is not None:
            result[output_key] = value

    numeric_aliases = {
        "area": ("area", "zone_area", "area_sq_ft"),
        "available_water": (
            "available_water",
            "available_water_capacity",
            "available_water_in",
            "awc",
        ),
        "crop_coefficient": ("crop_coefficient", "kc"),
        "efficiency": (
            "efficiency",
            "irrigation_efficiency",
            "application_efficiency",
        ),
        "flow_rate": ("flow_rate", "configured_flow_rate"),
        "head_count": ("head_count", "sprinkler_head_count", "nozzle_count"),
        "root_depth": ("root_depth", "root_depth_in"),
        "allowed_depletion": (
            "allowed_depletion",
            "allowable_depletion",
            "management_allowed_depletion",
        ),
        "modeled_soil_moisture_native_value": (
            "modeled_soil_moisture",
            "soil_moisture_level_at_end_of_day_pct",
            "soil_moisture",
            "moisture_value",
            "moisture",
        ),
    }
    for output_key, aliases in numeric_aliases.items():
        value = _number(_alias_value(source, aliases))
        if value is not None:
            result[output_key] = value

    if "flow_rate" in result:
        result["flow_rate_evidence_type"] = "configuration"
        result["flow_rate_physically_measured"] = False
    if "modeled_soil_moisture_native_value" in result:
        result["soil_moisture_evidence_type"] = "calculated"
        result["modeled_soil_moisture_units"] = "unknown"

    raw_events = _alias_value(source, ("latest_events", "events", "recent_events"))
    events = [_normalize_event(item) for item in _list(raw_events) if isinstance(item, dict)]
    if events:
        result["latest_events"] = events[:10]
    return {key: value for key, value in result.items() if value is not None}


ZONE_ENTITY_ATTRIBUTE_KEYS = (
    "zone_number",
    "zone_id",
    "name",
    "enabled",
    "wired",
    "smart_duration",
    "crop",
    "crop_type",
    "exposure",
    "exposure_type",
    "nozzle",
    "nozzle_type",
    "slope",
    "slope_type",
    "soil",
    "soil_type",
    "area",
    "available_water",
    "crop_coefficient",
    "efficiency",
    "flow_rate",
    "flow_rate_evidence_type",
    "flow_rate_physically_measured",
    "head_count",
    "root_depth",
    "allowed_depletion",
    "modeled_soil_moisture_native_value",
    "modeled_soil_moisture_units",
    "soil_moisture_evidence_type",
)


def zone_entity_attributes(zone: Any) -> dict[str, Any]:
    """Return the stable allowlisted attribute contract for one zone entity."""
    source = _mapping(zone)
    result = {
        key: source[key]
        for key in ZONE_ENTITY_ATTRIBUTE_KEYS
        if key in source
        and isinstance(source[key], (str, int, float, bool))
    }
    events = [
        _normalize_event(item)
        for item in _list(source.get("latest_events"))[:10]
        if isinstance(item, dict)
    ]
    if events:
        result["latest_events"] = events
    return result


def _zone_state_entries(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []
    if isinstance(value, list):
        return [_mapping(item) for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        entries = []
        for key, item in value.items():
            if isinstance(item, dict):
                entry = _mapping(item)
                entry.setdefault("zone_number", key)
            else:
                entry = {"zone_number": key, "state": item}
            entries.append(entry)
        return entries
    return []


def _is_running(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {
        "run",
        "running",
        "watering",
        "active",
        "open",
        "on",
        "1",
    }


def _is_explicit_idle(value: Any) -> bool:
    if isinstance(value, bool):
        return not value
    return str(value or "").strip().lower() in {
        "idle",
        "stopped",
        "off",
        "closed",
        "0",
        "false",
    }


def _is_explicit_finished(value: Any) -> bool:
    return _is_explicit_idle(value) or str(value or "").strip().lower() in {
        "complete",
        "completed",
        "cancelled",
        "canceled",
        "skipped",
        "failed",
    }


def _zone_name(zone_number: int | None, zones: list[dict[str, Any]]) -> str | None:
    for zone in zones:
        if zone.get("zone_number") == zone_number:
            return str(zone.get("name") or f"Zone {zone_number}")
    return f"Zone {zone_number}" if zone_number is not None else None


def _zone_id(zone_number: int | None, zones: list[dict[str, Any]]) -> Any:
    for zone in zones:
        if zone.get("zone_number") == zone_number:
            return zone.get("zone_id")
    return None


def _schedule_times(
    schedule: dict[str, Any], zone_run: dict[str, Any]
) -> tuple[str | None, str | None, str | None, list[str]]:
    start = None
    end = None
    ambiguous_fields: list[str] = []
    for key in (
        "start_time_utc",
        "started_at_utc",
        "start_at_utc",
        "actual_start_time_utc",
        "run_start_time_utc",
        "watering_start_time_utc",
        "start_ts",
        "start_time",
        "started_at",
        "start_at",
        "begin_time",
        "run_start_time",
    ):
        raw_value = zone_run.get(key, schedule.get(key))
        start = _timestamp(raw_value)
        if start:
            break
        if _naive_timestamp_text(raw_value):
            ambiguous_fields.append(key)
    for key in (
        "end_time_utc",
        "ended_at_utc",
        "end_at_utc",
        "actual_end_time_utc",
        "run_end_time_utc",
        "watering_end_time_utc",
        "complete_time_utc",
        "completed_at_utc",
        "end_ts",
        "end_time",
        "ended_at",
        "end_at",
        "finish_time",
        "run_end_time",
        "complete_time",
        "completed_at",
    ):
        raw_value = zone_run.get(key, schedule.get(key))
        end = _timestamp(raw_value)
        if end:
            break
        if _naive_timestamp_text(raw_value):
            ambiguous_fields.append(key)
    duration = None
    for key in (
        "commanded_duration",
        "planned_duration",
        "scheduled_duration",
        "target_duration",
        "watering_duration",
        "run_duration",
        "duration",
    ):
        duration = _integer(zone_run.get(key, schedule.get(key)))
        if duration is not None:
            break
    expected_end = None
    if start is not None and duration is not None:
        end_dt = datetime.fromisoformat(start).timestamp() + max(duration, 0)
        expected_end = datetime.fromtimestamp(end_dt, timezone.utc).isoformat()
    return start, end, expected_end, sorted(set(ambiguous_fields))


def _remaining_seconds(
    schedule: dict[str, Any], zone_run: dict[str, Any], now: datetime
) -> tuple[int | None, str | None]:
    for key in ("remaining_time", "remaining", "duration_left", "run_time_remaining"):
        remaining = _integer(zone_run.get(key, schedule.get(key)))
        if remaining is not None:
            return max(remaining, 0), "controller-reported"
    _, _, expected_end, _ = _schedule_times(schedule, zone_run)
    if expected_end is None:
        return None, None
    return (
        max(int(datetime.fromisoformat(expected_end).timestamp() - now.timestamp()), 0),
        "calculated",
    )


def _duration_fields(
    schedule: dict[str, Any],
    zone_run: dict[str, Any],
    start: str | None,
    end: str | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    commanded = None
    for key in (
        "commanded_duration",
        "planned_duration",
        "scheduled_duration",
        "target_duration",
        "watering_duration",
        "run_duration",
        "duration",
    ):
        commanded = _integer(zone_run.get(key, schedule.get(key)))
        if commanded is not None:
            result["commanded_duration_seconds"] = max(commanded, 0)
            result["commanded_duration_evidence_type"] = "controller-reported"
            break
    actual = None
    for key in ("actual_duration", "elapsed_duration", "watering_seconds"):
        actual = _integer(zone_run.get(key, schedule.get(key)))
        if actual is not None:
            result["duration_seconds"] = max(actual, 0)
            result["duration_evidence_type"] = "controller-reported"
            break
    if actual is None and start is not None and end is not None:
        elapsed = int(
            datetime.fromisoformat(end).timestamp()
            - datetime.fromisoformat(start).timestamp()
        )
        result["duration_seconds"] = max(elapsed, 0)
        result["duration_evidence_type"] = "calculated"
    elif actual is None:
        result["duration_evidence_type"] = "unsupported"
    return result


def _normalize_zone_run(
    schedule: dict[str, Any],
    zone_run: dict[str, Any],
    zones: list[dict[str, Any]],
    *,
    allow_parent_timing: bool,
) -> dict[str, Any]:
    zone_number = _integer(_first(zone_run, "zone_number", "zone", "zone_num"))
    timing_parent = schedule if allow_parent_timing else {}
    start, end, expected_end, ambiguous_fields = _schedule_times(
        timing_parent, zone_run
    )
    state = _primitive(_first(zone_run, "state", "status")) or _primitive(
        _first(schedule, "schedule_state", "state", "status")
    )
    zone_outcome = _primitive(
        _first(zone_run, "outcome", "result", "final_state")
    )
    schedule_outcome = _primitive(
        _first(schedule, "outcome", "result", "final_state")
    )
    outcome = zone_outcome
    outcome_evidence = "controller-reported" if outcome is not None else None
    if outcome is None and state is not None and not _is_running(state):
        outcome = state
        outcome_evidence = "inferred"
    if outcome is None and schedule_outcome is not None:
        outcome = schedule_outcome
        outcome_evidence = "controller-reported"
    if outcome is None:
        outcome = "unknown"
        outcome_evidence = "unsupported"
    source_value = _primitive(
        _first(zone_run, "source", "run_source", "trigger_type")
    ) or _primitive(_first(schedule, "source", "run_source", "trigger_type"))
    source_evidence = "controller-reported" if source_value is not None else "unsupported"
    if source_value is None:
        source_value = "unknown"
    skip_state = _primitive(
        _first(zone_run, "skip_state", "skip_status")
    ) or _primitive(_first(schedule, "skip_state", "skip_status"))
    skipped = _bool(_first(zone_run, "skipped", "is_skipped"))
    if skip_state is None and skipped is not None:
        skip_state = "skipped" if skipped else "not_skipped"
    interruption = _bool(_first(zone_run, "interrupted", "is_interrupted"))
    terminal = str(zone_outcome or _first(zone_run, "state", "status") or outcome or state or "").lower()
    interruption_evidence = "unsupported"
    if interruption is not None:
        interruption_evidence = "controller-reported"
    elif terminal in {"interrupted", "cancelled", "canceled", "aborted", "stopped"}:
        interruption = True
        interruption_evidence = "inferred"
    zone_run_id = _primitive(
        _first(zone_run, "zone_run_id", "run_id", "schedule_run_id", "id")
    )
    parent_run_id = _primitive(_first(schedule, "run_id", "schedule_run_id"))
    result: dict[str, Any] = {
        "run_id": parent_run_id or zone_run_id,
        "parent_run_id": parent_run_id,
        "zone_run_id": zone_run_id,
        "record_scope": "zone_run",
        "program_id": _primitive(_first(zone_run, "program_id", "program"))
        or _primitive(_first(schedule, "program_id", "program")),
        "schedule_id": _primitive(_first(zone_run, "schedule_id"))
        or _primitive(_first(schedule, "schedule_id", "id")),
        "zone_number": zone_number,
        "zone_id": _primitive(_first(zone_run, "zone_id")) or _zone_id(zone_number, zones),
        "zone_name": _primitive(_first(zone_run, "zone_name", "name"))
        or _zone_name(zone_number, zones),
        "state": state,
        "outcome": outcome,
        "outcome_evidence_type": outcome_evidence,
        "source": source_value,
        "source_evidence_type": source_evidence,
        "started_at": start,
        "ended_at": end,
        "expected_end_at": expected_end,
        "expected_end_evidence_type": "calculated" if expected_end else None,
        "skip_state": skip_state,
        "skip_reason": _primitive(_first(zone_run, "skip_reason", "reason"))
        or _primitive(_first(schedule, "skip_reason", "reason")),
        "interrupted": interruption,
        "interruption_reason": _primitive(
            _first(zone_run, "interruption_reason", "stop_reason", "cancel_reason")
        ),
        "interruption_evidence_type": interruption_evidence,
        "evidence_type": "controller-reported",
    }
    result.update(
        _duration_fields(
            timing_parent,
            zone_run,
            start,
            end,
        )
    )
    if ambiguous_fields:
        result["timestamp_ambiguity"] = {
            "supported": False,
            "fields": ambiguous_fields,
            "reason": "naive local timestamps have no UTC offset",
        }
    return {key: value for key, value in result.items() if value is not None}


def normalize_schedule(
    schedule: Any, zones: list[dict[str, Any]], now: datetime
) -> dict[str, Any]:
    """Normalize one schedule-run record with explicit evidence semantics."""
    source = _mapping(schedule)
    raw_zone_runs = _first(source, "zone_runs", "runs", "zones")
    zone_runs = [_mapping(item) for item in _list(raw_zone_runs) if isinstance(item, dict)]
    if not zone_runs and _first(source, "zone_number", "zone", "zone_num") is not None:
        zone_runs = [source]
    normalized_runs = [
        _normalize_zone_run(
            source,
            item,
            zones,
            allow_parent_timing=len(zone_runs) == 1,
        )
        for item in zone_runs
    ]

    parent_start, parent_end, parent_expected_end, _ = _schedule_times({}, source)

    running_zone = None
    inferred_running = False
    for raw, normalized in zip(zone_runs, normalized_runs):
        state = _first(raw, "state", "status")
        start_epoch = _epoch_seconds(normalized.get("started_at"))
        end_epoch = _epoch_seconds(
            normalized.get("ended_at") or normalized.get("expected_end_at")
        )
        if _is_running(state):
            running_zone = (raw, normalized)
            break
        if (
            start_epoch is not None
            and end_epoch is not None
            and start_epoch <= now.timestamp() <= end_epoch
        ):
            running_zone = (raw, normalized)
            inferred_running = True
            break
    selected_raw, selected = running_zone or (
        (zone_runs[0], normalized_runs[0]) if zone_runs else ({}, {})
    )

    state_raw = _first(source, "schedule_state", "state", "status")
    state = str(state_raw).lower() if state_raw is not None else "unknown"
    state_evidence = "controller-reported" if state_raw is not None else "unsupported"
    if inferred_running and not _is_running(state):
        state = "running"
        state_evidence = "inferred"
    schedule_starts = [
        epoch
        for epoch in (_epoch_seconds(item.get("started_at")) for item in normalized_runs)
        if epoch is not None
    ]
    schedule_ends = [
        epoch
        for epoch in (_epoch_seconds(item.get("ended_at")) for item in normalized_runs)
        if epoch is not None
    ]
    schedule_expected_ends = [
        epoch
        for epoch in (
            _epoch_seconds(item.get("expected_end_at")) for item in normalized_runs
        )
        if epoch is not None
    ]
    selected_start = selected.get("started_at") or _timestamp(
        _first(
            source,
            "start_time_utc",
            "started_at_utc",
            "start_at_utc",
            "start_ts",
            "start_time",
            "started_at",
            "start_at",
        )
    )
    selected_end = selected.get("ended_at") or _timestamp(
        _first(
            source,
            "end_time_utc",
            "ended_at_utc",
            "end_at_utc",
            "end_ts",
            "end_time",
            "ended_at",
            "end_at",
        )
    )
    start = (
        datetime.fromtimestamp(min(schedule_starts), timezone.utc).isoformat()
        if schedule_starts
        else parent_start or selected_start
    )
    end = (
        datetime.fromtimestamp(max(schedule_ends), timezone.utc).isoformat()
        if schedule_ends
        else parent_end or selected_end
    )
    expected_end = (
        datetime.fromtimestamp(max(schedule_expected_ends), timezone.utc).isoformat()
        if schedule_expected_ends
        else parent_expected_end or selected.get("expected_end_at")
    )
    skip_state = _primitive(_first(source, "skip_state", "skip_status"))
    skipped = _bool(_first(source, "skipped", "is_skipped"))
    if skip_state is None and skipped is not None:
        skip_state = "skipped" if skipped else "not_skipped"
    result: dict[str, Any] = {
        "run_id": _primitive(_first(source, "run_id", "schedule_run_id")),
        "program_id": _primitive(_first(source, "program_id", "program")),
        "schedule_id": _primitive(_first(source, "schedule_id", "id")),
        "schedule_name": _primitive(_first(source, "schedule_name", "name")),
        "schedule_type": _primitive(_first(source, "schedule_type", "type", "run_type")),
        "source": _primitive(_first(source, "source", "run_source", "trigger_type")),
        "state": state,
        "state_evidence_type": state_evidence,
        "outcome": _primitive(_first(source, "outcome", "result", "final_state")),
        "zone_number": selected.get("zone_number"),
        "zone_id": selected.get("zone_id"),
        "zone_name": selected.get("zone_name"),
        "started_at": start,
        "ended_at": end,
        "expected_end_at": expected_end,
        "expected_end_evidence_type": "calculated" if expected_end else None,
        "skip_state": skip_state,
        "skip_reason": _primitive(_first(source, "skip_reason", "reason")),
        "interrupted": _bool(_first(source, "interrupted", "is_interrupted")),
        "interruption_reason": _primitive(
            _first(source, "interruption_reason", "stop_reason", "cancel_reason")
        ),
        "evidence_type": "controller-reported",
    }
    result.update(
        _duration_fields(
            source,
            selected_raw,
            start,
            end,
        )
    )
    if _is_running(state):
        remaining, evidence = _remaining_seconds({}, source, now)
        if remaining is None:
            remaining, evidence = _remaining_seconds({}, selected_raw, now)
        if remaining is not None:
            result["remaining_seconds"] = remaining
            result["remaining_evidence_type"] = evidence
    if normalized_runs:
        result["zone_runs"] = normalized_runs
    return {key: value for key, value in result.items() if value is not None}


def _response_list(response: Any, keys: tuple[str, ...]) -> list[Any]:
    data = _data(response)
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            for nested_key in ("items", "records", "list"):
                if isinstance(value.get(nested_key), list):
                    return value[nested_key]
    for key in ("items", "records", "list"):
        if isinstance(data.get(key), list):
            return data[key]
    return []


def normalize_schedule_runs_response(
    response: Any,
    zones: list[dict[str, Any]],
    *,
    limit: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Normalize a bounded private schedule-runs response."""
    bounded_limit = min(max(int(limit), 1), MAX_HISTORY_ITEMS)
    observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    raw_runs = _response_list(response, ("schedules", "schedule_runs", "runs"))
    runs = [
        normalize_schedule(item, zones, observed_at)
        for item in raw_runs[:bounded_limit]
        if isinstance(item, dict)
    ]
    return {
        "supported": True,
        "runs": runs,
        "count": len(runs),
        "limit": bounded_limit,
        "observed_at": observed_at.isoformat(),
        "evidence_type": "controller-reported",
        "physical_state_verified": False,
    }


def _normalize_schedule_definition(
    schedule: Any, zones: list[dict[str, Any]]
) -> dict[str, Any]:
    source = _mapping(schedule)
    raw_zone_runs = _first(source, "zone_runs", "zones", "durations")
    normalized_zones = []
    for item in _list(raw_zone_runs):
        entry = _mapping(item)
        zone_number = _integer(_first(entry, "zone_number", "zone", "zone_num"))
        duration = _integer(
            _first(entry, "duration", "watering_duration", "run_duration")
        )
        normalized = {
            "zone_number": zone_number,
            "zone_id": _primitive(_first(entry, "zone_id")) or _zone_id(zone_number, zones),
            "zone_name": _primitive(_first(entry, "zone_name", "name"))
            or _zone_name(zone_number, zones),
            "duration_seconds": max(duration, 0) if duration is not None else None,
            "enabled": _bool(_first(entry, "enabled", "is_enabled")),
        }
        normalized_zones.append(
            {key: value for key, value in normalized.items() if value is not None}
        )
    days = _first(source, "days", "weekdays", "days_of_week")
    timestamp_values = {
        "start_date": _first(source, "start_date_utc", "start_date", "valid_from"),
        "end_date": _first(source, "end_date_utc", "end_date", "valid_until"),
        "next_run_at": _first(
            source,
            "next_run_at_utc",
            "next_run_time_utc",
            "next_start_time_utc",
            "next_run_at",
            "next_run_time",
            "next_start_time",
        ),
    }
    raw_cycle_soak = _mapping(source.get("cycle_soak"))
    cycle_source = {**source, **raw_cycle_soak}
    cycle_enabled_value = (
        _first(raw_cycle_soak, "enabled", "cycle_soak_enabled", "cycle_enabled")
        if raw_cycle_soak
        else _first(source, "cycle_soak_enabled", "cycle_enabled")
    )
    cycle_soak = {
        "enabled": _bool(cycle_enabled_value),
        "cycle_count": _integer(_first(cycle_source, "cycle_count", "cycles")),
        "cycle_duration_seconds": _integer(
            _first(cycle_source, "cycle_duration", "cycle_duration_seconds")
        ),
        "soak_duration_seconds": _integer(
            _first(cycle_source, "soak_duration", "soak_duration_seconds")
        ),
    }
    cycle_soak = {
        key: value for key, value in cycle_soak.items() if value is not None
    }
    result = {
        "schedule_id": _primitive(_first(source, "schedule_id", "id")),
        "name": _primitive(_first(source, "schedule_name", "name")),
        "enabled": _bool(_first(source, "enabled", "is_enabled", "enable")),
        "schedule_type": _primitive(_first(source, "schedule_type", "type")),
        "start_time": _primitive(_first(source, "start_time", "time")),
        "start_date": _timestamp(timestamp_values["start_date"]),
        "end_date": _timestamp(timestamp_values["end_date"]),
        "next_run_at": _timestamp(timestamp_values["next_run_at"]),
        "interval": _primitive(_first(source, "interval", "frequency")),
        "recurrence": _primitive(
            _first(source, "recurrence", "recurrence_rule", "repeat")
        ),
        "repeat_interval": _integer(
            _first(source, "repeat_interval", "day_interval")
        ),
        "odd_even": _primitive(_first(source, "odd_even", "day_parity")),
        "days": [item for item in _list(days) if isinstance(item, (str, int))],
        "cycle_soak": cycle_soak,
        "zone_runs": normalized_zones,
        "evidence_type": "controller-reported",
    }
    ambiguous_fields = [
        key for key, value in timestamp_values.items() if _naive_timestamp_text(value)
    ]
    if ambiguous_fields:
        result["timestamp_ambiguity"] = {
            "supported": False,
            "fields": ambiguous_fields,
            "reason": "naive local timestamps have no UTC offset",
        }
    return {
        key: value
        for key, value in result.items()
        if value is not None and value not in ([], {})
    }


def normalize_schedules_response(
    response: Any, zones: list[dict[str, Any]], now: datetime | None = None
) -> dict[str, Any]:
    """Normalize safe known fields from the private schedule-definition response."""
    observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    raw_schedules = _response_list(response, ("schedules", "schedule"))
    schedules = [
        _normalize_schedule_definition(item, zones)
        for item in raw_schedules[:MAX_HISTORY_ITEMS]
        if isinstance(item, dict)
    ]
    return {
        "supported": True,
        "schedules": schedules,
        "count": len(schedules),
        "observed_at": observed_at.isoformat(),
        "evidence_type": "controller-reported",
    }


def duration_seconds_from_fields(value: Any) -> int:
    """Return one exact bounded duration from seconds or legacy minutes."""
    entry = _mapping(value)
    present = [
        key
        for key in ("duration_seconds", "duration_minutes")
        if key in entry and entry[key] is not None
    ]
    if len(present) != 1:
        raise ValueError(
            "provide exactly one of duration_seconds or duration_minutes"
        )
    if present[0] == "duration_seconds":
        seconds = _strict_integer(entry["duration_seconds"])
        if seconds is None or seconds < 60 or seconds > 10_800:
            raise ValueError(
                "duration_seconds must be an exact integer from 60 through 10800"
            )
        return seconds
    minutes = _number(entry["duration_minutes"])
    if minutes is None or minutes < 1 or minutes > 180:
        raise ValueError("duration_minutes must be a number from 1 through 180")
    seconds = int(round(minutes * 60))
    if seconds < 60 or seconds > 10_800:
        raise ValueError("duration_minutes must resolve to 60 through 10800 seconds")
    return seconds


def validate_sequence(
    zone_runs: Any, valid_zone_numbers: set[int]
) -> list[dict[str, int]]:
    """Validate a bounded multi-zone quick-run request."""
    if not isinstance(zone_runs, list) or not zone_runs or len(zone_runs) > 8:
        raise ValueError("zones must contain between 1 and 8 entries")
    result = []
    seen: set[int] = set()
    total = 0
    for item in zone_runs:
        entry = _mapping(item)
        raw_zone_number = entry.get("zone", entry.get("zone_number"))
        zone_number = _strict_integer(raw_zone_number)
        if zone_number is None:
            raise ValueError(f"zone {raw_zone_number!r} must be an exact integer")
        if zone_number not in valid_zone_numbers:
            raise ValueError(f"zone {zone_number} is not enabled on this controller")
        if zone_number in seen:
            raise ValueError(f"zone {zone_number} is duplicated")
        seconds = duration_seconds_from_fields(entry)
        total += seconds
        if total > 3 * 60 * 60:
            raise ValueError("total sequence duration must not exceed 180 minutes")
        seen.add(zone_number)
        result.append({"zone_number": zone_number, "duration": seconds})
    return result


def apply_coordinator_state(
    snapshot: dict[str, Any],
    *,
    command_pending: bool | None = None,
    command_status: dict[str, Any] | None = None,
    partial: bool,
    endpoint_errors: list[str],
) -> dict[str, Any]:
    """Attach local coordinator health without changing controller evidence."""
    result = dict(snapshot)
    result["partial"] = bool(partial)
    result["endpoint_errors"] = sorted(str(item) for item in endpoint_errors)
    status = dict(command_status or {})
    if not status:
        status = {
            "state": "pending" if command_pending else "idle",
            "evidence_type": "commanded",
            "physical_state_verified": False,
        }
    pending = status.get("state") == "pending"
    result["command_pending"] = pending
    result["command_status"] = status
    health = dict(result.get("controller_health", {}))
    health.update(
        {
            "partial": bool(partial),
            "endpoint_errors": sorted(str(item) for item in endpoint_errors),
            "endpoint_health_evidence_type": "calculated",
        }
    )
    health.setdefault("evidence_type", "unsupported")
    result["controller_health"] = health
    return result


def reconcile_command_status(
    command_status: Any,
    *,
    watering: bool | None,
    active_zone_number: int | None,
    expired: bool,
) -> tuple[dict[str, Any], bool]:
    """Reconcile a local command latch against non-physical controller state."""
    status = _mapping(command_status)
    if status.get("state") != "pending":
        return status, False
    action = status.get("action")
    start_zone_matches = (
        action == "start_zone"
        and watering is True
        and (
            status.get("zone_number") is None
            or active_zone_number == status.get("zone_number")
        )
    )
    observed = start_zone_matches or (
        action == "start_sequence" and watering is True
    ) or (action == "stop" and watering is False)
    if observed:
        status["state"] = "controller_state_observed"
        status["evidence_type"] = "inferred"
        status["observed_watering"] = watering
        if active_zone_number is not None:
            status["observed_active_zone_number"] = active_zone_number
        status["physical_state_verified"] = False
        return status, False
    if expired:
        status["state"] = "timed_out"
        status["evidence_type"] = "calculated"
        status["physical_state_verified"] = False
        return status, False
    return status, True


def normalize_snapshot(
    iot_response: Any,
    zone_response: Any,
    info_response: Any,
    schedule_response: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Combine four Wyze endpoints into one stable, evidence-labelled snapshot."""
    now = now or datetime.now(timezone.utc)
    iot_data = _data(iot_response)
    props = _mapping(iot_data.get("props", iot_data))
    zone_data = _data(zone_response)
    raw_zones = _response_list(zone_response, ("zones", "zone"))
    if not raw_zones:
        raw_zones = _list(zone_data.get("zones"))
    zones = [normalize_zone(item) for item in raw_zones]
    zones = [item for item in zones if item.get("zone_number") is not None]

    config = _extract_known_values(info_response, CONFIG_KEYS)
    raw_schedules = _response_list(
        schedule_response, ("schedules", "schedule_runs", "runs")
    )
    schedules = [
        normalize_schedule(item, zones, now)
        for item in raw_schedules[:MAX_HISTORY_ITEMS]
        if isinstance(item, dict)
    ]

    running_schedule = next(
        (item for item in schedules if _is_running(item.get("state"))), None
    )
    active_zone_number = running_schedule.get("zone_number") if running_schedule else None
    active_zone_name = running_schedule.get("zone_name") if running_schedule else None
    active_zone_id = running_schedule.get("zone_id") if running_schedule else None
    remaining = running_schedule.get("remaining_seconds") if running_schedule else None
    remaining_evidence = (
        running_schedule.get("remaining_evidence_type") if running_schedule else None
    )
    started_at = running_schedule.get("started_at") if running_schedule else None
    expected_end = (
        running_schedule.get("expected_end_at") if running_schedule else None
    )
    expected_end_evidence = (
        running_schedule.get("expected_end_evidence_type")
        if running_schedule
        else None
    )
    watering_evidence = (
        running_schedule.get("state_evidence_type") if running_schedule else None
    )
    watering: bool | None = True if running_schedule is not None else None

    if running_schedule is None:
        zone_state_entries = _zone_state_entries(props.get("zone_state"))
        for entry in zone_state_entries:
            state = entry.get("state", entry.get("status", entry.get("running")))
            if _is_running(state):
                watering = True
                active_zone_number = _integer(entry.get("zone_number"))
                active_zone_name = entry.get("zone_name") or _zone_name(
                    active_zone_number, zones
                )
                active_zone_id = entry.get("zone_id") or _zone_id(
                    active_zone_number, zones
                )
                remaining, remaining_evidence = _remaining_seconds({}, entry, now)
                started_at, _, expected_end, _ = _schedule_times({}, entry)
                expected_end_evidence = "calculated" if expected_end else None
                watering_evidence = "controller-reported"
                break
        else:
            zone_states = [
                entry.get("state", entry.get("status", entry.get("running")))
                for entry in zone_state_entries
            ]
            if zone_states and all(_is_explicit_idle(state) for state in zone_states):
                watering = False
                watering_evidence = "controller-reported"
            elif schedules and all(
                _is_explicit_finished(item.get("state")) for item in schedules
            ):
                watering = False
                watering_evidence = "inferred"

    last_run = next(
        (item for item in schedules if not _is_running(item.get("state"))), None
    )
    iot_state = str(props.get("iot_state", "")).strip().lower()
    connected: bool | None
    if iot_state == "connected":
        connected = True
    elif iot_state in {"disconnected", "offline", "not_connected", "unavailable"}:
        connected = False
    else:
        connected = None
    health = {
        "connected": connected,
        "iot_state": _primitive(props.get("iot_state")),
        "iot_state_updated_at": _timestamp(props.get("iot_state_update_time")),
        "rssi": _integer(props.get("RSSI")),
        "ip": _primitive(props.get("IP")),
        "ssid": _primitive(props.get("ssid")),
        "firmware": _primitive(props.get("app_version")),
        "serial_number": _primitive(props.get("sn")),
        "wifi_mac": _primitive(props.get("wifi_mac")),
        "evidence_type": (
            "controller-reported" if connected is not None else "unsupported"
        ),
    }
    health = {key: value for key, value in health.items() if value is not None}
    return {
        "connected": connected,
        "watering": watering,
        "watering_state": {
            "state": (
                "watering" if watering is True else "idle" if watering is False else "unknown"
            ),
            "evidence_type": watering_evidence or "unsupported",
            "physical_state_verified": False,
        },
        "active_zone_number": active_zone_number,
        "active_zone_name": active_zone_name,
        "active_zone_id": active_zone_id,
        "remaining_seconds": remaining,
        "remaining_evidence_type": remaining_evidence,
        "started_at": started_at,
        "expected_end": expected_end,
        "expected_end_evidence_type": expected_end_evidence,
        "last_run_at": (last_run or {}).get("ended_at")
        or (last_run or {}).get("started_at"),
        "recent_runs": schedules[:10],
        "zones": zones,
        "config": config,
        "controller_health": health,
        "rssi": health.get("rssi"),
        "ip": health.get("ip"),
        "ssid": health.get("ssid"),
        "firmware": health.get("firmware"),
        "serial_number": health.get("serial_number"),
        "wifi_mac": health.get("wifi_mac"),
        "iot_state": health.get("iot_state"),
        "iot_state_updated_at": health.get("iot_state_updated_at"),
        "updated_at": now.astimezone(timezone.utc).isoformat(),
    }


def sprinkler_capabilities() -> dict[str, Any]:
    """Return the integration's static sprinkler capability contract."""
    supported = [
        {
            "capability": "normalized_snapshot",
            "supported": True,
            "access": "read",
            "semantics": "cached coordinator state; the service performs no network request",
        },
        {
            "capability": "watering_history",
            "supported": True,
            "access": "read",
            "semantics": "bounded private schedule-runs response with per-zone intervals",
        },
        {
            "capability": "native_schedule_definitions",
            "supported": True,
            "access": "read",
            "semantics": "safe known fields from the private schedule endpoint",
        },
        {
            "capability": "cycle_soak_and_recurrence",
            "supported": True,
            "access": "read",
            "semantics": "allowlisted native recurrence and cycle-soak fields when Wyze includes them",
        },
        {
            "capability": "upcoming_scheduled_runs",
            "supported": True,
            "access": "read",
            "semantics": "next_run_at is returned only when Wyze includes it in a schedule definition",
        },
        {
            "capability": "skip_configuration_and_decisions",
            "supported": True,
            "access": "read",
            "semantics": "skip settings plus native per-run skip state and reason when present",
        },
        {
            "capability": "active_zone_and_remaining_runtime",
            "supported": True,
            "access": "read",
            "semantics": "controller-reported or explicitly calculated; never physical valve feedback",
        },
        {
            "capability": "controller_health",
            "supported": True,
            "access": "read",
            "semantics": "controller-reported cloud connectivity, firmware, RSSI, SSID, and IP",
        },
        {
            "capability": "zone_configuration",
            "supported": True,
            "access": "read",
            "semantics": "allowlisted native identifiers and irrigation-model configuration",
        },
        {
            "capability": "modeled_zone_moisture",
            "supported": True,
            "access": "read",
            "semantics": "raw Wyze model value with unknown native units, labelled calculated and not a physical measurement",
        },
        {
            "capability": "start_zone",
            "supported": True,
            "access": "command",
            "semantics": "one enabled zone for an exact 60 through 10800 seconds",
        },
        {
            "capability": "start_sequence",
            "supported": True,
            "access": "command",
            "semantics": "ordered native quick-run of enabled zones, total at most 180 minutes",
        },
        {
            "capability": "stop_watering",
            "supported": True,
            "access": "command",
            "semantics": "stop the controller's current schedule or quick run",
        },
    ]
    unsupported = [
        {
            "capability": "physical_valve_feedback",
            "supported": False,
            "reason": "the audited Wyze payloads do not expose a physical valve-position signal",
        },
        {
            "capability": "physically_measured_flow",
            "supported": False,
            "reason": "flow_rate is irrigation configuration, not a measured flow signal",
        },
        {
            "capability": "electrical_load_or_valve_fault",
            "supported": False,
            "reason": "no electrical-load, valve-current, or physical-open field is available",
        },
        {
            "capability": "physically_measured_zone_moisture",
            "supported": False,
            "reason": "available moisture fields are Wyze model values, not a physical sensor reading",
        },
        {
            "capability": "schedule_create_update_delete_enable_disable",
            "supported": False,
            "reason": "no reviewed write contract is exposed; this overlay deliberately remains read-only",
        },
        {
            "capability": "native_schedule_manual_run",
            "supported": False,
            "reason": "the reviewed library exposes quick runs but no safe native-schedule run contract",
        },
        {
            "capability": "wyze_weather_dataset",
            "supported": False,
            "reason": "the reviewed endpoints expose skip configuration and decisions, not the weather dataset",
        },
    ]
    return {
        "integration_version": "0.1.40",
        "supported": supported,
        "unsupported": unsupported,
        "evidence_labels": [
            "commanded",
            "controller-reported",
            "calculated",
            "inferred",
            "reconstructed",
            "configuration",
            "unsupported",
        ],
        "physical_state_verified": False,
    }
