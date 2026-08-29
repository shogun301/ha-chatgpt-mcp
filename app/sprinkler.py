"""Typed Wyze Sprinkler contracts and provider-payload normalization.

The Wyze cloud payload is private and has changed over time.  This module keeps
that variability at the integration boundary while the MCP contract remains
stable, explicit, and honest about the provenance of every state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

StateEvidence = Literal[
    "commanded",
    "controller-reported",
    "calculated",
    "inferred",
    "physically-measured",
]
HistoryEvidence = Literal["physical", "controller-reported", "reconstructed"]
ScalarValue = str | int | float | bool | None


class SprinklerModel(BaseModel):
    """Strict output model that remains convenient for direct Python callers."""

    model_config = ConfigDict(extra="forbid")

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


class UnsupportedSignal(SprinklerModel):
    supported: bool = False
    reason: str
    upstream_evidence: str


class EntityStateSummary(SprinklerModel):
    entity_id: str
    state: ScalarValue
    friendly_name: str | None = None
    device_class: str | None = None
    unit_of_measurement: str | None = None
    last_changed: AwareDatetime | None = None
    last_updated: AwareDatetime | None = None


class ZoneEvent(SprinklerModel):
    event_id: str | None = None
    event_type: str | None = None
    state: str | None = None
    reason: str | None = None
    occurred_at: AwareDatetime | None = None
    source: str | None = None
    evidence: StateEvidence = "controller-reported"


class ZoneCapability(SprinklerModel):
    zone_id: str
    zone_number: int = Field(ge=1, le=8)
    native_zone_id: str | None = None
    zone_name: str | None = None
    enabled: bool
    configuration_evidence: StateEvidence = "controller-reported"
    configured_duration_seconds: int | None = Field(default=None, ge=0)
    smart_duration_seconds: int | None = Field(default=None, ge=0)
    soil_type: str | None = None
    vegetation_type: str | None = None
    sun_exposure: str | None = None
    slope: str | None = None
    nozzle_type: str | None = None
    area: float | None = Field(default=None, ge=0)
    area_unit: Literal["upstream_unspecified"] | None = None
    flow_rate: float | None = Field(default=None, ge=0)
    flow_rate_unit: Literal["upstream_unspecified"] | None = None
    flow_rate_evidence: StateEvidence | None = None
    flow_rate_physically_measured: bool = False
    available_water_capacity: float | None = None
    crop_coefficient: float | None = None
    efficiency: float | None = None
    allowed_depletion: float | None = None
    root_depth: float | None = None
    head_count: int | None = Field(default=None, ge=0)
    modeled_soil_moisture_native_value: float | None = Field(
        default=None, allow_inf_nan=False
    )
    moisture_unit: Literal["upstream_unspecified"] | None = None
    moisture_evidence: StateEvidence | None = None
    wired: bool | None = None
    recent_events: list[ZoneEvent] = Field(default_factory=list)
    last_updated: AwareDatetime | None = None


class ControllerState(SprinklerModel):
    state: str
    state_supported: bool
    evidence: StateEvidence | None = None
    observed_at: AwareDatetime | None = None
    connected: bool | None = None
    active_zone_id: str | None = None
    active_native_zone_id: str | None = None
    active_zone_name: str | None = None
    active_zone_evidence: StateEvidence | None = None
    remaining_runtime_seconds: int | None = Field(default=None, ge=0)
    remaining_runtime_evidence: StateEvidence | None = None
    expected_end_at: AwareDatetime | None = None
    expected_end_evidence: StateEvidence | None = None
    physical_state_verified: bool = False


class TelemetryProvenance(SprinklerModel):
    live_running_state_available: bool
    physical_state_verified: bool = False
    source: str | None = None
    observed_at: AwareDatetime | None = None
    partial_update: bool = False
    endpoint_errors: list[str] = Field(default_factory=list)
    note: str


class SprinklerSummary(SprinklerModel):
    controller: EntityStateSummary
    active_zone: EntityStateSummary
    remaining: EntityStateSummary
    last_watering: EntityStateSummary
    zones: list[ZoneCapability]
    controller_state: ControllerState
    telemetry: TelemetryProvenance


class SprinklerZoneList(SprinklerModel):
    count: int = Field(ge=0)
    zones: list[ZoneCapability]


class ConfigurationValue(SprinklerModel):
    name: str
    value: ScalarValue | list[ScalarValue]
    evidence: StateEvidence = "controller-reported"


class SprinklerConfiguration(SprinklerModel):
    entity_id: str
    state: str
    last_changed: AwareDatetime | None = None
    last_updated: AwareDatetime | None = None
    values: list[ConfigurationValue] = Field(default_factory=list)
    evidence: StateEvidence = "controller-reported"


class CapabilityItem(SprinklerModel):
    capability: str
    supported: bool
    operations: list[str] = Field(default_factory=list)
    evidence: StateEvidence | None = None
    semantics: str
    upstream_source: str
    limitation: str | None = None


class SprinklerCapabilities(SprinklerModel):
    controller_id: str
    zones: list[str]
    capabilities: list[CapabilityItem]


class SprinklerHistoryInterval(SprinklerModel):
    zone_id: str
    zone_name: str
    native_zone_id: str | None = None
    started_at: AwareDatetime
    ended_at: AwareDatetime | None = None
    duration_seconds: int | None = Field(default=None, ge=0)
    duration_supported: bool
    duration_evidence: StateEvidence | None = None
    commanded_duration_seconds: int | None = Field(default=None, ge=0)
    commanded_duration_evidence: StateEvidence | None = None
    source: str
    source_supported: bool
    source_evidence: StateEvidence | None = None
    outcome: str
    outcome_supported: bool
    outcome_evidence: StateEvidence | None = None
    interrupted: bool | None = None
    interruption_supported: bool
    interruption_evidence: StateEvidence | None = None
    run_id: str | None = None
    program_id: str | None = None
    evidence_type: HistoryEvidence


class SprinklerHistory(SprinklerModel):
    window_started_at: AwareDatetime
    window_ended_at: AwareDatetime
    count: int = Field(ge=0)
    intervals: list[SprinklerHistoryInterval]
    native_limit: int = Field(ge=1)
    native_run_count: int = Field(ge=0)
    native_interval_count: int = Field(ge=0)
    recorder_snapshot_count: int = Field(ge=0)
    recorder_interval_count: int = Field(ge=0)
    deduplicated_interval_count: int = Field(ge=0)
    omitted_ambiguous_timestamp_count: int = Field(ge=0)
    upstream_complete: bool
    limitation: str | None = None


class SprinklerCommandZone(SprinklerModel):
    zone_id: str
    native_zone_id: str | None = None
    duration_seconds: int | None = Field(default=None, ge=0)


class CommandObservation(SprinklerModel):
    command_id: str | None = None
    action: str | None = None
    zone_id: str | None = None
    requested_duration_seconds: int | None = Field(default=None, ge=0)
    zones: list[SprinklerCommandZone] = Field(default_factory=list)
    observed_at: AwareDatetime | None = None
    expires_at: AwareDatetime | None = None
    evidence: StateEvidence
    status: str
    physical_state_verified: bool = False


class SprinklerCommandStatus(SprinklerModel):
    pending_command: CommandObservation | None = None
    integration_command_status: CommandObservation | None = None
    last_mcp_command: CommandObservation | None = None
    controller_state: ControllerState
    note: str


class NativeScheduleZone(SprinklerModel):
    zone_id: str
    zone_number: int = Field(ge=1, le=8)
    native_zone_id: str | None = None
    zone_name: str | None = None
    duration_seconds: int | None = Field(default=None, ge=0)
    enabled: bool | None = None


class CycleSoak(SprinklerModel):
    enabled: bool | None = None
    cycle_count: int | None = Field(default=None, ge=0)
    cycle_duration_seconds: int | None = Field(default=None, ge=0)
    soak_duration_seconds: int | None = Field(default=None, ge=0)


class NativeSchedule(SprinklerModel):
    schedule_id: str
    name: str | None = None
    schedule_type: str | None = None
    enabled: bool | None = None
    state: str | None = None
    start_time: str | None = None
    start_date: AwareDatetime | None = None
    end_date: AwareDatetime | None = None
    next_run_at: AwareDatetime | None = None
    interval: str | int | None = None
    recurrence: str | None = None
    repeat_interval: int | None = None
    odd_even: str | None = None
    run_days: list[str] = Field(default_factory=list)
    zone_ids: list[str] = Field(default_factory=list)
    zone_runs: list[NativeScheduleZone] = Field(default_factory=list)
    cycle_soak: CycleSoak | None = None
    timestamp_ambiguity: UnsupportedSignal | None = None
    evidence: StateEvidence = "controller-reported"


class SprinklerScheduleList(SprinklerModel):
    count: int = Field(ge=0)
    schedules: list[NativeSchedule]
    read_supported: bool
    mutations: UnsupportedSignal


class UpcomingRun(SprinklerModel):
    run_id: str | None = None
    program_id: str | None = None
    program_name: str | None = None
    starts_at: AwareDatetime
    zone_ids: list[str] = Field(default_factory=list)
    source: str
    source_supported: bool
    evidence: StateEvidence | None = None


class SprinklerUpcomingRuns(SprinklerModel):
    count: int = Field(ge=0)
    runs: list[UpcomingRun]
    supported: bool
    feed_complete: bool = False
    limitation: str | None = None


class WeatherDecision(SprinklerModel):
    decision_type: str
    decision: str
    reason: str | None = None
    run_id: str | None = None
    observed_at: AwareDatetime | None = None
    evidence: StateEvidence


class ThresholdValue(SprinklerModel):
    name: str
    native_key: str
    value: ScalarValue
    unit: Literal["upstream_unspecified"] | None = None
    evidence: StateEvidence = "controller-reported"


class SprinklerWeatherDecisions(SprinklerModel):
    thresholds: list[ThresholdValue]
    decisions: list[WeatherDecision]
    wyze_weather_data: UnsupportedSignal
    sprinkler_plus_calculation: UnsupportedSignal


class SprinklerDiagnostics(SprinklerModel):
    connected: bool | None = None
    connectivity_supported: bool
    connectivity_evidence: StateEvidence | None = None
    firmware_version: str | None = None
    firmware_supported: bool
    firmware_evidence: StateEvidence | None = None
    signal_strength_native_value: int | None = None
    signal_strength_supported: bool
    signal_strength_units: Literal["upstream_unspecified"] | None = None
    signal_strength_evidence: StateEvidence | None = None
    endpoint_health_evidence: StateEvidence = "inferred"
    ip_address: str | None = None
    ip_address_supported: bool
    ip_address_evidence: StateEvidence | None = None
    ip_address_redacted: bool
    ssid_supported: bool
    ssid_evidence: StateEvidence | None = None
    ssid_redacted: bool
    endpoint_errors: list[str] = Field(default_factory=list)
    physical_feedback: UnsupportedSignal
    measured_flow: UnsupportedSignal
    electrical_load: UnsupportedSignal
    valve_faults: UnsupportedSignal


class SprinklerRefreshResult(SprinklerModel):
    status: Literal["completed"]
    controller: EntityStateSummary
    controller_evidence: StateEvidence = "controller-reported"
    refresh_evidence: StateEvidence = "commanded"
    physical_state_verified: bool = False


class SprinklerCommandResult(SprinklerModel):
    status: str
    command_id: str
    operation: str
    zones: list[SprinklerCommandZone]
    evidence: StateEvidence = "commanded"
    physical_state_verified: bool = False


def normalized_zone_id(zone_number: int) -> str:
    return f"zone-{zone_number}"


def zone_number_from_id(zone_id: str) -> int:
    if not zone_id.startswith("zone-") or not zone_id[5:].isdigit():
        raise ValueError("zone_id must use the stable form zone-1 through zone-8")
    zone = int(zone_id[5:])
    if not 1 <= zone <= 8:
        raise ValueError("zone_id must use the stable form zone-1 through zone-8")
    return zone


def timestamp_to_iso(value: Any) -> str | None:
    """Normalize common Wyze seconds/milliseconds/string timestamps to RFC 3339."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 10_000_000_000:
            numeric /= 1000
        try:
            return datetime.fromtimestamp(numeric, UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.isdigit():
        return timestamp_to_iso(int(text))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC).isoformat()


def unwrap_provider_response(value: Any) -> dict[str, Any]:
    """Unwrap HA response-service/device/provider envelopes without guessing data."""
    current = value
    for _ in range(5):
        if not isinstance(current, dict):
            return {}
        if "data" in current and isinstance(current["data"], dict):
            current = current["data"]
            continue
        if len(current) == 1:
            only = next(iter(current.values()))
            if isinstance(only, dict) and not set(current) & {
                "runs",
                "schedules",
                "zones",
                "controller",
                "capabilities",
            }:
                current = only
                continue
        return current
    return current if isinstance(current, dict) else {}


def sanitize_native_definition(value: dict[str, Any]) -> dict[str, Any]:
    """Drop credentials and location/network identifiers from native definitions."""
    blocked = {
        "access_token",
        "api_key",
        "device_id",
        "did",
        "did_uid",
        "ip",
        "ip_address",
        "latitude",
        "longitude",
        "mac",
        "nonce",
        "password",
        "ssid",
        "token",
        "wifi_mac",
    }
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key.lower() in blocked:
            continue
        if isinstance(item, dict):
            result[key] = sanitize_native_definition(item)
        elif isinstance(item, list):
            result[key] = [
                sanitize_native_definition(child) if isinstance(child, dict) else child
                for child in item
            ]
        else:
            result[key] = item
    return result
