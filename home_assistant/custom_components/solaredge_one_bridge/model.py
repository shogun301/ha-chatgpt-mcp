"""Validation and sanitization for SolarEdge Monitoring bridge snapshots.

This module deliberately has no Home Assistant dependencies so its trust boundary can
be tested in isolation. Only documented aggregate metrics cross that boundary.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

POWER_KEYS: Final = frozenset(
    {
        "production_power_w",
        "consumption_power_w",
        "grid_import_power_w",
        "grid_export_power_w",
        "battery_charge_power_w",
        "battery_discharge_power_w",
        "portal_live_ac_power_w",
        "maximum_ac_power_w",
        "grid_component_power_w",
        "consumption_component_power_w",
        "solar_component_power_w",
        "ac_storage_component_power_w",
        "dc_storage_component_power_w",
        "ev_charger_component_power_w",
        "battery_storage_state_power_w",
    }
)

ENERGY_KEYS: Final = frozenset(
    {
        "production_energy_kwh",
        "consumption_energy_kwh",
        "grid_import_energy_kwh",
        "grid_export_energy_kwh",
        "battery_charge_energy_kwh",
        "battery_discharge_energy_kwh",
        "battery_remaining_energy_kwh",
        "today_battery_charge_energy_endpoint_kwh",
        "today_battery_discharge_energy_endpoint_kwh",
        *(
            f"{prefix}_{name}"
            for prefix in ("today", "lifetime", "latest_interval")
            for name in (
                "production_energy_kwh",
                "consumption_energy_kwh",
                "grid_import_energy_kwh",
                "grid_export_energy_kwh",
                "production_to_home_energy_kwh",
                "production_to_battery_energy_kwh",
                "production_to_grid_energy_kwh",
                "production_unknown_energy_kwh",
                "consumption_from_battery_energy_kwh",
                "consumption_from_solar_energy_kwh",
                "consumption_from_grid_energy_kwh",
            )
        ),
        *(
            f"today_{name}"
            for name in (
                "storage_destination_total_energy_kwh",
                "storage_destination_building_energy_kwh",
                "storage_destination_grid_energy_kwh",
                "storage_destination_unknown_energy_kwh",
                "storage_source_total_energy_kwh",
                "storage_source_pv_energy_kwh",
                "storage_source_grid_energy_kwh",
                "storage_source_unknown_energy_kwh",
            )
        ),
    }
)

PERCENTAGE_KEYS: Final = frozenset(
    {
        "battery_state_of_energy_pct",
        "battery_storage_state_of_charge_pct",
        "ac_storage_charge_level_pct",
        "dc_storage_charge_level_pct",
        *(
            f"{prefix}_{name}"
            for prefix in ("today", "lifetime")
            for name in (
                "production_to_home_pct",
                "production_to_battery_pct",
                "production_to_grid_pct",
                "production_unknown_pct",
                "consumption_from_battery_pct",
                "consumption_from_solar_pct",
                "consumption_from_grid_pct",
                "performance_ratio_pct",
                "self_consumption_ratio_pct",
                "self_sufficiency_ratio_pct",
                "site_availability_pct",
            )
        ),
        *(
            f"today_{name}"
            for name in (
                "storage_destination_building_pct",
                "storage_destination_grid_pct",
                "storage_destination_unknown_pct",
                "storage_source_pv_pct",
                "storage_source_grid_pct",
                "storage_source_unknown_pct",
            )
        ),
    }
)

COUNT_KEYS: Final = frozenset(
    {
        "storage_operating_plan_block_count",
        "ac_storage_block_count",
        "dc_storage_block_count",
        "capability_inverter_count",
        "power_flow_refresh_rate_seconds",
        "energy_producer_count",
        "today_measurement_count",
        "lifetime_measurement_count",
    }
)

RATIO_KEYS: Final = frozenset(
    {
        "today_average_power_factor",
        "lifetime_average_power_factor",
        "today_yield",
        "lifetime_yield",
    }
)

TEXT_KEYS: Final = frozenset(
    {
        "storage_operating_plan",
        "bridge_fetched_at",
        "power_flow_last_update_time",
        "capability_viewer_type",
        "capability_site_type",
        "capability_international_system_units",
        "grid_component_status",
        "grid_component_direction",
        "consumption_component_status",
        "consumption_component_direction",
        "solar_component_status",
        "solar_component_direction",
        "ac_storage_component_status",
        "ac_storage_component_direction",
        "ac_storage_storage_plan",
        "dc_storage_component_status",
        "dc_storage_component_direction",
        "dc_storage_storage_plan",
        "ev_charger_component_status",
        "ev_charger_component_direction",
        "battery_storage_status",
        "battery_storage_timestamp",
        "latest_interval_start",
        "latest_interval_weather",
        "today_storage_distribution_start_date",
        "today_storage_distribution_end_date",
        *(
            f"{prefix}_{name}"
            for prefix in ("today", "lifetime")
            for name in (
                "start_date",
                "end_date",
                "chart_time_unit",
                "window_type",
                "timezone",
                "provider_timestamp",
                "late_production_start_date",
                "late_production_distribution_start_date",
                "late_consumption_start_date",
                "late_consumption_distribution_start_date",
                "late_performance_ratio_start_date",
                "late_yield_start_date",
            )
        ),
    }
)

BOOLEAN_KEYS: Final = frozenset(
    {
        "storage_operating_plan_active",
        "power_flow_is_real_time",
        "power_flow_is_communicating",
        "grid_component_active",
        "consumption_component_active",
        "consumption_component_is_consuming",
        "solar_component_active",
        "solar_component_is_producing",
        "ac_storage_component_active",
        "dc_storage_component_active",
        "ev_charger_component_active",
        "latest_interval_production_estimated",
        "latest_interval_consumption_estimated",
        *(
            f"capability_{name}"
            for name in (
                "has_production",
                "has_consumption_and_grid",
                "has_storage",
                "has_performance_ratio",
                "has_smart_devices",
                "has_ev_chargers",
                "has_billing_cycle_program",
                "show_inverter_graph",
                "can_normalize_data",
                "can_normalize_inverters_data",
                "can_edit_billing_period",
                "has_commercial_performance_ratio",
                "has_generator",
                "has_ac_storage",
                "has_dc_storage",
            )
        ),
        *(
            f"endpoint_{name}_available"
            for name in (
                "capabilities",
                "live_power",
                "power_flow",
                "current_day_energy",
                "lifetime_energy",
                "current_day_storage_distribution",
                "battery_storage_state",
                "current_day_battery_energy",
            )
        ),
    }
)

METRIC_KEYS: Final = POWER_KEYS | ENERGY_KEYS | PERCENTAGE_KEYS | COUNT_KEYS | RATIO_KEYS
STORAGE_STATUS_KEYS: Final = frozenset(
    {
        "storage_operating_plan",
        "storage_operating_plan_active",
        "storage_operating_plan_block_count",
    }
)
SNAPSHOT_KEYS: Final = METRIC_KEYS | TEXT_KEYS | BOOLEAN_KEYS | STORAGE_STATUS_KEYS
PROVIDER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ /-]{0,63}")
OPERATING_PLAN_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ /-]{0,63}")
MAX_OPERATING_PLAN_BLOCKS: Final = 1_000


class InvalidSnapshot(ValueError):
    """Raised when a bridge response is not a valid sanitized snapshot."""


@dataclass(frozen=True, slots=True)
class SolarEdgeSnapshot:
    """Sanitized aggregate SolarEdge data safe to expose to Home Assistant."""

    connected: bool
    observed_at: str | None
    provider: str | None
    site: Mapping[str, float | str | bool]
    completeness: Mapping[str, bool]
    storage_operating_plan: str | None
    storage_operating_plan_active: bool | None
    storage_operating_plan_block_count: int | None

    def value(self, key: str) -> float | None:
        """Return a metric only when it is present and not marked incomplete."""
        if self.completeness.get(key) is False:
            return None
        value = self.site.get(key)
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None

    def text(self, key: str) -> str | None:
        """Return one allowlisted text value when complete."""
        if self.completeness.get(key) is False:
            return None
        value = self.site.get(key)
        return value if isinstance(value, str) else None

    def flag(self, key: str) -> bool | None:
        """Return one allowlisted boolean value when complete."""
        if self.completeness.get(key) is False:
            return None
        value = self.site.get(key)
        return value if isinstance(value, bool) else None


def _parse_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise InvalidSnapshot("observed_at must be a non-empty ISO 8601 string or null")
    normalized = value.strip()
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as err:
        raise InvalidSnapshot("observed_at must be an ISO 8601 timestamp") from err
    if parsed.tzinfo is None:
        raise InvalidSnapshot("observed_at must include a timezone")
    return normalized


def _parse_metric(key: str, value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        return None
    if key in PERCENTAGE_KEYS and numeric > 100:
        return None
    if key in COUNT_KEYS and not numeric.is_integer():
        return None
    return numeric


def _parse_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 128
        or any(character in normalized for character in "\r\n\0")
    ):
        return None
    return normalized


def _parse_provider(value: Any) -> str | None:
    """Retain a concise provider label, never arbitrary provider metadata."""
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not PROVIDER_PATTERN.fullmatch(normalized):
        return None
    return normalized


def _parse_operating_plan(value: Any) -> str | None:
    """Retain only a concise plan label, never arbitrary policy metadata."""
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not OPERATING_PLAN_PATTERN.fullmatch(normalized):
        return None
    return normalized


def _parse_optional_bool(value: Any) -> bool | None:
    """Return a provider boolean without coercing strings or numbers."""
    return value if isinstance(value, bool) else None


def _parse_operating_plan_block_count(value: Any) -> int | None:
    """Return a bounded non-negative block count without boolean coercion."""
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_OPERATING_PLAN_BLOCKS
    ):
        return None
    return value


def parse_snapshot(payload: Any) -> SolarEdgeSnapshot:
    """Validate the envelope and retain only allowlisted aggregate metrics.

    Unknown fields are ignored so site identifiers, addresses, serial numbers, and
    credentials can never become entity state or attributes by accident.
    """
    if not isinstance(payload, Mapping):
        raise InvalidSnapshot("snapshot must be an object")

    connected = payload.get("connected")
    if not isinstance(connected, bool):
        raise InvalidSnapshot("connected must be a boolean")

    raw_site = payload.get("site")
    if not isinstance(raw_site, Mapping):
        raise InvalidSnapshot("site must be an object")

    site: dict[str, float | str | bool] = {}
    for key in METRIC_KEYS:
        parsed = _parse_metric(key, raw_site.get(key))
        if parsed is not None:
            site[key] = parsed
    for key in TEXT_KEYS:
        parsed_text = _parse_text(raw_site.get(key))
        if parsed_text is not None:
            site[key] = parsed_text
    for key in BOOLEAN_KEYS:
        parsed_boolean = _parse_optional_bool(raw_site.get(key))
        if parsed_boolean is not None:
            site[key] = parsed_boolean

    raw_completeness = payload.get("completeness", {})
    if not isinstance(raw_completeness, Mapping):
        raise InvalidSnapshot("completeness must be an object")
    completeness = {
        key: value
        for key, value in raw_completeness.items()
        if key in SNAPSHOT_KEYS and isinstance(value, bool)
    }

    return SolarEdgeSnapshot(
        connected=connected,
        observed_at=_parse_timestamp(payload.get("observed_at")),
        provider=_parse_provider(payload.get("provider")),
        site=site,
        completeness=completeness,
        storage_operating_plan=_parse_operating_plan(raw_site.get("storage_operating_plan")),
        storage_operating_plan_active=_parse_optional_bool(raw_site.get("storage_operating_plan_active")),
        storage_operating_plan_block_count=_parse_operating_plan_block_count(raw_site.get("storage_operating_plan_block_count")),
    )
