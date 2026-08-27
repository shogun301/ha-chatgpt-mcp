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
    }
)

PERCENTAGE_KEYS: Final = frozenset({"battery_state_of_energy_pct"})
METRIC_KEYS: Final = POWER_KEYS | ENERGY_KEYS | PERCENTAGE_KEYS
STORAGE_STATUS_KEYS: Final = frozenset(
    {
        "storage_operating_plan",
        "storage_operating_plan_active",
        "storage_operating_plan_block_count",
    }
)
SNAPSHOT_KEYS: Final = METRIC_KEYS | STORAGE_STATUS_KEYS
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
    site: Mapping[str, float]
    completeness: Mapping[str, bool]
    storage_operating_plan: str | None
    storage_operating_plan_active: bool | None
    storage_operating_plan_block_count: int | None

    def value(self, key: str) -> float | None:
        """Return a metric only when it is present and not marked incomplete."""
        if self.completeness.get(key) is False:
            return None
        return self.site.get(key)


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
    return numeric


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

    site: dict[str, float] = {}
    for key in METRIC_KEYS:
        parsed = _parse_metric(key, raw_site.get(key))
        if parsed is not None:
            site[key] = parsed

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
        storage_operating_plan=_parse_operating_plan(
            raw_site.get("storage_operating_plan")
        ),
        storage_operating_plan_active=_parse_optional_bool(
            raw_site.get("storage_operating_plan_active")
        ),
        storage_operating_plan_block_count=_parse_operating_plan_block_count(
            raw_site.get("storage_operating_plan_block_count")
        ),
    )
