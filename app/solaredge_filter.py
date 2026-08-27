"""Conservative filtering for SolarEdge bridge polling artifacts."""

from __future__ import annotations

import copy
import math
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, Final, Literal

STRONG_PRODUCTION_W: Final = 1_000.0
NEAR_ZERO_PRODUCTION_W: Final = 100.0
MAX_COMPARISON_AGE: Final = timedelta(minutes=15)
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

FilterAction = Literal[
    "accepted",
    "suppressed_first_near_zero",
    "suppressed_repeated_snapshot",
    "confirmed_near_zero",
    "recovered_after_suppression",
]


def _production_power(snapshot: Mapping[str, Any]) -> float | None:
    """Return one complete non-negative production value, if present."""
    if snapshot.get("connected") is not True:
        return None
    completeness = snapshot.get("completeness")
    if isinstance(completeness, Mapping) and completeness.get(
        "production_power_w"
    ) is False:
        return None
    site = snapshot.get("site")
    if not isinstance(site, Mapping):
        return None
    value = site.get("production_power_w")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        return None
    return numeric


def _observed_at(snapshot: Mapping[str, Any]) -> str | None:
    value = snapshot.get("observed_at")
    return value if isinstance(value, str) and value else None


def _observed_datetime(snapshot: Mapping[str, Any]) -> datetime | None:
    value = _observed_at(snapshot)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _without_instantaneous_power(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Return the current observation with all six power metrics incomplete."""
    filtered = copy.deepcopy(dict(snapshot))
    site = filtered.get("site")
    if isinstance(site, dict):
        for key in POWER_KEYS:
            site.pop(key, None)
    completeness = filtered.get("completeness")
    if not isinstance(completeness, dict):
        completeness = {}
        filtered["completeness"] = completeness
    for key in POWER_KEYS:
        completeness[key] = False
    return filtered


class SolarEdgeSnapshotFilter:
    """Debounce one abrupt strong-to-near-zero bridge snapshot atomically.

    The filter omits all six instantaneous power metrics until a distinct second
    low-production observation confirms an outage. Cumulative energy, state of
    energy, and plan data from the current observation remain available. A normal
    follow-up accepts the recovery immediately, removing the isolated notch
    without combining power metrics from different provider observations.
    """

    def __init__(self) -> None:
        self._accepted: dict[str, Any] | None = None
        self._pending_low = False
        self._pending_observed_at: str | None = None

    def apply(self, snapshot: Mapping[str, Any]) -> tuple[dict[str, Any], FilterAction]:
        """Return an atomic accepted snapshot and the filtering decision."""
        current = copy.deepcopy(dict(snapshot))
        current_power = _production_power(current)

        if self._accepted is None:
            self._accepted = current
            return copy.deepcopy(current), "accepted"

        previous_power = _production_power(self._accepted)
        previous_observed_at = _observed_datetime(self._accepted)
        current_observed_at_dt = _observed_datetime(current)
        recent = (
            previous_observed_at is None
            or current_observed_at_dt is None
            or (
                current_observed_at_dt >= previous_observed_at
                and current_observed_at_dt - previous_observed_at
                <= MAX_COMPARISON_AGE
            )
        )
        suspicious = (
            previous_power is not None
            and previous_power >= STRONG_PRODUCTION_W
            and current_power is not None
            and current_power <= NEAR_ZERO_PRODUCTION_W
            and recent
        )

        if suspicious:
            current_observed_at = _observed_at(current)
            if not self._pending_low:
                self._pending_low = True
                self._pending_observed_at = current_observed_at
                return (
                    _without_instantaneous_power(current),
                    "suppressed_first_near_zero",
                )

            pending_observed_at_dt = None
            if self._pending_observed_at is not None:
                try:
                    pending_observed_at_dt = datetime.fromisoformat(
                        self._pending_observed_at
                    )
                except ValueError:
                    pass
            if current_observed_at_dt is not None and (
                pending_observed_at_dt is None
                or current_observed_at_dt <= pending_observed_at_dt
            ):
                return (
                    _without_instantaneous_power(current),
                    "suppressed_repeated_snapshot",
                )

            self._accepted = current
            self._pending_low = False
            self._pending_observed_at = None
            return copy.deepcopy(current), "confirmed_near_zero"

        action: FilterAction = (
            "recovered_after_suppression" if self._pending_low else "accepted"
        )
        self._accepted = current
        self._pending_low = False
        self._pending_observed_at = None
        return copy.deepcopy(current), action
