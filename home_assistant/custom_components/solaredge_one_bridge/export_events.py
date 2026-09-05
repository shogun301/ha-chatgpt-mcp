"""Durable SolarEdge export-with-battery-headroom event model.

The state machine in this module deliberately has no Home Assistant imports.  The
Home Assistant adapter is responsible for persistence, recorder reads, and API
registration; keeping the event rules here makes restart and reconstruction
behaviour deterministic and directly testable.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any, Final, Literal
from zoneinfo import ZoneInfo

EVENT_SCHEMA_VERSION: Final = 2
GRID_EXPORT_THRESHOLD_W: Final = 500.0
CANDIDATE_SOC_THRESHOLD_PCT: Final = 100.0
ALERT_SOC_THRESHOLD_PCT: Final = 99.5
EXPORT_WITH_HEADROOM_SOC_THRESHOLD_PCT: Final = 95.0
BATTERY_DISCHARGE_THRESHOLD_W: Final = 250.0
BATTERY_CHARGE_HEADROOM_THRESHOLD_W: Final = 8500.0
BATTERY_TO_GRID_DURATION_SECONDS: Final = 5 * 60
EXPORT_WITH_HEADROOM_DURATION_SECONDS: Final = 10 * 60
EXPECTED_SAMPLE_SECONDS: Final = 5 * 60
MAX_COMPLETE_INTERVAL_SECONDS: Final = 2 * EXPECTED_SAMPLE_SECONDS
END_CONFIRMING_SAMPLES: Final = 2

BATTERY_TO_GRID = "battery-to-grid"
EXPORT_WITH_HEADROOM = "export-with-headroom"
CLASSIFICATION_BOTH = "both"

STATISTIC_FIELDS: Final = (
    "soc_pct",
    "grid_export_power_w",
    "battery_charge_power_w",
    "battery_discharge_power_w",
    "production_power_w",
    "consumption_power_w",
)


def _iso(value: datetime | None) -> str | None:
    """Return a normalized UTC timestamp."""
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValueError("event timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat()


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("stored event timestamps must include a timezone")
    return parsed.astimezone(UTC)


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if math.isfinite(numeric) else None


@dataclass(frozen=True, slots=True)
class OperatingPlanSnapshot:
    """Bounded operating-plan values attached to one synchronized sample."""

    state: str | None = None
    active: bool | None = None
    block_count: int | None = None
    provider: str | None = None
    observed_at: str | None = None
    completeness: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Any) -> OperatingPlanSnapshot:
        if not isinstance(value, dict):
            return cls()
        return cls(
            state=value.get("state") if isinstance(value.get("state"), str) else None,
            active=value.get("active")
            if isinstance(value.get("active"), bool)
            else None,
            block_count=value.get("block_count")
            if isinstance(value.get("block_count"), int)
            and not isinstance(value.get("block_count"), bool)
            else None,
            provider=value.get("provider")
            if isinstance(value.get("provider"), str)
            else None,
            observed_at=value.get("observed_at")
            if isinstance(value.get("observed_at"), str)
            else None,
            completeness=value.get("completeness")
            if isinstance(value.get("completeness"), bool)
            else None,
        )


@dataclass(frozen=True, slots=True)
class ExportSample:
    """One synchronized observation used by the event model."""

    at: datetime
    grid_export_power_w: float | None = None
    grid_export_energy_kwh: float | None = None
    soc_pct: float | None = None
    battery_charge_power_w: float | None = None
    battery_discharge_power_w: float | None = None
    production_power_w: float | None = None
    consumption_power_w: float | None = None
    operating_plan: OperatingPlanSnapshot = OperatingPlanSnapshot()
    source: Literal["live", "reconstructed"] = "live"

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("sample timestamp must be timezone-aware")

    def as_dict(self) -> dict[str, Any]:
        return {
            "at": _iso(self.at),
            "grid_export_power_w": self.grid_export_power_w,
            "grid_export_energy_kwh": self.grid_export_energy_kwh,
            "soc_pct": self.soc_pct,
            "battery_charge_power_w": self.battery_charge_power_w,
            "battery_discharge_power_w": self.battery_discharge_power_w,
            "production_power_w": self.production_power_w,
            "consumption_power_w": self.consumption_power_w,
            "operating_plan": self.operating_plan.as_dict(),
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ExportSample:
        at = _parse_time(value.get("at"))
        if at is None:
            raise ValueError("stored sample is missing at")
        source = value.get("source")
        return cls(
            at=at,
            grid_export_power_w=_number(value.get("grid_export_power_w")),
            grid_export_energy_kwh=_number(value.get("grid_export_energy_kwh")),
            soc_pct=_number(value.get("soc_pct")),
            battery_charge_power_w=_number(value.get("battery_charge_power_w")),
            battery_discharge_power_w=_number(value.get("battery_discharge_power_w")),
            production_power_w=_number(value.get("production_power_w")),
            consumption_power_w=_number(value.get("consumption_power_w")),
            operating_plan=OperatingPlanSnapshot.from_dict(value.get("operating_plan")),
            source=source if source in {"live", "reconstructed"} else "live",
        )


@dataclass(frozen=True, slots=True)
class EventTransition:
    """A one-shot transition for the Home Assistant event bus adapter."""

    kind: Literal["qualified", "completed"]
    event: dict[str, Any]
    sample: ExportSample


def _candidate(sample: ExportSample) -> bool | None:
    if sample.grid_export_power_w is None or sample.soc_pct is None:
        return None
    return (
        sample.grid_export_power_w > GRID_EXPORT_THRESHOLD_W
        and sample.soc_pct < CANDIDATE_SOC_THRESHOLD_PCT
    )


def _battery_to_grid_at_deadline(sample: ExportSample) -> bool:
    return bool(
        sample.grid_export_power_w is not None
        and sample.soc_pct is not None
        and sample.battery_discharge_power_w is not None
        and sample.grid_export_power_w > GRID_EXPORT_THRESHOLD_W
        and sample.soc_pct < ALERT_SOC_THRESHOLD_PCT
        and sample.battery_discharge_power_w > BATTERY_DISCHARGE_THRESHOLD_W
    )


def _export_with_headroom_at_deadline(sample: ExportSample) -> bool:
    return bool(
        sample.grid_export_power_w is not None
        and sample.soc_pct is not None
        and sample.battery_charge_power_w is not None
        and sample.grid_export_power_w > GRID_EXPORT_THRESHOLD_W
        and sample.soc_pct < EXPORT_WITH_HEADROOM_SOC_THRESHOLD_PCT
        and sample.battery_charge_power_w < BATTERY_CHARGE_HEADROOM_THRESHOLD_W
    )


def _event_id(namespace: str, candidate_start: datetime) -> str:
    normalized = candidate_start.astimezone(UTC)
    digest = hashlib.sha256(
        f"{namespace}|{normalized.isoformat()}".encode()
    ).hexdigest()[:12]
    return f"se-{normalized:%Y%m%dT%H%M%S}Z-{digest}"


def _thresholds() -> dict[str, float | int]:
    return {
        "grid_export_w": GRID_EXPORT_THRESHOLD_W,
        "candidate_soc_pct": CANDIDATE_SOC_THRESHOLD_PCT,
        "alert_soc_pct": ALERT_SOC_THRESHOLD_PCT,
        "export_with_headroom_soc_pct": EXPORT_WITH_HEADROOM_SOC_THRESHOLD_PCT,
        "battery_discharge_w": BATTERY_DISCHARGE_THRESHOLD_W,
        "battery_charge_headroom_w": BATTERY_CHARGE_HEADROOM_THRESHOLD_W,
        "battery_to_grid_duration_seconds": BATTERY_TO_GRID_DURATION_SECONDS,
        "export_with_headroom_duration_seconds": (
            EXPORT_WITH_HEADROOM_DURATION_SECONDS
        ),
        "end_confirming_samples": END_CONFIRMING_SAMPLES,
        "expected_sample_seconds": EXPECTED_SAMPLE_SECONDS,
    }


def _classification(qualified_rules: list[str]) -> str | None:
    rules = set(qualified_rules)
    if {BATTERY_TO_GRID, EXPORT_WITH_HEADROOM}.issubset(rules):
        return CLASSIFICATION_BOTH
    if BATTERY_TO_GRID in rules:
        return BATTERY_TO_GRID
    if EXPORT_WITH_HEADROOM in rules:
        return EXPORT_WITH_HEADROOM
    return None


def _new_event(namespace: str, sample: ExportSample) -> dict[str, Any]:
    at = _iso(sample.at)
    plan = sample.operating_plan.as_dict()
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": _event_id(namespace, sample.at),
        "status": "active",
        "classification": None,
        "source": sample.source,
        "candidate_start": at,
        "qualified_at": None,
        "end_at": None,
        "total_duration_seconds": 0.0,
        "post_notification_duration_seconds": None,
        "exported_energy_kwh": 0.0,
        "export_energy_method": "insufficient_samples",
        "export_energy_quality": "insufficient_data",
        "thresholds": _thresholds(),
        "statistics": {},
        "operating_plan": {
            "start": plan,
            "qualification": None,
            "end": None,
        },
        "operating_plan_changes": [{"at": at, "plan": plan}],
        "samples": [sample.as_dict()],
        "reconstruction": {
            "coverage_start": at if sample.source == "reconstructed" else None,
            "coverage_end": at if sample.source == "reconstructed" else None,
            "quality": "recorder-derived" if sample.source == "reconstructed" else None,
            "recovered_after_restart": False,
        },
        "_state": {
            "qualified_rules": [],
            "emitted_classifications": [],
            "pending_end_at": None,
            "pending_end_count": 0,
        },
    }


def _append_sample(event: dict[str, Any], sample: ExportSample) -> None:
    samples = event.setdefault("samples", [])
    if samples and samples[-1].get("at") == _iso(sample.at):
        samples[-1] = sample.as_dict()
    else:
        samples.append(sample.as_dict())
    changes = event.setdefault("operating_plan_changes", [])
    plan = sample.operating_plan.as_dict()
    # `observed_at` advances on every bridge poll. It is useful provenance on
    # each retained snapshot, but is not itself an operating-plan change.
    comparable_plan = {
        key: value for key, value in plan.items() if key != "observed_at"
    }
    previous_plan = changes[-1].get("plan", {}) if changes else {}
    comparable_previous = {
        key: value for key, value in previous_plan.items() if key != "observed_at"
    }
    if not changes or comparable_previous != comparable_plan:
        changes.append({"at": _iso(sample.at), "plan": plan})
    reconstruction = event.setdefault("reconstruction", {})
    if sample.source == "reconstructed":
        reconstruction["coverage_start"] = reconstruction.get("coverage_start") or _iso(
            sample.at
        )
        reconstruction["coverage_end"] = _iso(sample.at)
        reconstruction["quality"] = "recorder-derived"


def _sample_statistics(samples: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in STATISTIC_FIELDS:
        values = [
            numeric
            for sample in samples
            if (numeric := _number(sample.get(field))) is not None
        ]
        weighted_area = 0.0
        weighted_seconds = 0.0
        partial = False
        for left, right in pairwise(samples):
            left_at = _parse_time(left.get("at"))
            right_at = _parse_time(right.get("at"))
            left_value = _number(left.get(field))
            right_value = _number(right.get(field))
            if (
                left_at is None
                or right_at is None
                or left_value is None
                or right_value is None
            ):
                partial = True
                continue
            seconds = (right_at - left_at).total_seconds()
            if seconds <= 0 or seconds > MAX_COMPLETE_INTERVAL_SECONDS:
                partial = True
                continue
            weighted_area += ((left_value + right_value) / 2.0) * seconds
            weighted_seconds += seconds
        if weighted_seconds > 0:
            mean = weighted_area / weighted_seconds
            mean_method = "time_weighted_trapezoidal"
            mean_quality = "partial" if partial else "complete"
        elif values:
            mean = sum(values) / len(values)
            mean_method = (
                "single_sample_fallback"
                if len(values) == 1
                else "arithmetic_sample_fallback"
            )
            mean_quality = "insufficient_time_coverage"
        else:
            mean = None
            mean_method = "unavailable"
            mean_quality = "no_valid_samples"
        result[field] = {
            "start": _number(samples[0].get(field)) if samples else None,
            "end": _number(samples[-1].get(field)) if samples else None,
            "min": min(values) if values else None,
            "max": max(values) if values else None,
            "mean": mean,
            "mean_method": mean_method,
            "mean_quality": mean_quality,
            "count": len(values),
        }
    return result


def _energy(samples: list[dict[str, Any]]) -> tuple[float | None, str, str]:
    """Return energy, method, and explicit data-quality classification.

    A cumulative meter delta is used only when every synchronized boundary is
    below 100% SOC, the meter is monotonic, and no observation gap exceeds ten
    minutes.  Otherwise export power is trapezoidally integrated.  A linearly
    interpolated SOC=100 crossing bounds the last interval rather than silently
    counting it as wholly below 100%.
    """
    if len(samples) < 2:
        return 0.0, "insufficient_samples", "insufficient_data"

    times = [_parse_time(sample.get("at")) for sample in samples]
    if any(value is None for value in times):
        return None, "trapezoidal_export_power_integration", "estimated_partial"
    aware_times = [value for value in times if value is not None]
    gaps = [(right - left).total_seconds() for left, right in pairwise(aware_times)]
    cadence_complete = bool(gaps) and all(
        0 < gap <= MAX_COMPLETE_INTERVAL_SECONDS for gap in gaps
    )
    energies = [_number(sample.get("grid_export_energy_kwh")) for sample in samples]
    soc_values = [_number(sample.get("soc_pct")) for sample in samples]
    meter_complete = (
        cadence_complete
        and all(value is not None for value in energies)
        and all(
            value is not None and value < CANDIDATE_SOC_THRESHOLD_PCT
            for value in soc_values
        )
        and all(
            right >= left
            for left, right in pairwise(energies)
            if left is not None and right is not None
        )
    )
    if meter_complete:
        # A monotonic cumulative sensor can still be too stale/coarse to isolate
        # this interval (for example, an unchanged 30-minute reading across a
        # 10-minute event). Require every meter increment to agree reasonably
        # with the synchronized export-power samples before calling it complete.
        for index, seconds in enumerate(gaps):
            p0 = _number(samples[index].get("grid_export_power_w"))
            p1 = _number(samples[index + 1].get("grid_export_power_w"))
            e0 = energies[index]
            e1 = energies[index + 1]
            if p0 is None or p1 is None or e0 is None or e1 is None:
                meter_complete = False
                break
            power_kwh = ((p0 + p1) / 2.0) * seconds / 3_600_000
            meter_kwh = e1 - e0
            tolerance_kwh = max(0.02, power_kwh * 0.35)
            if abs(meter_kwh - power_kwh) > tolerance_kwh:
                meter_complete = False
                break
    if meter_complete:
        first = energies[0]
        last = energies[-1]
        assert first is not None and last is not None
        return (
            last - first,
            "cumulative_grid_export_energy_delta",
            "meter_delta_complete",
        )

    total_kwh = 0.0
    used_intervals = 0
    partial = not cadence_complete
    for index, seconds in enumerate(gaps):
        left = samples[index]
        right = samples[index + 1]
        p0 = _number(left.get("grid_export_power_w"))
        p1 = _number(right.get("grid_export_power_w"))
        s0 = _number(left.get("soc_pct"))
        s1 = _number(right.get("soc_pct"))
        if (
            p0 is None
            or p1 is None
            or s0 is None
            or s1 is None
            or seconds <= 0
            or seconds > MAX_COMPLETE_INTERVAL_SECONDS
        ):
            partial = True
            continue
        if s0 < CANDIDATE_SOC_THRESHOLD_PCT and s1 < CANDIDATE_SOC_THRESHOLD_PCT:
            total_kwh += ((p0 + p1) / 2.0) * seconds / 3_600_000
            used_intervals += 1
        elif s0 < CANDIDATE_SOC_THRESHOLD_PCT <= s1 and s1 != s0:
            fraction = (CANDIDATE_SOC_THRESHOLD_PCT - s0) / (s1 - s0)
            fraction = min(1.0, max(0.0, fraction))
            p_at_crossing = p0 + ((p1 - p0) * fraction)
            total_kwh += ((p0 + p_at_crossing) / 2.0) * (seconds * fraction) / 3_600_000
            used_intervals += 1
        elif s1 < CANDIDATE_SOC_THRESHOLD_PCT <= s0 and s1 != s0:
            crossing = (s0 - CANDIDATE_SOC_THRESHOLD_PCT) / (s0 - s1)
            crossing = min(1.0, max(0.0, crossing))
            p_at_crossing = p0 + ((p1 - p0) * crossing)
            below_fraction = 1.0 - crossing
            total_kwh += (
                ((p_at_crossing + p1) / 2.0) * (seconds * below_fraction) / 3_600_000
            )
            used_intervals += 1
    quality = (
        "estimated_complete" if used_intervals and not partial else "estimated_partial"
    )
    return (
        total_kwh if used_intervals else None,
        "trapezoidal_export_power_integration",
        quality,
    )


def _refresh_derived(event: dict[str, Any], *, through: datetime) -> None:
    start = _parse_time(event.get("candidate_start"))
    qualified = _parse_time(event.get("qualified_at"))
    end = _parse_time(event.get("end_at")) or through.astimezone(UTC)
    event["total_duration_seconds"] = (
        max(0.0, (end - start).total_seconds()) if start is not None else None
    )
    event["post_notification_duration_seconds"] = (
        max(0.0, (end - qualified).total_seconds()) if qualified is not None else None
    )
    event["statistics"] = _sample_statistics(event.get("samples", []))
    energy, method, quality = _energy(event.get("samples", []))
    event["exported_energy_kwh"] = energy
    event["export_energy_method"] = method
    event["export_energy_quality"] = quality


def public_event(
    event: dict[str, Any], *, include_samples: bool = True
) -> dict[str, Any]:
    """Return an API-safe copy without internal state-machine fields."""
    result = {key: value for key, value in event.items() if key != "_state"}
    if not include_samples:
        result.pop("samples", None)
        result.pop("operating_plan_changes", None)
        result["sample_count"] = len(event.get("samples", []))
    return json.loads(json.dumps(result, separators=(",", ":")))


class ExportEventEngine:
    """Deterministic event state machine used for live and recorder samples."""

    def __init__(
        self,
        namespace: str,
        *,
        completed_events: list[dict[str, Any]] | None = None,
        open_event: dict[str, Any] | None = None,
        grid_export_since: str | None = None,
        evaluated_deadlines: list[str] | None = None,
        last_sample: dict[str, Any] | None = None,
    ) -> None:
        self.namespace = namespace
        self.completed_events = completed_events or []
        self.open_event = open_event
        if grid_export_since is None and open_event is not None:
            samples = open_event.get("samples", [])
            latest_export = (
                _number(samples[-1].get("grid_export_power_w")) if samples else None
            )
            if latest_export is not None and latest_export > GRID_EXPORT_THRESHOLD_W:
                grid_export_since = open_event.get("_state", {}).get(
                    "grid_export_since"
                ) or open_event.get("candidate_start")
        self.grid_export_since = grid_export_since
        self.evaluated_deadlines = set(evaluated_deadlines or [])
        self.last_sample = last_sample

    def _update_export_timer(self, sample: ExportSample) -> None:
        """Track only the continuous export predicate used by both HA `for` rules."""
        export = sample.grid_export_power_w
        if export is None:
            # An unavailable current export reading cannot prove continuity.
            self.grid_export_since = None
        elif export > GRID_EXPORT_THRESHOLD_W:
            if self.grid_export_since is None:
                self.grid_export_since = _iso(sample.at)
                self.evaluated_deadlines.clear()
        else:
            self.grid_export_since = None
            self.evaluated_deadlines.clear()

    def _evaluate_qualification(
        self, sample: ExportSample, *, at: datetime
    ) -> list[EventTransition]:
        """Evaluate current values after the shared continuous-export deadline.

        This intentionally mirrors the original Home Assistant automation: only
        grid export is held continuously for five or ten minutes. SOC and battery
        power are point-in-time conditions at the respective deadline.
        """
        export_since = _parse_time(self.grid_export_since)
        if export_since is None:
            return []
        elapsed = (at.astimezone(UTC) - export_since).total_seconds()
        rule_specs = (
            (
                BATTERY_TO_GRID,
                BATTERY_TO_GRID_DURATION_SECONDS,
                _battery_to_grid_at_deadline(sample),
            ),
            (
                EXPORT_WITH_HEADROOM,
                EXPORT_WITH_HEADROOM_DURATION_SECONDS,
                _export_with_headroom_at_deadline(sample),
            ),
        )
        due: list[tuple[str, bool]] = []
        for rule, required_seconds, condition_now in rule_specs:
            if rule in self.evaluated_deadlines or elapsed < required_seconds:
                continue
            self.evaluated_deadlines.add(rule)
            due.append((rule, condition_now))
        current = self.open_event
        if current is None or _candidate(sample) is not True:
            return []
        state = current["_state"]
        state.setdefault("emitted_classifications", [])
        for rule, qualifies_now in due:
            if qualifies_now and rule not in state["qualified_rules"]:
                state["qualified_rules"].append(rule)
        current["classification"] = _classification(state["qualified_rules"])
        classification = current["classification"]
        if (
            classification is not None
            and classification not in state["emitted_classifications"]
        ):
            state["emitted_classifications"].append(classification)
            if current.get("qualified_at") is None:
                current["qualified_at"] = _iso(at)
                current["operating_plan"]["qualification"] = (
                    sample.operating_plan.as_dict()
                )
            _refresh_derived(current, through=at)
            return [EventTransition("qualified", public_event(current), sample)]
        if current.get("qualified_at") is None and classification is not None:
            current["qualified_at"] = _iso(at)
            current["operating_plan"]["qualification"] = sample.operating_plan.as_dict()
        _refresh_derived(current, through=at)
        return []

    def evaluate_deadline(
        self, sample: ExportSample, *, at: datetime
    ) -> list[EventTransition]:
        """Evaluate a live wall-clock deadline without inventing a meter sample."""
        return self._evaluate_qualification(sample, at=at)

    def process(self, sample: ExportSample) -> list[EventTransition]:
        """Apply one chronologically ordered synchronized sample."""
        transitions: list[EventTransition] = []
        previous = (
            ExportSample.from_dict(self.last_sample)
            if self.last_sample is not None
            else None
        )
        # Startup recovery may replay a bounded recorder window containing rows
        # older than the durable last sample. Reject those before touching the
        # continuous-export timer or evaluated deadlines.
        if previous is not None and sample.at.astimezone(UTC) <= previous.at.astimezone(
            UTC
        ):
            return transitions
        export_since = _parse_time(self.grid_export_since)
        if previous is not None and export_since is not None:
            for duration in (
                BATTERY_TO_GRID_DURATION_SECONDS,
                EXPORT_WITH_HEADROOM_DURATION_SECONDS,
            ):
                deadline = export_since.timestamp() + duration
                if previous.at.timestamp() < deadline < sample.at.timestamp():
                    transitions.extend(
                        self._evaluate_qualification(
                            previous, at=datetime.fromtimestamp(deadline, UTC)
                        )
                    )
        self._update_export_timer(sample)
        current = self.open_event

        candidate = _candidate(sample)
        if current is None:
            if candidate is not True:
                transitions.extend(self._evaluate_qualification(sample, at=sample.at))
                self.last_sample = sample.as_dict()
                return transitions
            current = _new_event(self.namespace, sample)
            self.open_event = current
            current["_state"]["grid_export_since"] = self.grid_export_since
        elif candidate is None:
            # Unknown values cannot prove the event ended.  They do break the
            # candidate observation, while export timer continuity was handled
            # independently above.
            state = current["_state"]
            state["pending_end_at"] = None
            state["pending_end_count"] = 0
            _append_sample(current, sample)
            _refresh_derived(current, through=sample.at)
            transitions.extend(self._evaluate_qualification(sample, at=sample.at))
            self.last_sample = sample.as_dict()
            return transitions
        elif candidate is False:
            state = current["_state"]
            if state.get("pending_end_at") is None:
                state["pending_end_at"] = _iso(sample.at)
                state["pending_end_count"] = 1
                _append_sample(current, sample)
                _refresh_derived(current, through=sample.at)
                transitions.extend(self._evaluate_qualification(sample, at=sample.at))
                self.last_sample = sample.as_dict()
                return transitions
            pending_end = _parse_time(state.get("pending_end_at"))
            if (
                pending_end is None
                or (sample.at.astimezone(UTC) - pending_end).total_seconds()
                > MAX_COMPLETE_INTERVAL_SECONDS
            ):
                state["pending_end_at"] = _iso(sample.at)
                state["pending_end_count"] = 1
                _append_sample(current, sample)
                _refresh_derived(current, through=sample.at)
                self.last_sample = sample.as_dict()
                return transitions
            state["pending_end_count"] = int(state.get("pending_end_count", 1)) + 1
            if state["pending_end_count"] < END_CONFIRMING_SAMPLES:
                self.last_sample = sample.as_dict()
                return transitions
            end_at = _parse_time(state.get("pending_end_at")) or sample.at
            current["end_at"] = _iso(end_at)
            current["status"] = "completed"
            current["operating_plan"]["end"] = current["samples"][-1]["operating_plan"]
            _refresh_derived(current, through=end_at)
            self.open_event = None
            if current.get("qualified_at") is not None:
                self.completed_events.append(current)
                transitions.append(
                    EventTransition("completed", public_event(current), sample)
                )
            self.last_sample = sample.as_dict()
            return transitions
        else:
            state = current["_state"]
            state["pending_end_at"] = None
            state["pending_end_count"] = 0
            _append_sample(current, sample)
        transitions.extend(self._evaluate_qualification(sample, at=sample.at))
        self.last_sample = sample.as_dict()
        return transitions

    def mark_recovered_after_restart(self) -> None:
        if self.open_event is not None:
            self.open_event.setdefault("reconstruction", {})[
                "recovered_after_restart"
            ] = True

    def import_completed(self, events: list[dict[str, Any]]) -> int:
        """Idempotently merge reconstructed completed alert events."""
        known = {
            event.get("event_id"): index
            for index, event in enumerate(self.completed_events)
        }
        if self.open_event is not None:
            known[self.open_event.get("event_id")] = -1
        added = 0
        for event in events:
            event_id = event.get("event_id")
            if not event_id or event.get("qualified_at") is None:
                continue
            if event_id in known:
                index = known[event_id]
                if index < 0:
                    continue
                existing = self.completed_events[index]
                if (
                    existing.get("source") == "reconstructed"
                    and event.get("source") == "reconstructed"
                    and int(event.get("schema_version", 0))
                    > int(existing.get("schema_version", 0))
                ):
                    self.completed_events[index] = event
                    added += 1
                continue
            self.completed_events.append(event)
            known[event_id] = len(self.completed_events) - 1
            added += 1
        self.completed_events.sort(key=lambda item: item.get("candidate_start") or "")
        return added


def select_event(
    events: list[dict[str, Any]], requested_id: str | None = None
) -> tuple[dict[str, Any] | None, str | None]:
    """Resolve an event ID with the dashboard's documented nonfatal fallback."""
    ordered = sorted(
        events,
        key=lambda event: (
            event.get("status") == "active",
            event.get("candidate_start") or "",
        ),
        reverse=True,
    )
    if requested_id and (
        selected := next(
            (event for event in ordered if event.get("event_id") == requested_id),
            None,
        )
    ):
        return selected, None
    if not ordered:
        return None, "No export alert events are available."
    if requested_id:
        return (
            ordered[0],
            f"Event '{requested_id}' was not found; showing newest event.",
        )
    return ordered[0], None


CSV_COLUMNS: Final = (
    "schema_version",
    "event_id",
    "status",
    "classification",
    "source",
    "candidate_start_local",
    "candidate_start_utc",
    "qualified_at_local",
    "qualified_at_utc",
    "end_at_local",
    "end_at_utc",
    "total_duration_seconds",
    "post_notification_duration_seconds",
    "exported_energy_kwh",
    "export_energy_method",
    "export_energy_quality",
    *(
        f"{prefix}_{field}"
        for prefix in (
            "soc_pct",
            "grid_export_power_w",
            "battery_charge_power_w",
            "battery_discharge_power_w",
            "production_power_w",
            "consumption_power_w",
        )
        for field in ("start", "end", "min", "max", "mean", "count")
    ),
    "operating_plan_start_json",
    "operating_plan_qualification_json",
    "operating_plan_end_json",
    "operating_plan_changes_json",
    "thresholds_json",
    "reconstruction_coverage_start_utc",
    "reconstruction_coverage_end_utc",
    "reconstruction_quality",
    "recovered_after_restart",
)


def _local_and_utc(value: str | None, timezone_name: str) -> tuple[str, str]:
    parsed = _parse_time(value)
    if parsed is None:
        return "", ""
    return parsed.astimezone(ZoneInfo(timezone_name)).isoformat(), parsed.isoformat()


def event_csv(events: list[dict[str, Any]], timezone_name: str) -> str:
    """Serialize the same event values exposed by WebSocket as stable CSV rows."""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for event in events:
        start_local, start_utc = _local_and_utc(
            event.get("candidate_start"), timezone_name
        )
        qualified_local, qualified_utc = _local_and_utc(
            event.get("qualified_at"), timezone_name
        )
        end_local, end_utc = _local_and_utc(event.get("end_at"), timezone_name)
        reconstruction = event.get("reconstruction", {})
        row: dict[str, Any] = {
            "schema_version": event.get("schema_version"),
            "event_id": event.get("event_id"),
            "status": event.get("status"),
            "classification": event.get("classification"),
            "source": event.get("source"),
            "candidate_start_local": start_local,
            "candidate_start_utc": start_utc,
            "qualified_at_local": qualified_local,
            "qualified_at_utc": qualified_utc,
            "end_at_local": end_local,
            "end_at_utc": end_utc,
            "total_duration_seconds": event.get("total_duration_seconds"),
            "post_notification_duration_seconds": event.get(
                "post_notification_duration_seconds"
            ),
            "exported_energy_kwh": event.get("exported_energy_kwh"),
            "export_energy_method": event.get("export_energy_method"),
            "export_energy_quality": event.get("export_energy_quality"),
            "operating_plan_start_json": json.dumps(
                event.get("operating_plan", {}).get("start"),
                separators=(",", ":"),
            ),
            "operating_plan_qualification_json": json.dumps(
                event.get("operating_plan", {}).get("qualification"),
                separators=(",", ":"),
            ),
            "operating_plan_end_json": json.dumps(
                event.get("operating_plan", {}).get("end"),
                separators=(",", ":"),
            ),
            "operating_plan_changes_json": json.dumps(
                event.get("operating_plan_changes", []),
                separators=(",", ":"),
            ),
            "thresholds_json": json.dumps(
                event.get("thresholds", {}), separators=(",", ":"), sort_keys=True
            ),
            "reconstruction_coverage_start_utc": reconstruction.get("coverage_start"),
            "reconstruction_coverage_end_utc": reconstruction.get("coverage_end"),
            "reconstruction_quality": reconstruction.get("quality"),
            "recovered_after_restart": reconstruction.get(
                "recovered_after_restart", False
            ),
        }
        statistics = event.get("statistics", {})
        for metric in STATISTIC_FIELDS:
            for field in ("start", "end", "min", "max", "mean", "count"):
                row[f"{metric}_{field}"] = statistics.get(metric, {}).get(field)
        writer.writerow(row)
    return output.getvalue()
