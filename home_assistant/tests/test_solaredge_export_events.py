"""Regression tests for the durable SolarEdge export event model."""

from __future__ import annotations

import csv
import importlib.util
import io
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

MODULE_PATH = (
    Path(__file__).parents[1]
    / "custom_components"
    / "solaredge_one_bridge"
    / "export_events.py"
)
SPEC = importlib.util.spec_from_file_location("solaredge_export_events", MODULE_PATH)
assert SPEC and SPEC.loader
events = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = events
SPEC.loader.exec_module(events)


def _sample(
    at: datetime,
    *,
    export_w: float | None = 1_000,
    # Below every state-of-charge threshold, including the 95% export-with-headroom bound.
    soc_pct: float | None = 94,
    charge_w: float | None = 0,
    discharge_w: float | None = 300,
    export_kwh: float | None = None,
) -> events.ExportSample:
    return events.ExportSample(
        at=at,
        grid_export_power_w=export_w,
        grid_export_energy_kwh=export_kwh,
        soc_pct=soc_pct,
        battery_charge_power_w=charge_w,
        battery_discharge_power_w=discharge_w,
        production_power_w=4_000,
        consumption_power_w=3_000,
        operating_plan=events.OperatingPlanSnapshot(
            state="Time of Use",
            active=True,
            block_count=4,
            provider="monitoring_api_v1",
        ),
    )


def test_event_qualifies_each_deadline_once_and_completes_after_two_samples() -> None:
    start = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
    engine = events.ExportEventEngine("test-site")

    assert engine.process(_sample(start, export_kwh=100.0)) == []

    five_minute = engine.process(
        _sample(start + timedelta(minutes=5), export_kwh=100.083)
    )
    assert [transition.kind for transition in five_minute] == ["qualified"]
    assert five_minute[0].event["classification"] == events.BATTERY_TO_GRID

    ten_minute = engine.process(
        _sample(start + timedelta(minutes=10), export_kwh=100.166)
    )
    assert [transition.kind for transition in ten_minute] == ["qualified"]
    assert ten_minute[0].event["classification"] == events.CLASSIFICATION_BOTH
    assert engine.process(_sample(start + timedelta(minutes=11))) == []

    assert engine.process(
        _sample(start + timedelta(minutes=15), export_w=0, export_kwh=100.166)
    ) == []
    completed = engine.process(
        _sample(start + timedelta(minutes=20), export_w=0, export_kwh=100.166)
    )

    assert [transition.kind for transition in completed] == ["completed"]
    result = completed[0].event
    assert result["status"] == "completed"
    assert result["classification"] == events.CLASSIFICATION_BOTH
    assert result["end_at"] == (start + timedelta(minutes=15)).isoformat()
    assert engine.open_event is None
    assert len(engine.completed_events) == 1


def test_unknown_values_do_not_end_an_open_event_or_invent_qualification() -> None:
    start = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
    engine = events.ExportEventEngine("test-site")
    engine.process(_sample(start))

    assert engine.process(
        _sample(start + timedelta(minutes=5), soc_pct=None)
    ) == []
    assert engine.open_event is not None
    assert engine.open_event["status"] == "active"
    assert engine.open_event["qualified_at"] is None


def test_public_event_csv_and_selection_share_the_same_stable_values() -> None:
    start = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
    engine = events.ExportEventEngine("test-site")
    engine.process(_sample(start))
    qualified = engine.process(_sample(start + timedelta(minutes=5)))[0].event

    selected, message = events.select_event([qualified], "missing-id")
    assert selected == qualified
    assert message == "Event 'missing-id' was not found; showing newest event."

    text = events.event_csv([qualified], "UTC")
    row = next(csv.DictReader(io.StringIO(text)))
    assert row["event_id"] == qualified["event_id"]
    assert row["classification"] == events.BATTERY_TO_GRID
    assert row["qualified_at_utc"] == qualified["qualified_at"]
    assert row["qualified_at_local"].endswith("+00:00")


def test_completed_event_import_is_idempotent() -> None:
    event = {
        "schema_version": events.EVENT_SCHEMA_VERSION,
        "event_id": "se-example",
        "status": "completed",
        "candidate_start": "2026-09-02T12:00:00+00:00",
        "qualified_at": "2026-09-02T12:05:00+00:00",
        "source": "reconstructed",
    }
    engine = events.ExportEventEngine("test-site")

    assert engine.import_completed([event]) == 1
    assert engine.import_completed([event]) == 0
    assert engine.completed_events == [event]
