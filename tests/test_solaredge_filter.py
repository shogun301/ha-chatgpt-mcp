"""Tests for atomic SolarEdge bridge snapshot debouncing."""

from __future__ import annotations

import unittest
from pathlib import Path

from app.solaredge_filter import POWER_KEYS, SolarEdgeSnapshotFilter


def snapshot(
    observed_at: str,
    production: float,
    *,
    consumption: float = 2_600.0,
    grid_import: float = 0.0,
    battery_charge: float = 0.0,
    production_energy: float = 42_000.0,
) -> dict:
    site = {
        "production_power_w": production,
        "consumption_power_w": consumption,
        "grid_import_power_w": grid_import,
        "grid_export_power_w": 0.0,
        "battery_charge_power_w": battery_charge,
        "battery_discharge_power_w": 0.0,
        "production_energy_kwh": production_energy,
        "battery_state_of_energy_pct": 92.0,
    }
    return {
        "connected": True,
        "provider": "solaredge_monitoring_portal",
        "observed_at": observed_at,
        "site": site,
        "completeness": {key: True for key in site},
    }


class SolarEdgeSnapshotFilterTests(unittest.TestCase):
    def test_internal_bridge_serializes_filter_state_transitions(self) -> None:
        source = (Path(__file__).parents[1] / "app" / "server.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("async with _solaredge_snapshot_filter_lock:", source)
        self.assertIn("_solaredge_snapshot_filter.apply(snapshot)", source)

    def test_isolated_near_zero_snapshot_omits_power_atomically(self) -> None:
        filter_ = SolarEdgeSnapshotFilter()
        strong = snapshot(
            "2026-08-26T13:58:17-07:00",
            9_290.0,
            consumption=2_840.0,
            battery_charge=6_450.0,
            production_energy=42_039.0,
        )
        artifact = snapshot(
            "2026-08-26T14:03:22-07:00",
            0.0,
            grid_import=2_600.0,
            production_energy=42_043.096,
        )
        recovery = snapshot(
            "2026-08-26T14:08:23-07:00",
            9_310.0,
            consumption=1_450.0,
            grid_import=1_210.0,
            battery_charge=9_070.0,
            production_energy=42_043.096,
        )

        accepted, action = filter_.apply(strong)
        self.assertEqual(accepted, strong)
        self.assertEqual(action, "accepted")

        accepted, action = filter_.apply(artifact)
        self.assertTrue(POWER_KEYS.isdisjoint(accepted["site"]))
        self.assertTrue(
            all(accepted["completeness"][key] is False for key in POWER_KEYS)
        )
        self.assertEqual(accepted["site"]["production_energy_kwh"], 42_043.096)
        self.assertEqual(accepted["site"]["battery_state_of_energy_pct"], 92.0)
        self.assertEqual(action, "suppressed_first_near_zero")

        accepted, action = filter_.apply(recovery)
        self.assertEqual(accepted, recovery)
        self.assertEqual(action, "recovered_after_suppression")

    def test_distinct_second_near_zero_snapshot_confirms_real_outage(self) -> None:
        filter_ = SolarEdgeSnapshotFilter()
        strong = snapshot("2026-08-26T13:58:17-07:00", 9_290.0)
        first_low = snapshot(
            "2026-08-26T14:03:22-07:00", 3.0, grid_import=2_597.0
        )
        second_low = snapshot(
            "2026-08-26T14:08:23-07:00", 0.0, grid_import=2_600.0
        )

        filter_.apply(strong)
        accepted, action = filter_.apply(first_low)
        self.assertTrue(POWER_KEYS.isdisjoint(accepted["site"]))
        self.assertEqual(action, "suppressed_first_near_zero")

        accepted, action = filter_.apply(second_low)
        self.assertEqual(accepted, second_low)
        self.assertEqual(action, "confirmed_near_zero")

    def test_duplicate_and_out_of_order_low_do_not_confirm_outage(self) -> None:
        filter_ = SolarEdgeSnapshotFilter()
        strong = snapshot("2026-08-26T13:58:17-07:00", 9_290.0)
        cached_low = snapshot(
            "2026-08-26T14:03:22-07:00", 0.0, grid_import=2_600.0
        )
        older_low = snapshot(
            "2026-08-26T14:02:00-07:00", 0.0, grid_import=2_600.0
        )

        filter_.apply(strong)
        filter_.apply(cached_low)
        for candidate in (cached_low, older_low):
            accepted, action = filter_.apply(candidate)
            self.assertTrue(POWER_KEYS.isdisjoint(accepted["site"]))
            self.assertEqual(action, "suppressed_repeated_snapshot")

    def test_startup_low_nonzero_cloud_and_stale_drop_are_not_filtered(self) -> None:
        startup_filter = SolarEdgeSnapshotFilter()
        startup_low = snapshot("2026-08-26T06:00:00-07:00", 0.0)
        accepted, action = startup_filter.apply(startup_low)
        self.assertEqual(accepted, startup_low)
        self.assertEqual(action, "accepted")

        filter_ = SolarEdgeSnapshotFilter()
        filter_.apply(snapshot("2026-08-26T13:58:17-07:00", 9_290.0))
        cloudy = snapshot("2026-08-26T14:03:22-07:00", 350.0)
        accepted, action = filter_.apply(cloudy)
        self.assertEqual(accepted, cloudy)
        self.assertEqual(action, "accepted")

        stale_filter = SolarEdgeSnapshotFilter()
        stale_filter.apply(snapshot("2026-08-26T13:00:00-07:00", 9_290.0))
        stale_drop = snapshot("2026-08-26T14:00:00-07:00", 0.0)
        accepted, action = stale_filter.apply(stale_drop)
        self.assertEqual(accepted, stale_drop)
        self.assertEqual(action, "accepted")

    def test_incomplete_production_is_not_hidden(self) -> None:
        filter_ = SolarEdgeSnapshotFilter()
        filter_.apply(snapshot("2026-08-26T13:58:17-07:00", 9_290.0))
        incomplete = snapshot("2026-08-26T14:03:22-07:00", 0.0)
        incomplete["completeness"]["production_power_w"] = False

        accepted, action = filter_.apply(incomplete)

        self.assertEqual(accepted, incomplete)
        self.assertEqual(action, "accepted")


if __name__ == "__main__":
    unittest.main()
