"""Typed Gosund discovery and switch control; no provider credentials or live devices."""
from __future__ import annotations

import asyncio
import contextlib
import unittest
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

from tests import test_safety  # noqa: F401 - configures the sanitized shared environment

from app import config
from app.server import (
    ALLOWED_SERVICES,
    TURNABLE_DOMAINS,
    _gosund_device_match,
    audit,
    claims_context,
    control_gosund_switch,
    get_gosund_device_status,
    list_gosund_devices,
    mcp,
)

OFFICE = "a" * 32
HEATER = "b" * 32
THERMOSTAT = "c" * 32
DEVICES = [
    {
        "id": OFFICE,
        "name": "Smart Plug",
        "name_by_user": "Office lamp plug",
        "manufacturer": "Tuya",
        "model": "Gosund WP3 (wp3abc)",
        "area_id": "office",
        "disabled_by": None,
    },
    {
        "id": HEATER,
        "name": "Smart Socket",
        "name_by_user": "Heater plug",
        "manufacturer": "Tuya",
        "model": "Smart Socket (sock01)",
        "area_id": "bedroom",
        "disabled_by": None,
    },
    {
        "id": THERMOSTAT,
        "name": "Hall thermostat",
        "name_by_user": None,
        "manufacturer": "Google",
        "model": "Nest",
        "area_id": "hall",
        "disabled_by": None,
    },
]
ENTITIES = [
    {"entity_id": "switch.office_lamp_plug", "device_id": OFFICE, "platform": "tuya", "disabled_by": None},
    {"entity_id": "switch.office_lamp_plug_usb", "device_id": OFFICE, "platform": "tuya", "disabled_by": "user"},
    {"entity_id": "sensor.office_lamp_plug_power", "device_id": OFFICE, "platform": "tuya", "disabled_by": None},
    {
        "entity_id": "sensor.office_lamp_plug_energy",
        "device_id": OFFICE,
        "platform": "tuya",
        "disabled_by": None,
        "original_device_class": "energy",
    },
    {"entity_id": "sensor.office_lamp_plug_signal", "device_id": OFFICE, "platform": "tuya", "disabled_by": None},
    {"entity_id": "light.office_lamp_plug_indicator", "device_id": OFFICE, "platform": "tuya", "disabled_by": None},
    {"entity_id": "switch.heater_plug", "device_id": HEATER, "platform": "localtuya", "disabled_by": None},
    {"entity_id": "climate.hall", "device_id": THERMOSTAT, "platform": "nest", "disabled_by": None},
    {"entity_id": "switch.hall_fan", "device_id": THERMOSTAT, "platform": "nest", "disabled_by": None},
]


def _states(office_state: str = "on") -> list[dict]:
    stamp = "2026-09-18T10:00:00+00:00"
    return [
        {
            "entity_id": "switch.office_lamp_plug",
            "state": office_state,
            "attributes": {"friendly_name": "Office lamp plug", "ip_address": "192.0.2.10"},
            "last_changed": stamp,
            "last_updated": stamp,
        },
        {
            "entity_id": "sensor.office_lamp_plug_power",
            "state": "12.5",
            "attributes": {"device_class": "power", "unit_of_measurement": "W"},
            "last_updated": stamp,
        },
        {
            "entity_id": "sensor.office_lamp_plug_energy",
            "state": "3.25",
            "attributes": {"unit_of_measurement": "kWh"},
            "last_updated": stamp,
        },
        {
            "entity_id": "sensor.office_lamp_plug_signal",
            "state": "-60",
            "attributes": {"device_class": "signal_strength", "unit_of_measurement": "dBm"},
        },
        {"entity_id": "light.office_lamp_plug_indicator", "state": "off", "attributes": {}},
        {"entity_id": "switch.heater_plug", "state": "unavailable", "attributes": {}},
        {"entity_id": "climate.hall", "state": "heat", "attributes": {}},
        {"entity_id": "switch.hall_fan", "state": "off", "attributes": {}},
    ]


@contextlib.contextmanager
def _registry(
    states: AsyncMock, device_ids: frozenset[str] = frozenset({HEATER})
) -> Iterator[None]:
    with (
        patch("app.server.ha.devices", new=AsyncMock(return_value=DEVICES)),
        patch("app.server.ha.entity_registry", new=AsyncMock(return_value=ENTITIES)),
        patch("app.server.ha.states", new=states),
        patch("app.server.GOSUND_DEVICE_IDS", device_ids),
    ):
        yield


class GosundConfigurationTests(unittest.TestCase):
    def test_marker_parsing_defaults_normalizes_and_bounds(self) -> None:
        self.assertEqual(config.parse_gosund_markers(None), ("gosund",))
        self.assertEqual(
            config.parse_gosund_markers(" Gosund, WP3 ,gosund,, "), ("gosund", "wp3")
        )
        with self.assertRaisesRegex(RuntimeError, "at least one"):
            config.parse_gosund_markers(" , ")
        with self.assertRaisesRegex(RuntimeError, "printable"):
            config.parse_gosund_markers("gosund,bad\tmarker")
        with self.assertRaisesRegex(RuntimeError, "at most"):
            config.parse_gosund_markers(",".join(f"m{index}" for index in range(21)))
        self.assertEqual(config.GOSUND_DEVICE_MARKERS, ("gosund",))
        self.assertEqual(config.GOSUND_DEVICE_IDS, frozenset())

    def test_device_id_parsing_requires_exact_registry_ids(self) -> None:
        self.assertEqual(config.parse_gosund_device_ids(None), frozenset())
        self.assertEqual(
            config.parse_gosund_device_ids(f" {OFFICE}, {HEATER} ,"),
            frozenset({OFFICE, HEATER}),
        )
        with self.assertRaisesRegex(RuntimeError, "exact 32-character"):
            config.parse_gosund_device_ids("switch.office_lamp_plug")
        with self.assertRaisesRegex(RuntimeError, "exact 32-character"):
            config.parse_gosund_device_ids(OFFICE.upper())
        with self.assertRaisesRegex(RuntimeError, "at most"):
            config.parse_gosund_device_ids(
                ",".join(f"{index:032x}" for index in range(51))
            )


class GosundDiscoveryTests(unittest.TestCase):
    def test_registry_match_uses_markers_and_configured_ids_case_insensitively(
        self,
    ) -> None:
        with patch("app.server.GOSUND_DEVICE_IDS", frozenset({HEATER})):
            self.assertEqual(_gosund_device_match(DEVICES[0]), "model")
            self.assertEqual(_gosund_device_match(DEVICES[1]), "configured_device_id")
            self.assertIsNone(_gosund_device_match(DEVICES[2]))
            self.assertEqual(
                _gosund_device_match({"id": "x", "manufacturer": "GOSUND"}),
                "manufacturer",
            )
            self.assertEqual(
                _gosund_device_match({"id": "x", "name_by_user": "gosund heater"}),
                "name_by_user",
            )
            self.assertIsNone(_gosund_device_match({"id": "x", "identifiers": [["tuya", "gosund"]]}))
        with patch("app.server.GOSUND_DEVICE_IDS", frozenset()):
            self.assertIsNone(_gosund_device_match(DEVICES[1]))

    def test_listing_reports_enabled_switches_readings_and_skips_other_devices(
        self,
    ) -> None:
        with _registry(AsyncMock(return_value=_states())):
            result = asyncio.run(list_gosund_devices())
        self.assertEqual(result["count"], 2)
        self.assertFalse(result["truncated"])
        self.assertEqual(result["markers"], ["gosund"])
        self.assertEqual(result["configured_device_count"], 1)
        office, heater = result["devices"]
        self.assertEqual(office["id"], OFFICE)
        self.assertEqual(office["name"], "Office lamp plug")
        self.assertEqual(office["match"], "model")
        self.assertEqual(office["integrations"], ["tuya"])
        self.assertEqual(
            [item["entity_id"] for item in office["switches"]],
            ["switch.office_lamp_plug"],
        )
        self.assertEqual(office["switches"][0]["attributes"]["ip_address"], "[REDACTED]")
        self.assertEqual(
            [item["entity_id"] for item in office["lights"]],
            ["light.office_lamp_plug_indicator"],
        )
        self.assertEqual(set(office["readings"]), {"power", "energy"})
        self.assertEqual(office["readings"]["power"]["value"], 12.5)
        self.assertEqual(office["readings"]["power"]["unit"], "W")
        self.assertEqual(office["readings"]["energy"]["value"], 3.25)
        self.assertEqual(office["other_entity_count"], 1)
        self.assertEqual(heater["match"], "configured_device_id")
        self.assertEqual(heater["integrations"], ["localtuya"])
        self.assertEqual(heater["switches"][0]["state"], "unavailable")
        self.assertEqual(heater["readings"], {})
        self.assertNotIn(THERMOSTAT, {item["id"] for item in result["devices"]})

    def test_listing_filters_by_area_and_truncates(self) -> None:
        with _registry(AsyncMock(return_value=_states())):
            by_area = asyncio.run(list_gosund_devices(area_id="bedroom"))
            limited = asyncio.run(list_gosund_devices(limit=1))
            nothing = asyncio.run(list_gosund_devices(area_id="garage"))
        self.assertEqual([item["id"] for item in by_area["devices"]], [HEATER])
        self.assertEqual(limited["count"], 1)
        self.assertTrue(limited["truncated"])
        self.assertEqual(nothing["count"], 0)
        self.assertFalse(nothing["truncated"])

    def test_status_resolves_registry_id_unique_name_and_member_entity(self) -> None:
        with _registry(AsyncMock(return_value=_states())):
            by_id = asyncio.run(get_gosund_device_status(OFFICE))
            by_name = asyncio.run(get_gosund_device_status("heater PLUG"))
            by_entity = asyncio.run(
                get_gosund_device_status("sensor.office_lamp_plug_power")
            )
            with self.assertRaisesRegex(ValueError, "does not belong"):
                asyncio.run(get_gosund_device_status("switch.hall_fan"))
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                asyncio.run(get_gosund_device_status("Hall thermostat"))
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                asyncio.run(get_gosund_device_status(THERMOSTAT))
        self.assertEqual(by_id["device"]["id"], OFFICE)
        self.assertEqual(by_name["device"]["id"], HEATER)
        self.assertEqual(by_entity["device"]["id"], OFFICE)

    def test_unreadable_reading_values_become_null(self) -> None:
        states = _states()
        for state in states:
            if state["entity_id"] == "sensor.office_lamp_plug_power":
                state["state"] = "unavailable"
            if state["entity_id"] == "sensor.office_lamp_plug_energy":
                state["state"] = "nan"
        with _registry(AsyncMock(return_value=states)):
            result = asyncio.run(get_gosund_device_status(OFFICE))
        readings = result["device"]["readings"]
        self.assertIsNone(readings["power"]["value"])
        self.assertEqual(readings["power"]["state"], "unavailable")
        self.assertIsNone(readings["energy"]["value"])


class GosundControlTests(unittest.TestCase):
    def test_control_requires_write_scope(self) -> None:
        token = claims_context.set({"scope": "mcp:read"})
        try:
            with (
                _registry(AsyncMock(return_value=_states())),
                patch("app.server.ha.call_service", new=AsyncMock()) as call,
            ):
                with self.assertRaises(PermissionError):
                    asyncio.run(
                        control_gosund_switch("switch.office_lamp_plug", "turn_off")
                    )
            call.assert_not_awaited()
        finally:
            claims_context.reset(token)

    def test_control_fails_closed_outside_configured_gosund_devices(self) -> None:
        token = claims_context.set({"scope": "mcp:read mcp:write"})
        try:
            with (
                _registry(AsyncMock(return_value=_states())),
                patch("app.server.ha.call_service", new=AsyncMock()) as call,
            ):
                with self.assertRaisesRegex(PermissionError, "not an enabled entity"):
                    asyncio.run(control_gosund_switch("switch.hall_fan", "turn_off"))
                with self.assertRaisesRegex(PermissionError, "not an enabled entity"):
                    asyncio.run(
                        control_gosund_switch("switch.office_lamp_plug_usb", "turn_on")
                    )
                with self.assertRaisesRegex(ValueError, "must be a switch entity"):
                    asyncio.run(
                        control_gosund_switch(
                            "light.office_lamp_plug_indicator", "turn_on"
                        )
                    )
                with self.assertRaises(ValueError):
                    asyncio.run(control_gosund_switch("switch.Bad Entity", "turn_on"))
            with (
                _registry(AsyncMock(return_value=_states()), frozenset()),
                patch("app.server.ha.call_service", new=AsyncMock()) as unconfigured,
            ):
                with self.assertRaisesRegex(PermissionError, "not an enabled entity"):
                    asyncio.run(control_gosund_switch("switch.heater_plug", "turn_on"))
            call.assert_not_awaited()
            unconfigured.assert_not_awaited()
        finally:
            claims_context.reset(token)

    def test_control_calls_exact_switch_service_and_reads_back(self) -> None:
        token = claims_context.set(
            {"scope": "mcp:read mcp:write", "sub": "owner", "client_id": "test"}
        )
        try:
            call = AsyncMock(return_value=[])
            with (
                _registry(AsyncMock(side_effect=[_states("on"), _states("off")])),
                patch("app.server.ha.call_service", new=call),
                patch(
                    "app.server.ha.state",
                    new=AsyncMock(side_effect=AssertionError("bulk readback expected")),
                ),
                patch("app.server.asyncio.sleep", new=AsyncMock()),
            ):
                result = asyncio.run(
                    control_gosund_switch("switch.office_lamp_plug", "turn_off")
                )
            call.assert_awaited_once_with(
                "switch", "turn_off", {"entity_id": "switch.office_lamp_plug"}
            )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["action"], "turn_off")
            self.assertEqual(result["expected_state"], "off")
            self.assertTrue(result["confirmed"])
            self.assertEqual(result["state"]["state"], "off")
            self.assertEqual(result["state"]["attributes"]["ip_address"], "[REDACTED]")
            self.assertEqual(result["device"]["id"], OFFICE)
            self.assertEqual(result["device"]["readings"]["power"]["value"], 12.5)
            latest = audit.latest_tool_call({"control_gosund_switch"})
            self.assertEqual(latest["entity_id"], "switch.office_lamp_plug")
            self.assertEqual(latest["action"], "turn_off")
            self.assertEqual(latest["device_id"], OFFICE)
            self.assertTrue(latest["confirmed"])
            self.assertNotIn("readings", latest)
        finally:
            claims_context.reset(token)

    def test_control_reports_unconfirmed_readback_without_retrying(self) -> None:
        token = claims_context.set({"scope": "mcp:read mcp:write"})
        try:
            call = AsyncMock(return_value=[])
            with (
                _registry(AsyncMock(side_effect=[_states("off"), _states("off")])),
                patch("app.server.ha.call_service", new=call),
                patch("app.server.asyncio.sleep", new=AsyncMock()),
            ):
                result = asyncio.run(
                    control_gosund_switch("switch.office_lamp_plug", "turn_on")
                )
            call.assert_awaited_once()
            self.assertEqual(result["expected_state"], "on")
            self.assertFalse(result["confirmed"])
            self.assertEqual(result["state"]["state"], "off")
        finally:
            claims_context.reset(token)


class GosundRegistryTests(unittest.TestCase):
    def test_tools_are_advertised_with_bounded_schemas_and_safe_annotations(
        self,
    ) -> None:
        tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
        for name in ("list_gosund_devices", "get_gosund_device_status"):
            with self.subTest(tool=name):
                self.assertTrue(tools[name].annotations.read_only_hint)
                self.assertFalse(tools[name].annotations.open_world_hint)
        control = tools["control_gosund_switch"]
        self.assertFalse(control.annotations.read_only_hint)
        self.assertFalse(control.annotations.destructive_hint)
        self.assertTrue(control.annotations.idempotent_hint)
        self.assertFalse(control.annotations.open_world_hint)
        properties = control.input_schema["properties"]
        self.assertEqual(properties["action"]["enum"], ["turn_on", "turn_off"])
        self.assertEqual(set(control.input_schema["required"]), {"entity_id", "action"})
        listing = tools["list_gosund_devices"].input_schema["properties"]
        self.assertEqual(listing["limit"]["maximum"], 200)
        self.assertEqual(listing["limit"]["default"], 100)

    def test_generic_switch_routing_is_unchanged(self) -> None:
        self.assertEqual(ALLOWED_SERVICES["switch"], {"turn_on", "turn_off", "toggle"})
        self.assertIn("switch", TURNABLE_DOMAINS)
        for domain in ("gosund", "tuya", "localtuya", "tuya_local", "tasmota"):
            self.assertNotIn(domain, ALLOWED_SERVICES)

    def test_listing_result_crosses_the_redaction_boundary(self) -> None:
        with _registry(AsyncMock(return_value=_states())):
            result = asyncio.run(mcp.call_tool("list_gosund_devices", {"limit": 5}))
        rendered = " ".join(getattr(item, "text", "") for item in result.content)
        self.assertNotIn("192.0.2.10", rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertIn("switch.office_lamp_plug", rendered)


if __name__ == "__main__":
    unittest.main()
