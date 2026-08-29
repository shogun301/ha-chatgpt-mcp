from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_temporary_root = tempfile.TemporaryDirectory()
_root = Path(_temporary_root.name)
for _name, _value in {
    "ha_token": "test-home-assistant-token",
    "oauth_password_hash": "$argon2id$v=19$m=65536,t=3,p=4$dGVzdA$dGVzdA",
    "jwt_secret": "test-jwt-secret-that-is-long-enough-for-unit-tests",
    "origin_shared_secret": "test-origin-shared-secret",
}.items():
    (_root / _name).write_text(_value, encoding="utf-8")

os.environ.update(
    {
        "PUBLIC_BASE_URL": "https://example.invalid",
        "FRONTEND_PUBLIC_URL": "https://ha.example.invalid",
        "HA_BASE_URL": "http://127.0.0.1:8123",
        "HA_TOKEN_FILE": str(_root / "ha_token"),
        "OAUTH_PASSWORD_HASH_FILE": str(_root / "oauth_password_hash"),
        "JWT_SECRET_FILE": str(_root / "jwt_secret"),
        "ORIGIN_SHARED_SECRET_FILE": str(_root / "origin_shared_secret"),
        "DATABASE_PATH": str(_root / "oauth.sqlite3"),
        "AUDIT_LOG_PATH": str(_root / "audit.jsonl"),
        "HA_CONFIG_PATH": str(_root / "ha-config"),
        "BACKUP_PATH": str(_root / "backups"),
        "HOST_DIAGNOSTICS_PATH": str(_root / "host-diagnostics"),
    }
)
(_root / "ha-config").mkdir()
(_root / "backups").mkdir()
(_root / "host-diagnostics").mkdir()

from app import config
from app.audit import AuditLog
from app.ha_client import (
    HomeAssistantClient,
    parse_rfc3339,
    redact_sensitive,
    summarize_state,
    validate_automation_id,
    validate_entity_id,
)
from app.oauth import OAuthServer
from app.server import (
    DEFAULT_TEMPERATURE_PRESETS,
    SERVER_VERSION,
    ThermostatScheduleEntry,
    _build_solaredge_bridge_snapshot,
    _build_thermostat_schedule,
    _build_sprinkler_telemetry,
    _clock_seconds,
    _entity_ids,
    _replace_schedule_preset,
    _require_confirmed,
    _require_diagnostics,
    _validate_automation_config,
    _validate_dashboard_config,
    _validate_media_content_id,
    call_service,
    claims_context,
    clean_vacuum_rooms,
    create_automation,
    create_calendar_event,
    get_calendar_events,
    get_home_overview,
    get_schedule,
    get_solar_power_flow,
    get_solar_storage_summary,
    get_solar_summary,
    get_sprinkler_summary,
    list_vacuum_rooms,
    mcp,
    refresh_sprinkler,
    run_sprinkler_zone,
    search_media,
    send_mobile_notification,
    set_nest_fan_timer,
    set_time_value,
    update_automation,
)


class CloudToolSurfaceTests(unittest.TestCase):
    def test_server_advertises_expanded_typed_surface(self) -> None:
        tools = asyncio.run(mcp.list_tools())
        names = {tool.name for tool in tools}
        self.assertEqual(mcp.version, "2.7.3")
        self.assertEqual(len(names), 107)
        self.assertTrue(
            {
                "get_home_overview",
                "get_thermostat_schedule",
                "update_thermostat_schedule",
                "update_temperature_preset",
                "control_light",
                "control_media_player",
                "control_vacuum",
                "control_cover",
                "control_lock",
                "send_mobile_notification",
                "get_weather_forecast",
                "get_long_term_statistics",
                "get_solar_summary",
                "compare_solar_modules",
                "get_solaredge_connection_status",
                "begin_solaredge_authorization",
                "get_solaredge_site_overview",
                "get_solaredge_energy_history",
                "get_solaredge_power_history",
                "get_solaredge_device_telemetry",
                "get_solaredge_site_alerts",
                "get_solar_power_flow",
                "get_solar_energy_breakdown",
                "get_solar_storage_summary",
                "get_system_health",
                "create_home_assistant_backup",
                "clean_vacuum_rooms",
                "set_nest_fan_timer",
                "speak_text",
                "browse_media",
                "run_sprinkler_zone",
                "trigger_automation",
                "list_dashboards",
                "update_dashboard",
                "get_host_runtime_health",
                "get_restart_outage_diagnostics",
                "list_diagnostic_events",
                "get_fixed_route_health",
                "get_lan_gateway_status",
                "list_lan_nodes",
                "probe_lan_node",
                "get_capability_sync_status",
                "list_sprinkler_zones",
                "get_sprinkler_configuration",
                "get_sprinkler_history",
                "refresh_sprinkler",
                "run_sprinkler_sequence",
                "get_sprinkler_capabilities",
                "get_sprinkler_command_status",
                "list_sprinkler_schedules",
                "get_sprinkler_upcoming_runs",
                "get_sprinkler_weather_and_decisions",
                "get_sprinkler_controller_diagnostics",
                "run_sprinkler_zone_exact",
                "run_sprinkler_sequence_exact",
                "get_calendar_events",
                "create_calendar_event",
                "get_schedule",
                "set_time_value",
            }.issubset(names)
        )

    def test_home_overview_exposes_service_version(self) -> None:
        with (
            patch(
                "app.server.ha.config",
                new=AsyncMock(
                    return_value={
                        "version": "2026.8.2",
                        "time_zone": "America/Los_Angeles",
                        "unit_system": {"temperature": "°F"},
                    }
                ),
            ),
            patch(
                "app.server.ha.states",
                new=AsyncMock(return_value=[{"entity_id": "light.test"}]),
            ),
            patch(
                "app.server.ha.integrations",
                new=AsyncMock(return_value=[{"state": "loaded"}]),
            ),
        ):
            result = asyncio.run(get_home_overview())
        self.assertEqual(result["service_version"], SERVER_VERSION)
        self.assertEqual(result["version"], "2026.8.2")


class SolarEdgeBridgeSnapshotTests(unittest.TestCase):
    def test_snapshot_maps_directional_power_and_lifetime_energy(self) -> None:
        portal = MagicMock()
        portal.live_power_flow = AsyncMock(
            return_value={
                "components": {
                    "solar_production": {"current_power_w": 7900.0},
                    "consumption": {"current_power_w": 4900.0},
                    "grid": {"current_power_w": 3000.0, "status": "EXPORT"},
                    "dc_storage": {
                        "current_power_w": 500.0,
                        "status": "DISCHARGING",
                        "chargeLevel": 82.0,
                    },
                },
                "last_update_time": "2026-08-23T16:00:00-07:00",
                "storage_operating_plan": {
                    "plan": "MAX_SELF_CONSUMPTION",
                    "is_active": True,
                    "block_count": 4,
                },
            }
        )
        lifetime = {
            "totals_kwh": {
                "production": 41869.308,
                "consumption": 50211.336,
                "import": 20046.732,
                "export": 13652.317,
            },
            "production_distribution": {"production_to_battery_kwh": 6679.9085},
            "consumption_distribution": {"consumption_from_battery_kwh": 7135.215},
        }
        with (
            patch("app.server.solaredge_portal", portal),
            patch(
                "app.server._solaredge_lifetime_energy",
                new=AsyncMock(return_value=lifetime),
            ),
        ):
            result = asyncio.run(_build_solaredge_bridge_snapshot())

        self.assertTrue(result["connected"])
        self.assertEqual(result["site"]["production_power_w"], 7900.0)
        self.assertEqual(result["site"]["grid_import_power_w"], 0.0)
        self.assertEqual(result["site"]["grid_export_power_w"], 3000.0)
        self.assertEqual(result["site"]["battery_charge_power_w"], 0.0)
        self.assertEqual(result["site"]["battery_discharge_power_w"], 500.0)
        self.assertEqual(result["site"]["battery_state_of_energy_pct"], 82.0)
        self.assertEqual(
            result["site"]["storage_operating_plan"], "MAX_SELF_CONSUMPTION"
        )
        self.assertIs(result["site"]["storage_operating_plan_active"], True)
        self.assertEqual(result["site"]["storage_operating_plan_block_count"], 4)
        self.assertEqual(result["site"]["grid_import_energy_kwh"], 20046.732)
        self.assertEqual(result["site"]["battery_charge_energy_kwh"], 6679.9085)
        self.assertTrue(all(result["completeness"].values()))


class SolarEdgeFocusedReadTests(unittest.TestCase):
    def test_power_flow_exposes_only_normalized_storage_plan_summary(self) -> None:
        portal = MagicMock()
        portal.capabilities = AsyncMock(return_value={"has_storage": True})
        portal.live_power_flow = AsyncMock(
            return_value={
                "components": {"solar_production": {"current_power_w": 1000.0}},
                "last_update_time": "2026-08-23T16:00:00-07:00",
                "storage_operating_plan": {
                    "plan": "MAX_SELF_CONSUMPTION",
                    "is_active": True,
                    "block_count": 4,
                },
            }
        )

        with patch("app.server.solaredge_portal", portal):
            result = asyncio.run(get_solar_power_flow())

        self.assertEqual(
            result["power_flow"]["storage_operating_plan"],
            {
                "plan": "MAX_SELF_CONSUMPTION",
                "is_active": True,
                "block_count": 4,
            },
        )

    def test_storage_summary_includes_current_storage_plan(self) -> None:
        portal = MagicMock()
        portal.completed_energy_summary = AsyncMock(
            return_value={
                "start_date": "2026-08-16",
                "end_date": "2026-08-22",
                "production_distribution": {},
                "consumption_distribution": {},
            }
        )
        portal.live_power_flow = AsyncMock(
            return_value={
                "components": {"dc_storage": {"chargeLevel": 82.0}},
                "storage_operating_plan": {
                    "plan": "MAX_SELF_CONSUMPTION",
                    "is_active": True,
                    "block_count": 4,
                },
            }
        )
        portal.storage_distribution = AsyncMock(return_value={"distribution": {}})

        with (
            patch("app.server.solaredge_portal", portal),
            patch(
                "app.server._solaredge_lifetime_energy",
                new=AsyncMock(return_value={}),
            ),
        ):
            result = asyncio.run(get_solar_storage_summary(days=7))

        self.assertEqual(
            result["storage_operating_plan"],
            {
                "plan": "MAX_SELF_CONSUMPTION",
                "is_active": True,
                "block_count": 4,
            },
        )


class SprinklerTelemetryTests(unittest.TestCase):
    @staticmethod
    def states(
        *,
        zone_1_time: str = "unknown",
        stop_time: str = "unknown",
        duration: str = "1",
    ) -> dict[str, dict]:
        values = {"button.sprinkler_controller_stop_all_zones": stop_time}
        for zone in range(1, config.SPRINKLER_ZONE_COUNT + 1):
            values[f"number.sprinkler_controller_zone_{zone}"] = (
                duration if zone == 1 else "24.55"
            )
            values[f"button.sprinkler_controller_zone_{zone}"] = (
                zone_1_time if zone == 1 else "unknown"
            )
        return {
            entity_id: {"entity_id": entity_id, "state": state, "attributes": {}}
            for entity_id, state in values.items()
        }

    def test_latest_stop_is_reported_as_inferred_not_physical(self) -> None:
        telemetry = _build_sprinkler_telemetry(
            self.states(
                zone_1_time="2026-08-23T05:19:07+00:00",
                stop_time="2026-08-23T05:19:08+00:00",
            )
        )["telemetry"]
        self.assertEqual(telemetry["last_observed_command"]["action"], "stop_all")
        self.assertEqual(telemetry["running_state"]["value"], "inferred_stopped")
        self.assertFalse(telemetry["physical_state_verified"])
        self.assertFalse(telemetry["live_running_state_available"])

    def test_matching_mcp_run_uses_exact_duration_for_estimate(self) -> None:
        telemetry = _build_sprinkler_telemetry(
            self.states(zone_1_time="2026-08-23T05:19:07+00:00", duration="24.55"),
            now=parse_rfc3339("2026-08-23T05:19:37+00:00", "now"),
            last_mcp_entry={
                "event": "tool_call",
                "tool": "run_sprinkler_zone",
                "timestamp": "2026-08-23T05:19:08+00:00",
                "zone": 1,
                "duration_minutes": 1,
            },
        )["telemetry"]
        self.assertEqual(telemetry["running_state"]["value"], "possibly_running")
        self.assertTrue(telemetry["running_state"]["estimated_running"])
        self.assertEqual(
            telemetry["last_observed_command"]["duration_source"],
            "matching_mcp_audit_command",
        )
        self.assertEqual(telemetry["last_observed_command"]["duration_minutes"], 1)
        self.assertEqual(telemetry["seconds_remaining_estimate"], 30)

    def test_summary_includes_best_available_telemetry(self) -> None:
        states = {
            "sensor.sprinkler_controller_watering_status": {
                "entity_id": "sensor.sprinkler_controller_watering_status",
                "state": "idle",
                "attributes": {
                    "source": "wyze_cloud_schedule_and_zone_state",
                    "observed_at": "2026-08-27T06:22:45+00:00",
                    "partial_update": False,
                    "endpoint_errors": [],
                    "physical_state_verified": False,
                },
            },
            "sensor.sprinkler_controller_active_zone": {
                "entity_id": "sensor.sprinkler_controller_active_zone",
                "state": "unknown",
                "attributes": {},
            },
            "sensor.sprinkler_controller_watering_time_remaining": {
                "entity_id": "sensor.sprinkler_controller_watering_time_remaining",
                "state": "unknown",
                "attributes": {},
            },
            "sensor.sprinkler_controller_last_watering": {
                "entity_id": "sensor.sprinkler_controller_last_watering",
                "state": "2026-08-26T13:00:00+00:00",
                "attributes": {"recent_runs": []},
            },
        }
        for zone in range(1, config.SPRINKLER_ZONE_COUNT + 1):
            states[f"sensor.sprinkler_controller_zone_{zone}_metadata"] = {
                "entity_id": f"sensor.sprinkler_controller_zone_{zone}_metadata",
                "state": "enabled",
                "attributes": {
                    "zone_number": zone,
                    "name": f"Zone {zone}",
                    "enabled": True,
                },
            }
            states[f"number.sprinkler_controller_zone_{zone}"] = {
                "entity_id": f"number.sprinkler_controller_zone_{zone}",
                "state": "15",
                "attributes": {},
            }

        async def state(entity_id: str) -> dict:
            return states[entity_id]

        with (
            patch("app.server.ha.state", new=state),
        ):
            result = asyncio.run(get_sprinkler_summary())
        self.assertEqual(result["controller"]["state"], "idle")
        self.assertTrue(result["telemetry"]["live_running_state_available"])
        self.assertFalse(result["telemetry"]["physical_state_verified"])
        self.assertEqual(len(result["zones"]), config.SPRINKLER_ZONE_COUNT)


class IdentifierValidationTests(unittest.TestCase):
    def test_valid_entity_ids(self) -> None:
        for value in ("climate.hallway", "light.front_door", "automation.test_1"):
            validate_entity_id(value)

    def test_invalid_entity_ids(self) -> None:
        for value in ("light", "Light.front", "light.front door", "../secret"):
            with self.assertRaises(ValueError):
                validate_entity_id(value)

    def test_valid_automation_ids(self) -> None:
        for value in ("morning", "123456789", "nest-schedule_v2"):
            validate_automation_id(value)


class OAuthScopeTests(unittest.TestCase):
    def test_scope_defaults_to_read_write(self) -> None:
        self.assertEqual(OAuthServer._normalize_scope(None), "mcp:read mcp:write")

    def test_diagnostic_guard_accepts_dedicated_or_existing_strongest_scope(
        self,
    ) -> None:
        for scope in (
            "mcp:read mcp:diagnostics",
            "mcp:read mcp:write",
        ):
            token = claims_context.set({"scope": scope})
            try:
                _require_diagnostics()
            finally:
                claims_context.reset(token)

    def test_diagnostic_guard_rejects_incomplete_scope_sets(self) -> None:
        for scope in ("", "mcp:read", "mcp:write", "mcp:diagnostics"):
            token = claims_context.set({"scope": scope})
            try:
                with self.assertRaises(PermissionError):
                    _require_diagnostics()
            finally:
                claims_context.reset(token)

    def test_unknown_scope_is_rejected(self) -> None:
        self.assertIsNone(OAuthServer._normalize_scope("mcp:read admin"))

    def test_diagnostics_scope_is_supported_without_changing_legacy_default(
        self,
    ) -> None:
        self.assertEqual(
            OAuthServer._normalize_scope("mcp:read mcp:diagnostics"),
            "mcp:diagnostics mcp:read",
        )
        self.assertEqual(OAuthServer._normalize_scope(None), "mcp:read mcp:write")


class RedactionTests(unittest.TestCase):
    def test_recursive_redaction_covers_keys_and_url_query_tokens(self) -> None:
        value = {
            "access_token": "top-secret",
            "token": "standalone-token",
            "nested": [
                {
                    "password": "pw",
                    "url": "https://user:pass@ha.invalid/path?token=abc&safe=yes",
                    "entity_picture": "/api/camera_proxy/camera.test?access_token=picture-secret",
                }
            ],
            "ap": {"ssid": "private-network", "ip": "192.0.2.2"},
        }
        safe = redact_sensitive(value)
        rendered = str(safe)
        for secret in (
            "top-secret",
            "standalone-token",
            "pw",
            "abc",
            "picture-secret",
            "user:pass",
            "private-network",
            "192.0.2.2",
        ):
            self.assertNotIn(secret, rendered)
        self.assertIn("safe=yes", safe["nested"][0]["url"])

    def test_state_summary_is_sanitized(self) -> None:
        result = summarize_state(
            {
                "entity_id": "camera.test",
                "state": "idle",
                "attributes": {"friendly_name": "Camera", "access_token": "secret"},
            }
        )
        self.assertEqual(result["attributes"]["access_token"], "[REDACTED]")

    def test_audit_log_sanitizes_nested_fields(self) -> None:
        path = _root / "redaction-audit.jsonl"
        AuditLog(path).write("test", payload={"authorization": "Bearer secret"})
        self.assertNotIn("Bearer secret", path.read_text(encoding="utf-8"))

    def test_audit_log_returns_latest_matching_tool_call(self) -> None:
        path = _root / "latest-tool-audit.jsonl"
        log = AuditLog(path)
        log.write("tool_call", tool="run_sprinkler_zone", zone=1)
        log.write("http_request", path="/health")
        log.write("tool_call", tool="stop_sprinklers")
        latest = log.latest_tool_call({"run_sprinkler_zone", "stop_sprinklers"})
        self.assertIsNotNone(latest)
        self.assertEqual(latest["tool"], "stop_sprinklers")

    def test_every_mcp_result_crosses_the_redaction_boundary(self) -> None:
        services = [
            {
                "domain": "light",
                "services": {
                    "turn_on": {
                        "name": "Turn on",
                        "fields": {"access_token": "must-never-leave-mcp"},
                    }
                },
            }
        ]
        with patch("app.server.ha.services", AsyncMock(return_value=services)):
            result = asyncio.run(mcp.call_tool("list_services", {}))
        rendered = " ".join(getattr(item, "text", "") for item in result.content)
        self.assertNotIn("must-never-leave-mcp", rendered)
        self.assertIn("[REDACTED]", rendered)


class TimeAndGenericServiceSafetyTests(unittest.TestCase):
    def test_rfc3339_requires_timezone(self) -> None:
        with self.assertRaises(ValueError):
            parse_rfc3339("2026-08-22T12:00:00", "start_time")
        self.assertEqual(
            parse_rfc3339("2026-08-22T12:00:00Z", "start_time")
            .tzinfo.utcoffset(None)
            .total_seconds(),
            0,
        )

    def test_history_is_bounded_to_31_days(self) -> None:
        client = HomeAssistantClient("http://ha", "token", _root, _root)
        with self.assertRaisesRegex(ValueError, "31 days"):
            asyncio.run(
                client.history(
                    ["sensor.test"],
                    "2026-01-01T00:00:00Z",
                    "2026-03-01T00:00:00Z",
                    True,
                )
            )

    def test_statistics_excludes_bucket_starting_at_end_time(self) -> None:
        client = HomeAssistantClient("http://ha", "token", _root, _root)
        client.call_service_response = AsyncMock(
            return_value={
                "statistics": {
                    "sensor:test": [
                        {
                            "start": "2026-08-15T07:00:00+00:00",
                            "change": 1,
                        },
                        {
                            "start": "2026-08-16T07:00:00+00:00",
                            "change": 2,
                        },
                    ]
                }
            }
        )
        result = asyncio.run(
            client.statistics(
                ["sensor:test"],
                "2026-08-15T00:00:00-07:00",
                "2026-08-16T00:00:00-07:00",
                "day",
                ["change"],
            )
        )
        self.assertEqual(len(result["sensor:test"]), 1)
        self.assertEqual(result["sensor:test"][0]["change"], 1)

    def test_exact_target_rejects_hidden_keys(self) -> None:
        with self.assertRaises(ValueError):
            _entity_ids({"entity_id": "light.test", "device_id": "bulk"})

    def test_generic_service_rejects_cross_domain_and_data_target(self) -> None:
        token = claims_context.set({"scope": "mcp:read mcp:write"})
        try:
            with self.assertRaisesRegex(ValueError, "domain must match"):
                asyncio.run(
                    call_service("light", "turn_on", {"entity_id": "switch.test"})
                )
            with self.assertRaisesRegex(ValueError, "Targets are allowed only"):
                asyncio.run(
                    call_service(
                        "light",
                        "turn_on",
                        {"entity_id": "light.test"},
                        {"entity_id": "light.other"},
                    )
                )
            with self.assertRaises(ValueError):
                asyncio.run(
                    call_service(
                        "automation", "trigger", {"entity_id": "automation.test"}
                    )
                )
        finally:
            claims_context.reset(token)


class ConfigurationSafetyTests(unittest.TestCase):
    def test_safe_automation_is_accepted(self) -> None:
        config = _validate_automation_config(
            {
                "alias": "Safe light",
                "triggers": [{"trigger": "time", "at": "08:00:00"}],
                "actions": [
                    {"action": "light.turn_on", "target": {"entity_id": "light.test"}}
                ],
            }
        )
        self.assertEqual(config["mode"], "single")

    def test_automation_accepts_exact_input_text_pending_command_write(self) -> None:
        config = _validate_automation_config(
            {
                "alias": "Record pending thermostat command",
                "triggers": [{"trigger": "time", "at": "08:00:00"}],
                "actions": [
                    {
                        "action": "input_text.set_value",
                        "target": {
                            "entity_id": "input_text.thermostat_pending_command"
                        },
                        "data": {"value": '{"temperature": 75}'},
                    }
                ],
            }
        )
        self.assertEqual(config["actions"][0]["action"], "input_text.set_value")

    def test_automation_accepts_only_configured_sprinkler_buttons(self) -> None:
        base = {
            "alias": "Water one sprinkler zone",
            "triggers": [{"trigger": "time", "at": "05:00:00"}],
        }
        configured = tuple(
            f"button.sprinkler_controller_zone_{zone}" for zone in range(1, 4)
        )
        with patch(
            "app.server.config.AUTOMATION_SPRINKLER_BUTTON_ENTITIES", configured
        ):
            for entity_id in configured:
                config = _validate_automation_config(
                    {
                        **base,
                        "actions": [
                            {
                                "action": "button.press",
                                "target": {"entity_id": entity_id},
                            }
                        ],
                    }
                )
                self.assertEqual(config["actions"][0]["target"]["entity_id"], entity_id)

            rejected = (
                "button.unrelated",
                "button.sprinkler_controller_stop_all_zones",
                "button.sprinkler_controller_zone_4",
                "{{ sprinkler_button }}",
            )
            for entity_id in rejected:
                with self.subTest(entity_id=entity_id), self.assertRaises(ValueError):
                    _validate_automation_config(
                        {
                            **base,
                            "actions": [
                                {
                                    "action": "button.press",
                                    "target": {"entity_id": entity_id},
                                }
                            ],
                        }
                    )

            for action in (
                {
                    "action": "button.press",
                    "target": {"entity_id": list(configured[:2])},
                },
                {
                    "action": "button.press",
                    "target": {"entity_id": configured[0]},
                    "data": {"unexpected": True},
                },
                {
                    "action": "button.turn_on",
                    "target": {"entity_id": configured[0]},
                },
            ):
                with self.subTest(action=action), self.assertRaises(ValueError):
                    _validate_automation_config({**base, "actions": [action]})

        with patch("app.server.config.AUTOMATION_SPRINKLER_BUTTON_ENTITIES", ()):
            with self.assertRaises(ValueError):
                _validate_automation_config(
                    {
                        **base,
                        "actions": [
                            {
                                "action": "button.press",
                                "target": {"entity_id": configured[0]},
                            }
                        ],
                    }
                )

    def test_automation_accepts_only_bounded_daily_home_forecast(self) -> None:
        base = {
            "alias": "Fetch forecast",
            "triggers": [{"trigger": "time", "at": "05:00:00"}],
        }
        accepted = {
            "action": "weather.get_forecasts",
            "target": {"entity_id": "weather.forecast_home"},
            "data": {"type": "daily"},
            "response_variable": "daily_forecast",
            "continue_on_error": True,
        }
        with patch(
            "app.server.config.AUTOMATION_DAILY_FORECAST_ENTITY",
            "weather.forecast_home",
        ):
            config = _validate_automation_config({**base, "actions": [accepted]})
            self.assertEqual(
                config["actions"][0]["response_variable"], "daily_forecast"
            )

            rejected = (
                {**accepted, "target": {"entity_id": "weather.other"}},
                {**accepted, "target": {"entity_id": "{{ weather_entity }}"}},
                {key: value for key, value in accepted.items() if key != "data"},
                {**accepted, "data": {"type": "hourly"}},
                {
                    key: value
                    for key, value in accepted.items()
                    if key != "response_variable"
                },
                {**accepted, "response_variable": "{{ result_name }}"},
                {**accepted, "response_variable": "x" * 65},
                {**accepted, "continue_on_error": "yes"},
                {**accepted, "action": "weather.get_forecast"},
            )
            for action in rejected:
                with self.subTest(action=action), self.assertRaises(ValueError):
                    _validate_automation_config({**base, "actions": [action]})

        with patch("app.server.config.AUTOMATION_DAILY_FORECAST_ENTITY", None):
            with self.assertRaises(ValueError):
                _validate_automation_config({**base, "actions": [accepted]})

    def test_automation_create_and_update_still_require_confirmation(self) -> None:
        automation = {
            "alias": "Confirmed only",
            "triggers": [{"trigger": "time", "at": "05:00:00"}],
            "actions": [{"delay": "00:00:01"}],
        }
        with patch(
            "app.server.ha.save_automation_config", new=AsyncMock()
        ) as save_automation:
            with self.assertRaises(PermissionError):
                asyncio.run(create_automation("confirmed_only", automation, False))
            with self.assertRaises(PermissionError):
                asyncio.run(update_automation("confirmed_only", automation, False))
        save_automation.assert_not_awaited()

    def test_automation_blocks_scripts_and_dynamic_services(self) -> None:
        base = {"alias": "Unsafe", "triggers": [{"trigger": "time", "at": "08:00:00"}]}
        for action in (
            {"action": "script.turn_on", "target": {"entity_id": "script.anything"}},
            {"action": "{{ service_name }}", "target": {"entity_id": "light.test"}},
            {"action": "light.turn_on", "data": {"entity_id": "light.test"}},
            {"action": "light.turn_on"},
            {"action": "mqtt.publish", "data": {"topic": "unsafe"}},
        ):
            with self.assertRaises(ValueError):
                _validate_automation_config({**base, "actions": [action]})

    def test_dashboard_requires_views_and_rejects_secrets(self) -> None:
        self.assertEqual(
            _validate_dashboard_config({"views": [{"title": "Home", "cards": []}]})[
                "views"
            ][0]["title"],
            "Home",
        )
        with self.assertRaises(ValueError):
            _validate_dashboard_config({"views": []})
        with self.assertRaisesRegex(ValueError, "credentials"):
            _validate_dashboard_config(
                {"views": [{"title": "Home"}], "access_token": "secret"}
            )


class TypedToolPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.token = claims_context.set({"scope": "mcp:read mcp:write"})

    def tearDown(self) -> None:
        claims_context.reset(self.token)

    def test_nest_fan_timer_uses_duration_object_and_exact_target(self) -> None:
        with patch(
            "app.server.ha.call_service", new=AsyncMock(return_value=[])
        ) as mocked:
            asyncio.run(set_nest_fan_timer("climate.hallway", 30))
        mocked.assert_awaited_once_with(
            "nest",
            "set_fan_timer",
            {"duration": {"seconds": 1800}},
            {"entity_id": "climate.hallway"},
        )

    def test_vacuum_room_clean_uses_dreame_segment_target(self) -> None:
        with (
            patch(
                "app.server.list_vacuum_rooms",
                new=AsyncMock(return_value={"rooms": [{"id": 1}, {"id": 2}]}),
            ),
            patch(
                "app.server.ha.call_service", new=AsyncMock(return_value=[])
            ) as mocked,
        ):
            asyncio.run(clean_vacuum_rooms([2, 1, 2], "vacuum.primary_vacuum"))
        mocked.assert_awaited_once_with(
            "dreame_vacuum",
            "vacuum_clean_segment",
            {"segments": [2, 1], "repeats": 1},
            {"entity_id": "vacuum.primary_vacuum"},
        )

    def test_vacuum_room_clean_resolves_exact_room_names(self) -> None:
        with (
            patch(
                "app.server.list_vacuum_rooms",
                new=AsyncMock(
                    return_value={
                        "rooms": [
                            {"id": 1, "name": "Kitchen"},
                            {"id": 2, "name": "Family Room"},
                        ]
                    }
                ),
            ),
            patch(
                "app.server.ha.call_service", new=AsyncMock(return_value=[])
            ) as mocked,
        ):
            asyncio.run(
                clean_vacuum_rooms(
                    entity_id="vacuum.primary_vacuum",
                    room_names=["family room", "Kitchen"],
                    repeats=2,
                )
            )
        mocked.assert_awaited_once_with(
            "dreame_vacuum",
            "vacuum_clean_segment",
            {"segments": [2, 1], "repeats": 2},
            {"entity_id": "vacuum.primary_vacuum"},
        )

    def test_vacuum_room_listing_flattens_dreame_map_groups(self) -> None:
        state = {
            "entity_id": "vacuum.primary_vacuum",
            "attributes": {
                "rooms": {
                    "Hillcrest": [
                        {"id": 6, "name": "Kitchen", "type": 4},
                        {"id": 11, "name": "Family Room", "type": 0},
                    ]
                }
            },
        }
        with patch("app.server.ha.state", new=AsyncMock(return_value=state)):
            result = asyncio.run(list_vacuum_rooms())
        self.assertEqual(result["count"], 2)
        self.assertEqual(
            result["rooms"][0], {"id": 6, "name": "Kitchen", "map": "Hillcrest"}
        )

    def test_sprinkler_uses_guarded_native_service(self) -> None:
        calls = []

        async def service(domain, service, data, target=None):
            calls.append((domain, service, data, target))
            return []

        with (
            patch("app.server.ha.call_service", new=service),
            patch(
                "app.server._sprinkler_zone_records",
                new=AsyncMock(return_value=[{"zone": 1, "enabled": True}]),
            ),
            patch(
                "app.server._sprinkler_device_id",
                new=AsyncMock(return_value="device-registry-id"),
            ),
        ):
            result = asyncio.run(run_sprinkler_zone(1, 15, True))
        self.assertEqual([item[1] for item in calls], ["run_sprinkler_zone"])
        self.assertEqual(calls[0][0], "wyzeapi")
        self.assertEqual(calls[0][2]["device_id"], ["device-registry-id"])
        self.assertEqual(result["status"], "provider_accepted")

    def test_sprinkler_refresh_uses_controller_device_target(self) -> None:
        status = {
            "entity_id": "sensor.sprinkler_system_watering_status",
            "state": "idle",
            "attributes": {"endpoint_errors": []},
        }
        with (
            patch(
                "app.server._sprinkler_device_id",
                new=AsyncMock(return_value="device-id"),
            ),
            patch(
                "app.server.ha.call_service", new=AsyncMock(return_value=[])
            ) as service,
            patch("app.server.ha.state", new=AsyncMock(return_value=status)),
        ):
            result = asyncio.run(refresh_sprinkler())
        service.assert_awaited_once_with(
            "wyzeapi", "refresh_sprinkler", {"device_id": ["device-id"]}
        )
        self.assertEqual(result["controller"]["state"], "idle")

    def test_calendar_schedule_and_time_tools_use_exact_targets(self) -> None:
        events_response = {
            "calendar.household": {"events": [{"summary": "Appointment"}]}
        }
        schedule_response = {"schedule.test": {"monday": []}}
        with patch(
            "app.server.ha.call_service_response",
            new=AsyncMock(side_effect=[events_response, schedule_response]),
        ) as response:
            events = asyncio.run(
                get_calendar_events(
                    "calendar.household",
                    "2026-08-27T00:00:00+00:00",
                    "2026-08-28T00:00:00+00:00",
                )
            )
            schedule = asyncio.run(get_schedule("schedule.test"))
        self.assertEqual(events["count"], 1)
        self.assertEqual(schedule["schedule"], {"monday": []})
        self.assertEqual(
            response.await_args_list[0].args[3], {"entity_id": "calendar.household"}
        )

        readback = {
            "entity_id": "time.dnd_start",
            "state": "22:30:00",
            "attributes": {},
        }
        with (
            patch(
                "app.server.ha.call_service", new=AsyncMock(return_value=[])
            ) as service,
            patch("app.server.ha.state", new=AsyncMock(return_value=readback)),
        ):
            result = asyncio.run(set_time_value("time.dnd_start", "22:30"))
        service.assert_awaited_once_with(
            "time", "set_value", {"time": "22:30"}, {"entity_id": "time.dnd_start"}
        )
        self.assertEqual(result["status"], "completed")

    def test_calendar_write_validates_shape_before_call(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one"):
            asyncio.run(
                create_calendar_event(
                    "calendar.household", "Invalid", start_time=None, end_time=None
                )
            )

    def test_mobile_notification_rejects_external_urls(self) -> None:
        with self.assertRaisesRegex(ValueError, "relative"):
            asyncio.run(send_mobile_notification("Hello", url="https://evil.invalid"))

    def test_media_content_rejects_camera_secrets_and_private_urls(self) -> None:
        for value in (
            "/api/camera_proxy/camera.front",
            "https://media.example/audio.mp3?token=secret",
            "https://user:pass@media.example/audio.mp3",
            "https://192.168." + "1.2/audio.mp3",
            "http://media.example/audio.mp3",
        ):
            with self.assertRaises(ValueError):
                _validate_media_content_id(value)
        _validate_media_content_id("media-source://media_source/local/chime.mp3")
        _validate_media_content_id("https://media.example/audio.mp3")

    def test_search_media_returns_unsupported_without_provider_call(self) -> None:
        state = {
            "entity_id": "media_player.cast",
            "attributes": {"supported_features": 131072 | 512},
        }
        provider = AsyncMock()
        with (
            patch("app.server.ha.state", new=AsyncMock(return_value=state)),
            patch("app.server.ha.call_service_response", new=provider),
        ):
            result = asyncio.run(search_media("media_player.cast", "jazz"))
        self.assertFalse(result["supported"])
        self.assertEqual(result["reason"], "entity_does_not_advertise_search_media")
        provider.assert_not_awaited()

    def test_search_media_zero_features_is_unsupported(self) -> None:
        state = {
            "entity_id": "media_player.basic",
            "attributes": {"supported_features": 0},
        }
        provider = AsyncMock()
        with (
            patch("app.server.ha.state", new=AsyncMock(return_value=state)),
            patch("app.server.ha.call_service_response", new=provider),
        ):
            result = asyncio.run(search_media("media_player.basic", "jazz"))
        self.assertFalse(result["supported"])
        provider.assert_not_awaited()

    def test_search_media_supported_calls_provider(self) -> None:
        state = {
            "entity_id": "media_player.searchable",
            "attributes": {"supported_features": 4194304},
        }
        provider = AsyncMock(return_value={"media_player.searchable": {"children": []}})
        with (
            patch("app.server.ha.state", new=AsyncMock(return_value=state)),
            patch("app.server.ha.call_service_response", new=provider),
        ):
            result = asyncio.run(search_media("media_player.searchable", "jazz"))
        self.assertTrue(result["supported"])
        provider.assert_awaited_once_with(
            "media_player",
            "search_media",
            {"search_query": "jazz"},
            {"entity_id": "media_player.searchable"},
        )

    def test_solar_summary_falls_back_to_nonzero_inverter(self) -> None:
        metadata = [
            {
                "statistic_id": "solaredge:production",
                "name": "solaredge Production",
                "has_sum": True,
            },
            {
                "statistic_id": "solaredge:inverter_1",
                "name": "solaredge Inverter 1",
                "has_sum": True,
            },
        ]
        rows = {
            "solaredge:production": [
                {"start": "2026-08-15T07:00:00+00:00", "change": 0}
            ],
            "solaredge:inverter_1": [
                {
                    "start": "2026-08-15T07:00:00+00:00",
                    "end": "2026-08-16T07:00:00+00:00",
                    "change": 70.173,
                },
                {
                    "start": "2026-08-16T07:00:00+00:00",
                    "end": "2026-08-17T07:00:00+00:00",
                    "change": 69.569,
                },
            ],
        }
        with (
            patch(
                "app.server._solaredge_metadata", new=AsyncMock(return_value=metadata)
            ),
            patch(
                "app.server._completed_solar_window",
                new=AsyncMock(return_value=("start", "end")),
            ),
            patch("app.server.ha.statistics", new=AsyncMock(return_value=rows)),
        ):
            result = asyncio.run(get_solar_summary(2))
        self.assertEqual(result["production"]["source_method"], "inverter_fallback")
        self.assertEqual(
            result["production"]["selected_statistic_ids"],
            ["solaredge:inverter_1"],
        )
        self.assertEqual(result["production"]["total_kwh"], 139.742)
        self.assertTrue(result["production"]["complete"])

    def test_solar_summary_prefers_populated_production_statistic(self) -> None:
        metadata = [
            {
                "statistic_id": "solaredge:production",
                "name": "solaredge Production",
                "has_sum": True,
            },
            {
                "statistic_id": "solaredge:inverter_1",
                "name": "solaredge Inverter 1",
                "has_sum": True,
            },
        ]
        rows = {
            "solaredge:production": [
                {"start": "2026-08-15T07:00:00+00:00", "change": 50}
            ],
            "solaredge:inverter_1": [
                {"start": "2026-08-15T07:00:00+00:00", "change": 50}
            ],
        }
        with (
            patch(
                "app.server._solaredge_metadata", new=AsyncMock(return_value=metadata)
            ),
            patch(
                "app.server._completed_solar_window",
                new=AsyncMock(return_value=("start", "end")),
            ),
            patch("app.server.ha.statistics", new=AsyncMock(return_value=rows)),
        ):
            result = asyncio.run(get_solar_summary(1))
        self.assertEqual(result["production"]["source_method"], "production_statistic")
        self.assertEqual(result["production"]["total_kwh"], 50)
        self.assertEqual(len(result["production"]["selected_statistic_ids"]), 1)


class ScheduleSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = {
            "id": "living_space_nest_schedule",
            "name": "Living Space Nest Schedule",
            "icon": "mdi:thermostat-auto",
        }

    def entry(
        self,
        start: str,
        end: str,
        preset: str,
        days: list[str] | None = None,
    ) -> ThermostatScheduleEntry:
        return ThermostatScheduleEntry(
            days=days
            or [
                "monday",
                "tuesday",
                "wednesday",
                "thursday",
                "friday",
                "saturday",
                "sunday",
            ],
            start_time=start,
            end_time=end,
            preset=preset,
        )

    def test_clock_parsing_accepts_end_of_day(self) -> None:
        self.assertEqual(_clock_seconds("24:00", allow_24=True), 86_400)
        with self.assertRaises(ValueError):
            _clock_seconds("24:00", allow_24=False)

    def test_complete_week_is_rendered_with_shared_temperatures(self) -> None:
        schedule = _build_thermostat_schedule(
            "living_space",
            [
                self.entry("00:00", "08:00", "Eco"),
                self.entry("08:00", "24:00", "Comfort"),
            ],
            dict(DEFAULT_TEMPERATURE_PRESETS),
            self.current,
        )
        self.assertEqual(schedule["monday"][0]["data"]["temperature"], 80)
        self.assertEqual(schedule["sunday"][-1]["to"], "24:00:00")

    def test_gap_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "gap"):
            _build_thermostat_schedule(
                "living_space",
                [
                    self.entry("00:00", "08:00", "Eco"),
                    self.entry("09:00", "24:00", "Comfort"),
                ],
                dict(DEFAULT_TEMPERATURE_PRESETS),
                self.current,
            )

    def test_overlap_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "overlap"):
            _build_thermostat_schedule(
                "living_space",
                [
                    self.entry("00:00", "09:00", "Eco"),
                    self.entry("08:00", "24:00", "Comfort"),
                ],
                dict(DEFAULT_TEMPERATURE_PRESETS),
                self.current,
            )

    def test_bedroom_range_is_added(self) -> None:
        current = dict(
            self.current, id="bedroom_nest_schedule", name="Bedroom Nest Schedule"
        )
        schedule = _build_thermostat_schedule(
            "bedroom",
            [self.entry("00:00", "24:00", "Sleep")],
            dict(DEFAULT_TEMPERATURE_PRESETS),
            current,
        )
        data = schedule["monday"][0]["data"]
        self.assertEqual(data["target_temp_low"], 65)
        self.assertEqual(data["target_temp_high"], 72)

    def test_preset_replacement_updates_temperature_and_high_limit(self) -> None:
        schedule = dict(self.current)
        for day in (
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        ):
            schedule[day] = [
                {
                    "from": "00:00:00",
                    "to": "24:00:00",
                    "data": {
                        "period": "Eco",
                        "temperature": 79,
                        "target_temp_low": 56,
                        "target_temp_high": 79,
                    },
                }
            ]
        replaced = _replace_schedule_preset(schedule, "Eco", 80)
        self.assertEqual(replaced["monday"][0]["data"]["temperature"], 80)
        self.assertEqual(replaced["monday"][0]["data"]["target_temp_high"], 80)
        self.assertEqual(replaced["monday"][0]["data"]["target_temp_low"], 56)

    def test_high_impact_action_requires_confirmation(self) -> None:
        with self.assertRaises(PermissionError):
            _require_confirmed(False, "test action")
        _require_confirmed(True, "test action")


if __name__ == "__main__":
    unittest.main()
