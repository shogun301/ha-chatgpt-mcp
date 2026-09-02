"""Focused tests for the SolarEdge Monitoring bridge trust boundary."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path

COMPONENT = Path(__file__).parents[1] / "custom_components" / "solaredge_one_bridge"


def _load_module(name: str, filename: str):
    package_name = "solaredge_one_bridge"
    if package_name not in sys.modules:
        package = types.ModuleType(package_name)
        package.__path__ = [str(COMPONENT)]
        sys.modules[package_name] = package
    qualified = f"{package_name}.{name}"
    spec = importlib.util.spec_from_file_location(qualified, COMPONENT / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified] = module
    spec.loader.exec_module(module)
    return module


model = _load_module("model", "model.py")
const = _load_module("const", "const.py")
client_module = _load_module("client", "client.py")


def test_parser_allowlists_metrics_and_never_propagates_sensitive_fields() -> None:
    snapshot = model.parse_snapshot(
        {
            "connected": True,
            "observed_at": "2026-08-23T12:34:56Z",
            "provider": "monitoring_api_v1",
            "site": {
                "production_power_w": 8123,
                "grid_import_energy_kwh": 42.5,
                "battery_state_of_energy_pct": 61,
                "storage_operating_plan": "Time of Use",
                "storage_operating_plan_active": True,
                "storage_operating_plan_block_count": 4,
                "storage_operating_plan_policy": {"secret": "sensitive"},
                "site_id": "sensitive",
                "address": "sensitive",
                "serial": "sensitive",
                "api_key": "sensitive",
            },
            "completeness": {
                "production_power_w": True,
                "storage_operating_plan": True,
                "site_id": True,
            },
            "credentials": {"secret": "sensitive"},
        }
    )

    assert snapshot.connected is True
    assert snapshot.provider == "monitoring_api_v1"
    assert snapshot.site == {
        "production_power_w": 8123.0,
        "grid_import_energy_kwh": 42.5,
        "battery_state_of_energy_pct": 61.0,
        "storage_operating_plan": "Time of Use",
        "storage_operating_plan_active": True,
        "storage_operating_plan_block_count": 4.0,
    }
    assert snapshot.completeness == {
        "production_power_w": True,
        "storage_operating_plan": True,
    }
    assert snapshot.storage_operating_plan == "Time of Use"
    assert snapshot.storage_operating_plan_active is True
    assert snapshot.storage_operating_plan_block_count == 4
    assert "sensitive" not in repr(snapshot)


def test_parser_omits_invalid_and_explicitly_incomplete_values() -> None:
    snapshot = model.parse_snapshot(
        {
            "connected": True,
            "observed_at": None,
            "provider": {"name": "must-not-leak"},
            "site": {
                "production_power_w": float("nan"),
                "consumption_power_w": -1,
                "grid_import_power_w": True,
                "grid_export_power_w": 100,
                "battery_state_of_energy_pct": 101,
                "production_energy_kwh": None,
            },
            "completeness": {"grid_export_power_w": False},
        }
    )

    assert snapshot.site == {"grid_export_power_w": 100.0}
    assert snapshot.provider is None
    assert snapshot.value("grid_export_power_w") is None
    assert snapshot.value("production_power_w") is None


def test_parser_rejects_invalid_envelope() -> None:
    for payload in (
        None,
        {},
        {"connected": "yes", "site": {}},
        {"connected": True, "site": []},
        {"connected": True, "site": {}, "completeness": []},
        {"connected": True, "site": {}, "observed_at": "not-a-date"},
        {"connected": True, "site": {}, "observed_at": "2026-08-23T12:00:00"},
    ):
        try:
            model.parse_snapshot(payload)
        except model.InvalidSnapshot:
            pass
        else:
            raise AssertionError(f"invalid payload accepted: {payload!r}")


class _FakeResponse:
    def __init__(self, status: int, payload) -> None:
        self.status = status
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self, *, content_type=None):
        return self._payload


class _FakeSession:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.calls = []

    def get(self, endpoint, **kwargs):
        self.calls.append((endpoint, kwargs))
        return self.response


def test_client_sends_only_bridge_secret_header_and_uses_strict_timeout() -> None:
    session = _FakeSession(
        _FakeResponse(200, {"connected": False, "observed_at": None, "site": {}})
    )
    client = client_module.SolarEdgeBridgeClient(
        session, "http://127.0.0.1:8000/internal/solaredge/snapshot", "test-secret"
    )
    snapshot = asyncio.run(client.async_get_snapshot())

    assert snapshot.connected is False
    endpoint, kwargs = session.calls[0]
    assert endpoint.endswith("/internal/solaredge/snapshot")
    assert kwargs["headers"] == {const.BRIDGE_SECRET_HEADER: "test-secret"}
    assert kwargs["timeout"].total == const.DEFAULT_TIMEOUT_SECONDS


def test_client_uses_bounded_full_data_endpoint_and_requires_an_object() -> None:
    session = _FakeSession(_FakeResponse(200, {"capability_inverter_count": 1}))
    client = client_module.SolarEdgeBridgeClient(
        session, "http://127.0.0.1:8000/internal/solaredge/snapshot", "test-secret"
    )

    payload = asyncio.run(client.async_get_full_data())

    assert payload == {"capability_inverter_count": 1}
    endpoint, kwargs = session.calls[0]
    assert endpoint == "http://127.0.0.1:8000/internal/solaredge/full-data"
    assert kwargs["headers"] == {const.BRIDGE_SECRET_HEADER: "test-secret"}

    invalid = client_module.SolarEdgeBridgeClient(
        _FakeSession(_FakeResponse(200, [])),
        "http://127.0.0.1:8000/internal/solaredge/snapshot",
        "test-secret",
    )
    try:
        asyncio.run(invalid.async_get_full_data())
    except client_module.BridgeConnectionError:
        pass
    else:
        raise AssertionError("non-object full data was accepted")


def test_client_classifies_authentication_failure() -> None:
    session = _FakeSession(_FakeResponse(401, {}))
    client = client_module.SolarEdgeBridgeClient(
        session, "http://127.0.0.1:8000/internal/solaredge/snapshot", "wrong"
    )
    try:
        asyncio.run(client.async_get_snapshot())
    except client_module.BridgeAuthenticationError:
        pass
    else:
        raise AssertionError("authentication failure was not classified")


def test_provider_label_is_bounded_and_sanitized() -> None:
    base = {"connected": True, "observed_at": None, "site": {}}
    assert model.parse_snapshot({**base, "provider": "portal_fallback"}).provider == (
        "portal_fallback"
    )
    assert model.parse_snapshot({**base, "provider": "x" * 65}).provider is None
    assert (
        model.parse_snapshot({**base, "provider": "provider\nsecret"}).provider is None
    )


def test_operating_plan_status_is_bounded_strict_and_privacy_preserving() -> None:
    base = {"connected": True, "observed_at": None, "site": {}}
    snapshot = model.parse_snapshot(
        {
            **base,
            "site": {
                "storage_operating_plan": "x" * 65,
                "storage_operating_plan_active": 1,
                "storage_operating_plan_block_count": True,
                "storage_operating_plan_schedule": "must-not-leak",
            },
        }
    )
    assert snapshot.storage_operating_plan is None
    assert snapshot.storage_operating_plan_active is None
    assert snapshot.storage_operating_plan_block_count is None
    assert "must-not-leak" not in repr(snapshot)

    snapshot = model.parse_snapshot(
        {
            **base,
            "site": {
                "storage_operating_plan": "Maximize Self Consumption",
                "storage_operating_plan_active": False,
                "storage_operating_plan_block_count": 0,
            },
        }
    )
    assert snapshot.storage_operating_plan == "Maximize Self Consumption"
    assert snapshot.storage_operating_plan_active is False
    assert snapshot.storage_operating_plan_block_count == 0


def test_polling_interval_is_five_minutes() -> None:
    assert const.DEFAULT_UPDATE_INTERVAL.total_seconds() == 300


def test_snapshot_contract_contains_only_the_reviewed_scalar_fields() -> None:
    assert len(model.POWER_KEYS) == 15
    assert len(model.ENERGY_KEYS) == 50
    assert len(model.PERCENTAGE_KEYS) == 32
    assert len(model.COUNT_KEYS) == 8
    assert len(model.RATIO_KEYS) == 4
    assert len(model.TEXT_KEYS) == 50
    assert len(model.BOOLEAN_KEYS) == 36
    assert len(model.METRIC_KEYS) == 109
    assert len(model.STORAGE_STATUS_KEYS) == 3
    assert len(model.SNAPSHOT_KEYS) == 195


def test_parser_preserves_reviewed_text_flags_and_integer_counts() -> None:
    snapshot = model.parse_snapshot(
        {
            "connected": True,
            "observed_at": "2026-09-02T10:00:00Z",
            "site": {
                "capability_viewer_type": "Owner",
                "endpoint_power_flow_available": False,
                "capability_inverter_count": 2,
                "power_flow_refresh_rate_seconds": 300.5,
                "bridge_fetched_at": "value\nthat-must-not-survive",
            },
        }
    )

    assert snapshot.text("capability_viewer_type") == "Owner"
    assert snapshot.flag("endpoint_power_flow_available") is False
    assert snapshot.value("capability_inverter_count") == 2.0
    assert snapshot.value("power_flow_refresh_rate_seconds") is None
    assert snapshot.text("bridge_fetched_at") is None


def test_sensor_platform_preserves_metrics_and_adds_one_plan_status_entity() -> None:
    source = (COMPONENT / "sensor.py").read_text(encoding="utf-8")
    assert "for description in SENSOR_DESCRIPTIONS" in source
    assert "SolarEdgeStorageOperatingPlanSensor(entry.runtime_data)" in source
    assert 'attributes["active"]' in source
    assert 'attributes["block_count"]' in source


def test_config_flow_enforces_single_instance() -> None:
    config_flow_source = (COMPONENT / "config_flow.py").read_text(encoding="utf-8")
    assert "single_instance_allowed" in config_flow_source
    assert "_async_current_entries" in config_flow_source
    assert "_abort_if_unique_id_configured" in config_flow_source


def test_endpoint_validation_rejects_public_and_credentialed_urls() -> None:
    assert client_module.is_local_endpoint(
        "http://127.0.0.1:8000/internal/solaredge/snapshot"
    )
    assert client_module.is_local_endpoint(
        "http://ha-chatgpt-mcp:8000/internal/solaredge/snapshot"
    )
    assert client_module.is_local_endpoint("https://192.0.2.44/bridge")
    assert not client_module.is_local_endpoint("https://api.example.com/bridge")
    assert not client_module.is_local_endpoint("http://user:password@127.0.0.1/bridge")
    assert not client_module.is_local_endpoint("file:///config/secrets.yaml")
