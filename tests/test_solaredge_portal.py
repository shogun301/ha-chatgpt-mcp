from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import tempfile
import unittest
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from app.solaredge_portal import (
    SolarEdgePortalAuthenticationError,
    SolarEdgePortalClient,
    SolarEdgePortalConfig,
    SolarEdgePortalError,
)


class _Content:
    def __init__(self, body: bytes, chunk_size: int | None = None) -> None:
        self.body = body
        self.chunk_size = chunk_size or max(1, len(body))

    async def iter_chunked(self, ignored_size):
        for offset in range(0, len(self.body), self.chunk_size):
            yield self.body[offset : offset + self.chunk_size]


class _Response:
    def __init__(
        self,
        status: int,
        body: object | str | bytes = b"",
        *,
        url: str = "https://monitoring.solaredge.com/ok",
        history: list[object] | None = None,
        content_length: int | None = None,
        chunk_size: int | None = None,
    ) -> None:
        self.status = status
        if isinstance(body, bytes):
            raw = body
        elif isinstance(body, str):
            raw = body.encode()
        else:
            raw = json.dumps(body).encode()
        self.url = url
        self.history = history or []
        self.content = _Content(raw, chunk_size)
        self.content_length = len(raw) if content_length is None else content_length
        self.charset = "utf-8"

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class _Session:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict]] = []
        self.cookie_jar = []
        self.closed = False

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    async def close(self):
        self.closed = True


class _RecordingPortal(SolarEdgePortalClient):
    def __init__(self, config, responses=None, **kwargs):
        super().__init__(config, **kwargs)
        self.calls = []
        self.responses = list(responses or [])

    async def _dashboard_get(self, operation, path, params=None):
        self.calls.append((operation, path, list(params or [])))
        return self.responses.pop(0)


class _RetryPortal(SolarEdgePortalClient):
    def __init__(self, config, responses):
        super().__init__(config)
        self.responses = list(responses)
        self.login_calls = []

    async def _ensure_login(self, *, force=False):
        self.login_calls.append(force)
        self._authorization_header = "Bearer refreshed" if force else "Bearer initial"

    async def _request(self, *args, **kwargs):
        return self.responses.pop(0)


class PortalTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = SolarEdgePortalConfig(
            username="user@example.test",
            password="correct horse battery staple",
            site_id="4211658",
            timezone_name="America/Los_Angeles",
            cache_ttl_seconds=60,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()


class ConfigurationAndLoginTests(PortalTestCase):
    def test_dedicated_secret_files_load_without_plaintext_environment_contract(
        self,
    ) -> None:
        username = self.root / "username"
        password = self.root / "password"
        site = self.root / "site"
        username.write_text("portal-user\n", encoding="utf-8")
        password.write_text("portal-password\n", encoding="utf-8")
        site.write_text("4211658\n", encoding="utf-8")
        loaded = SolarEdgePortalConfig.from_secret_files(
            username_file=username,
            password_file=password,
            site_id_file=site,
            timezone_name="America/Los_Angeles",
        )
        self.assertEqual(loaded.username, "portal-user")
        self.assertEqual(loaded.password, "portal-password")
        self.assertEqual(loaded.site_id, "4211658")

    def test_site_id_timezone_and_response_limits_are_validated(self) -> None:
        for site_id in ("../1", "abc", "1?x=2"):
            with self.assertRaises(ValueError):
                SolarEdgePortalConfig("u", "p", site_id, "America/Los_Angeles")
        with self.assertRaises(ValueError):
            SolarEdgePortalConfig("u", "p", "1", "Not/A_Zone")
        with self.assertRaises(ValueError):
            SolarEdgePortalConfig("u", "p", "1", "UTC", max_response_bytes=100)

    def test_login_uses_s256_pkce_exact_hosts_and_expected_exchange(self) -> None:
        login_page = (
            '<form action="/oauth2/login"><input name="csrf" value="hidden"></form>'
        )
        session = _Session(
            [
                _Response(
                    200,
                    login_page,
                    url="https://login.solaredge.com/oauth2/authorize",
                ),
                _Response(
                    200,
                    b"",
                    url="https://monitoring.solaredge.com/mfe/auth/callback?code=authorization-code",
                ),
                _Response(
                    200,
                    {"access_token": "access-token", "token_type": "Bearer"},
                    url="https://login.solaredge.com/oauth2/token",
                ),
                _Response(
                    200,
                    {},
                    url="https://monitoring.solaredge.com/services/auth/token?legacy=false",
                ),
            ]
        )
        client = SolarEdgePortalClient(self.config, session=session)
        asyncio.run(client._ensure_login())

        self.assertEqual(len(session.calls), 4)
        authorize = urlsplit(session.calls[0][1])
        query = parse_qs(authorize.query)
        self.assertEqual(authorize.hostname, "login.solaredge.com")
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(
            query["redirect_uri"],
            ["https://monitoring.solaredge.com/mfe/auth/callback"],
        )
        form_call = session.calls[1]
        self.assertEqual(form_call[1], "https://login.solaredge.com/oauth2/login")
        self.assertEqual(form_call[2]["data"]["csrf"], "hidden")
        self.assertEqual(form_call[2]["data"]["username"], self.config.username)
        self.assertEqual(form_call[2]["data"]["password"], self.config.password)

        token_form = session.calls[2][2]["data"]
        verifier = token_form["code_verifier"]
        expected_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        self.assertEqual(query["code_challenge"], [expected_challenge])
        self.assertEqual(token_form["code"], "authorization-code")
        self.assertEqual(
            session.calls[3][1],
            "https://monitoring.solaredge.com/services/auth/token?legacy=false",
        )
        self.assertEqual(
            session.calls[3][2]["headers"]["Authorization"], "Bearer access-token"
        )

    def test_untrusted_form_action_is_rejected_before_credentials_are_sent(
        self,
    ) -> None:
        session = _Session(
            [
                _Response(
                    200,
                    '<form action="https://evil.example/login"></form>',
                    url="https://login.solaredge.com/oauth2/authorize",
                )
            ]
        )
        client = SolarEdgePortalClient(self.config, session=session)
        with self.assertRaises(SolarEdgePortalAuthenticationError):
            asyncio.run(client._ensure_login())
        self.assertEqual(len(session.calls), 1)

    def test_untrusted_redirect_is_rejected(self) -> None:
        session = _Session(
            [_Response(200, b"", url="https://evil.example/callback?code=secret")]
        )
        client = SolarEdgePortalClient(self.config, session=session)
        with self.assertRaisesRegex(SolarEdgePortalAuthenticationError, "untrusted"):
            asyncio.run(client._ensure_login())

    def test_login_lock_collapses_concurrent_login_attempts(self) -> None:
        class LockClient(SolarEdgePortalClient):
            def __init__(self, config):
                super().__init__(config)
                self.count = 0

            async def _login(self):
                self.count += 1
                await asyncio.sleep(0.01)
                self._authorization_header = "Bearer token"
                self._last_login_monotonic = self._monotonic()

        async def run_test():
            client = LockClient(self.config)
            await asyncio.gather(*(client._ensure_login() for _ in range(10)))
            return client

        client = asyncio.run(run_test())
        self.assertEqual(client.count, 1)

    def test_response_is_rejected_before_or_while_exceeding_bound(self) -> None:
        client = SolarEdgePortalClient(self.config)
        oversized_header = _Response(200, b"x", content_length=3 * 1024 * 1024)
        with self.assertRaisesRegex(SolarEdgePortalError, "too large"):
            asyncio.run(client._read_bounded(oversized_header, "test"))

        body = b"x" * (self.config.max_response_bytes + 1)
        streaming = _Response(200, body, content_length=None, chunk_size=65536)
        streaming.content_length = None
        with self.assertRaisesRegex(SolarEdgePortalError, "too large"):
            asyncio.run(client._read_bounded(streaming, "test"))


class EndpointAndNormalizationTests(PortalTestCase):
    def test_exact_capability_and_live_endpoint_paths_and_queries(self) -> None:
        client = _RecordingPortal(
            self.config,
            responses=[
                {
                    "hasProduction": True,
                    "hasConsumptionAndGrid": True,
                    "hasStorage": True,
                    "hasAcStorage": True,
                    "hasDcStorage": False,
                },
                {"currentPower": 2},
                {"solarProduction": {"currentPower": 7.59}},
            ],
        )
        capabilities = asyncio.run(client.capabilities())
        live = asyncio.run(client.live_power())
        flow = asyncio.run(client.live_power_flow())
        self.assertTrue(capabilities["has_consumption_and_grid"])
        self.assertEqual(live["current_power_w"], 2000)
        self.assertEqual(
            flow["components"]["solar_production"]["current_power_w"], 7590
        )
        self.assertEqual(client.calls[0][1], "/site-details/4211658/components")
        self.assertEqual(client.calls[1][1], "/live-power/sites/4211658")
        self.assertEqual(client.calls[2][1], "/power-flow/v2/sites/4211658")
        self.assertEqual(
            client.calls[2][2],
            [
                ("components", "grid"),
                ("components", "consumption"),
                ("components", "ac-storage"),
                ("components", "dc-storage"),
                ("components", "ev-charger"),
            ],
        )

    def test_live_flow_normalizes_kw_to_w_and_preserves_direction_status_and_time(
        self,
    ) -> None:
        client = _RecordingPortal(
            self.config,
            responses=[
                {
                    "solarProduction": {
                        "currentPower": 7.59,
                        "status": "ACTIVE",
                        "lastUpdateTime": "2026-08-23T10:00:00-07:00",
                    },
                    "grid": {
                        "currentPower": 1.25,
                        "status": "IMPORT",
                        "direction": "FROM_GRID",
                        "lastUpdateTime": "2026-08-23T10:00:01-07:00",
                    },
                    "acStorage": {
                        "currentPower": 0.5,
                        "status": "CHARGING",
                        "chargeLevel": 81,
                    },
                    "storagePlan": {
                        "name": "MAX_SELF_CONSUMPTION",
                        "isActive": True,
                        "blockCount": 4,
                        "actor": "not-for-public-output",
                        "authorization": "secret-value",
                    },
                }
            ],
        )
        result = asyncio.run(client.live_power_flow())
        self.assertEqual(
            result["components"]["solar_production"]["current_power_w"], 7590
        )
        self.assertEqual(result["components"]["grid"]["current_power_w"], 1250)
        self.assertEqual(result["components"]["grid"]["status"], "IMPORT")
        self.assertEqual(result["components"]["grid"]["direction"], "FROM_GRID")
        self.assertEqual(result["components"]["ac_storage"]["chargeLevel"], 81)
        self.assertEqual(result["last_update_time"], "2026-08-23T10:00:01-07:00")
        self.assertEqual(
            result["storage_operating_plan"],
            {
                "plan": "MAX_SELF_CONSUMPTION",
                "is_active": True,
                "block_count": 4,
            },
        )
        self.assertNotIn("actor", str(result))
        self.assertNotIn("secret-value", str(result))

    def test_live_flow_accepts_scalar_storage_plan_metadata(self) -> None:
        client = _RecordingPortal(
            self.config,
            responses=[
                {
                    "solarProduction": {"currentPower": 1.0},
                    "storagePlan": "TIME_OF_USE",
                    "isActive": False,
                    "blockCount": 2,
                }
            ],
        )

        result = asyncio.run(client.live_power_flow())

        self.assertEqual(
            result["storage_operating_plan"],
            {"plan": "TIME_OF_USE", "is_active": False, "block_count": 2},
        )

    def test_energy_history_uses_exact_query_and_normalizes_wh_to_kwh(self) -> None:
        client = _RecordingPortal(
            self.config,
            responses=[
                {
                    "production": 7590,
                    "consumption": 4590,
                    "import": 1000,
                    "export": 4000,
                    "productionDistribution": {"storage": 1000, "grid": 2000},
                    "chart": {
                        "measurements": [
                            {
                                "type": "production",
                                "values": [
                                    {
                                        "time": "2026-08-23T10:00:00-07:00",
                                        "value": 1500,
                                    }
                                ],
                            }
                        ]
                    },
                }
            ],
        )
        result = asyncio.run(
            client.energy_history(date(2026, 8, 20), date(2026, 8, 22))
        )
        self.assertEqual(result["totals_kwh"]["production"], 7.59)
        self.assertEqual(result["totals_kwh"]["consumption"], 4.59)
        self.assertEqual(result["production_distribution"]["storage_kwh"], 1.0)
        point = result["chart"]["measurements"][0]["values"][0]
        self.assertEqual(point["value_kwh"], 1.5)
        self.assertEqual(point["time"], "2026-08-23T10:00:00-07:00")
        params = client.calls[0][2]
        self.assertEqual(client.calls[0][1], "/energy/sites/4211658")
        self.assertEqual(
            params[:3],
            [
                ("chart-time-unit", "days"),
                ("start-date", "2026-08-20"),
                ("end-date", "2026-08-22"),
            ],
        )
        self.assertEqual(
            [value for key, value in params if key == "measurement-types"],
            [
                "production",
                "yield",
                "consumption",
                "production-distribution-with-storage",
                "consumption-distribution-with-storage",
                "import",
                "export",
            ],
        )
        self.assertIn(("isCniViewer", "true"), params)

    def test_completed_and_current_windows_use_local_calendar_dates(self) -> None:
        fixed_now = lambda: datetime(2026, 8, 23, 17, 0, tzinfo=UTC)
        completed = _RecordingPortal(self.config, responses=[{}], now=fixed_now)
        completed_result = asyncio.run(completed.completed_energy_summary(7))
        self.assertEqual(completed_result["start_date"], "2026-08-16")
        self.assertEqual(completed_result["end_date"], "2026-08-22")
        self.assertEqual(completed_result["window_type"], "completed_local_dates")
        self.assertEqual(completed_result["timezone"], "America/Los_Angeles")

        current = _RecordingPortal(self.config, responses=[{}], now=fixed_now)
        current_result = asyncio.run(current.current_day_energy_summary())
        self.assertEqual(current_result["start_date"], "2026-08-23")
        self.assertEqual(current_result["end_date"], "2026-08-23")
        self.assertEqual(current_result["chart_time_unit"], "quarter-hours")

        lifetime = _RecordingPortal(self.config, responses=[{}], now=fixed_now)
        lifetime_result = asyncio.run(lifetime.lifetime_energy_summary())
        self.assertEqual(lifetime_result["start_date"], "2000-01-01")
        self.assertEqual(lifetime_result["end_date"], "2026-08-23")
        self.assertEqual(lifetime_result["chart_time_unit"], "years")
        self.assertEqual(
            lifetime_result["window_type"],
            "lifetime_through_current_local_date",
        )
        self.assertEqual(lifetime.calls[0][1], "/energy/sites/4211658")

    def test_storage_and_battery_use_only_fixed_paths_and_units(self) -> None:
        client = _RecordingPortal(
            self.config,
            responses=[
                {"chargeEnergy": 5000, "dischargeEnergy": 2000},
                {
                    "currentPower": 1.5,
                    "remainingEnergy": 7200,
                    "stateOfCharge": 84,
                    "status": "CHARGING",
                    "timestamp": "2026-08-23T17:00:00Z",
                    "serialNumber": "private",
                },
                {"chargeEnergy": 3000},
            ],
        )
        distribution = asyncio.run(
            client.storage_distribution(date(2026, 8, 1), date(2026, 8, 2))
        )
        state = asyncio.run(
            client.battery_storage_state(
                datetime(2026, 8, 23, 0, tzinfo=UTC),
                datetime(2026, 8, 24, 0, tzinfo=UTC),
            )
        )
        battery = asyncio.run(client.battery_energy(date(2026, 8, 1), date(2026, 8, 2)))
        self.assertEqual(distribution["distribution"]["charge_energy_kwh"], 5)
        self.assertEqual(state["current_power_w"], 1500)
        self.assertEqual(state["remaining_energy_kwh"], 7.2)
        self.assertEqual(state["stateOfCharge"], 84)
        self.assertEqual(state["status"], "CHARGING")
        self.assertEqual(state["timestamp"], "2026-08-23T17:00:00Z")
        self.assertNotIn("private", json.dumps(state))
        self.assertEqual(battery["charge_energy_kwh"], 3)
        self.assertEqual(
            [call[1] for call in client.calls],
            [
                "/storage/energy/distribution/sites/4211658",
                "/battery/sites/4211658/storage-state",
                "/battery/sites/4211658",
            ],
        )

    def test_date_and_timestamp_windows_are_bounded(self) -> None:
        client = _RecordingPortal(self.config)
        with self.assertRaisesRegex(ValueError, "31 days"):
            asyncio.run(
                client.energy_history(
                    date(2026, 1, 1),
                    date(2026, 2, 2),
                    chart_time_unit="quarter-hours",
                )
            )

    def test_specific_yield_is_not_mislabeled_or_converted_as_energy(self) -> None:
        client = _RecordingPortal(
            self.config,
            responses=[
                {
                    "yield": 4.25,
                    "chart": {
                        "measurements": [{"type": "yield", "values": [{"value": 3.75}]}]
                    },
                }
            ],
        )
        result = asyncio.run(
            client.energy_history(date(2026, 8, 22), date(2026, 8, 22))
        )
        self.assertNotIn("yield", result["totals_kwh"])
        point = result["chart"]["measurements"][0]["values"][0]
        self.assertEqual(point["value"], 3.75)
        self.assertNotIn("value_kwh", point)
        with self.assertRaisesRegex(ValueError, "timezones"):
            asyncio.run(
                client.battery_storage_state(datetime(2026, 1, 1), datetime(2026, 1, 2))
            )

    def test_no_public_generic_request_method_is_exposed(self) -> None:
        public = {
            name for name in dir(SolarEdgePortalClient) if not name.startswith("_")
        }
        self.assertNotIn("request", public)
        self.assertNotIn("get", public)
        self.assertNotIn("call", public)


class ReliabilityTests(PortalTestCase):
    def test_authenticated_get_retries_auth_once(self) -> None:
        client = _RetryPortal(
            self.config,
            [_Response(401, {}), _Response(200, {"currentPower": 1})],
        )
        result = asyncio.run(
            client._dashboard_get("live power", "/live-power/sites/4211658")
        )
        self.assertEqual(result, {"currentPower": 1})
        self.assertEqual(client.login_calls, [False, True])

    def test_second_auth_failure_stops_without_response_details(self) -> None:
        client = _RetryPortal(
            self.config,
            [
                _Response(401, {"access_token": "must-not-leak"}),
                _Response(403, {"siteId": "4211658"}),
            ],
        )
        with self.assertRaises(SolarEdgePortalError) as caught:
            asyncio.run(
                client._dashboard_get("live power", "/live-power/sites/4211658")
            )
        rendered = str(caught.exception)
        self.assertNotIn("must-not-leak", rendered)
        self.assertNotIn("4211658", rendered)
        self.assertEqual(len(client.login_calls), 2)

    def test_cache_returns_independent_copy(self) -> None:
        class CacheClient(SolarEdgePortalClient):
            def __init__(self, config):
                super().__init__(config, monotonic=lambda: 100)
                self.count = 0

            async def _ensure_login(self, *, force=False):
                self._authorization_header = "Bearer token"

            async def _authenticated_get(self, operation, path, params):
                self.count += 1
                return {"value": 1}

        client = CacheClient(self.config)
        first = asyncio.run(client._dashboard_get("test", "/live-power/sites/4211658"))
        first["value"] = 99
        second = asyncio.run(client._dashboard_get("test", "/live-power/sites/4211658"))
        self.assertEqual(second, {"value": 1})
        self.assertEqual(client.count, 1)

    def test_provider_health_never_exposes_site_or_urls(self) -> None:
        client = _RecordingPortal(
            self.config,
            responses=[{"hasProduction": True}],
        )
        result = asyncio.run(client.provider_health(refresh=True))
        rendered = json.dumps(result)
        self.assertTrue(result["reachable"])
        self.assertNotIn(self.config.site_id, rendered)
        self.assertNotIn("monitoring.solaredge.com", rendered)


if __name__ == "__main__":
    unittest.main()
