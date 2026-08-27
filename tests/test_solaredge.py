from __future__ import annotations

import asyncio
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.fernet import Fernet

from app.solaredge import (
    API_BASE_URL,
    OAUTH_SCOPES,
    SolarEdgeAuthorizationError,
    SolarEdgeClient,
    SolarEdgeConfig,
    SolarEdgeOAuthManager,
    SolarEdgeRateLimitError,
    sanitize_solaredge_result,
)


class _Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class _OAuthStub(SolarEdgeOAuthManager):
    def __init__(self, config: SolarEdgeConfig, clock: _Clock) -> None:
        super().__init__(config, now=clock)
        self.forms: list[dict[str, str]] = []
        self.responses: list[dict[str, object] | Exception] = []

    async def _post_token(self, data):
        self.forms.append(dict(data))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _ClientStub(SolarEdgeClient):
    def __init__(self, config, oauth, responses, *, clock=None, sleep=None):
        self.responses = list(responses)
        self.gets = []
        super().__init__(
            config,
            oauth=oauth,
            monotonic=clock or (lambda: 100.0),
            sleep=sleep or asyncio.sleep,
        )

    async def _get(self, path, params, access_token):
        self.gets.append((path, dict(params), access_token))
        return self.responses.pop(0)


class SolarEdgeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.clock = _Clock()
        self.config = SolarEdgeConfig(
            client_id="client-id",
            client_secret="client-secret",
            redirect_uri="https://home.example/solaredge/oauth/callback",
            token_store_path=self.root / "tokens.enc",
            encryption_key=Fernet.generate_key(),
            site_id="4211658",
            cache_ttl_seconds=60,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def authorized_oauth(self) -> _OAuthStub:
        oauth = _OAuthStub(self.config, self.clock)
        oauth._store.save(
            {
                "access_token": "access-one",
                "refresh_token": "refresh-one",
                "site_id": "4211658",
                "scope": "SITE_DATA DEVICE_DATA",
                "expires_at": self.clock.value + 3600,
                "refresh_expires_at": self.clock.value + 86400,
            }
        )
        return oauth


class OAuthTests(SolarEdgeTestCase):
    def test_authorization_url_is_fixed_and_contains_exact_callback_and_scopes(self) -> None:
        oauth = _OAuthStub(self.config, self.clock)
        first = oauth.begin_authorization()
        second = oauth.begin_authorization()
        parsed = urlsplit(first["authorization_url"])
        query = parse_qs(parsed.query)

        self.assertEqual(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "https://connect.solaredge.com/authorize",
        )
        self.assertEqual(query["client_id"], ["client-id"])
        self.assertEqual(query["redirect_uri"], [self.config.redirect_uri])
        self.assertEqual(query["scope"], [" ".join(OAUTH_SCOPES)])
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["access_duration"], ["24"])
        self.assertEqual(query["state"], [first["state"]])
        self.assertNotEqual(first["state"], second["state"])

    def test_state_expires_after_ten_minutes_and_cannot_be_replayed(self) -> None:
        oauth = _OAuthStub(self.config, self.clock)
        started = oauth.begin_authorization()
        oauth.responses.append(
            {
                "access_token": "access",
                "refresh_token": "refresh",
                "expires_in": 7200,
            }
        )
        asyncio.run(oauth.handle_callback("code", "4211658", started["state"]))
        with self.assertRaisesRegex(SolarEdgeAuthorizationError, "already used"):
            asyncio.run(oauth.handle_callback("code", "4211658", started["state"]))

        expired = oauth.begin_authorization()
        self.clock.value += 601
        with self.assertRaisesRegex(SolarEdgeAuthorizationError, "expired"):
            asyncio.run(oauth.handle_callback("code", "4211658", expired["state"]))

    def test_exchange_is_form_shaped_including_exact_redirect_and_site(self) -> None:
        oauth = _OAuthStub(self.config, self.clock)
        started = oauth.begin_authorization()
        oauth.responses.append(
            {
                "access_token": "access-value",
                "refresh_token": "refresh-value",
                "expires_in": 7200,
                "refresh_expires_in": 2592000,
                "scope": "SITE_DATA DEVICE_DATA",
            }
        )
        result = asyncio.run(
            oauth.handle_callback("secret-code", "4211658", started["state"])
        )
        self.assertEqual(
            oauth.forms[0],
            {
                "grant_type": "authorization_code",
                "code": "secret-code",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "redirect_uri": self.config.redirect_uri,
                "site_id": "4211658",
            },
        )
        self.assertTrue(result["authorized"])
        self.assertEqual(result["site_id"], "4211658")
        rendered = json.dumps(result)
        self.assertNotIn("access-value", rendered)
        self.assertNotIn("refresh-value", rendered)
        self.assertNotIn("client-secret", rendered)

    def test_token_file_is_encrypted_and_owner_only_where_supported(self) -> None:
        oauth = _OAuthStub(self.config, self.clock)
        oauth._store.save(
            {
                "access_token": "must-not-be-plaintext",
                "refresh_token": "also-secret",
                "site_id": "4211658",
            }
        )
        raw = self.config.token_store_path.read_bytes()
        self.assertNotIn(b"must-not-be-plaintext", raw)
        self.assertNotIn(b"also-secret", raw)
        self.assertEqual(oauth._store.load()["access_token"], "must-not-be-plaintext")
        if os.name != "nt":
            self.assertEqual(
                stat.S_IMODE(self.config.token_store_path.stat().st_mode), 0o600
            )

    def test_refresh_rotates_pair_atomically_and_preserves_old_store_on_failure(self) -> None:
        oauth = self.authorized_oauth()
        before = self.config.token_store_path.read_bytes()
        oauth.responses.append(SolarEdgeAuthorizationError("provider failed"))
        with self.assertRaises(SolarEdgeAuthorizationError):
            asyncio.run(oauth.refresh(force=True))
        self.assertEqual(self.config.token_store_path.read_bytes(), before)
        self.assertEqual(oauth._store.load()["refresh_token"], "refresh-one")

        oauth.responses.append(
            {
                "access_token": "access-two",
                "refresh_token": "refresh-two",
                "expires_in": 7200,
            }
        )
        refreshed = asyncio.run(oauth.refresh(force=True))
        self.assertEqual(refreshed["access_token"], "access-two")
        self.assertEqual(refreshed["refresh_token"], "refresh-two")
        self.assertEqual(oauth._store.load()["refresh_token"], "refresh-two")
        self.assertEqual(
            oauth.forms[-1],
            {
                "grant_type": "refresh_token",
                "refresh_token": "refresh-one",
                "client_id": "client-id",
                "client_secret": "client-secret",
            },
        )

    def test_access_and_refresh_expiry_are_bounded_to_provider_lifetimes(self) -> None:
        oauth = _OAuthStub(self.config, self.clock)
        started = oauth.begin_authorization()
        oauth.responses.append(
            {
                "access_token": "access",
                "refresh_token": "refresh",
                "expires_in": 999999,
                "refresh_expires_in": 99999999,
            }
        )
        asyncio.run(oauth.handle_callback("code", "4211658", started["state"]))
        stored = oauth._store.load()
        self.assertEqual(stored["expires_at"], self.clock.value + 7200)
        self.assertEqual(stored["refresh_expires_at"], self.clock.value + 2592000)

    def test_invalid_redirect_and_path_injection_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            SolarEdgeConfig(
                client_id="id",
                client_secret="secret",
                redirect_uri="http://example.test/callback",
                token_store_path=self.root / "x",
                encryption_key=Fernet.generate_key(),
            )
        oauth = self.authorized_oauth()
        client = _ClientStub(self.config, oauth, [])
        with self.assertRaisesRegex(ValueError, "device_id"):
            asyncio.run(client.meter_import_power("../private"))


class ClientTests(SolarEdgeTestCase):
    def test_all_fixed_basic_paths(self) -> None:
        oauth = self.authorized_oauth()
        responses = [(200, {}, {"ok": True})] * 9
        client = _ClientStub(self.config, oauth, responses)
        asyncio.run(client.site_overview())
        asyncio.run(client.energy(startTime="2026-08-01"))
        asyncio.run(client.power())
        asyncio.run(client.performance())
        asyncio.run(client.alerts())
        asyncio.run(client.inventory())
        asyncio.run(client.inverter_telemetry())
        asyncio.run(client.meter_telemetry())
        asyncio.run(client.storage_telemetry())
        self.assertEqual(
            [item[0] for item in client.gets],
            [
                "/sites/4211658/overview",
                "/sites/4211658/energy",
                "/sites/4211658/power",
                "/sites/4211658/overview/performance",
                "/sites/4211658/alerts",
                "/sites/4211658/devices",
                "/sites/4211658/inverters/telemetry",
                "/sites/4211658/meters/telemetry",
                "/sites/4211658/storage/telemetry",
            ],
        )
        self.assertTrue(all(item[2] == "access-one" for item in client.gets))
        self.assertEqual(client.gets[1][1], {"startTime": "2026-08-01"})

    def test_fixed_meter_and_storage_measurement_paths(self) -> None:
        oauth = self.authorized_oauth()
        responses = [(200, {}, {"value": 1})] * 10
        client = _ClientStub(self.config, oauth, responses)
        calls = [
            client.meter_import_power("meter-A"),
            client.meter_import_energy("meter-A"),
            client.meter_export_power("meter-A"),
            client.meter_export_energy("meter-A"),
            client.storage_charge_power("battery-A"),
            client.storage_charge_energy("battery-A"),
            client.storage_discharge_power("battery-A"),
            client.storage_discharge_energy("battery-A"),
            client.storage_state_of_energy("battery-A"),
            client.storage_remaining_energy("battery-A"),
        ]
        for call in calls:
            asyncio.run(call)
        self.assertEqual(
            [path for path, _, _ in client.gets],
            [
                "/sites/4211658/meters/meter-A/import-power",
                "/sites/4211658/meters/meter-A/import-energy",
                "/sites/4211658/meters/meter-A/export-power",
                "/sites/4211658/meters/meter-A/export-energy",
                "/sites/4211658/storage/battery-A/charge-power",
                "/sites/4211658/storage/battery-A/charge-energy",
                "/sites/4211658/storage/battery-A/discharge-power",
                "/sites/4211658/storage/battery-A/discharge-energy",
                "/sites/4211658/storage/battery-A/state-of-energy",
                "/sites/4211658/storage/battery-A/remaining-energy",
            ],
        )

    def test_401_forces_one_refresh_then_retries_once(self) -> None:
        oauth = self.authorized_oauth()
        oauth.responses.append(
            {
                "access_token": "access-two",
                "refresh_token": "refresh-two",
                "expires_in": 7200,
            }
        )
        client = _ClientStub(
            self.config,
            oauth,
            [(401, {}, {"error": "unauthorized"}), (200, {}, {"power": 42})],
        )
        result = asyncio.run(client.power())
        self.assertEqual(result, {"power": 42})
        self.assertEqual([item[2] for item in client.gets], ["access-one", "access-two"])
        self.assertEqual(len(oauth.forms), 1)

    def test_second_401_is_not_retried_or_leaked(self) -> None:
        oauth = self.authorized_oauth()
        oauth.responses.append(
            {
                "access_token": "access-two",
                "refresh_token": "refresh-two",
                "expires_in": 7200,
            }
        )
        client = _ClientStub(
            self.config,
            oauth,
            [(401, {}, {"token": "do-not-leak"}), (401, {}, {"token": "still-secret"})],
        )
        with self.assertRaisesRegex(Exception, r"\(401\)") as error:
            asyncio.run(client.power())
        self.assertNotIn("do-not-leak", str(error.exception))
        self.assertNotIn("still-secret", str(error.exception))
        self.assertEqual(len(client.gets), 2)

    def test_429_honors_short_retry_once_and_reports_long_wait(self) -> None:
        oauth = self.authorized_oauth()
        sleeps = []

        async def record_sleep(value):
            sleeps.append(value)

        client = _ClientStub(
            self.config,
            oauth,
            [(429, {"Retry-After": "2"}, {}), (200, {}, {"ok": True})],
            sleep=record_sleep,
        )
        self.assertEqual(asyncio.run(client.power()), {"ok": True})
        self.assertEqual(sleeps, [2.0])

        client = _ClientStub(
            self.config,
            oauth,
            [(429, {"Retry-After": "60"}, {})],
            sleep=record_sleep,
        )
        with self.assertRaises(SolarEdgeRateLimitError) as error:
            asyncio.run(client.power())
        self.assertEqual(error.exception.retry_after, 60.0)

    def test_cache_prevents_duplicate_provider_call_and_expires(self) -> None:
        oauth = self.authorized_oauth()
        monotonic = _Clock(100)
        client = _ClientStub(
            self.config,
            oauth,
            [(200, {}, {"power": 1}), (200, {}, {"power": 2})],
            clock=monotonic,
        )
        self.assertEqual(asyncio.run(client.power()), {"power": 1})
        self.assertEqual(asyncio.run(client.power()), {"power": 1})
        first = asyncio.run(client.power())
        first["power"] = 999
        self.assertEqual(asyncio.run(client.power()), {"power": 1})
        self.assertEqual(len(client.gets), 1)
        monotonic.value += 61
        self.assertEqual(asyncio.run(client.power()), {"power": 2})
        self.assertEqual(len(client.gets), 2)

    def test_result_sanitization_removes_address_serials_and_secrets(self) -> None:
        raw = {
            "site": {
                "name": "Home",
                "address": "private",
                "location": {"latitude": 1, "longitude": 2},
                "energy": 123.4,
            },
            "devices": [
                {
                    "serialNumber": "private-serial",
                    "deviceSN": "another-private-serial",
                    "sn": "also-private",
                    "type": "METER",
                    "status": "ACTIVE",
                    "power": 5,
                }
            ],
            "access_token": "secret-token",
        }
        cleaned = sanitize_solaredge_result(raw)
        rendered = json.dumps(cleaned)
        for private in (
            "private-serial",
            "another-private-serial",
            "also-private",
            "private",
            "secret-token",
        ):
            self.assertNotIn(private, rendered)
        self.assertEqual(cleaned["site"]["energy"], 123.4)
        self.assertEqual(cleaned["devices"][0]["type"], "METER")
        self.assertEqual(cleaned["devices"][0]["status"], "ACTIVE")
        self.assertEqual(cleaned["devices"][0]["power"], 5)

    def test_provider_host_is_not_configurable(self) -> None:
        oauth = self.authorized_oauth()
        client = _ClientStub(self.config, oauth, [(200, {}, {})])
        asyncio.run(client.power())
        self.assertEqual(API_BASE_URL, "https://monitoringapi.solaredge.com/v2")
        self.assertEqual(client.gets[0][0], "/sites/4211658/power")


if __name__ == "__main__":
    unittest.main()
