from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Sequence
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import aiohttp


_OAUTH_CLIENT_ID = "ugfnsujd3384sshcjehaphlh3"
_OAUTH_REDIRECT_URI = "https://monitoring.solaredge.com/mfe/auth/callback"
_OAUTH_AUTHORIZE_URL = "https://login.solaredge.com/oauth2/authorize"
_OAUTH_TOKEN_URL = "https://login.solaredge.com/oauth2/token"
_AUTH_EXCHANGE_URL = "https://monitoring.solaredge.com/services/auth/token?legacy=false"
_DASHBOARD_BASE_URL = "https://monitoring.solaredge.com/services/dashboard"

_LOGIN_HOST = "login.solaredge.com"
_MONITORING_HOST = "monitoring.solaredge.com"
_LOGIN_REFRESH_SECONDS = 3600
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_HISTORY_DAYS = 3660
_MAX_QUARTER_HOUR_DAYS = 31
_SAFE_SITE_ID = re.compile(r"^[0-9]{1,32}$")
_FORM_RE = re.compile(r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE)
_INPUT_RE = re.compile(r"<input[^>]+>", re.IGNORECASE)
_NAME_RE = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)
_VALUE_RE = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)
_CHART_UNITS = {"quarter-hours", "days", "months", "years"}
_MEASUREMENT_TYPES = (
    "production",
    "yield",
    "consumption",
    "production-distribution-with-storage",
    "consumption-distribution-with-storage",
    "import",
    "export",
)
_POWER_FLOW_COMPONENTS = (
    "grid",
    "consumption",
    "ac-storage",
    "dc-storage",
    "ev-charger",
)
_PRIVATE_KEYS = {
    "address",
    "city",
    "country",
    "email",
    "latitude",
    "location",
    "longitude",
    "phone",
    "postalcode",
    "serial",
    "serialnumber",
    "siteid",
    "sn",
    "street",
    "username",
    "zip",
    "zipcode",
}
_SECRET_KEYS = {
    "accesstoken",
    "authorization",
    "clientsecret",
    "code",
    "password",
    "refreshtoken",
    "secret",
    "token",
}


class SolarEdgePortalError(RuntimeError):
    """A deliberately non-sensitive portal error."""


class SolarEdgePortalAuthenticationError(SolarEdgePortalError):
    pass


@dataclass(frozen=True, slots=True)
class SolarEdgePortalConfig:
    username: str
    password: str
    site_id: str
    timezone_name: str
    timeout_seconds: float = 20.0
    cache_ttl_seconds: float = 60.0
    max_response_bytes: int = _MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if not self.username or not self.password:
            raise ValueError("SolarEdge portal credentials are required")
        _validate_site_id(self.site_id)
        try:
            ZoneInfo(self.timezone_name)
        except ZoneInfoNotFoundError as exc:
            # Windows Python does not bundle the IANA database. The deployed
            # Linux image does; retain an exact fallback only for this home's
            # configured timezone so an arbitrary misspelling is still rejected.
            if self.timezone_name not in {"UTC", "America/Los_Angeles"}:
                raise ValueError("SolarEdge portal timezone is invalid") from exc
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds cannot be negative")
        if not 1024 <= self.max_response_bytes <= 8 * 1024 * 1024:
            raise ValueError("max_response_bytes is outside the safe range")

    @classmethod
    def from_secret_files(
        cls,
        *,
        username_file: Path,
        password_file: Path,
        site_id_file: Path,
        timezone_name: str,
        **kwargs: Any,
    ) -> SolarEdgePortalConfig:
        return cls(
            username=_read_secret(username_file, "username"),
            password=_read_secret(password_file, "password"),
            site_id=_read_secret(site_id_file, "site ID"),
            timezone_name=timezone_name,
            **kwargs,
        )

    @classmethod
    def from_env(cls) -> SolarEdgePortalConfig:
        """Load only secret-file references; plaintext credential env vars are unsupported."""
        return cls.from_secret_files(
            username_file=Path(_required_env("SOLAREDGE_PORTAL_USERNAME_FILE")),
            password_file=Path(_required_env("SOLAREDGE_PORTAL_PASSWORD_FILE")),
            site_id_file=Path(_required_env("SOLAREDGE_PORTAL_SITE_ID_FILE")),
            timezone_name=_required_env("SOLAREDGE_PORTAL_TIMEZONE"),
        )


class SolarEdgePortalClient:
    """Hardened read-only client for a fixed SolarEdge dashboard endpoint set."""

    def __init__(
        self,
        config: SolarEdgePortalConfig | None = None,
        *,
        session: aiohttp.ClientSession | None = None,
        now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config or SolarEdgePortalConfig.from_env()
        self._session = session
        self._owns_session = session is None
        self._now = now or (lambda: datetime.now(UTC))
        self._monotonic = monotonic
        self._login_lock = asyncio.Lock()
        self._authorization_header: str | None = None
        self._last_login_monotonic = 0.0
        self._last_success_at: datetime | None = None
        self._cache: dict[str, tuple[float, Any]] = {}

    async def close(self) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

    async def capabilities(self) -> dict[str, Any]:
        payload = await self._dashboard_get(
            "site capabilities", f"/site-details/{self.config.site_id}/components"
        )
        safe = _sanitize(payload)
        return {
            "has_production": _find_bool(safe, "hasProduction"),
            "has_consumption_and_grid": _find_bool(safe, "hasConsumptionAndGrid"),
            "has_storage": _find_bool(safe, "hasStorage"),
            "has_ac_storage": _find_bool(safe, "hasAcStorage"),
            "has_dc_storage": _find_bool(safe, "hasDcStorage"),
        }

    async def live_power(self) -> dict[str, Any]:
        payload = await self._dashboard_get(
            "live power", f"/live-power/sites/{self.config.site_id}"
        )
        return _normalize_power_payload(payload)

    async def live_power_flow(self) -> dict[str, Any]:
        params = [("components", component) for component in _POWER_FLOW_COMPONENTS]
        payload = await self._dashboard_get(
            "power flow", f"/power-flow/v2/sites/{self.config.site_id}", params
        )
        normalized = _normalize_power_payload(payload)
        storage_operating_plan = _storage_operating_plan_summary(normalized)
        return {
            "components": {
                public_name: _component(normalized, provider_name)
                for public_name, provider_name in (
                    ("solar_production", "solarProduction"),
                    ("consumption", "consumption"),
                    ("grid", "grid"),
                    ("ac_storage", "acStorage"),
                    ("dc_storage", "dcStorage"),
                    ("ev_charger", "evCharger"),
                )
                if _component(normalized, provider_name) is not None
            },
            "last_update_time": _latest_timestamp(normalized),
            "storage_operating_plan": storage_operating_plan,
        }

    async def completed_energy_summary(
        self, days: int = 7, *, as_of: date | None = None
    ) -> dict[str, Any]:
        if not 1 <= days <= 366:
            raise ValueError("days must be between 1 and 366")
        local_today = as_of or self._local_today()
        end_date = local_today - timedelta(days=1)
        start_date = end_date - timedelta(days=days - 1)
        result = await self.energy_history(start_date, end_date, chart_time_unit="days")
        result["window_type"] = "completed_local_dates"
        result["expected_days"] = days
        result["timezone"] = self.config.timezone_name
        return result

    async def current_day_energy_summary(
        self, *, local_date: date | None = None
    ) -> dict[str, Any]:
        selected = local_date or self._local_today()
        result = await self.energy_history(
            selected, selected, chart_time_unit="quarter-hours"
        )
        result["window_type"] = "current_local_date"
        result["timezone"] = self.config.timezone_name
        return result

    async def lifetime_energy_summary(self) -> dict[str, Any]:
        """Return cumulative Energy totals using the portal's proven lifetime query."""
        start_date = date(2000, 1, 1)
        end_date = self._local_today()
        result = await self._energy_request(
            start_date, end_date, chart_time_unit="years", allow_lifetime=True
        )
        result["window_type"] = "lifetime_through_current_local_date"
        result["timezone"] = self.config.timezone_name
        return result

    async def energy_history(
        self,
        start_date: date,
        end_date: date,
        *,
        chart_time_unit: str = "days",
    ) -> dict[str, Any]:
        return await self._energy_request(
            start_date, end_date, chart_time_unit=chart_time_unit, allow_lifetime=False
        )

    async def _energy_request(
        self,
        start_date: date,
        end_date: date,
        *,
        chart_time_unit: str,
        allow_lifetime: bool,
    ) -> dict[str, Any]:
        _validate_date_window(
            start_date, end_date, chart_time_unit, allow_lifetime=allow_lifetime
        )
        params: list[tuple[str, str]] = [
            ("chart-time-unit", chart_time_unit),
            ("start-date", start_date.isoformat()),
            ("end-date", end_date.isoformat()),
            *(("measurement-types", value) for value in _MEASUREMENT_TYPES),
            ("isCniViewer", "true"),
        ]
        payload = await self._dashboard_get(
            "energy history", f"/energy/sites/{self.config.site_id}", params
        )
        normalized = _normalize_energy_payload(payload)
        return {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "chart_time_unit": chart_time_unit,
            "totals_kwh": {
                name: _find_number(normalized, f"{name}_kwh")
                for name in ("production", "consumption", "import", "export")
                if _find_number(normalized, f"{name}_kwh") is not None
            },
            "production_distribution": _find_key(normalized, "productionDistribution"),
            "consumption_distribution": _find_key(
                normalized, "consumptionDistribution"
            ),
            "chart": _find_key(normalized, "chart"),
            "provider_timestamp": _latest_timestamp(normalized),
        }

    async def storage_distribution(
        self, start_date: date, end_date: date
    ) -> dict[str, Any]:
        _validate_date_window(start_date, end_date, "days")
        payload = await self._dashboard_get(
            "storage distribution",
            f"/storage/energy/distribution/sites/{self.config.site_id}",
            [
                ("start-date", start_date.isoformat()),
                ("end-date", end_date.isoformat()),
            ],
        )
        return {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "distribution": _normalize_energy_payload(payload),
        }

    async def battery_storage_state(
        self, from_time: datetime, to_time: datetime
    ) -> dict[str, Any]:
        start, end = _validate_datetime_window(from_time, to_time)
        payload = await self._dashboard_get(
            "battery storage state",
            f"/battery/sites/{self.config.site_id}/storage-state",
            [("from", _iso_z(start)), ("to", _iso_z(end))],
        )
        return _normalize_battery_payload(payload)

    async def battery_energy(self, start_date: date, end_date: date) -> dict[str, Any]:
        _validate_date_window(start_date, end_date, "days")
        payload = await self._dashboard_get(
            "battery energy",
            f"/battery/sites/{self.config.site_id}",
            [
                ("start-date", start_date.isoformat()),
                ("end-date", end_date.isoformat()),
            ],
        )
        return _normalize_battery_payload(payload)

    async def provider_health(self, *, refresh: bool = False) -> dict[str, Any]:
        try:
            capabilities = await self.capabilities() if refresh else None
        except SolarEdgePortalError as exc:
            return {
                "configured": True,
                "reachable": False,
                "authenticated": self._authorization_header is not None,
                "error_type": type(exc).__name__,
            }
        return {
            "configured": True,
            "reachable": self._last_success_at is not None or capabilities is not None,
            "authenticated": self._authorization_header is not None,
            "last_success_at": self._last_success_at.isoformat()
            if self._last_success_at
            else None,
            "cache_entries": len(self._cache),
            "capabilities": capabilities,
        }

    async def _dashboard_get(
        self,
        operation: str,
        path: str,
        params: Sequence[tuple[str, str]] | None = None,
    ) -> Any:
        if not path.startswith("/") or ".." in path:
            raise ValueError("SolarEdge portal endpoint is invalid")
        cache_key = json.dumps(
            [operation, path, list(params or ())], separators=(",", ":")
        )
        cached = self._cache.get(cache_key)
        now = self._monotonic()
        if cached and cached[0] > now:
            return _deep_copy(cached[1])

        await self._ensure_login()
        payload = await self._authenticated_get(operation, path, params)
        self._cache[cache_key] = (
            now + self.config.cache_ttl_seconds,
            _deep_copy(payload),
        )
        return payload

    async def _authenticated_get(
        self,
        operation: str,
        path: str,
        params: Sequence[tuple[str, str]] | None,
    ) -> Any:
        for attempt in range(2):
            response = await self._request(
                "GET",
                f"{_DASHBOARD_BASE_URL}{path}",
                params=params,
                headers=self._auth_headers(),
                allow_redirects=False,
            )
            async with response:
                if response.status in {401, 403} and attempt == 0:
                    self._invalidate_login()
                    await self._ensure_login(force=True)
                    continue
                if 300 <= response.status < 400:
                    raise SolarEdgePortalError(
                        f"SolarEdge portal {operation} returned an unsafe redirect"
                    )
                if response.status >= 400:
                    raise SolarEdgePortalError(
                        f"SolarEdge portal {operation} failed ({response.status})"
                    )
                payload = await self._read_json(response, operation)
                self._last_success_at = self._now().astimezone(UTC)
                return payload
        raise SolarEdgePortalAuthenticationError(
            "SolarEdge portal authentication was rejected"
        )

    async def _ensure_login(self, *, force: bool = False) -> None:
        if not force and self._login_is_fresh():
            return
        async with self._login_lock:
            if not force and self._login_is_fresh():
                return
            self._invalidate_login()
            await self._login()

    async def _login(self) -> None:
        verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .rstrip(b"=")
            .decode("ascii")
        )
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        auth_url = f"{_OAUTH_AUTHORIZE_URL}?{urlencode({'client_id': _OAUTH_CLIENT_ID, 'response_type': 'code', 'redirect_uri': _OAUTH_REDIRECT_URI, 'code_challenge': challenge, 'code_challenge_method': 'S256'})}"

        response = await self._request("GET", auth_url, allow_redirects=True)
        async with response:
            self._validate_login_redirect_chain(response)
            code = self._extract_authorization_code(response)
            if code is None:
                page = await self._read_text(response, "login page")
                action, form_data = self._parse_login_form(page, str(response.url))
                form_data["username"] = self.config.username
                form_data["password"] = self.config.password
                response = await self._request(
                    "POST", action, data=form_data, allow_redirects=True
                )
                async with response:
                    self._validate_login_redirect_chain(response)
                    code = self._extract_authorization_code(response)
        if code is None:
            raise SolarEdgePortalAuthenticationError(
                "SolarEdge portal did not complete authorization"
            )

        response = await self._request(
            "POST",
            _OAUTH_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": _OAUTH_CLIENT_ID,
                "redirect_uri": _OAUTH_REDIRECT_URI,
                "code": code,
                "code_verifier": verifier,
            },
            allow_redirects=False,
        )
        async with response:
            if response.status >= 400:
                raise SolarEdgePortalAuthenticationError(
                    f"SolarEdge portal token exchange failed ({response.status})"
                )
            token_payload = await self._read_json(response, "token exchange")
        access_token = (
            token_payload.get("access_token")
            if isinstance(token_payload, Mapping)
            else None
        )
        if not isinstance(access_token, str) or not access_token:
            raise SolarEdgePortalAuthenticationError(
                "SolarEdge portal token exchange was invalid"
            )

        authorization_header = f"Bearer {access_token}"
        response = await self._request(
            "POST",
            _AUTH_EXCHANGE_URL,
            json_body=token_payload,
            headers={"Authorization": authorization_header},
            allow_redirects=False,
        )
        async with response:
            if response.status >= 400:
                raise SolarEdgePortalAuthenticationError(
                    f"SolarEdge portal session exchange failed ({response.status})"
                )
            await self._drain_bounded(response, "session exchange")
        self._authorization_header = authorization_header
        self._last_login_monotonic = self._monotonic()

    def _parse_login_form(
        self, page: str, current_url: str
    ) -> tuple[str, dict[str, str]]:
        action_match = _FORM_RE.search(page)
        action = html.unescape(action_match.group(1)) if action_match else current_url
        resolved = urljoin(current_url, action)
        _validate_login_url(resolved)
        form_data: dict[str, str] = {}
        for input_match in _INPUT_RE.finditer(page):
            attributes = input_match.group(0)
            name_match = _NAME_RE.search(attributes)
            if not name_match:
                continue
            value_match = _VALUE_RE.search(attributes)
            form_data[html.unescape(name_match.group(1))] = (
                html.unescape(value_match.group(1)) if value_match else ""
            )
        return resolved, form_data

    def _extract_authorization_code(
        self, response: aiohttp.ClientResponse
    ) -> str | None:
        for candidate in [*response.history, response]:
            parsed = urlsplit(str(candidate.url))
            if (parsed.scheme, parsed.hostname, parsed.path) != (
                "https",
                _MONITORING_HOST,
                "/mfe/auth/callback",
            ):
                continue
            if parsed.port not in (None, 443):
                raise SolarEdgePortalAuthenticationError(
                    "SolarEdge portal returned an invalid authorization redirect"
                )
            query = parse_qs(parsed.query)
            if "error" in query:
                raise SolarEdgePortalAuthenticationError(
                    "SolarEdge portal authorization was denied"
                )
            code = query.get("code", [None])[0]
            if isinstance(code, str) and 0 < len(code) <= 4096:
                return code
        return None

    def _validate_login_redirect_chain(self, response: aiohttp.ClientResponse) -> None:
        for candidate in [*response.history, response]:
            parsed = urlsplit(str(candidate.url))
            if parsed.scheme != "https" or parsed.username or parsed.password:
                raise SolarEdgePortalAuthenticationError(
                    "SolarEdge portal returned an unsafe login redirect"
                )
            if parsed.hostname not in {
                _LOGIN_HOST,
                _MONITORING_HOST,
            } or parsed.port not in (None, 443):
                raise SolarEdgePortalAuthenticationError(
                    "SolarEdge portal returned an untrusted login redirect"
                )

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: Sequence[tuple[str, str]] | None = None,
        data: Mapping[str, str] | None = None,
        json_body: Any | None = None,
        headers: Mapping[str, str] | None = None,
        allow_redirects: bool,
    ) -> aiohttp.ClientResponse:
        session = await self._get_session()
        try:
            return await session.request(
                method,
                url,
                params=params,
                data=data,
                json=json_body,
                headers=headers,
                allow_redirects=allow_redirects,
                timeout=aiohttp.ClientTimeout(
                    total=self.config.timeout_seconds, connect=5
                ),
            )
        except asyncio.TimeoutError as exc:
            raise SolarEdgePortalError("SolarEdge portal request timed out") from exc
        except aiohttp.ClientError as exc:
            raise SolarEdgePortalError("SolarEdge portal request failed") from exc

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                cookie_jar=aiohttp.CookieJar(), raise_for_status=False
            )
        return self._session

    async def _read_text(self, response: aiohttp.ClientResponse, operation: str) -> str:
        data = await self._read_bounded(response, operation)
        try:
            return data.decode(response.charset or "utf-8", errors="strict")
        except (LookupError, UnicodeDecodeError) as exc:
            raise SolarEdgePortalError(
                f"SolarEdge portal {operation} returned invalid text"
            ) from exc

    async def _read_json(self, response: aiohttp.ClientResponse, operation: str) -> Any:
        data = await self._read_bounded(response, operation)
        try:
            return json.loads(data.decode("utf-8")) if data else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SolarEdgePortalError(
                f"SolarEdge portal {operation} returned invalid JSON"
            ) from exc

    async def _drain_bounded(
        self, response: aiohttp.ClientResponse, operation: str
    ) -> None:
        await self._read_bounded(response, operation)

    async def _read_bounded(
        self, response: aiohttp.ClientResponse, operation: str
    ) -> bytes:
        content_length = response.content_length
        if (
            content_length is not None
            and content_length > self.config.max_response_bytes
        ):
            raise SolarEdgePortalError(
                f"SolarEdge portal {operation} response was too large"
            )
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.content.iter_chunked(64 * 1024):
            size += len(chunk)
            if size > self.config.max_response_bytes:
                raise SolarEdgePortalError(
                    f"SolarEdge portal {operation} response was too large"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    def _auth_headers(self) -> dict[str, str]:
        if self._authorization_header is None:
            raise SolarEdgePortalAuthenticationError(
                "SolarEdge portal session is unavailable"
            )
        headers = {"Authorization": self._authorization_header}
        session = self._session
        if session is not None:
            for cookie in session.cookie_jar:
                if cookie.key == "CSRF-TOKEN" and cookie["domain"] == _MONITORING_HOST:
                    headers["X-CSRF-TOKEN"] = cookie.value
                    break
        return headers

    def _login_is_fresh(self) -> bool:
        return (
            self._authorization_header is not None
            and self._monotonic() - self._last_login_monotonic < _LOGIN_REFRESH_SECONDS
        )

    def _invalidate_login(self) -> None:
        self._authorization_header = None
        self._last_login_monotonic = 0.0

    def _local_today(self) -> date:
        return _local_date(self._now(), self.config.timezone_name)


def _normalize_power_payload(payload: Any) -> dict[str, Any]:
    return _normalize_measurements(_sanitize(payload), inherited_unit="power")


def _normalize_energy_payload(payload: Any) -> dict[str, Any]:
    return _normalize_measurements(_sanitize(payload), inherited_unit="energy")


def _normalize_battery_payload(payload: Any) -> dict[str, Any]:
    return _normalize_measurements(_sanitize(payload), inherited_unit=None)


def _normalize_measurements(value: Any, *, inherited_unit: str | None) -> Any:
    if isinstance(value, Mapping):
        measurement_type = value.get("type") or value.get("measurementType")
        mapping_unit = (
            None
            if isinstance(measurement_type, str)
            and _normalized_key(measurement_type) == "yield"
            else inherited_unit
        )
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = _normalized_key(str(key))
            unit = _unit_for_key(normalized, mapping_unit)
            output_key = (
                _unit_key(str(key), unit)
                if isinstance(item, (int, float))
                else str(key)
            )
            result[output_key] = _normalize_measurements(item, inherited_unit=unit)
        return result
    if isinstance(value, list):
        return [
            _normalize_measurements(item, inherited_unit=inherited_unit)
            for item in value
        ]
    if isinstance(value, tuple):
        return [
            _normalize_measurements(item, inherited_unit=inherited_unit)
            for item in value
        ]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if inherited_unit == "power":
            return round(float(value) * 1000.0, 3)
        if inherited_unit == "energy":
            return round(float(value) / 1000.0, 6)
    return value


def _unit_for_key(key: str, inherited: str | None) -> str | None:
    if key in {"stateofcharge", "stateofenergy"} or any(
        marker in key
        for marker in (
            "timestamp",
            "time",
            "date",
            "percent",
            "ratio",
            "level",
            "soc",
            "count",
        )
    ):
        return None
    if "power" in key:
        return "power"
    if "energy" in key:
        return "energy"
    if key == "yield":
        return None
    if any(
        marker in key
        for marker in (
            "production",
            "consumption",
            "import",
            "export",
            "charge",
            "discharge",
        )
    ):
        return inherited or "energy"
    if key in {"values", "value", "data", "measurements", "chart"}:
        return inherited
    return inherited if key in {"solar", "grid", "storage", "battery"} else None


def _unit_key(key: str, unit: str | None) -> str:
    if unit is None:
        return key
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", key).replace("-", "_").casefold()
    suffix = "_w" if unit == "power" else "_kwh"
    return snake if snake.endswith(suffix) else f"{snake}{suffix}"


def _component(payload: Mapping[str, Any], provider_name: str) -> dict[str, Any] | None:
    value = _find_key(payload, provider_name)
    if not isinstance(value, Mapping):
        return None
    return {
        key: item
        for key, item in value.items()
        if _normalized_key(key)
        in {
            "currentpowerw",
            "powerw",
            "status",
            "direction",
            "chargelevel",
            "stateofcharge",
            "lastupdatetime",
            "timestamp",
        }
    }


def _storage_operating_plan_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return only non-sensitive current storage-plan metadata from power flow."""
    raw_plan = _find_key(payload, "storagePlan")
    plan_scope = raw_plan if isinstance(raw_plan, Mapping) else payload

    plan_name: str | None = None
    if isinstance(raw_plan, str):
        candidate = raw_plan.strip()
        if candidate and len(candidate) <= 128:
            plan_name = candidate
    elif isinstance(raw_plan, Mapping):
        for wanted in ("plan", "name", "type", "mode"):
            candidate = next(
                (
                    value
                    for key, value in raw_plan.items()
                    if _normalized_key(str(key)) == _normalized_key(wanted)
                ),
                None,
            )
            if isinstance(candidate, str):
                candidate = candidate.strip()
                if candidate and len(candidate) <= 128:
                    plan_name = candidate
                    break

    active = _find_key(plan_scope, "isActive")
    if not isinstance(active, bool) and plan_scope is not payload:
        active = _find_key(payload, "isActive")

    block_count = _find_number(plan_scope, "blockCount")
    if block_count is None and plan_scope is not payload:
        block_count = _find_number(payload, "blockCount")

    summary: dict[str, Any] = {}
    if plan_name is not None:
        summary["plan"] = plan_name
    if isinstance(active, bool):
        summary["is_active"] = active
    if block_count is not None and block_count >= 0 and block_count.is_integer():
        summary["block_count"] = int(block_count)
    return summary


def _sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = _normalized_key(str(key))
            if _private_or_secret_key(normalized):
                continue
            result[str(key)] = _sanitize(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    return value


def _private_or_secret_key(key: str) -> bool:
    return (
        key in _PRIVATE_KEYS
        or key in _SECRET_KEYS
        or "address" in key
        or "accesstoken" in key
        or "refreshtoken" in key
        or key.endswith(("serial", "serialnumber", "devicesn"))
    )


def _find_key(value: Any, wanted: str) -> Any:
    if isinstance(value, Mapping):
        wanted_normalized = _normalized_key(wanted)
        for key, item in value.items():
            if _normalized_key(str(key)) == wanted_normalized:
                return item
        for item in value.values():
            found = _find_key(item, wanted)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_key(item, wanted)
            if found is not None:
                return found
    return None


def _find_number(value: Any, wanted: str) -> float | None:
    result = _find_key(value, wanted)
    if isinstance(result, (int, float)) and not isinstance(result, bool):
        return float(result)
    return None


def _find_bool(value: Any, wanted: str) -> bool:
    result = _find_key(value, wanted)
    return bool(result) if isinstance(result, bool) else False


def _latest_timestamp(value: Any) -> str | None:
    candidates: list[str] = []

    def collect(item: Any, key: str | None = None) -> None:
        if isinstance(item, Mapping):
            for child_key, child in item.items():
                collect(child, str(child_key))
        elif isinstance(item, list):
            for child in item:
                collect(child, key)
        elif (
            isinstance(item, str)
            and key
            and any(
                marker in _normalized_key(key)
                for marker in ("timestamp", "updatetime", "datetime")
            )
        ):
            candidates.append(item)

    collect(value)
    return max(candidates) if candidates else None


def _validate_site_id(value: str) -> None:
    if not isinstance(value, str) or not _SAFE_SITE_ID.fullmatch(value):
        raise ValueError("SolarEdge portal site ID is invalid")


def _validate_login_url(value: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != _LOGIN_HOST
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise SolarEdgePortalAuthenticationError(
            "SolarEdge portal login form target is untrusted"
        )


def _validate_date_window(
    start: date,
    end: date,
    chart_time_unit: str,
    *,
    allow_lifetime: bool = False,
) -> None:
    if not isinstance(start, date) or not isinstance(end, date):
        raise ValueError("SolarEdge portal dates are required")
    if chart_time_unit not in _CHART_UNITS:
        raise ValueError("SolarEdge portal chart_time_unit is invalid")
    if end < start:
        raise ValueError("SolarEdge portal end_date precedes start_date")
    days = (end - start).days + 1
    if days > _MAX_HISTORY_DAYS and not (
        allow_lifetime and start == date(2000, 1, 1) and chart_time_unit == "years"
    ):
        raise ValueError("SolarEdge portal history window is too large")
    if chart_time_unit == "quarter-hours" and days > _MAX_QUARTER_HOUR_DAYS:
        raise ValueError("Quarter-hour SolarEdge history is limited to 31 days")


def _validate_datetime_window(
    start: datetime, end: datetime
) -> tuple[datetime, datetime]:
    if not isinstance(start, datetime) or not isinstance(end, datetime):
        raise ValueError("SolarEdge portal timestamps are required")
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("SolarEdge portal timestamps require timezones")
    normalized_start = start.astimezone(UTC)
    normalized_end = end.astimezone(UTC)
    if normalized_end <= normalized_start:
        raise ValueError("SolarEdge portal end timestamp must be later")
    if normalized_end - normalized_start > timedelta(days=31):
        raise ValueError("SolarEdge battery state window is limited to 31 days")
    return normalized_start, normalized_end


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _local_date(value: datetime, timezone_name: str) -> date:
    try:
        return value.astimezone(ZoneInfo(timezone_name)).date()
    except ZoneInfoNotFoundError:
        if timezone_name == "UTC":
            return value.astimezone(UTC).date()
        if timezone_name != "America/Los_Angeles":
            raise ValueError("SolarEdge portal timezone is unavailable")
        utc_value = value.astimezone(UTC)
        year = utc_value.year
        march_first = date(year, 3, 1)
        second_sunday = 8 + ((6 - march_first.weekday()) % 7)
        november_first = date(year, 11, 1)
        first_sunday = 1 + ((6 - november_first.weekday()) % 7)
        dst_start = datetime(year, 3, second_sunday, 10, tzinfo=UTC)
        dst_end = datetime(year, 11, first_sunday, 9, tzinfo=UTC)
        offset = timedelta(hours=-7 if dst_start <= utc_value < dst_end else -8)
        return (utc_value + offset).date()


def _read_secret(path: Path, label: str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(
            f"SolarEdge portal {label} secret could not be read"
        ) from exc
    if not value:
        raise RuntimeError(f"SolarEdge portal {label} secret is empty")
    return value


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required setting: {name}")
    return value


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _deep_copy(value: Any) -> Any:
    return json.loads(json.dumps(value))
