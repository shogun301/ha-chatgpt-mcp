from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import quote, urlencode, urlsplit

import aiohttp
from cryptography.fernet import Fernet, InvalidToken


AUTHORIZATION_URL = "https://connect.solaredge.com/authorize"
API_BASE_URL = "https://monitoringapi.solaredge.com/v2"
TOKEN_URL = f"{API_BASE_URL}/oauth2/token"
REVOKE_URL = f"{API_BASE_URL}/oauth2/revoke-token"
OAUTH_SCOPES = ("SITE_DATA", "DEVICE_DATA")

_STATE_TTL_SECONDS = 10 * 60
_DEFAULT_ACCESS_LIFETIME_SECONDS = 2 * 60 * 60
_DEFAULT_REFRESH_LIFETIME_SECONDS = 30 * 24 * 60 * 60
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PRIVATE_KEYS = {
    "address",
    "city",
    "country",
    "email",
    "fulladdress",
    "latitude",
    "location",
    "longitude",
    "phone",
    "postalcode",
    "serial",
    "serialid",
    "serialnumber",
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
    "refreshtoken",
    "secret",
    "token",
}


class SolarEdgeError(RuntimeError):
    """Base error with messages that never contain SolarEdge secrets."""


class SolarEdgeAuthorizationError(SolarEdgeError):
    pass


class SolarEdgeRateLimitError(SolarEdgeError):
    def __init__(self, retry_after: float | None = None) -> None:
        self.retry_after = retry_after
        suffix = (
            f"; retry after {retry_after:g} seconds"
            if retry_after is not None
            else ""
        )
        super().__init__(f"SolarEdge rate limit exceeded{suffix}")


@dataclass(frozen=True, slots=True)
class SolarEdgeConfig:
    client_id: str
    client_secret: str
    redirect_uri: str
    token_store_path: Path
    encryption_key: str | bytes
    site_id: str | None = None
    timeout_seconds: float = 20.0
    cache_ttl_seconds: float = 60.0
    max_rate_limit_wait_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not self.client_id.strip() or not self.client_secret.strip():
            raise ValueError("SolarEdge client credentials are required")
        _validate_redirect_uri(self.redirect_uri)
        if self.site_id is not None:
            _validate_identifier(self.site_id, "site_id")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds cannot be negative")
        if self.max_rate_limit_wait_seconds < 0:
            raise ValueError("max_rate_limit_wait_seconds cannot be negative")
        try:
            Fernet(self.encryption_key)
        except (TypeError, ValueError) as exc:
            raise ValueError("SolarEdge encryption_key must be a Fernet key") from exc

    @classmethod
    def from_env(cls) -> SolarEdgeConfig:
        key = os.environ.get("SOLAREDGE_TOKEN_ENCRYPTION_KEY", "").strip()
        key_file = os.environ.get("SOLAREDGE_TOKEN_ENCRYPTION_KEY_FILE", "").strip()
        if not key and key_file:
            key = Path(key_file).read_text(encoding="utf-8").strip()
        return cls(
            client_id=_required_env("SOLAREDGE_CLIENT_ID"),
            client_secret=_required_env("SOLAREDGE_CLIENT_SECRET"),
            redirect_uri=_required_env("SOLAREDGE_REDIRECT_URI"),
            token_store_path=Path(_required_env("SOLAREDGE_TOKEN_STORE_PATH")),
            encryption_key=key,
            site_id=os.environ.get("SOLAREDGE_SITE_ID", "").strip() or None,
        )


class _EncryptedTokenStore:
    def __init__(self, path: Path, encryption_key: str | bytes) -> None:
        self.path = Path(path)
        self._fernet = Fernet(encryption_key)

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            decrypted = self._fernet.decrypt(self.path.read_bytes())
            value = json.loads(decrypted.decode("utf-8"))
        except (OSError, InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SolarEdgeAuthorizationError(
                "SolarEdge token storage could not be read"
            ) from exc
        if not isinstance(value, dict):
            raise SolarEdgeAuthorizationError("SolarEdge token storage is invalid")
        return value

    def save(self, value: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        payload = json.dumps(
            dict(value), separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        encrypted = self._fernet.encrypt(payload)
        temporary = self.path.with_name(
            f".{self.path.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            with temporary.open("xb") as stream:
                os.chmod(temporary, 0o600)
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        finally:
            if temporary.exists():
                temporary.unlink()

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class SolarEdgeOAuthManager:
    """SolarEdge Site Access OAuth with replay-safe state and encrypted tokens."""

    def __init__(
        self,
        config: SolarEdgeConfig | None = None,
        *,
        session: aiohttp.ClientSession | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.config = config or SolarEdgeConfig.from_env()
        self._store = _EncryptedTokenStore(
            self.config.token_store_path, self.config.encryption_key
        )
        self._session = session
        self._owns_session = session is None
        self._now = now
        self._states: dict[str, float] = {}
        self._refresh_lock = asyncio.Lock()

    async def close(self) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

    def begin_authorization(self) -> dict[str, Any]:
        now = self._now()
        self._prune_states(now)
        state = secrets.token_urlsafe(32)
        expires_at = now + _STATE_TTL_SECONDS
        self._states[state] = expires_at
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.config.client_id,
                "redirect_uri": self.config.redirect_uri,
                "scope": " ".join(OAUTH_SCOPES),
                "state": state,
                "access_duration": "24",
            }
        )
        return {
            "authorization_url": f"{AUTHORIZATION_URL}?{query}",
            "state": state,
            "expires_at": _isoformat(expires_at),
        }

    async def handle_callback(
        self, code: str, site_id: str, state: str
    ) -> dict[str, Any]:
        if not isinstance(code, str) or not code.strip() or len(code) > 4096:
            raise SolarEdgeAuthorizationError("SolarEdge authorization code is invalid")
        _validate_identifier(site_id, "site_id")
        self._consume_state(state)
        token = await self._post_token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "redirect_uri": self.config.redirect_uri,
                "site_id": site_id,
            }
        )
        stored = self._normalize_token(token, site_id=site_id)
        self._store.save(stored)
        return self.status()

    def status(self) -> dict[str, Any]:
        token = self._store.load()
        if token is None:
            return {
                "configured": True,
                "authorized": False,
                "scopes": list(OAUTH_SCOPES),
            }
        now = self._now()
        return {
            "configured": True,
            "authorized": bool(token.get("refresh_token")),
            "site_id": token.get("site_id"),
            "scopes": _safe_scopes(token.get("scope")),
            "access_expires_at": _isoformat(_number(token.get("expires_at"))),
            "access_valid": _number(token.get("expires_at")) > now,
            "refresh_expires_at": _isoformat(
                _number(token.get("refresh_expires_at"))
            ),
        }

    async def access_token(self, *, min_validity_seconds: float = 60) -> str:
        token = self._store.load()
        if token is None:
            raise SolarEdgeAuthorizationError("SolarEdge is not authorized")
        if _number(token.get("expires_at")) <= self._now() + min_validity_seconds:
            token = await self.refresh()
        access_token = token.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise SolarEdgeAuthorizationError("SolarEdge access token is unavailable")
        return access_token

    async def refresh(self, *, force: bool = False) -> dict[str, Any]:
        async with self._refresh_lock:
            current = self._store.load()
            if current is None:
                raise SolarEdgeAuthorizationError("SolarEdge is not authorized")
            if not force and _number(current.get("expires_at")) > self._now() + 60:
                return current
            refresh_token = current.get("refresh_token")
            if not isinstance(refresh_token, str) or not refresh_token:
                raise SolarEdgeAuthorizationError(
                    "SolarEdge refresh token is unavailable"
                )
            response = await self._post_token(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                }
            )
            # Persist the complete rotated pair in one atomic replace. If the
            # provider omits a new refresh token, keep the still-valid current one.
            merged = self._normalize_token(
                response,
                site_id=str(current.get("site_id") or self.config.site_id or ""),
                previous=current,
            )
            self._store.save(merged)
            return merged

    async def revoke(self) -> dict[str, Any]:
        current = self._store.load()
        if current is None:
            return {"revoked": False, "reason": "not_authorized"}
        token = current.get("refresh_token") or current.get("access_token")
        if not isinstance(token, str) or not token:
            self._store.clear()
            return {"revoked": True}
        await self._post_form(
            REVOKE_URL,
            {
                "token": token,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            },
        )
        self._store.clear()
        return {"revoked": True}

    async def _post_token(self, data: Mapping[str, str]) -> dict[str, Any]:
        response = await self._post_form(TOKEN_URL, data)
        if not isinstance(response, dict):
            raise SolarEdgeAuthorizationError(
                "SolarEdge token endpoint returned an invalid response"
            )
        if not isinstance(response.get("access_token"), str):
            raise SolarEdgeAuthorizationError(
                "SolarEdge token endpoint did not return an access token"
            )
        return response

    async def _post_form(self, url: str, data: Mapping[str, str]) -> Any:
        session = await self._get_session()
        try:
            async with session.post(url, data=dict(data)) as response:
                raw = await response.text()
                if response.status >= 400:
                    raise SolarEdgeAuthorizationError(
                        f"SolarEdge authorization request failed ({response.status})"
                    )
                try:
                    return json.loads(raw) if raw else {}
                except json.JSONDecodeError as exc:
                    raise SolarEdgeAuthorizationError(
                        "SolarEdge authorization endpoint returned invalid JSON"
                    ) from exc
        except asyncio.TimeoutError as exc:
            raise SolarEdgeAuthorizationError(
                "SolarEdge authorization request timed out"
            ) from exc
        except aiohttp.ClientError as exc:
            raise SolarEdgeAuthorizationError(
                "SolarEdge authorization request failed"
            ) from exc

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=self.config.timeout_seconds, connect=5
                ),
                raise_for_status=False,
            )
        return self._session

    def _consume_state(self, state: str) -> None:
        if not isinstance(state, str) or not state:
            raise SolarEdgeAuthorizationError("SolarEdge OAuth state is invalid")
        now = self._now()
        expires_at = self._states.pop(state, None)
        self._prune_states(now)
        if expires_at is None or expires_at < now:
            raise SolarEdgeAuthorizationError(
                "SolarEdge OAuth state is expired or already used"
            )

    def _prune_states(self, now: float) -> None:
        self._states = {
            value: expiry for value, expiry in self._states.items() if expiry >= now
        }

    def _normalize_token(
        self,
        token: Mapping[str, Any],
        *,
        site_id: str,
        previous: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        _validate_identifier(site_id, "site_id")
        now = self._now()
        access_token = token.get("access_token")
        refresh_token = token.get("refresh_token") or (previous or {}).get(
            "refresh_token"
        )
        if not isinstance(access_token, str) or not access_token:
            raise SolarEdgeAuthorizationError("SolarEdge access token is unavailable")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise SolarEdgeAuthorizationError("SolarEdge refresh token is unavailable")
        expires_in = min(
            _positive_number(
                token.get("expires_in"), _DEFAULT_ACCESS_LIFETIME_SECONDS
            ),
            _DEFAULT_ACCESS_LIFETIME_SECONDS,
        )
        refresh_expires_in = min(
            _positive_number(
                token.get("refresh_expires_in"), _DEFAULT_REFRESH_LIFETIME_SECONDS
            ),
            _DEFAULT_REFRESH_LIFETIME_SECONDS,
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": str(token.get("token_type") or "Bearer"),
            "scope": token.get("scope") or (previous or {}).get("scope") or " ".join(OAUTH_SCOPES),
            "site_id": site_id,
            "obtained_at": now,
            "expires_at": now + expires_in,
            "refresh_expires_at": now + refresh_expires_in,
        }


class SolarEdgeClient:
    """Read-only client exposing only fixed, documented Monitoring API paths."""

    def __init__(
        self,
        config: SolarEdgeConfig | None = None,
        *,
        oauth: SolarEdgeOAuthManager | None = None,
        session: aiohttp.ClientSession | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config or (oauth.config if oauth else SolarEdgeConfig.from_env())
        self.oauth = oauth or SolarEdgeOAuthManager(self.config, session=session)
        self._session = session
        self._owns_session = session is None
        self._sleep = sleep
        self._monotonic = monotonic
        self._cache: dict[str, tuple[float, Any]] = {}

    async def close(self) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None
        if self.oauth is not None and self.oauth._session is not self._session:
            await self.oauth.close()

    async def site_overview(self, site_id: str | None = None, **params: Any) -> Any:
        return await self._site_request(site_id, "/overview", params=params)

    async def energy(self, site_id: str | None = None, **params: Any) -> Any:
        return await self._site_request(site_id, "/energy", params=params)

    async def power(self, site_id: str | None = None, **params: Any) -> Any:
        return await self._site_request(site_id, "/power", params=params)

    async def performance(self, site_id: str | None = None, **params: Any) -> Any:
        return await self._site_request(site_id, "/overview/performance", params=params)

    async def alerts(self, site_id: str | None = None, **params: Any) -> Any:
        return await self._site_request(site_id, "/alerts", params=params)

    async def inventory(self, site_id: str | None = None) -> Any:
        return await self._site_request(site_id, "/devices")

    async def inverter_telemetry(
        self, site_id: str | None = None, **params: Any
    ) -> Any:
        return await self._site_request(site_id, "/inverters/telemetry", params=params)

    async def meter_telemetry(
        self, site_id: str | None = None, **params: Any
    ) -> Any:
        return await self._site_request(site_id, "/meters/telemetry", params=params)

    async def storage_telemetry(
        self, site_id: str | None = None, **params: Any
    ) -> Any:
        return await self._site_request(site_id, "/storage/telemetry", params=params)

    async def meter_import_power(self, meter_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("meters", meter_id, "import-power", site_id, params)

    async def meter_import_energy(self, meter_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("meters", meter_id, "import-energy", site_id, params)

    async def meter_export_power(self, meter_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("meters", meter_id, "export-power", site_id, params)

    async def meter_export_energy(self, meter_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("meters", meter_id, "export-energy", site_id, params)

    async def storage_charge_power(self, storage_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("storage", storage_id, "charge-power", site_id, params)

    async def storage_charge_energy(self, storage_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("storage", storage_id, "charge-energy", site_id, params)

    async def storage_discharge_power(self, storage_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("storage", storage_id, "discharge-power", site_id, params)

    async def storage_discharge_energy(self, storage_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("storage", storage_id, "discharge-energy", site_id, params)

    async def storage_state_of_energy(self, storage_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("storage", storage_id, "state-of-energy", site_id, params)

    async def storage_remaining_energy(self, storage_id: str, site_id: str | None = None, **params: Any) -> Any:
        return await self._measurement("storage", storage_id, "remaining-energy", site_id, params)

    async def _measurement(
        self,
        family: str,
        device_id: str,
        measurement: str,
        site_id: str | None,
        params: Mapping[str, Any],
    ) -> Any:
        _validate_identifier(device_id, "device_id")
        return await self._site_request(
            site_id,
            f"/{family}/{quote(device_id, safe='')}/{measurement}",
            params=params,
        )

    async def _site_request(
        self,
        site_id: str | None,
        suffix: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        resolved = site_id or self.config.site_id or self.oauth.status().get("site_id")
        if not isinstance(resolved, str):
            raise ValueError("SolarEdge site_id is required")
        _validate_identifier(resolved, "site_id")
        path = f"/sites/{quote(resolved, safe='')}{suffix}"
        return await self._request(path, params=params)

    async def _request(
        self, path: str, *, params: Mapping[str, Any] | None = None
    ) -> Any:
        if not path.startswith("/sites/") or ".." in path:
            raise ValueError("SolarEdge API path is not allowlisted")
        safe_params = _normalize_params(params)
        cache_key = f"{path}?{urlencode(sorted(safe_params.items()), doseq=True)}"
        cached = self._cache.get(cache_key)
        now = self._monotonic()
        if cached and cached[0] > now:
            return copy.deepcopy(cached[1])

        response_data = await self._request_with_retries(path, safe_params)
        sanitized = sanitize_solaredge_result(response_data)
        self._cache[cache_key] = (
            now + self.config.cache_ttl_seconds,
            copy.deepcopy(sanitized),
        )
        return sanitized

    async def _request_with_retries(
        self, path: str, params: Mapping[str, Any]
    ) -> Any:
        refreshed = False
        rate_retried = False
        while True:
            access_token = await self.oauth.access_token()
            status, headers, body = await self._get(path, params, access_token)
            if status == 401 and not refreshed:
                await self.oauth.refresh(force=True)
                refreshed = True
                continue
            if status == 429:
                retry_after = _retry_after(headers.get("Retry-After"))
                if (
                    not rate_retried
                    and retry_after is not None
                    and retry_after <= self.config.max_rate_limit_wait_seconds
                ):
                    rate_retried = True
                    await self._sleep(retry_after)
                    continue
                raise SolarEdgeRateLimitError(retry_after)
            if status >= 400:
                raise SolarEdgeError(f"SolarEdge API request failed ({status})")
            return body

    async def _get(
        self, path: str, params: Mapping[str, Any], access_token: str
    ) -> tuple[int, Mapping[str, str], Any]:
        session = await self._get_session()
        url = f"{API_BASE_URL}{path}"
        try:
            async with session.get(
                url,
                params=dict(params),
                headers={"Authorization": f"Bearer {access_token}"},
            ) as response:
                raw = await response.text()
                try:
                    body = json.loads(raw) if raw else {}
                except json.JSONDecodeError as exc:
                    raise SolarEdgeError("SolarEdge API returned invalid JSON") from exc
                return response.status, response.headers, body
        except asyncio.TimeoutError as exc:
            raise SolarEdgeError("SolarEdge API request timed out") from exc
        except aiohttp.ClientError as exc:
            raise SolarEdgeError("SolarEdge API request failed") from exc

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=self.config.timeout_seconds, connect=5
                ),
                raise_for_status=False,
            )
        return self._session


def sanitize_solaredge_result(value: Any, *, _key: str | None = None) -> Any:
    """Remove credentials, addresses, and serial identifiers from tool-facing data."""
    normalized_key = _normalized_key(_key) if _key else None
    if normalized_key and _is_private_or_secret_key(normalized_key):
        return None
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = _normalized_key(str(key))
            if _is_private_or_secret_key(normalized):
                continue
            result[str(key)] = sanitize_solaredge_result(item, _key=str(key))
        return result
    if isinstance(value, list):
        return [sanitize_solaredge_result(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_solaredge_result(item) for item in value]
    return value


def _normalize_params(params: Mapping[str, Any] | None) -> dict[str, Any]:
    if not params:
        return {}
    result: dict[str, Any] = {}
    for key, value in params.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", key):
            raise ValueError("SolarEdge query parameter name is invalid")
        if isinstance(value, bool):
            result[key] = str(value).lower()
        elif isinstance(value, (str, int, float)) and len(str(value)) <= 256:
            result[key] = value
        else:
            raise ValueError("SolarEdge query parameter value is invalid")
    return result


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required setting: {name}")
    return value


def _validate_redirect_uri(value: str) -> None:
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise ValueError("SolarEdge redirect_uri is invalid") from exc
    local_http = parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}
    if not (parts.scheme == "https" or local_http) or not parts.netloc or parts.fragment:
        raise ValueError("SolarEdge redirect_uri must be HTTPS or local HTTP")


def _validate_identifier(value: str, field: str) -> None:
    if not isinstance(value, str) or not _SAFE_IDENTIFIER.fullmatch(value):
        raise ValueError(f"SolarEdge {field} is invalid")


def _safe_scopes(value: Any) -> list[str]:
    if isinstance(value, str):
        scopes = value.replace(",", " ").split()
    elif isinstance(value, list):
        scopes = [str(item) for item in value]
    else:
        scopes = list(OAUTH_SCOPES)
    return [scope for scope in scopes if scope in OAUTH_SCOPES]


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _positive_number(value: Any, default: float) -> float:
    parsed = _number(value)
    return parsed if parsed > 0 else default


def _isoformat(timestamp: float) -> str | None:
    if timestamp <= 0:
        return None
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        parsed = float(value)
    except ValueError:
        try:
            when = datetime.fromisoformat(value).astimezone(UTC)
        except ValueError:
            return None
        parsed = (when - datetime.now(UTC)).total_seconds()
    return max(0.0, parsed)


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _is_private_or_secret_key(normalized: str) -> bool:
    if normalized in _PRIVATE_KEYS or normalized in _SECRET_KEYS:
        return True
    if "address" in normalized or "accesstoken" in normalized or "refreshtoken" in normalized:
        return True
    return normalized.endswith(("serial", "serialid", "serialnumber", "devicesn"))
