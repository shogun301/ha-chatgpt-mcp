from __future__ import annotations

import asyncio
import json
import re
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import aiohttp

ENTITY_ID_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
AUTOMATION_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(access_?token|api_?key|auth|authorization|cookie|credential|password|secret|"
    r"token|private_?key|encryption_?key|signature|refresh_?token|webhook_?id|ssid|bssid|ap|"
    r"ip|ip_?address|mac|mac_?address|host|hostname|stream_?source|still_?image_?url)($|_)",
    re.IGNORECASE,
)
SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "auth",
    "authsig",
    "authorization",
    "code",
    "key",
    "password",
    "secret",
    "signature",
    "sig",
    "token",
}
MAX_HISTORY_SPAN = timedelta(days=31)


class HomeAssistantError(RuntimeError):
    pass


class HomeAssistantClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        config_path: Path,
        backup_path: Path,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.config_path = config_path
        self.backup_path = backup_path
        self._session: aiohttp.ClientSession | None = None
        self._ws_lock = asyncio.Lock()

    async def start(self) -> None:
        timeout = aiohttp.ClientTimeout(total=30, connect=5)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"Authorization": f"Bearer {self.token}"},
            raise_for_status=False,
        )

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    @property
    def session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError("Home Assistant client is not started")
        return self._session

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        timeout_seconds: int | None = None,
    ) -> Any:
        request_options: dict[str, Any] = {"params": params, "json": json_body}
        if timeout_seconds is not None:
            request_options["timeout"] = aiohttp.ClientTimeout(total=timeout_seconds)
        async with self.session.request(
            method, f"{self.base_url}{path}", **request_options
        ) as response:
            raw = await response.text()
            if response.status >= 400:
                raise HomeAssistantError(
                    f"Home Assistant request failed ({response.status})"
                )
            if not raw:
                return None
            try:
                return redact_sensitive(json.loads(raw))
            except json.JSONDecodeError as exc:
                raise HomeAssistantError(
                    "Home Assistant returned invalid JSON"
                ) from exc

    async def ws_command(self, command: dict[str, Any]) -> Any:
        async with self._ws_lock:
            ws_url = (
                self.base_url.replace("http://", "ws://", 1).replace(
                    "https://", "wss://", 1
                )
                + "/api/websocket"
            )
            async with self.session.ws_connect(ws_url, heartbeat=20) as websocket:
                greeting = await websocket.receive_json()
                if greeting.get("type") != "auth_required":
                    raise HomeAssistantError(
                        "Unexpected Home Assistant WebSocket greeting"
                    )
                await websocket.send_json({"type": "auth", "access_token": self.token})
                authenticated = await websocket.receive_json()
                if authenticated.get("type") != "auth_ok":
                    raise HomeAssistantError(
                        "Home Assistant rejected the service identity"
                    )
                payload = dict(command)
                payload["id"] = 1
                await websocket.send_json(payload)
                while True:
                    message = await websocket.receive_json()
                    if message.get("id") == 1:
                        if not message.get("success"):
                            error = message.get("error", {})
                            raise HomeAssistantError(
                                f"Home Assistant WebSocket command failed: "
                                f"{error.get('code', 'unknown')}"
                            )
                        return redact_sensitive(message.get("result"))

    async def config(self) -> dict[str, Any]:
        return await self.request("GET", "/api/config")

    async def states(self) -> list[dict[str, Any]]:
        return await self.request("GET", "/api/states")

    async def state(self, entity_id: str) -> dict[str, Any]:
        validate_entity_id(entity_id)
        return await self.request("GET", f"/api/states/{quote(entity_id, safe='.')}")

    async def services(self) -> list[dict[str, Any]]:
        return await self.request("GET", "/api/services")

    async def areas(self) -> list[dict[str, Any]]:
        return await self.ws_command({"type": "config/area_registry/list"})

    async def devices(self) -> list[dict[str, Any]]:
        return await self.ws_command({"type": "config/device_registry/list"})

    async def entity_registry(self) -> list[dict[str, Any]]:
        return await self.ws_command({"type": "config/entity_registry/list"})

    async def integrations(self) -> list[dict[str, Any]]:
        return await self.ws_command({"type": "config_entries/get"})

    async def schedules(self) -> list[dict[str, Any]]:
        return await self.ws_command({"type": "schedule/list"})

    async def update_schedule(self, schedule: dict[str, Any]) -> Any:
        schedule_id = str(schedule.get("id", ""))
        validate_automation_id(schedule_id)
        command: dict[str, Any] = {
            "type": "schedule/update",
            "schedule_id": schedule_id,
            "name": schedule.get("name") or schedule_id,
            "icon": schedule.get("icon"),
        }
        for day in (
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        ):
            periods = schedule.get(day)
            if not isinstance(periods, list):
                raise ValueError(f"schedule.{day} must be a list")
            command[day] = periods
        return await self.ws_command(command)

    async def history(
        self,
        entity_ids: list[str],
        start_time: str,
        end_time: str | None,
        minimal_response: bool,
    ) -> Any:
        for entity_id in entity_ids:
            validate_entity_id(entity_id)
        start = parse_rfc3339(start_time, "start_time")
        end = parse_rfc3339(end_time, "end_time") if end_time else datetime.now(UTC)
        if end <= start:
            raise ValueError("end_time must be later than start_time")
        if end - start > MAX_HISTORY_SPAN:
            raise ValueError("History queries are limited to 31 days")
        params: dict[str, Any] = {
            "filter_entity_id": ",".join(entity_ids),
            "minimal_response": "true" if minimal_response else "false",
            "no_attributes": "false",
            "significant_changes_only": "false",
        }
        if end_time:
            params["end_time"] = end_time
        return await self.request(
            "GET",
            f"/api/history/period/{quote(start_time, safe=':-+TZ.')}",
            params=params,
        )

    async def statistic_ids(self) -> list[dict[str, Any]]:
        return await self.ws_command({"type": "recorder/list_statistic_ids"})

    async def weather_forecast(self, entity_id: str, forecast_type: str) -> Any:
        return await self.call_service_response(
            "weather",
            "get_forecasts",
            {"type": forecast_type},
            {"entity_id": entity_id},
        )

    async def statistics(
        self,
        statistic_ids: list[str],
        start_time: str,
        end_time: str,
        period: str,
        types: list[str],
        units: dict[str, str] | None = None,
    ) -> Any:
        start = parse_rfc3339(start_time, "start_time")
        end = parse_rfc3339(end_time, "end_time")
        if end <= start:
            raise ValueError("end_time must be later than start_time")
        if end - start > timedelta(days=366 * 5):
            raise ValueError("Statistics queries are limited to five years")
        data: dict[str, Any] = {
            "start_time": start.isoformat(),
            "end_time": end.isoformat(),
            "statistic_ids": statistic_ids,
            "period": period,
            "types": types,
        }
        if units:
            data["units"] = units
        response = await self.call_service_response("recorder", "get_statistics", data)
        result = (response or {}).get("statistics", response or {})
        if not isinstance(result, dict):
            return result

        # recorder.get_statistics can include the bucket beginning exactly at
        # end_time. Keep the public contract half-open so a seven-day request
        # always returns at most the seven requested daily buckets.
        bounded: dict[str, Any] = {}
        for statistic_id, rows in result.items():
            if not isinstance(rows, list):
                bounded[statistic_id] = rows
                continue
            included = []
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("start"), str):
                    continue
                try:
                    row_start = parse_rfc3339(row["start"], "statistics row start")
                except ValueError:
                    continue
                if start <= row_start < end:
                    included.append(row)
            bounded[statistic_id] = included
        return bounded

    async def dashboards(self) -> list[dict[str, Any]]:
        return await self.ws_command({"type": "lovelace/dashboards/list"})

    async def dashboard_config(self, url_path: str | None = None) -> dict[str, Any]:
        command: dict[str, Any] = {"type": "lovelace/config"}
        if url_path:
            command["url_path"] = url_path
        return await self.ws_command(command)

    async def create_dashboard(
        self, url_path: str, title: str, icon: str | None
    ) -> Any:
        command: dict[str, Any] = {
            "type": "lovelace/dashboards/create",
            "url_path": url_path,
            "title": title,
            "show_in_sidebar": True,
            "require_admin": False,
            "mode": "storage",
            "allow_single_word": True,
        }
        if icon:
            command["icon"] = icon
        return await self.ws_command(command)

    async def delete_dashboard(self, dashboard_id: str) -> Any:
        return await self.ws_command(
            {"type": "lovelace/dashboards/delete", "dashboard_id": dashboard_id}
        )

    async def save_dashboard_config(
        self, config: dict[str, Any], url_path: str | None = None
    ) -> Any:
        command: dict[str, Any] = {"type": "lovelace/config/save", "config": config}
        if url_path:
            command["url_path"] = url_path
        return await self.ws_command(command)

    async def call_service(
        self,
        domain: str,
        service: str,
        data: dict[str, Any],
        target: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
    ) -> Any:
        payload = dict(data)
        if target:
            payload.update(target)
        return await self.request(
            "POST",
            f"/api/services/{domain}/{service}",
            json_body=payload,
            timeout_seconds=timeout_seconds,
        )

    async def call_service_response(
        self,
        domain: str,
        service: str,
        data: dict[str, Any],
        target: dict[str, Any] | None = None,
    ) -> Any:
        command: dict[str, Any] = {
            "type": "call_service",
            "domain": domain,
            "service": service,
            "service_data": data,
            "return_response": True,
        }
        if target:
            command["target"] = target
        result = await self.ws_command(command)
        return (result or {}).get("response")

    async def get_automation_config(self, automation_id: str) -> dict[str, Any]:
        validate_automation_id(automation_id)
        return await self.request(
            "GET", f"/api/config/automation/config/{quote(automation_id, safe='_-')}"
        )

    async def save_automation_config(
        self, automation_id: str, config: dict[str, Any]
    ) -> Any:
        validate_automation_id(automation_id)
        return await self.request(
            "POST",
            f"/api/config/automation/config/{quote(automation_id, safe='_-')}",
            json_body=config,
        )

    def backup_automations(self, operation: str) -> str:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        destination = self.backup_path / f"{timestamp}-{operation}"
        destination.mkdir(parents=True, mode=0o700, exist_ok=False)
        copied = False
        for name in ("automations.yaml", "configuration.yaml"):
            source = self.config_path / name
            if source.exists():
                shutil.copy2(source, destination / name)
                copied = True
        if not copied:
            raise HomeAssistantError(
                "No Home Assistant automation configuration was found"
            )
        manifest = {
            "created_at": datetime.now(UTC).isoformat(),
            "operation": operation,
            "files": sorted(path.name for path in destination.iterdir()),
        }
        (destination / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
        return str(destination)

    def backup_schedules(self, operation: str) -> str:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        destination = self.backup_path / f"{timestamp}-{operation}"
        destination.mkdir(parents=True, mode=0o700, exist_ok=False)
        source = self.config_path / ".storage" / "schedule"
        if not source.exists():
            raise HomeAssistantError("Home Assistant schedule storage was not found")
        shutil.copy2(source, destination / "schedule")
        manifest = {
            "created_at": datetime.now(UTC).isoformat(),
            "operation": operation,
            "files": ["schedule"],
        }
        (destination / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
        return str(destination)

    def backup_dashboard(
        self, operation: str, url_path: str, config: dict[str, Any]
    ) -> str:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        destination = self.backup_path / f"{timestamp}-{operation}"
        destination.mkdir(parents=True, mode=0o700, exist_ok=False)
        (destination / f"{url_path}.json").write_text(
            json.dumps(redact_sensitive(config), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return str(destination)


def validate_entity_id(entity_id: str) -> None:
    if not ENTITY_ID_RE.fullmatch(entity_id):
        raise ValueError("Invalid Home Assistant entity_id")


def validate_automation_id(automation_id: str) -> None:
    if not AUTOMATION_ID_RE.fullmatch(automation_id):
        raise ValueError("Invalid automation ID")


def parse_rfc3339(value: str, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError(f"{field} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _redact_url(value: str) -> str:
    if "?" not in value and "://" not in value:
        return value
    try:
        parts = urlsplit(value)
        query = [
            (key, "[REDACTED]" if key.casefold() in SENSITIVE_QUERY_KEYS else item)
            for key, item in parse_qsl(parts.query, keep_blank_values=True)
        ]
        netloc = parts.netloc
        if parts.username is not None or parts.password is not None:
            hostname = parts.hostname or ""
            netloc = f"{hostname}:{parts.port}" if parts.port is not None else hostname
        return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), parts.fragment))
    except ValueError:
        return "[REDACTED_URL]"


def redact_sensitive(value: Any, *, _key: str | None = None) -> Any:
    """Recursively remove credentials and private network identifiers from tool output/logs."""
    if _key and SENSITIVE_KEY_RE.search(_key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(key): redact_sensitive(item, _key=str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        return _redact_url(value)
    return value


def summarize_state(state: dict[str, Any]) -> dict[str, Any]:
    attributes = redact_sensitive(state.get("attributes") or {})
    return {
        "entity_id": state.get("entity_id"),
        "state": state.get("state"),
        "friendly_name": attributes.get("friendly_name"),
        "device_class": attributes.get("device_class"),
        "unit_of_measurement": attributes.get("unit_of_measurement"),
        "last_changed": state.get("last_changed"),
        "last_updated": state.get("last_updated"),
        "attributes": attributes,
    }
