from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import re
import time
import uuid
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import UTC, date, datetime, timedelta
from statistics import median
from typing import Annotated, Any, Literal
from urllib.parse import parse_qsl, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from mcp.server import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Mount, Route

from . import config
from .audit import AuditLog
from .capability_sync import CapabilitySync
from .diagnostics import (
    COMPONENTS as DIAGNOSTIC_COMPONENTS,
    SEVERITIES as DIAGNOSTIC_SEVERITIES,
    DiagnosticsReader,
)
from .ha_client import (
    HomeAssistantClient,
    HomeAssistantError,
    parse_rfc3339,
    redact_sensitive,
    summarize_state,
    validate_automation_id,
    validate_entity_id,
)
from .lan import LanDiagnostics
from .oauth import OAuthServer, OAuthStore
from .solaredge import (
    OAUTH_SCOPES,
    SolarEdgeAuthorizationError,
    SolarEdgeClient,
    SolarEdgeConfig,
    SolarEdgeError,
    SolarEdgeOAuthManager,
)
from .solaredge_filter import SolarEdgeSnapshotFilter
from .solaredge_portal import (
    SolarEdgePortalClient,
    SolarEdgePortalConfig,
    SolarEdgePortalError,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOGGER = logging.getLogger("ha_chatgpt_mcp")
SERVER_VERSION = "2.6.1"
audit = AuditLog(config.AUDIT_LOG_PATH)
oauth = OAuthServer(
    OAuthStore(config.DATABASE_PATH),
    issuer=config.PUBLIC_BASE_URL,
    resource=config.MCP_RESOURCE,
    jwt_secret=config.JWT_SECRET,
    password_hash=config.OAUTH_PASSWORD_HASH,
)
ha = HomeAssistantClient(
    config.HA_BASE_URL,
    config.HA_TOKEN,
    config.HA_CONFIG_PATH,
    config.BACKUP_PATH,
)
diagnostics = DiagnosticsReader(config.HOST_DIAGNOSTICS_PATH)
lan_diagnostics = LanDiagnostics()
capability_sync = CapabilitySync(config.CAPABILITY_SYNC_PATH, SERVER_VERSION)


def _build_solaredge() -> tuple[SolarEdgeOAuthManager | None, SolarEdgeClient | None]:
    required = (
        config.SOLAREDGE_CLIENT_ID,
        config.SOLAREDGE_CLIENT_SECRET,
        config.SOLAREDGE_TOKEN_KEY,
        config.SOLAREDGE_TOKEN_STORE_PATH,
        config.SOLAREDGE_REDIRECT_URI,
    )
    if not all(required):
        return None, None
    provider_config = SolarEdgeConfig(
        client_id=str(config.SOLAREDGE_CLIENT_ID),
        client_secret=str(config.SOLAREDGE_CLIENT_SECRET),
        redirect_uri=str(config.SOLAREDGE_REDIRECT_URI),
        token_store_path=config.SOLAREDGE_TOKEN_STORE_PATH,
        encryption_key=str(config.SOLAREDGE_TOKEN_KEY),
        cache_ttl_seconds=2 * 60 * 60,
    )
    provider_oauth = SolarEdgeOAuthManager(provider_config)
    return provider_oauth, SolarEdgeClient(provider_config, oauth=provider_oauth)


solaredge_oauth, solaredge = _build_solaredge()


def _build_solaredge_portal() -> SolarEdgePortalClient | None:
    required = (
        config.SOLAREDGE_PORTAL_USERNAME_FILE,
        config.SOLAREDGE_PORTAL_PASSWORD_FILE,
        config.SOLAREDGE_PORTAL_SITE_ID_FILE,
        config.SOLAREDGE_PORTAL_TIMEZONE,
    )
    if not all(required):
        return None
    portal_config = SolarEdgePortalConfig.from_secret_files(
        username_file=config.SOLAREDGE_PORTAL_USERNAME_FILE,
        password_file=config.SOLAREDGE_PORTAL_PASSWORD_FILE,
        site_id_file=config.SOLAREDGE_PORTAL_SITE_ID_FILE,
        timezone_name=str(config.SOLAREDGE_PORTAL_TIMEZONE),
        cache_ttl_seconds=60,
    )
    return SolarEdgePortalClient(portal_config)


solaredge_portal = _build_solaredge_portal()
_solaredge_lifetime_cache: tuple[float, dict[str, Any]] | None = None
_SOLAREDGE_LIFETIME_CACHE_SECONDS = 30 * 60
_solaredge_snapshot_filter = SolarEdgeSnapshotFilter()
_solaredge_snapshot_filter_lock = asyncio.Lock()

claims_context: ContextVar[dict[str, Any] | None] = ContextVar(
    "claims_context", default=None
)

READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
WRITE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=False,
)
IDEMPOTENT_WRITE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
DESTRUCTIVE_WRITE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=False,
)

ALLOWED_SERVICES: dict[str, set[str]] = {
    "light": {"turn_on", "turn_off", "toggle"},
    "switch": {"turn_on", "turn_off", "toggle"},
    "fan": {"turn_on", "turn_off", "toggle", "set_percentage", "set_preset_mode"},
    "climate": {
        "turn_on",
        "turn_off",
        "set_temperature",
        "set_hvac_mode",
        "set_fan_mode",
        "set_preset_mode",
    },
    "media_player": {
        "turn_on",
        "turn_off",
        "media_play",
        "media_pause",
        "media_stop",
        "volume_set",
        "volume_up",
        "volume_down",
        "volume_mute",
        "select_source",
    },
    "scene": {"turn_on"},
    "input_boolean": {"turn_on", "turn_off", "toggle"},
    "input_text": {"set_value"},
    "input_number": {"set_value", "increment", "decrement"},
    "input_select": {"select_option", "select_next", "select_previous"},
    "humidifier": {"turn_on", "turn_off", "set_humidity", "set_mode"},
    "water_heater": {"turn_on", "turn_off", "set_temperature", "set_operation_mode"},
    "vacuum": {"start", "pause", "stop", "return_to_base", "locate", "clean_spot"},
}

TURNABLE_DOMAINS = {
    "fan",
    "humidifier",
    "input_boolean",
    "light",
    "media_player",
    "switch",
    "vacuum",
    "water_heater",
}

SCHEDULE_DAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)
DEFAULT_TEMPERATURE_PRESETS: dict[str, float] = {
    "Sleep": 72,
    "Comfort": 74,
    "Morning": 75,
    "Afternoon": 76,
    "Evening": 77,
    "Peak": 78,
    "Eco": 80,
}
BEDROOM_LOW_BY_PRESET: dict[str, float] = {
    "Sleep": 65,
    "Comfort": 68,
    "Morning": 67,
    "Afternoon": 68,
    "Evening": 68,
    "Peak": 68,
    "Eco": 56,
}
THERMOSTATS: dict[str, dict[str, str]] = {
    "living_space": {
        "climate": config.LIVING_CLIMATE_ENTITY,
        "schedule": config.LIVING_SCHEDULE_ID,
        "automation": config.LIVING_AUTOMATION_ENTITY,
    },
    "bedroom": {
        "climate": config.BEDROOM_CLIMATE_ENTITY,
        "schedule": config.BEDROOM_SCHEDULE_ID,
        "automation": config.BEDROOM_AUTOMATION_ENTITY,
    },
}
AWAY_AUTOMATION = config.AWAY_AUTOMATION_ENTITY
PRESENCE_ENTITY = config.PRESENCE_ENTITY
PRESET_PATH = config.DATABASE_PATH.parent / "thermostat_presets.json"
schedule_lock = asyncio.Lock()
DASHBOARD_PATH_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
STATISTIC_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")
SERVICE_PART_RE = re.compile(r"^[a-z0-9_]{1,64}$")
TIME_VALUE_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?$")
MAX_SERVICE_DATA_BYTES = 16_384
MAX_DASHBOARD_CONFIG_BYTES = 256_000
MEDIA_FEATURES = {
    "media_pause": 1,
    "media_seek": 2,
    "volume_set": 4,
    "volume_mute": 8,
    "media_previous_track": 16,
    "media_next_track": 32,
    "turn_on": 128,
    "turn_off": 256,
    "play_media": 512,
    "volume_up": 1024,
    "volume_down": 1024,
    "select_source": 2048,
    "media_stop": 4096,
    "media_play": 16384,
    "shuffle_set": 32768,
    "repeat_set": 262144,
    "join": 524288,
    "unjoin": 524288,
    "browse_media": 131072,
    "search_media": 4194304,
}
SENSITIVE_URL_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "key",
    "password",
    "secret",
    "signature",
    "token",
}
SPRINKLER_ZONES = {
    zone: (
        f"number.{config.SPRINKLER_ENTITY_PREFIX}_zone_{zone}",
        f"button.{config.SPRINKLER_ENTITY_PREFIX}_zone_{zone}",
    )
    for zone in range(1, config.SPRINKLER_ZONE_COUNT + 1)
}
SPRINKLER_STOP = f"button.{config.SPRINKLER_ENTITY_PREFIX}_stop_all_zones"
SPRINKLER_STATUS = f"sensor.{config.SPRINKLER_ENTITY_PREFIX}_watering_status"
SPRINKLER_ACTIVE_ZONE = f"sensor.{config.SPRINKLER_ENTITY_PREFIX}_active_zone"
SPRINKLER_REMAINING = f"sensor.{config.SPRINKLER_ENTITY_PREFIX}_watering_time_remaining"
SPRINKLER_LAST_WATERING = f"sensor.{config.SPRINKLER_ENTITY_PREFIX}_last_watering"
SPRINKLER_CONFIGURATION = f"sensor.{config.SPRINKLER_ENTITY_PREFIX}_configuration"
SPRINKLER_ZONE_METADATA = {
    zone: f"sensor.{config.SPRINKLER_ENTITY_PREFIX}_zone_{zone}_metadata"
    for zone in range(1, config.SPRINKLER_ZONE_COUNT + 1)
}
AUTOMATION_BLOCKED_DOMAINS = {
    "alarm_control_panel",
    "backup",
    "button",
    "camera",
    "hassio",
    "homeassistant",
    "lock",
    "recorder",
    "script",
    "shell_command",
    "siren",
}
AUTOMATION_EXTRA_SERVICES: dict[str, set[str]] = {
    "cast": {"show_lovelace_view"},
    "dreame_vacuum": {"vacuum_clean_segment"},
    "nest": {"set_fan_timer"},
    "notify": {config.MOBILE_NOTIFY_SERVICE},
    "number": {"set_value"},
    "select": {"select_option"},
    "todo": {"add_item", "update_item"},
    "tts": {"speak"},
}
AUTOMATION_TARGET_DOMAIN = {
    "cast": "media_player",
    "dreame_vacuum": "vacuum",
    "nest": "climate",
    "tts": "tts",
}

DayName = Literal[
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
]
PresetName = Literal[
    "Sleep",
    "Comfort",
    "Morning",
    "Afternoon",
    "Evening",
    "Peak",
    "Eco",
]
ThermostatTarget = Literal["living_space", "bedroom", "both"]
DiagnosticComponent = Literal[
    "home_assistant",
    "mcp",
    "docker",
    "kernel",
    "cgroup",
    "systemd",
    "cloudflare_tunnel",
    "wireguard",
    "reverse_proxy",
    "endpoint_probe",
]
DiagnosticSeverity = Literal["info", "warning", "error", "critical"]
LanService = Literal[
    "dns",
    "http",
    "https",
    "rtsp",
    "ipp",
    "mqtt",
    "asus_ssh",
    "cast_http",
    "cast_tls",
    "jetdirect",
]


class RedactingMCPServer(MCPServer):
    """Apply the output sanitizer after every tool body and before MCP serialization."""

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context: Context[Any, Any] | None = None,
    ) -> Any:
        if context is None:
            context = Context(mcp_server=self, subscriptions=self._subscriptions)
        raw_result = await self._tool_manager.call_tool(
            name, arguments, context, convert_result=False
        )
        if isinstance(raw_result, (dict, list, tuple, str)):
            raw_result = redact_sensitive(raw_result)
        tool = self._tool_manager.get_tool(name)
        if tool is None:
            raise ValueError(f"Unknown tool: {name}")
        return tool.fn_metadata.convert_result(raw_result)


class ThermostatScheduleEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    days: Annotated[list[DayName], Field(min_length=1, max_length=7)]
    start_time: Annotated[
        str, Field(description="Local time in HH:MM format, such as 08:00.")
    ]
    end_time: Annotated[
        str, Field(description="Local time in HH:MM format; 24:00 is allowed.")
    ]
    preset: PresetName
    target_temp_low: Annotated[float | None, Field(ge=45, le=85)] = None


class NotificationLinkAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Annotated[str, Field(min_length=1, max_length=80)]
    url: Annotated[str, Field(min_length=1, max_length=500)]


class SprinklerSequenceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    zone: Annotated[int, Field(strict=True, ge=1, le=8)]
    duration_minutes: Annotated[float, Field(ge=1, le=180)]


mcp = RedactingMCPServer(
    config.MCP_DISPLAY_NAME,
    version=SERVER_VERSION,
    instructions=(
        "For an outage, call get_home_overview, then get_fixed_route_health, then "
        "get_restart_outage_diagnostics for a bounded window; use list_diagnostic_events "
        "only if the structured result is insufficient. Separate confirmed evidence, supported "
        "inference, and unresolved gaps. Prefer the narrow typed tool matching the request; "
        "use read-only tools freely for "
        "discovery and status. Resolve the exact entity and current state before acting, and read "
        "back meaningful device state after a mutation. Exact device-and-action requests authorize "
        "the matching routine write tool without redundant confirmation. Use the dedicated "
        "thermostat schedule and shared-preset tools for schedule work: schedule and shared-preset "
        "updates do not change current setpoints, while apply_temperature_preset and "
        "resume_thermostat_schedule do. High-impact buttons, locks, garage/gate/door movement, "
        "sirens, security controls, and destructive removals require explicit current-turn "
        "confirmation. Use call_service only when no focused tool fits; never use it for security "
        "controls, administration, shell commands, shutdown, credentials, or broad or ambiguous "
        "changes. For home-LAN discovery or reachability, use the fixed read-only LAN tools; "
        "they accept only node IDs inside the configured home subnet and a closed service list. "
        "Never trigger any physical side effect merely to test connectivity."
    ),
)


def _require_write() -> None:
    claims = claims_context.get()
    scopes = set(str((claims or {}).get("scope", "")).split())
    if "mcp:write" not in scopes:
        raise PermissionError("This connection is not authorized for write tools")


def _require_diagnostics() -> None:
    """Allow the dedicated read-only scope or the existing strongest connection scope."""
    claims = claims_context.get()
    scopes = set(str((claims or {}).get("scope", "")).split())
    if "mcp:read" not in scopes or not ({"mcp:diagnostics", "mcp:write"} & scopes):
        raise PermissionError("This connection is not authorized for host diagnostics")


def _audit_tool(tool: str, **fields: Any) -> None:
    claims = claims_context.get() or {}
    audit.write(
        "tool_call",
        tool=tool,
        subject=claims.get("sub"),
        client_id=claims.get("client_id"),
        **fields,
    )


def _entity_ids(target: dict[str, Any]) -> list[str]:
    raw = target.get("entity_id")
    if raw is None:
        raise ValueError(
            "target.entity_id is required; area and device bulk targeting are disabled"
        )
    values = [raw] if isinstance(raw, str) else raw
    if not isinstance(values, list) or not values or len(values) > 5:
        raise ValueError("target.entity_id must identify between 1 and 5 entities")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("Every entity_id must be a string")
        validate_entity_id(value)
        result.append(value)
    if set(target) != {"entity_id"}:
        raise ValueError("Only exact entity_id targets are accepted by call_service")
    return result


def _contains_target_key(value: Any) -> bool:
    if isinstance(value, dict):
        if set(value) & {"entity_id", "device_id", "area_id", "label_id", "floor_id"}:
            return True
        return any(_contains_target_key(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_target_key(item) for item in value)
    return False


def _bounded_object(value: Any, name: str, maximum: int) -> None:
    try:
        size = len(
            json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be JSON serializable") from exc
    if size > maximum:
        raise ValueError(f"{name} exceeds the {maximum}-byte limit")


def _validate_dashboard_path(url_path: str) -> None:
    if not DASHBOARD_PATH_RE.fullmatch(url_path):
        raise ValueError(
            "url_path must contain only lowercase letters, digits, and hyphens"
        )


def _validate_statistic_ids(statistic_ids: list[str]) -> None:
    if not statistic_ids or len(statistic_ids) > 50:
        raise ValueError("Provide between 1 and 50 statistic IDs")
    if any(not STATISTIC_ID_RE.fullmatch(item) for item in statistic_ids):
        raise ValueError("Invalid statistic ID")


def _require_confirmed(confirmed: bool, action: str) -> None:
    if confirmed is not True:
        raise PermissionError(
            f"{action} requires the user's explicit current-turn confirmation"
        )


def _target_names(target: ThermostatTarget) -> list[str]:
    return ["living_space", "bedroom"] if target == "both" else [target]


def _thermostat_name(identifier: str) -> str:
    normalized = identifier.removeprefix("schedule.")
    if identifier in THERMOSTATS:
        return identifier
    for name, details in THERMOSTATS.items():
        if normalized == details["schedule"] or identifier == details["climate"]:
            return name
    raise ValueError("Thermostat must be living_space or bedroom")


def _load_presets() -> dict[str, float]:
    if not PRESET_PATH.exists():
        return dict(DEFAULT_TEMPERATURE_PRESETS)
    try:
        loaded = json.loads(PRESET_PATH.read_text(encoding="utf-8"))
        if set(loaded) != set(DEFAULT_TEMPERATURE_PRESETS):
            raise ValueError("preset names do not match the supported registry")
        result = {name: float(loaded[name]) for name in DEFAULT_TEMPERATURE_PRESETS}
        if any(value < 45 or value > 95 for value in result.values()):
            raise ValueError("preset temperature is outside the supported range")
        return result
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        LOGGER.error("invalid_preset_registry error_type=%s", type(exc).__name__)
        raise HomeAssistantError("The thermostat preset registry is invalid") from exc


def _save_presets(presets: dict[str, float]) -> None:
    PRESET_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = PRESET_PATH.with_name(f".{PRESET_PATH.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(presets, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(PRESET_PATH)
    finally:
        temporary.unlink(missing_ok=True)


def _clock_seconds(value: str, *, allow_24: bool) -> int:
    pieces = value.split(":")
    if len(pieces) not in {2, 3} or any(not item.isdigit() for item in pieces):
        raise ValueError(f"Invalid time {value!r}; use HH:MM")
    hour, minute = int(pieces[0]), int(pieces[1])
    second = int(pieces[2]) if len(pieces) == 3 else 0
    if hour == 24 and allow_24 and minute == 0 and second == 0:
        return 86_400
    if hour > 23 or minute > 59 or second > 59:
        raise ValueError(f"Invalid time {value!r}; use HH:MM")
    return hour * 3600 + minute * 60 + second


def _format_clock(seconds: int) -> str:
    if seconds == 86_400:
        return "24:00:00"
    hour, remainder = divmod(seconds, 3600)
    minute, second = divmod(remainder, 60)
    return f"{hour:02d}:{minute:02d}:{second:02d}"


def _schedule_map(schedules: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("id")): item for item in schedules}


def _build_thermostat_schedule(
    thermostat_name: str,
    entries: list[ThermostatScheduleEntry],
    presets: dict[str, float],
    current: dict[str, Any],
) -> dict[str, Any]:
    periods_by_day: dict[str, list[tuple[int, int, ThermostatScheduleEntry]]] = {
        day: [] for day in SCHEDULE_DAYS
    }
    for entry in entries:
        start = _clock_seconds(entry.start_time, allow_24=False)
        end = _clock_seconds(entry.end_time, allow_24=True)
        if start >= end:
            raise ValueError(
                "Every thermostat schedule period must end after it starts"
            )
        for day in entry.days:
            periods_by_day[day].append((start, end, entry))

    result: dict[str, Any] = {
        "id": current["id"],
        "name": current.get("name") or current["id"],
        "icon": current.get("icon"),
    }
    for day in SCHEDULE_DAYS:
        periods = sorted(periods_by_day[day], key=lambda item: (item[0], item[1]))
        cursor = 0
        rendered: list[dict[str, Any]] = []
        for start, end, entry in periods:
            if start != cursor:
                relation = "overlap" if start < cursor else "gap"
                raise ValueError(
                    f"{day} contains a schedule {relation} at {_format_clock(start)}"
                )
            temperature = presets[entry.preset]
            data: dict[str, Any] = {
                "period": entry.preset,
                "temperature": temperature,
            }
            if thermostat_name == "bedroom":
                low = (
                    entry.target_temp_low
                    if entry.target_temp_low is not None
                    else BEDROOM_LOW_BY_PRESET[entry.preset]
                )
                if low >= temperature:
                    raise ValueError(
                        f"{day} {entry.preset} target_temp_low must be below {temperature:g}"
                    )
                data["target_temp_low"] = low
                data["target_temp_high"] = temperature
            rendered.append(
                {
                    "from": _format_clock(start),
                    "to": _format_clock(end),
                    "data": data,
                }
            )
            cursor = end
        if cursor != 86_400:
            raise ValueError(
                f"{day} must cover the complete day from 00:00 through 24:00"
            )
        result[day] = rendered
    return result


def _replace_schedule_preset(
    schedule: dict[str, Any], preset: str, temperature: float
) -> dict[str, Any]:
    replacement = {
        "id": schedule["id"],
        "name": schedule.get("name") or schedule["id"],
        "icon": schedule.get("icon"),
    }
    for day in SCHEDULE_DAYS:
        periods = json.loads(json.dumps(schedule.get(day, [])))
        for period in periods:
            data = period.get("data") or {}
            if data.get("period") == preset:
                data["temperature"] = temperature
                if "target_temp_high" in data:
                    data["target_temp_high"] = temperature
                period["data"] = data
        replacement[day] = periods
    return replacement


async def _apply_schedule_definitions(
    replacements: list[dict[str, Any]], originals: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    updated: list[str] = []
    try:
        for replacement in replacements:
            await ha.update_schedule(replacement)
            updated.append(replacement["id"])
        readback_map = _schedule_map(await ha.schedules())
        for replacement in replacements:
            actual = readback_map.get(replacement["id"])
            if actual is None or any(
                actual.get(day) != replacement.get(day) for day in SCHEDULE_DAYS
            ):
                raise HomeAssistantError(
                    f"Schedule readback did not match for {replacement['id']}"
                )
        return [readback_map[item["id"]] for item in replacements]
    except Exception:
        for schedule_id in reversed(updated):
            original = originals.get(schedule_id)
            if original is not None:
                try:
                    await ha.update_schedule(original)
                except Exception:
                    LOGGER.exception(
                        "schedule_rollback_failed schedule_id=%s", schedule_id
                    )
        raise


@mcp.tool(title="List Home Assistant entities", annotations=READ)
async def list_entities(
    domain: Annotated[
        str | None, Field(description="Optional exact entity domain, such as climate.")
    ] = None,
    limit: Annotated[int, Field(ge=1, le=500)] = 200,
) -> dict[str, Any]:
    """List current Home Assistant entities and concise state information."""
    states = await ha.states()
    if domain:
        states = [
            item for item in states if item["entity_id"].split(".", 1)[0] == domain
        ]
    items = [summarize_state(item) for item in states[:limit]]
    _audit_tool("list_entities", domain=domain, count=len(items))
    return {"count": len(items), "entities": items, "truncated": len(states) > limit}


@mcp.tool(title="Search Home Assistant entities", annotations=READ)
async def search_entities(
    query: Annotated[str, Field(min_length=1, max_length=120)],
    domain: str | None = None,
    limit: Annotated[int, Field(ge=1, le=100)] = 25,
) -> dict[str, Any]:
    """Search entity IDs, friendly names, and states case-insensitively."""
    needle = query.casefold()
    matches = []
    for state in await ha.states():
        entity_id = state["entity_id"]
        if domain and entity_id.split(".", 1)[0] != domain:
            continue
        attributes = state.get("attributes") or {}
        haystack = " ".join(
            [
                entity_id,
                str(attributes.get("friendly_name", "")),
                str(state.get("state", "")),
            ]
        ).casefold()
        if needle in haystack:
            matches.append(summarize_state(state))
    items = matches[:limit]
    _audit_tool("search_entities", domain=domain, count=len(items))
    return {"count": len(items), "entities": items, "truncated": len(matches) > limit}


@mcp.tool(title="Get entity state", annotations=READ)
async def get_state(entity_id: str) -> dict[str, Any]:
    """Read one exact Home Assistant entity's current state and attributes."""
    result = summarize_state(await ha.state(entity_id))
    _audit_tool("get_state", entity_id=entity_id)
    return result


@mcp.tool(title="List Home Assistant devices", annotations=READ)
async def list_devices(
    area_id: str | None = None,
    manufacturer: str | None = None,
    limit: Annotated[int, Field(ge=1, le=500)] = 200,
) -> dict[str, Any]:
    """List registered Home Assistant devices with stable IDs and area assignments."""
    devices, entities = await asyncio.gather(ha.devices(), ha.entity_registry())
    counts: dict[str, int] = defaultdict(int)
    for entity in entities:
        if entity.get("device_id"):
            counts[entity["device_id"]] += 1
    filtered = []
    for device in devices:
        if area_id and device.get("area_id") != area_id:
            continue
        if (
            manufacturer
            and manufacturer.casefold()
            not in str(device.get("manufacturer", "")).casefold()
        ):
            continue
        filtered.append(
            {
                "id": device.get("id"),
                "name": device.get("name_by_user") or device.get("name"),
                "manufacturer": device.get("manufacturer"),
                "model": device.get("model"),
                "area_id": device.get("area_id"),
                "disabled_by": device.get("disabled_by"),
                "entity_count": counts.get(device.get("id"), 0),
            }
        )
    items = filtered[:limit]
    _audit_tool("list_devices", area_id=area_id, count=len(items))
    return {"count": len(items), "devices": items, "truncated": len(filtered) > limit}


@mcp.tool(title="Get Home Assistant device", annotations=READ)
async def get_device(identifier: str) -> dict[str, Any]:
    """Get one device by exact registry ID or case-insensitive device name."""
    devices, entities, states = await asyncio.gather(
        ha.devices(), ha.entity_registry(), ha.states()
    )
    device = next((item for item in devices if item.get("id") == identifier), None)
    if device is None:
        matches = [
            item
            for item in devices
            if (item.get("name_by_user") or item.get("name") or "").casefold()
            == identifier.casefold()
        ]
        if len(matches) != 1:
            raise ValueError(
                "Device name is missing or ambiguous; use the exact device registry ID"
            )
        device = matches[0]
    state_by_id = {item["entity_id"]: item for item in states}
    device_entities = []
    for entity in entities:
        if entity.get("device_id") == device.get("id"):
            state = state_by_id.get(entity["entity_id"])
            device_entities.append(
                summarize_state(state)
                if state
                else {"entity_id": entity["entity_id"], "state": None}
            )
    _audit_tool("get_device", device_id=device.get("id"))
    return {
        "device": {
            "id": device.get("id"),
            "name": device.get("name_by_user") or device.get("name"),
            "manufacturer": device.get("manufacturer"),
            "model": device.get("model"),
            "area_id": device.get("area_id"),
            "sw_version": device.get("sw_version"),
        },
        "entities": device_entities,
    }


@mcp.tool(title="List Home Assistant areas", annotations=READ)
async def list_areas() -> dict[str, Any]:
    """List configured Home Assistant areas and stable area IDs."""
    areas = await ha.areas()
    items = [
        {"area_id": item.get("area_id"), "name": item.get("name")} for item in areas
    ]
    _audit_tool("list_areas", count=len(items))
    return {"count": len(items), "areas": items}


@mcp.tool(title="Get entity history", annotations=READ)
async def get_history(
    entity_ids: Annotated[list[str], Field(min_length=1, max_length=10)],
    start_time: Annotated[
        str, Field(description="RFC3339 timestamp for the start of the query.")
    ],
    end_time: Annotated[
        str | None, Field(description="Optional RFC3339 end timestamp.")
    ] = None,
    minimal_response: bool = True,
) -> dict[str, Any]:
    """Read bounded Home Assistant history for one to ten exact entity IDs."""
    result = await ha.history(entity_ids, start_time, end_time, minimal_response)
    _audit_tool("get_history", entity_count=len(entity_ids))
    return {"entity_ids": entity_ids, "history": result}


@mcp.tool(title="Get weather forecast", annotations=READ)
async def get_weather_forecast(
    entity_id: str = "weather.forecast_home",
    forecast_type: Literal["daily", "hourly", "twice_daily"] = "daily",
) -> dict[str, Any]:
    """Read a current Home Assistant weather forecast for one exact weather entity."""
    validate_entity_id(entity_id)
    if not entity_id.startswith("weather."):
        raise ValueError("entity_id must be a weather entity")
    state = await ha.state(entity_id)
    feature = {"daily": 1, "hourly": 2, "twice_daily": 4}[forecast_type]
    if int((state.get("attributes") or {}).get("supported_features", 0)) & feature == 0:
        raise ValueError(
            f"This weather entity does not support {forecast_type} forecasts"
        )
    response = await ha.weather_forecast(entity_id, forecast_type)
    forecast = ((response or {}).get(entity_id) or {}).get("forecast", [])
    _audit_tool(
        "get_weather_forecast", entity_id=entity_id, forecast_type=forecast_type
    )
    return {
        "entity": summarize_state(state),
        "forecast_type": forecast_type,
        "forecast": forecast[:168],
        "truncated": len(forecast) > 168,
    }


@mcp.tool(title="Get calendar events", annotations=READ)
async def get_calendar_events(
    entity_id: str,
    start_time: str,
    end_time: str,
) -> dict[str, Any]:
    """Read one calendar's events in an exact bounded RFC3339 window."""
    validate_entity_id(entity_id)
    if not entity_id.startswith("calendar."):
        raise ValueError("entity_id must be a calendar entity")
    start = parse_rfc3339(start_time, "start_time")
    end = parse_rfc3339(end_time, "end_time")
    if end <= start:
        raise ValueError("end_time must be later than start_time")
    if end - start > timedelta(days=31):
        raise ValueError("Calendar queries are limited to 31 days")
    response = await ha.call_service_response(
        "calendar",
        "get_events",
        {"start_date_time": start.isoformat(), "end_date_time": end.isoformat()},
        {"entity_id": entity_id},
    )
    value = (response or {}).get(entity_id, response or {})
    raw_events = (value or {}).get("events") or []
    events = list(raw_events)[:200]
    _audit_tool("get_calendar_events", entity_id=entity_id, count=len(events))
    return {
        "entity_id": entity_id,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "count": len(events),
        "events": events,
        "truncated": len(raw_events) > 200,
    }


@mcp.tool(title="Create calendar event", annotations=WRITE)
async def create_calendar_event(
    entity_id: str,
    summary: Annotated[str, Field(min_length=1, max_length=200)],
    start_time: str | None = None,
    end_time: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    description: Annotated[str | None, Field(max_length=2000)] = None,
    location: Annotated[str | None, Field(max_length=300)] = None,
) -> dict[str, Any]:
    """Create one timed or all-day event on one exact Home Assistant calendar."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("calendar."):
        raise ValueError("entity_id must be a calendar entity")
    timed = start_time is not None or end_time is not None
    all_day = start_date is not None or end_date is not None
    if timed == all_day:
        raise ValueError("Provide exactly one complete time pair or date pair")
    data: dict[str, Any] = {"summary": summary}
    if timed:
        if start_time is None or end_time is None:
            raise ValueError("Both start_time and end_time are required")
        start = parse_rfc3339(start_time, "start_time")
        end = parse_rfc3339(end_time, "end_time")
        if end <= start or end - start > timedelta(days=31):
            raise ValueError("Timed events must be positive and at most 31 days")
        data.update(
            {"start_date_time": start.isoformat(), "end_date_time": end.isoformat()}
        )
    else:
        if start_date is None or end_date is None:
            raise ValueError("Both start_date and end_date are required")
        try:
            start = date.fromisoformat(start_date)
            end = date.fromisoformat(end_date)
        except ValueError as exc:
            raise ValueError("Calendar dates must use YYYY-MM-DD") from exc
        if end <= start or (end - start).days > 31:
            raise ValueError("All-day events must be positive and at most 31 days")
        data.update({"start_date": start.isoformat(), "end_date": end.isoformat()})
    if description is not None:
        data["description"] = description
    if location is not None:
        data["location"] = location
    await ha.call_service("calendar", "create_event", data, {"entity_id": entity_id})
    _audit_tool("create_calendar_event", entity_id=entity_id)
    return {"status": "accepted", "entity_id": entity_id, "summary": summary}


@mcp.tool(title="Get generic schedule", annotations=READ)
async def get_schedule(entity_id: str) -> dict[str, Any]:
    """Read one exact Home Assistant schedule entity without changing it."""
    validate_entity_id(entity_id)
    if not entity_id.startswith("schedule."):
        raise ValueError("entity_id must be a schedule entity")
    response = await ha.call_service_response(
        "schedule", "get_schedule", {}, {"entity_id": entity_id}
    )
    _audit_tool("get_schedule", entity_id=entity_id)
    return {
        "entity_id": entity_id,
        "schedule": (response or {}).get(entity_id, response),
    }


@mcp.tool(title="Set time entity value", annotations=IDEMPOTENT_WRITE)
async def set_time_value(entity_id: str, value: str) -> dict[str, Any]:
    """Set one exact time entity to HH:MM or HH:MM:SS and read it back."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("time."):
        raise ValueError("entity_id must be a time entity")
    if not TIME_VALUE_RE.fullmatch(value):
        raise ValueError("value must use HH:MM or HH:MM:SS")
    await ha.call_service(
        "time", "set_value", {"time": value}, {"entity_id": entity_id}
    )
    readback = await ha.state(entity_id)
    if str(readback.get("state")) not in {value, f"{value}:00"}:
        raise HomeAssistantError("Time entity readback did not match")
    _audit_tool("set_time_value", entity_id=entity_id)
    return {"status": "completed", "entity": summarize_state(readback)}


@mcp.tool(title="List long-term statistic IDs", annotations=READ)
async def list_statistics(
    query: Annotated[str | None, Field(max_length=120)] = None,
    source: Annotated[str | None, Field(max_length=80)] = None,
    limit: Annotated[int, Field(ge=1, le=500)] = 200,
) -> dict[str, Any]:
    """List recorder statistic IDs and metadata, including SolarEdge statistics-only data."""
    matches = []
    needle = query.casefold() if query else None
    for item in await ha.statistic_ids():
        if source and str(item.get("source", "")).casefold() != source.casefold():
            continue
        haystack = " ".join(
            str(item.get(key, "")) for key in ("statistic_id", "name", "source")
        )
        if needle and needle not in haystack.casefold():
            continue
        matches.append(
            {
                "statistic_id": item.get("statistic_id"),
                "name": item.get("name"),
                "source": item.get("source"),
                "unit_of_measurement": item.get("statistics_unit_of_measurement")
                or item.get("unit_of_measurement"),
                "unit_class": item.get("unit_class"),
                "has_mean": item.get("has_mean"),
                "has_sum": item.get("has_sum"),
            }
        )
    items = matches[:limit]
    _audit_tool("list_statistics", query=query, source=source, count=len(items))
    return {"count": len(items), "statistics": items, "truncated": len(matches) > limit}


@mcp.tool(title="Get long-term statistics", annotations=READ)
async def get_long_term_statistics(
    statistic_ids: Annotated[list[str], Field(min_length=1, max_length=50)],
    start_time: str,
    end_time: str,
    period: Literal["5minute", "hour", "day", "week", "month", "year"] = "day",
    types: Annotated[
        list[Literal["change", "last_reset", "max", "mean", "min", "state", "sum"]],
        Field(min_length=1, max_length=7),
    ]
    | None = None,
    energy_unit: Literal["Wh", "kWh", "MWh"] | None = None,
) -> dict[str, Any]:
    """Read bounded recorder statistics for exact statistic IDs."""
    _validate_statistic_ids(statistic_ids)
    units = {"energy": energy_unit} if energy_unit else None
    requested_types = list(dict.fromkeys(types or ["change", "sum"]))
    result = await ha.statistics(
        statistic_ids, start_time, end_time, period, requested_types, units
    )
    _audit_tool(
        "get_long_term_statistics", statistic_count=len(statistic_ids), period=period
    )
    return {
        "period": period,
        "start_time": start_time,
        "end_time": end_time,
        "statistics": result,
    }


async def _solaredge_metadata() -> list[dict[str, Any]]:
    return [
        item
        for item in await ha.statistic_ids()
        if str(item.get("source", "")).casefold() == "solaredge"
        or "solaredge" in str(item.get("statistic_id", "")).casefold()
    ]


async def _completed_solar_window(days: int) -> tuple[str, str]:
    # SolarEdge data can arrive late. Use complete days in Home Assistant's local timezone.
    time_zone = str((await ha.config()).get("time_zone") or "UTC")
    try:
        local_zone = ZoneInfo(time_zone)
    except ZoneInfoNotFoundError:
        local_zone = UTC
    guarded = datetime.now(local_zone) - timedelta(hours=12)
    end = guarded.replace(hour=0, minute=0, second=0, microsecond=0)
    return (end - timedelta(days=days)).isoformat(), end.isoformat()


@mcp.tool(title="Get SolarEdge production summary", annotations=READ)
async def get_solar_summary(
    days: Annotated[int, Field(ge=1, le=366)] = 30,
) -> dict[str, Any]:
    """Summarize complete-day SolarEdge energy statistics from Home Assistant recorder data."""
    metadata = await _solaredge_metadata()
    if not metadata:
        return {
            "available": False,
            "reason": "No SolarEdge recorder statistics were found",
        }
    production_candidates = [
        item
        for item in metadata
        if item.get("has_sum")
        and any(
            word in f"{item.get('name', '')} {item.get('statistic_id', '')}".casefold()
            for word in ("production", "generated")
        )
        and not any(
            word in f"{item.get('name', '')} {item.get('statistic_id', '')}".casefold()
            for word in ("optimizer", "module", "battery", "inverter", "string")
        )
    ]
    inverter_candidates = [
        item
        for item in metadata
        if item.get("has_sum")
        and "inverter"
        in f"{item.get('name', '')} {item.get('statistic_id', '')}".casefold()
        and not any(
            word in f"{item.get('name', '')} {item.get('statistic_id', '')}".casefold()
            for word in ("optimizer", "module", "battery", "string")
        )
    ]
    string_candidates = [
        item
        for item in metadata
        if item.get("has_sum")
        and "string"
        in f"{item.get('name', '')} {item.get('statistic_id', '')}".casefold()
        and not any(
            word in f"{item.get('name', '')} {item.get('statistic_id', '')}".casefold()
            for word in ("optimizer", "module", "battery")
        )
    ]
    query_candidates = list(
        {
            str(item["statistic_id"]): item
            for item in (
                production_candidates + inverter_candidates + string_candidates
            )
        }.values()
    )
    if not query_candidates:
        return {
            "available": False,
            "reason": "No aggregate SolarEdge production statistics were found",
        }
    ids = [str(item["statistic_id"]) for item in query_candidates[:20]]
    start, end = await _completed_solar_window(days)
    rows = await ha.statistics(
        ids, start, end, "day", ["change", "sum"], {"energy": "kWh"}
    )

    def total_for(statistic_id: str) -> float:
        return sum(float(row.get("change") or 0) for row in rows.get(statistic_id, []))

    nonzero_production = [
        item
        for item in production_candidates
        if str(item["statistic_id"]) in ids and total_for(str(item["statistic_id"])) > 0
    ]
    if nonzero_production:
        # Dedicated production statistics are site aggregates. Select the
        # strongest populated one instead of risking double counting aliases.
        selected = [
            max(
                nonzero_production,
                key=lambda item: total_for(str(item["statistic_id"])),
            )
        ]
        source_method = "production_statistic"
    else:
        selected = [
            item
            for item in inverter_candidates
            if str(item["statistic_id"]) in ids
            and total_for(str(item["statistic_id"])) > 0
        ]
        source_method = "inverter_fallback"
        if not selected:
            selected = [
                item
                for item in string_candidates
                if str(item["statistic_id"]) in ids
                and total_for(str(item["statistic_id"])) > 0
            ]
            source_method = "string_fallback"
    if not selected:
        selected = (production_candidates or inverter_candidates or string_candidates)[
            :1
        ]
        source_method = "zero_data"

    selected_ids = [str(item["statistic_id"]) for item in selected]
    daily_by_start: dict[str, dict[str, Any]] = {}
    for statistic_id in selected_ids:
        for row in rows.get(statistic_id, []):
            row_start = str(row.get("start") or "")
            if not row_start:
                continue
            day = daily_by_start.setdefault(
                row_start,
                {
                    "start": row_start,
                    "end": row.get("end"),
                    "change_kwh": 0.0,
                },
            )
            day["change_kwh"] += float(row.get("change") or 0)
    daily = []
    for item in sorted(daily_by_start.values(), key=lambda value: value["start"]):
        item["change_kwh"] = round(float(item["change_kwh"]), 3)
        daily.append(item)

    totals = {}
    metadata_by_id = {str(item["statistic_id"]): item for item in query_candidates}
    for statistic_id in selected_ids:
        item = metadata_by_id[statistic_id]
        statistic_id = str(item["statistic_id"])
        values = rows.get(statistic_id, [])
        totals[statistic_id] = {
            "name": item.get("name"),
            "unit": "kWh",
            "total_change": round(
                sum(float(row.get("change") or 0) for row in values), 3
            ),
            "days_with_data": len(values),
            "daily": values,
        }
    _audit_tool("get_solar_summary", days=days, statistic_count=len(ids))
    return {
        "available": True,
        "complete_day_window": {
            "start": start,
            "end": end,
            "late_data_guard_hours": 12,
        },
        "production": {
            "source_method": source_method,
            "selected_statistic_ids": selected_ids,
            "total_kwh": round(sum(item["change_kwh"] for item in daily), 3),
            "days_with_data": len(daily),
            "expected_days": days,
            "complete": len(daily) == days,
            "daily": daily,
        },
        "statistics": totals,
        "solaredge_statistic_count": len(metadata),
    }


@mcp.tool(title="Compare SolarEdge modules", annotations=READ)
async def compare_solar_modules(
    days: Annotated[int, Field(ge=2, le=90)] = 14,
    underperformance_threshold_pct: Annotated[float, Field(ge=1, le=80)] = 15,
) -> dict[str, Any]:
    """Compare complete-day SolarEdge optimizer/module energy against the peer median."""
    metadata = await _solaredge_metadata()
    modules = [
        item
        for item in metadata
        if item.get("has_sum")
        and any(
            word in f"{item.get('name', '')} {item.get('statistic_id', '')}".casefold()
            for word in ("optimizer", "module")
        )
    ]
    if not modules:
        return {
            "available": False,
            "reason": "No SolarEdge optimizer/module statistics were found",
        }
    ids = [str(item["statistic_id"]) for item in modules[:50]]
    start, end = await _completed_solar_window(days)
    rows = await ha.statistics(ids, start, end, "day", ["change"], {"energy": "kWh"})
    totals = {
        statistic_id: sum(
            float(row.get("change") or 0) for row in rows.get(statistic_id, [])
        )
        for statistic_id in ids
    }
    names = {str(item["statistic_id"]): str(item.get("name") or "") for item in modules}

    def string_name(statistic_id: str) -> str:
        label = f"{names.get(statistic_id, '')} {statistic_id}"
        match = re.search(r"(?:optimizer|module)\s+(\d+\.\d+)\.\d+\b", label, re.I)
        return match.group(1) if match else "unassigned"

    buckets: dict[str, list[float]] = defaultdict(list)
    for statistic_id, value in totals.items():
        if value > 0:
            buckets[string_name(statistic_id)].append(value)
    medians = {
        name: median(values) if values else 0.0 for name, values in buckets.items()
    }
    comparison = []
    for statistic_id, total in sorted(totals.items(), key=lambda pair: pair[1]):
        module_string = string_name(statistic_id)
        peer_median = medians.get(module_string, 0.0)
        delta_pct = ((total - peer_median) / peer_median * 100) if peer_median else None
        comparison.append(
            {
                "statistic_id": statistic_id,
                "name": names.get(statistic_id),
                "string": module_string,
                "energy_kwh": round(total, 3),
                "string_median_kwh": round(peer_median, 3),
                "vs_string_median_pct": round(delta_pct, 1)
                if delta_pct is not None
                else None,
                "underperforming": delta_pct is not None
                and delta_pct <= -underperformance_threshold_pct,
            }
        )
    _audit_tool("compare_solar_modules", days=days, module_count=len(comparison))
    return {
        "available": True,
        "complete_day_window": {
            "start": start,
            "end": end,
            "late_data_guard_hours": 12,
        },
        "comparison_basis": "median energy among optimizers on the same string",
        "strings": {
            name: {"module_count": len(values), "median_kwh": round(medians[name], 3)}
            for name, values in sorted(buckets.items())
        },
        "threshold_pct": underperformance_threshold_pct,
        "modules": comparison,
    }


def _require_solaredge() -> tuple[SolarEdgeOAuthManager, SolarEdgeClient]:
    if solaredge_oauth is None or solaredge is None:
        raise SolarEdgeAuthorizationError(
            "SolarEdge ONE credentials are not configured"
        )
    return solaredge_oauth, solaredge


def _require_solaredge_portal() -> SolarEdgePortalClient:
    if solaredge_portal is None:
        raise SolarEdgePortalError(
            "SolarEdge Monitoring portal credentials are not configured"
        )
    return solaredge_portal


async def _solaredge_lifetime_energy() -> dict[str, Any]:
    global _solaredge_lifetime_cache
    provider = _require_solaredge_portal()
    now = time.monotonic()
    if (
        _solaredge_lifetime_cache is not None
        and now - _solaredge_lifetime_cache[0] < _SOLAREDGE_LIFETIME_CACHE_SECONDS
    ):
        return json.loads(json.dumps(_solaredge_lifetime_cache[1]))
    result = await provider.lifetime_energy_summary()
    _solaredge_lifetime_cache = (now, result)
    return json.loads(json.dumps(result))


def _portal_local_date() -> datetime:
    timezone_name = str(config.SOLAREDGE_PORTAL_TIMEZONE or "UTC")
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise SolarEdgePortalError("SolarEdge portal timezone is invalid") from exc
    return datetime.now(zone)


def _component_number(component: Any, *keys: str) -> float | None:
    if not isinstance(component, dict):
        return None
    for key in keys:
        value = component.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0.0, float(value))
    return None


def _component_text(component: Any, *keys: str) -> str:
    if not isinstance(component, dict):
        return ""
    for key in keys:
        value = component.get(key)
        if isinstance(value, str):
            return value.casefold()
    return ""


async def _build_solaredge_bridge_snapshot() -> dict[str, Any]:
    provider = _require_solaredge_portal()
    flow, lifetime = await asyncio.gather(
        provider.live_power_flow(), _solaredge_lifetime_energy()
    )
    components = flow.get("components", {})
    if not isinstance(components, dict):
        components = {}

    solar = components.get("solar_production", {})
    consumption = components.get("consumption", {})
    grid = components.get("grid", {})
    storage_candidates = [
        item
        for item in (
            components.get("dc_storage"),
            components.get("ac_storage"),
        )
        if isinstance(item, dict)
    ]
    storage = next(
        (
            item
            for item in storage_candidates
            if _component_number(item, "chargeLevel", "stateOfCharge") is not None
        ),
        storage_candidates[0] if storage_candidates else {},
    )
    storage_operating_plan = flow.get("storage_operating_plan", {})
    if not isinstance(storage_operating_plan, dict):
        storage_operating_plan = {}

    grid_power = _component_number(grid, "current_power_w", "power_w")
    grid_status = _component_text(grid, "status", "direction")
    grid_import = (
        grid_power
        if grid_power is not None
        and ("import" in grid_status or "from_grid" in grid_status)
        else 0.0
        if grid_power is not None
        else None
    )
    grid_export = (
        grid_power
        if grid_power is not None
        and ("export" in grid_status or "to_grid" in grid_status)
        else 0.0
        if grid_power is not None
        else None
    )

    storage_power = _component_number(storage, "current_power_w", "power_w")
    storage_status = _component_text(storage, "status", "direction")
    battery_charge = (
        storage_power
        if storage_power is not None
        and "charg" in storage_status
        and "discharg" not in storage_status
        else 0.0
        if storage_power is not None
        else None
    )
    battery_discharge = (
        storage_power
        if storage_power is not None and "discharg" in storage_status
        else 0.0
        if storage_power is not None
        else None
    )

    totals = lifetime.get("totals_kwh", {})
    production_distribution = lifetime.get("production_distribution", {})
    consumption_distribution = lifetime.get("consumption_distribution", {})
    if not isinstance(totals, dict):
        totals = {}
    if not isinstance(production_distribution, dict):
        production_distribution = {}
    if not isinstance(consumption_distribution, dict):
        consumption_distribution = {}

    site: dict[str, Any] = {
        "production_power_w": _component_number(solar, "current_power_w", "power_w"),
        "consumption_power_w": _component_number(
            consumption, "current_power_w", "power_w"
        ),
        "grid_import_power_w": grid_import,
        "grid_export_power_w": grid_export,
        "battery_charge_power_w": battery_charge,
        "battery_discharge_power_w": battery_discharge,
        "battery_state_of_energy_pct": _component_number(
            storage, "chargeLevel", "stateOfCharge"
        ),
        "production_energy_kwh": _component_number(totals, "production"),
        "consumption_energy_kwh": _component_number(totals, "consumption"),
        "grid_import_energy_kwh": _component_number(totals, "import"),
        "grid_export_energy_kwh": _component_number(totals, "export"),
        "battery_charge_energy_kwh": _component_number(
            production_distribution,
            "production_to_battery_kwh",
            "storage_kwh",
        ),
        "battery_discharge_energy_kwh": _component_number(
            consumption_distribution,
            "consumption_from_battery_kwh",
            "storage_kwh",
        ),
        "storage_operating_plan": storage_operating_plan.get("plan"),
        "storage_operating_plan_active": storage_operating_plan.get("is_active"),
        "storage_operating_plan_block_count": storage_operating_plan.get("block_count"),
    }
    clean_site = {key: value for key, value in site.items() if value is not None}
    observed_at = flow.get("last_update_time")
    if not isinstance(observed_at, str) or not observed_at:
        observed_at = datetime.now(UTC).isoformat()
    return {
        "connected": True,
        "provider": "solaredge_monitoring_portal",
        "observed_at": observed_at,
        "site": clean_site,
        "completeness": {key: value is not None for key, value in site.items()},
    }


def _solaredge_window(days: int) -> tuple[str, str]:
    end = datetime.now(UTC).replace(microsecond=0)
    start = end - timedelta(days=days)
    return start.isoformat(), end.isoformat()


@mcp.tool(title="Get SolarEdge ONE connection status", annotations=READ)
async def get_solaredge_connection_status() -> dict[str, Any]:
    """Report official V2 status and the guarded Monitoring portal fallback."""
    official: dict[str, Any]
    if solaredge_oauth is None:
        official = {
            "configured": False,
            "authorized": False,
            "scopes": list(OAUTH_SCOPES),
        }
    else:
        official = solaredge_oauth.status()
        official.pop("site_id", None)
        official["site_authorized"] = bool(official.get("authorized"))

    if solaredge_portal is None:
        portal_status: dict[str, Any] = {"configured": False, "reachable": False}
    else:
        portal_status = await solaredge_portal.provider_health(refresh=True)

    effective_provider = (
        "solaredge_one_v2"
        if bool(official.get("authorized"))
        else "solaredge_monitoring_portal"
        if bool(portal_status.get("reachable"))
        else None
    )
    return {
        "configured": bool(official.get("configured"))
        or bool(portal_status.get("configured")),
        "authorized": bool(official.get("authorized")),
        "provider": "solaredge_one_v2_with_portal_fallback",
        "effective_provider": effective_provider,
        "official_v2": official,
        "monitoring_portal_fallback": portal_status,
        "privacy": "site identifiers, addresses, and device serials omitted",
    }


@mcp.tool(title="Begin SolarEdge ONE authorization", annotations=WRITE)
async def begin_solaredge_authorization() -> dict[str, Any]:
    """Create a short-lived SolarEdge consent link for the configured read-only app."""
    _require_write()
    provider_oauth, _ = _require_solaredge()
    authorization = provider_oauth.begin_authorization()
    _audit_tool("begin_solaredge_authorization")
    return {
        "authorization_url": authorization["authorization_url"],
        "expires_at": authorization["expires_at"],
        "scopes": list(OAUTH_SCOPES),
        "access_duration_months": 24,
    }


@mcp.tool(title="Get SolarEdge ONE site overview", annotations=READ)
async def get_solaredge_site_overview(
    days: Annotated[int, Field(ge=1, le=31)] = 1,
) -> dict[str, Any]:
    """Read production and consumption totals from SolarEdge ONE V2."""
    _, provider = _require_solaredge()
    start, end = _solaredge_window(days)
    result = await provider.site_overview(**{"from": start, "to": end})
    _audit_tool("get_solaredge_site_overview", days=days)
    return {
        "provider": "solaredge_one_v2",
        "window": {"from": start, "to": end},
        "data": result,
    }


@mcp.tool(title="Get SolarEdge ONE energy history", annotations=READ)
async def get_solaredge_energy_history(
    days: Annotated[int, Field(ge=1, le=31)] = 7,
    resolution: Literal[
        "QUARTER_HOUR", "HOUR", "DAY", "WEEK", "MONTH", "TOTAL"
    ] = "DAY",
) -> dict[str, Any]:
    """Read bounded site-level production and consumption energy history."""
    _, provider = _require_solaredge()
    start, end = _solaredge_window(days)
    result = await provider.energy(
        **{"from": start, "to": end, "resolution": resolution}
    )
    _audit_tool("get_solaredge_energy_history", days=days, resolution=resolution)
    return {
        "provider": "solaredge_one_v2",
        "window": {"from": start, "to": end},
        "resolution": resolution,
        "data": result,
    }


@mcp.tool(title="Get SolarEdge ONE power history", annotations=READ)
async def get_solaredge_power_history(
    hours: Annotated[int, Field(ge=1, le=168)] = 24,
    resolution: Literal["QUARTER_HOUR", "HOUR", "DAY"] = "QUARTER_HOUR",
) -> dict[str, Any]:
    """Read bounded site-level power history; free-tier minimum is 15 minutes."""
    _, provider = _require_solaredge()
    end = datetime.now(UTC).replace(microsecond=0)
    start = end - timedelta(hours=hours)
    result = await provider.power(
        **{
            "from": start.isoformat(),
            "to": end.isoformat(),
            "resolution": resolution,
        }
    )
    _audit_tool("get_solaredge_power_history", hours=hours, resolution=resolution)
    return {
        "provider": "solaredge_one_v2",
        "window": {"from": start.isoformat(), "to": end.isoformat()},
        "resolution": resolution,
        "data": result,
    }


@mcp.tool(title="Get SolarEdge ONE device telemetry", annotations=READ)
async def get_solaredge_device_telemetry() -> dict[str, Any]:
    """Read privacy-filtered inverter, meter, battery, and inventory telemetry."""
    _, provider = _require_solaredge()
    inventory, inverters, meters, storage = await asyncio.gather(
        provider.inventory(),
        provider.inverter_telemetry(),
        provider.meter_telemetry(),
        provider.storage_telemetry(),
    )
    _audit_tool("get_solaredge_device_telemetry")
    return {
        "provider": "solaredge_one_v2",
        "fetched_at": datetime.now(UTC).isoformat(),
        "inventory": inventory,
        "inverters": inverters,
        "meters": meters,
        "storage": storage,
        "privacy": "addresses and device serial identifiers omitted",
    }


@mcp.tool(title="Get SolarEdge ONE site alerts", annotations=READ)
async def get_solaredge_site_alerts() -> dict[str, Any]:
    """Read current and historical alerts for the authorized SolarEdge site."""
    _, provider = _require_solaredge()
    result = await provider.alerts()
    _audit_tool("get_solaredge_site_alerts")
    return {
        "provider": "solaredge_one_v2",
        "fetched_at": datetime.now(UTC).isoformat(),
        "data": result,
    }


@mcp.tool(title="Get live SolarEdge power flow", annotations=READ)
async def get_solar_power_flow() -> dict[str, Any]:
    """Read live power direction and privacy-safe current storage-plan metadata."""
    provider = _require_solaredge_portal()
    capabilities, flow = await asyncio.gather(
        provider.capabilities(), provider.live_power_flow()
    )
    _audit_tool("get_solar_power_flow")
    return {
        "provider": "solaredge_monitoring_portal_fallback",
        "fetched_at": datetime.now(UTC).isoformat(),
        "capabilities": capabilities,
        "power_flow": flow,
        "units": "power values are watts; battery level is percent",
    }


@mcp.tool(title="Get SolarEdge energy breakdown", annotations=READ)
async def get_solar_energy_breakdown(
    days: Annotated[int, Field(ge=1, le=366)] = 7,
    include_today: bool = False,
) -> dict[str, Any]:
    """Read production, consumption, grid, and battery energy for local dates."""
    provider = _require_solaredge_portal()
    if include_today:
        end_date = _portal_local_date().date()
        start_date = end_date - timedelta(days=days - 1)
        result = await provider.energy_history(
            start_date,
            end_date,
            chart_time_unit="quarter-hours" if days == 1 else "days",
        )
        result["window_type"] = "includes_current_local_date"
        result["timezone"] = str(config.SOLAREDGE_PORTAL_TIMEZONE)
    else:
        result = await provider.completed_energy_summary(days)
    _audit_tool("get_solar_energy_breakdown", days=days, include_today=include_today)
    return {
        "provider": "solaredge_monitoring_portal_fallback",
        "energy": result,
        "units": "energy values are kilowatt-hours",
    }


@mcp.tool(title="Get SolarEdge storage summary", annotations=READ)
async def get_solar_storage_summary(
    days: Annotated[int, Field(ge=1, le=366)] = 7,
) -> dict[str, Any]:
    """Read current battery state and completed-day charge/discharge flows."""
    provider = _require_solaredge_portal()
    energy = await provider.completed_energy_summary(days)
    start_date = datetime.fromisoformat(str(energy["start_date"])).date()
    end_date = datetime.fromisoformat(str(energy["end_date"])).date()
    flow, distribution, lifetime = await asyncio.gather(
        provider.live_power_flow(),
        provider.storage_distribution(start_date, end_date),
        _solaredge_lifetime_energy(),
    )
    _audit_tool("get_solar_storage_summary", days=days)
    return {
        "provider": "solaredge_monitoring_portal_fallback",
        "current_storage": {
            key: value
            for key, value in flow.get("components", {}).items()
            if key in {"ac_storage", "dc_storage"}
        },
        "storage_operating_plan": flow.get("storage_operating_plan", {}),
        "completed_local_date_window": {
            "start_date": energy["start_date"],
            "end_date": energy["end_date"],
            "production_distribution": energy.get("production_distribution"),
            "consumption_distribution": energy.get("consumption_distribution"),
            "storage_distribution": distribution.get("distribution"),
        },
        "lifetime": {
            "production_distribution": lifetime.get("production_distribution"),
            "consumption_distribution": lifetime.get("consumption_distribution"),
        },
        "units": "power values are watts, energy values are kilowatt-hours",
    }


@mcp.tool(title="Get Home Assistant system health", annotations=READ)
async def get_system_health() -> dict[str, Any]:
    """Summarize core reachability, unavailable entities, and integration health."""
    ha_config, states, integrations, registry = await asyncio.gather(
        ha.config(), ha.states(), ha.integrations(), ha.entity_registry()
    )
    platform_by_entity = {
        item.get("entity_id"): item.get("platform") for item in registry
    }
    unavailable: dict[str, int] = defaultdict(int)
    for state in states:
        if state.get("state") in {"unavailable", "unknown"}:
            unavailable[
                str(platform_by_entity.get(state.get("entity_id")) or "unknown")
            ] += 1
    failed_integrations = [
        {
            "domain": item.get("domain"),
            "title": item.get("title"),
            "state": item.get("state"),
            "reason": item.get("reason"),
        }
        for item in integrations
        if item.get("state") != "loaded"
    ]
    result = {
        "version": ha_config.get("version"),
        "state_count": len(states),
        "unavailable_or_unknown_count": sum(unavailable.values()),
        "unavailable_by_integration": dict(
            sorted(unavailable.items(), key=lambda pair: (-pair[1], pair[0]))
        ),
        "integration_count": len(integrations),
        "failed_integrations": failed_integrations,
    }
    _audit_tool("get_system_health", unavailable=result["unavailable_or_unknown_count"])
    return result


@mcp.tool(title="Get current host and runtime health", annotations=READ)
async def get_host_runtime_health() -> dict[str, Any]:
    """Read the latest sanitized host, container, resource, and collector snapshot."""
    _require_diagnostics()
    result = diagnostics.get_current_health()
    started = time.monotonic()
    try:
        ha_config = await ha.config()
        internal_connection = {
            "reachable": True,
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "home_assistant_version": ha_config.get("version"),
        }
    except HomeAssistantError:
        internal_connection = {
            "reachable": False,
            "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "home_assistant_version": None,
        }
    result["mcp_internal_home_assistant_connection"] = internal_connection
    _audit_tool(
        "get_host_runtime_health",
        fresh=bool(result.get("fresh")),
        complete=bool(result.get("complete")),
    )
    return result


@mcp.tool(title="Diagnose restarts and outages", annotations=READ)
async def get_restart_outage_diagnostics(
    since_hours: Annotated[float | None, Field(gt=0, le=168)] = None,
    start_time: Annotated[str | None, Field(max_length=64)] = None,
    end_time: Annotated[str | None, Field(max_length=64)] = None,
    limit: Annotated[int, Field(ge=1, le=200)] = 100,
) -> dict[str, Any]:
    """Correlate bounded persistent restart, OOM, host, tunnel, and route evidence."""
    _require_diagnostics()
    result = diagnostics.get_restart_outage_diagnostics(
        since_hours=since_hours,
        start=start_time,
        end=end_time,
        limit=limit,
    )
    _audit_tool(
        "get_restart_outage_diagnostics",
        window_mode="explicit" if start_time is not None else "since_hours",
        since_hours=since_hours,
        limit=limit,
        event_count=result.get("event_count"),
        truncated=bool(result.get("truncated")),
    )
    return result


@mcp.tool(title="List sanitized diagnostic events", annotations=READ)
async def list_diagnostic_events(
    components: Annotated[
        list[DiagnosticComponent] | None, Field(max_length=10)
    ] = None,
    severities: Annotated[list[DiagnosticSeverity] | None, Field(max_length=4)] = None,
    since_hours: Annotated[float | None, Field(gt=0, le=168)] = None,
    start_time: Annotated[str | None, Field(max_length=64)] = None,
    end_time: Annotated[str | None, Field(max_length=64)] = None,
    limit: Annotated[int, Field(ge=1, le=200)] = 100,
) -> dict[str, Any]:
    """Return bounded allowlisted events; arbitrary paths, logs, and searches are unavailable."""
    _require_diagnostics()
    component_values = list(components) if components is not None else None
    severity_values = list(severities) if severities is not None else None
    if (
        component_values is not None
        and not set(component_values) <= DIAGNOSTIC_COMPONENTS
    ):
        raise ValueError("components contains an unsupported value")
    if (
        severity_values is not None
        and not set(severity_values) <= DIAGNOSTIC_SEVERITIES
    ):
        raise ValueError("severities contains an unsupported value")
    result = diagnostics.get_diagnostic_events(
        since_hours=since_hours,
        start=start_time,
        end=end_time,
        components=component_values,
        severities=severity_values,
        limit=limit,
    )
    _audit_tool(
        "list_diagnostic_events",
        window_mode="explicit" if start_time is not None else "since_hours",
        since_hours=since_hours,
        component_count=len(component_values or []),
        severity_count=len(severity_values or []),
        limit=limit,
        returned_count=result.get("count"),
        truncated=bool(result.get("truncated")),
    )
    return result


@mcp.tool(title="Check fixed Home Assistant and MCP routes", annotations=READ)
async def get_fixed_route_health() -> dict[str, Any]:
    """Probe only the configured frontend and MCP routes and their fixed local origins."""
    _require_diagnostics()
    result = await diagnostics.get_fixed_route_health()
    routes = result.get("routes") or {}
    _audit_tool(
        "get_fixed_route_health",
        frontend_present="home_assistant_frontend" in routes,
        mcp_present="mcp" in routes,
    )
    return result


@mcp.tool(title="Get fixed home-LAN route status", annotations=READ)
async def get_lan_gateway_status() -> dict[str, Any]:
    """Check the routed home-LAN path using only fixed router TCP services."""
    _require_diagnostics()
    result = await lan_diagnostics.gateway_status()
    _audit_tool(
        "get_lan_gateway_status",
        reachable=bool(result.get("home_lan_route_reachable")),
    )
    return result


@mcp.tool(title="List reachable home-LAN nodes", annotations=READ)
async def list_lan_nodes(
    services: Annotated[list[LanService] | None, Field(max_length=10)] = None,
    max_results: Annotated[int, Field(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    """Discover nodes by bounded TCP-connect checks against fixed services only."""
    _require_diagnostics()
    result = await lan_diagnostics.scan(services, max_results=max_results)
    _audit_tool(
        "list_lan_nodes",
        service_count=len(services or []),
        returned_count=result.get("count"),
        truncated=bool(result.get("truncated")),
    )
    return result


@mcp.tool(title="Probe one home-LAN node", annotations=READ)
async def probe_lan_node(
    node_id: Annotated[
        str,
        Field(
            pattern=r"^node-\d{3}$",
            max_length=8,
            description="Opaque fixed-subnet node ID, such as node-067.",
        ),
    ],
    services: Annotated[list[LanService] | None, Field(max_length=10)] = None,
) -> dict[str, Any]:
    """Probe one node using only the closed allowlist of TCP services."""
    _require_diagnostics()
    result = await lan_diagnostics.probe_node(node_id, services)
    _audit_tool(
        "probe_lan_node",
        node_id=node_id,
        service_count=len(services or []),
        reachable=bool(result.get("reachable")),
    )
    return result


@mcp.tool(title="Get backup status", annotations=READ)
async def get_backup_status() -> dict[str, Any]:
    """Read Home Assistant automatic-backup event and manager/timestamp sensor status."""
    states = await ha.states()
    items = [
        summarize_state(state)
        for state in states
        if state["entity_id"] == "event.backup_automatic_backup"
        or "backup" in state["entity_id"].casefold()
        and state["entity_id"].split(".", 1)[0] in {"binary_sensor", "event", "sensor"}
    ]
    _audit_tool("get_backup_status", count=len(items))
    return {"count": len(items), "entities": items}


@mcp.tool(title="Create Home Assistant backup", annotations=DESTRUCTIVE_WRITE)
async def create_home_assistant_backup(confirmed: bool = False) -> dict[str, Any]:
    """Request an automatic Home Assistant backup after explicit current-turn confirmation."""
    _require_write()
    _require_confirmed(confirmed, "Creating a Home Assistant backup")
    result = await ha.call_service(
        "backup", "create_automatic", {}, timeout_seconds=180
    )
    _audit_tool("create_home_assistant_backup")
    return {"status": "accepted", "result": result}


@mcp.tool(title="List Home Assistant dashboards", annotations=READ)
async def list_dashboards() -> dict[str, Any]:
    """List Lovelace dashboards and their storage metadata."""
    dashboards = await ha.dashboards()
    items = [
        {
            key: item.get(key)
            for key in (
                "id",
                "url_path",
                "title",
                "icon",
                "show_in_sidebar",
                "require_admin",
                "mode",
            )
        }
        for item in dashboards
    ]
    _audit_tool("list_dashboards", count=len(items))
    return {"count": len(items), "dashboards": items}


@mcp.tool(title="Get Home Assistant dashboard", annotations=READ)
async def get_dashboard(url_path: str = "lovelace") -> dict[str, Any]:
    """Read one complete storage-mode Lovelace dashboard configuration."""
    if url_path != "lovelace":
        _validate_dashboard_path(url_path)
    dashboard = await ha.dashboard_config(None if url_path == "lovelace" else url_path)
    _audit_tool("get_dashboard", url_path=url_path)
    return {"url_path": url_path, "config": dashboard}


def _validate_dashboard_config(dashboard: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(dashboard, dict):
        raise ValueError("dashboard must be an object")
    _bounded_object(dashboard, "dashboard", MAX_DASHBOARD_CONFIG_BYTES)
    if redact_sensitive(dashboard) != dashboard:
        raise ValueError(
            "dashboard must not contain credentials or secret-bearing fields"
        )
    views = dashboard.get("views")
    if not isinstance(views, list) or not views:
        raise ValueError("dashboard.views must be a non-empty list")
    for index, view in enumerate(views):
        if not isinstance(view, dict):
            raise ValueError(f"dashboard.views[{index}] must be an object")
        if not isinstance(view.get("title"), str) or not view["title"].strip():
            raise ValueError(f"dashboard.views[{index}].title is required")
        if "cards" in view and not isinstance(view["cards"], list):
            raise ValueError(f"dashboard.views[{index}].cards must be a list")
    return dashboard


@mcp.tool(title="Create Home Assistant dashboard", annotations=WRITE)
async def create_dashboard(
    url_path: str,
    title: Annotated[str, Field(min_length=1, max_length=80)],
    dashboard: dict[str, Any],
    icon: Annotated[str | None, Field(max_length=80)] = None,
) -> dict[str, Any]:
    """Create a storage-mode dashboard at one new exact path and save its validated config."""
    _require_write()
    _validate_dashboard_path(url_path)
    config_value = _validate_dashboard_config(dashboard)
    existing = await ha.dashboards()
    if any(item.get("url_path") == url_path for item in existing):
        raise ValueError("Dashboard already exists; use update_dashboard")
    created = await ha.create_dashboard(url_path, title, icon)
    try:
        await ha.save_dashboard_config(config_value, url_path)
    except Exception:
        dashboard_id = created.get("id") if isinstance(created, dict) else None
        if dashboard_id:
            try:
                await ha.delete_dashboard(str(dashboard_id))
            except Exception:
                LOGGER.exception(
                    "dashboard_create_rollback_failed url_path=%s", url_path
                )
        raise
    readback = await ha.dashboard_config(url_path)
    _audit_tool("create_dashboard", url_path=url_path)
    return {"status": "completed", "url_path": url_path, "config": readback}


@mcp.tool(title="Update Home Assistant dashboard", annotations=IDEMPOTENT_WRITE)
async def update_dashboard(url_path: str, dashboard: dict[str, Any]) -> dict[str, Any]:
    """Replace one dashboard config after a timestamped backup and verify the readback."""
    _require_write()
    if url_path != "lovelace":
        _validate_dashboard_path(url_path)
    config_value = _validate_dashboard_config(dashboard)
    current = await ha.dashboard_config(None if url_path == "lovelace" else url_path)
    backup = ha.backup_dashboard("update-dashboard", url_path, current)
    path_argument = None if url_path == "lovelace" else url_path
    try:
        await ha.save_dashboard_config(config_value, path_argument)
        readback = await ha.dashboard_config(path_argument)
        if readback != config_value:
            raise HomeAssistantError(
                "Dashboard readback did not match the requested configuration"
            )
    except Exception:
        try:
            await ha.save_dashboard_config(current, path_argument)
        except Exception:
            LOGGER.exception("dashboard_update_rollback_failed url_path=%s", url_path)
        raise
    _audit_tool("update_dashboard", url_path=url_path, backup=backup)
    return {
        "status": "completed",
        "url_path": url_path,
        "backup": backup,
        "config": readback,
    }


@mcp.tool(title="List Home Assistant services", annotations=READ)
async def list_services(domain: str | None = None) -> dict[str, Any]:
    """List Home Assistant service schemas and whether generic calls are allowlisted."""
    domains = await ha.services()
    items = []
    for item in domains:
        if domain and item.get("domain") != domain:
            continue
        services = []
        for name, detail in (item.get("services") or {}).items():
            services.append(
                {
                    "service": name,
                    "name": detail.get("name"),
                    "description": detail.get("description"),
                    "fields": detail.get("fields", {}),
                    "generic_call_allowed": name
                    in ALLOWED_SERVICES.get(item.get("domain"), set()),
                }
            )
        items.append({"domain": item.get("domain"), "services": services})
    _audit_tool("list_services", domain=domain, count=len(items))
    return {"domains": items}


@mcp.tool(
    title="Get Home Assistant capability synchronization status", annotations=READ
)
async def get_capability_sync_status(refresh: bool = False) -> dict[str, Any]:
    """Report persistent HA service drift since the current MCP release was deployed."""
    if refresh:
        result = await capability_sync.refresh(ha)
    else:
        result = capability_sync.status()
        if result.get("last_checked") is None:
            result = await capability_sync.refresh(ha)
    _audit_tool(
        "get_capability_sync_status",
        status=result.get("status"),
        added=len((result.get("drift") or {}).get("added") or []),
        removed=len((result.get("drift") or {}).get("removed") or []),
        changed=len((result.get("drift") or {}).get("changed") or []),
    )
    return result


@mcp.tool(title="Get Home Assistant overview", annotations=READ)
async def get_home_overview() -> dict[str, Any]:
    """Summarize MCP/HA versions, health, entity domains, and integration states."""
    ha_config, states, integrations = await asyncio.gather(
        ha.config(), ha.states(), ha.integrations()
    )
    domain_counts: dict[str, int] = defaultdict(int)
    for state in states:
        domain_counts[state["entity_id"].split(".", 1)[0]] += 1
    integration_states: dict[str, int] = defaultdict(int)
    for integration in integrations:
        integration_states[str(integration.get("state") or "unknown")] += 1
    result = {
        "service_version": SERVER_VERSION,
        "version": ha_config.get("version"),
        "time_zone": ha_config.get("time_zone"),
        "unit_system": ha_config.get("unit_system"),
        "entity_count": len(states),
        "entity_domains": dict(sorted(domain_counts.items())),
        "integration_count": len(integrations),
        "integration_states": dict(sorted(integration_states.items())),
    }
    _audit_tool("get_home_overview", entity_count=len(states))
    return result


@mcp.tool(title="List Home Assistant integrations", annotations=READ)
async def list_integrations(
    domain: str | None = None,
    state: str | None = None,
) -> dict[str, Any]:
    """List integration entries and their current load state without returning credentials."""
    items = []
    for integration in await ha.integrations():
        if domain and integration.get("domain") != domain:
            continue
        if state and integration.get("state") != state:
            continue
        items.append(
            {
                "entry_id": integration.get("entry_id"),
                "domain": integration.get("domain"),
                "title": integration.get("title"),
                "state": integration.get("state"),
                "source": integration.get("source"),
                "disabled_by": integration.get("disabled_by"),
                "reason": integration.get("reason"),
                "supports_options": integration.get("supports_options"),
                "supports_reconfigure": integration.get("supports_reconfigure"),
            }
        )
    _audit_tool("list_integrations", domain=domain, state=state, count=len(items))
    return {"count": len(items), "integrations": items}


@mcp.tool(title="List Home Assistant registry entities", annotations=READ)
async def list_registry_entities(
    domain: str | None = None,
    device_id: str | None = None,
    area_id: str | None = None,
    include_disabled: bool = False,
    limit: Annotated[int, Field(ge=1, le=1000)] = 500,
) -> dict[str, Any]:
    """List entity-registry records, including entities that currently have no state."""
    matches = []
    for entity in await ha.entity_registry():
        entity_id = str(entity.get("entity_id") or "")
        if domain and not entity_id.startswith(f"{domain}."):
            continue
        if device_id and entity.get("device_id") != device_id:
            continue
        if area_id and entity.get("area_id") != area_id:
            continue
        if not include_disabled and entity.get("disabled_by") is not None:
            continue
        matches.append(
            {
                "entity_id": entity_id,
                "name": entity.get("name") or entity.get("original_name"),
                "device_id": entity.get("device_id"),
                "area_id": entity.get("area_id"),
                "platform": entity.get("platform"),
                "disabled_by": entity.get("disabled_by"),
                "hidden_by": entity.get("hidden_by"),
            }
        )
    items = matches[:limit]
    _audit_tool("list_registry_entities", domain=domain, count=len(items))
    return {"count": len(items), "entities": items, "truncated": len(matches) > limit}


@mcp.tool(title="Get thermostat summary", annotations=READ)
async def get_thermostat_summary(target: ThermostatTarget = "both") -> dict[str, Any]:
    """Read thermostat state, active schedule period, presence, and away-control status."""
    names = _target_names(target)
    entity_ids = []
    for name in names:
        entity_ids.extend(
            [THERMOSTATS[name]["climate"], f"schedule.{THERMOSTATS[name]['schedule']}"]
        )
    states = await asyncio.gather(
        *(ha.state(entity_id) for entity_id in entity_ids),
        ha.state(PRESENCE_ENTITY),
        ha.state(AWAY_AUTOMATION),
    )
    state_map = {item["entity_id"]: summarize_state(item) for item in states}
    thermostats = {}
    for name in names:
        details = THERMOSTATS[name]
        thermostats[name] = {
            "climate": state_map[details["climate"]],
            "schedule": state_map[f"schedule.{details['schedule']}"],
        }
    result = {
        "thermostats": thermostats,
        "presence": state_map[PRESENCE_ENTITY],
        "away_automation": state_map[AWAY_AUTOMATION],
    }
    _audit_tool("get_thermostat_summary", target=target)
    return result


@mcp.tool(title="List thermostat schedules", annotations=READ)
async def list_thermostat_schedules() -> dict[str, Any]:
    """Read both complete editable thermostat schedules for every day of the week."""
    schedule_map = _schedule_map(await ha.schedules())
    items = [schedule_map[details["schedule"]] for details in THERMOSTATS.values()]
    _audit_tool("list_thermostat_schedules", count=len(items))
    return {"count": len(items), "schedules": items}


@mcp.tool(title="Get thermostat schedule", annotations=READ)
async def get_thermostat_schedule(thermostat: str) -> dict[str, Any]:
    """Read one complete thermostat schedule by living_space, bedroom, schedule ID, or climate ID."""
    name = _thermostat_name(thermostat)
    schedule_id = THERMOSTATS[name]["schedule"]
    schedule = _schedule_map(await ha.schedules()).get(schedule_id)
    if schedule is None:
        raise HomeAssistantError("The thermostat schedule was not found")
    _audit_tool("get_thermostat_schedule", thermostat=name)
    return {"thermostat": name, "schedule": schedule}


@mcp.tool(title="Get shared thermostat presets", annotations=READ)
async def get_temperature_presets() -> dict[str, Any]:
    """Read the shared named temperature registry and report schedule blocks that drift from it."""
    presets = _load_presets()
    drifts = []
    usage: dict[str, dict[str, int]] = {
        name: {key: 0 for key in THERMOSTATS} for name in presets
    }
    schedule_map = _schedule_map(await ha.schedules())
    for thermostat_name, details in THERMOSTATS.items():
        schedule = schedule_map.get(details["schedule"], {})
        for day in SCHEDULE_DAYS:
            for period in schedule.get(day, []):
                data = period.get("data") or {}
                preset = data.get("period")
                if preset not in presets:
                    continue
                usage[preset][thermostat_name] += 1
                if float(data.get("temperature")) != presets[preset]:
                    drifts.append(
                        {
                            "thermostat": thermostat_name,
                            "day": day,
                            "from": period.get("from"),
                            "preset": preset,
                            "scheduled_temperature": data.get("temperature"),
                            "shared_temperature": presets[preset],
                        }
                    )
    _audit_tool("get_temperature_presets", drift_count=len(drifts))
    return {"presets": presets, "usage": usage, "drift": drifts}


@mcp.tool(title="List to-do items", annotations=READ)
async def list_todo_items(
    entity_id: str = "todo.shopping_list",
    status: Literal["needs_action", "completed"] = "needs_action",
) -> dict[str, Any]:
    """Read items from one exact Home Assistant to-do list."""
    validate_entity_id(entity_id)
    if not entity_id.startswith("todo."):
        raise ValueError("entity_id must be a todo entity")
    response = await ha.call_service_response(
        "todo", "get_items", {"status": status}, {"entity_id": entity_id}
    )
    items = ((response or {}).get(entity_id) or {}).get("items", [])
    _audit_tool("list_todo_items", entity_id=entity_id, status=status, count=len(items))
    return {"entity_id": entity_id, "status": status, "items": items}


@mcp.tool(title="List Home Assistant automations", annotations=READ)
async def list_automations() -> dict[str, Any]:
    """List Home Assistant automation entities and their enabled states."""
    items = [
        summarize_state(state)
        for state in await ha.states()
        if state["entity_id"].startswith("automation.")
    ]
    _audit_tool("list_automations", count=len(items))
    return {"count": len(items), "automations": items}


async def _resolve_automation(identifier: str) -> tuple[str, str]:
    states = [
        item
        for item in await ha.states()
        if item["entity_id"].startswith("automation.")
    ]
    for state in states:
        attributes = state.get("attributes") or {}
        if identifier in {state["entity_id"], str(attributes.get("id", ""))}:
            automation_id = str(
                attributes.get("id") or state["entity_id"].split(".", 1)[1]
            )
            return state["entity_id"], automation_id
    raise ValueError("Automation not found; use list_automations first")


@mcp.tool(title="Get Home Assistant automation", annotations=READ)
async def get_automation(identifier: str) -> dict[str, Any]:
    """Get one automation's current state and editable configuration."""
    entity_id, automation_id = await _resolve_automation(identifier)
    state, automation_config = await asyncio.gather(
        ha.state(entity_id), ha.get_automation_config(automation_id)
    )
    _audit_tool("get_automation", entity_id=entity_id)
    return {"state": summarize_state(state), "config": automation_config}


@mcp.tool(title="Call an allowlisted Home Assistant service", annotations=WRITE)
async def call_service(
    domain: str,
    service: str,
    target: dict[str, Any],
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call one normal allowlisted service against one to five exact entity IDs."""
    _require_write()
    if not SERVICE_PART_RE.fullmatch(domain) or not SERVICE_PART_RE.fullmatch(service):
        raise ValueError("Invalid service domain or name")
    if service not in ALLOWED_SERVICES.get(domain, set()):
        raise ValueError(
            "That service is not available through the generic call_service tool"
        )
    entity_ids = _entity_ids(target)
    if any(entity_id.split(".", 1)[0] != domain for entity_id in entity_ids):
        raise ValueError("Every target entity domain must match the service domain")
    service_data = data or {}
    if not isinstance(service_data, dict):
        raise ValueError("data must be an object")
    if _contains_target_key(service_data):
        raise ValueError("Targets are allowed only in target.entity_id, not data")
    _bounded_object(service_data, "data", MAX_SERVICE_DATA_BYTES)
    result = await ha.call_service(
        domain, service, service_data, {"entity_id": entity_ids}
    )
    _audit_tool("call_service", domain=domain, service=service, entity_ids=entity_ids)
    return {
        "status": "accepted",
        "domain": domain,
        "service": service,
        "result": result,
    }


@mcp.tool(title="Set climate temperature", annotations=IDEMPOTENT_WRITE)
async def set_climate_temperature(
    entity_id: str,
    temperature: Annotated[float, Field(ge=45, le=95)],
    hvac_mode: str | None = None,
) -> dict[str, Any]:
    """Set an exact climate entity's target temperature; never use as a connectivity test."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("climate."):
        raise ValueError("entity_id must be a climate entity")
    payload: dict[str, Any] = {"temperature": temperature, "entity_id": entity_id}
    if hvac_mode:
        payload["hvac_mode"] = hvac_mode
    await ha.call_service("climate", "set_temperature", payload)
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("set_climate_temperature", entity_id=entity_id)
    return {"status": "completed", "state": state}


@mcp.tool(title="Set climate mode", annotations=IDEMPOTENT_WRITE)
async def set_climate_mode(entity_id: str, hvac_mode: str) -> dict[str, Any]:
    """Set the HVAC mode of one exact climate entity."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("climate."):
        raise ValueError("entity_id must be a climate entity")
    current = await ha.state(entity_id)
    allowed = (current.get("attributes") or {}).get("hvac_modes", [])
    if hvac_mode not in allowed:
        raise ValueError(f"Unsupported HVAC mode for this entity: {hvac_mode}")
    await ha.call_service(
        "climate", "set_hvac_mode", {"entity_id": entity_id, "hvac_mode": hvac_mode}
    )
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("set_climate_mode", entity_id=entity_id)
    return {"status": "completed", "state": state}


@mcp.tool(title="Update thermostat schedule", annotations=IDEMPOTENT_WRITE)
async def update_thermostat_schedule(
    thermostat: Literal["living_space", "bedroom"],
    entries: Annotated[
        list[ThermostatScheduleEntry], Field(min_length=1, max_length=100)
    ],
) -> dict[str, Any]:
    """Use this when the user explicitly requests replacing one complete weekly thermostat schedule."""
    _require_write()
    async with schedule_lock:
        schedules = _schedule_map(await ha.schedules())
        schedule_id = THERMOSTATS[thermostat]["schedule"]
        current = schedules.get(schedule_id)
        if current is None:
            raise HomeAssistantError("The requested thermostat schedule was not found")
        replacement = _build_thermostat_schedule(
            thermostat, entries, _load_presets(), current
        )
        backup = ha.backup_schedules(f"update-{schedule_id}")
        readback = await _apply_schedule_definitions(
            [replacement], {schedule_id: current}
        )
    _audit_tool(
        "update_thermostat_schedule",
        thermostat=thermostat,
        schedule_id=schedule_id,
        backup=backup,
    )
    return {
        "status": "completed",
        "thermostat": thermostat,
        "backup": backup,
        "schedule": readback[0],
        "note": "The current setpoint was not changed; use resume_thermostat_schedule if requested.",
    }


@mcp.tool(title="Update shared thermostat preset", annotations=IDEMPOTENT_WRITE)
async def update_temperature_preset(
    preset: PresetName,
    temperature: Annotated[float, Field(ge=45, le=95)],
) -> dict[str, Any]:
    """Use this when the user explicitly changes one named temperature shared by both thermostats."""
    _require_write()
    async with schedule_lock:
        presets = _load_presets()
        originals = _schedule_map(await ha.schedules())
        selected_originals = {
            details["schedule"]: originals[details["schedule"]]
            for details in THERMOSTATS.values()
        }
        replacements = [
            _replace_schedule_preset(schedule, preset, temperature)
            for schedule in selected_originals.values()
        ]
        backup = ha.backup_schedules(f"update-preset-{preset.casefold()}")
        readback = await _apply_schedule_definitions(replacements, selected_originals)
        previous_presets = dict(presets)
        presets[preset] = temperature
        try:
            _save_presets(presets)
        except Exception:
            for original in selected_originals.values():
                try:
                    await ha.update_schedule(original)
                except Exception:
                    LOGGER.exception(
                        "preset_registry_rollback_failed schedule_id=%s", original["id"]
                    )
            _save_presets(previous_presets)
            raise
    _audit_tool(
        "update_temperature_preset",
        preset=preset,
        temperature=temperature,
        backup=backup,
    )
    return {
        "status": "completed",
        "preset": preset,
        "temperature": temperature,
        "backup": backup,
        "updated_schedules": [item["id"] for item in readback],
        "note": "Current thermostat setpoints were not changed.",
    }


@mcp.tool(title="Apply thermostat preset", annotations=IDEMPOTENT_WRITE)
async def apply_temperature_preset(
    target: ThermostatTarget,
    preset: PresetName,
) -> dict[str, Any]:
    """Use this when the user explicitly asks to apply a named temperature now."""
    _require_write()
    temperature = _load_presets()[preset]
    names = _target_names(target)
    for name in names:
        await ha.call_service(
            "climate",
            "set_temperature",
            {"entity_id": THERMOSTATS[name]["climate"], "temperature": temperature},
        )
    await asyncio.sleep(1)
    states = [
        summarize_state(await ha.state(THERMOSTATS[name]["climate"])) for name in names
    ]
    _audit_tool(
        "apply_temperature_preset",
        target=target,
        preset=preset,
        temperature=temperature,
    )
    return {
        "status": "completed",
        "target": target,
        "preset": preset,
        "temperature": temperature,
        "states": states,
    }


@mcp.tool(title="Resume thermostat schedule", annotations=WRITE)
async def resume_thermostat_schedule(
    target: ThermostatTarget = "both",
) -> dict[str, Any]:
    """Use this when the user asks to cancel manual overrides and restore scheduled or away control."""
    _require_write()
    presence = await ha.state(PRESENCE_ENTITY)
    if presence.get("state") == "home":
        names = _target_names(target)
        for name in names:
            await ha.call_service(
                "automation",
                "trigger",
                {
                    "entity_id": THERMOSTATS[name]["automation"],
                    "skip_condition": False,
                },
            )
        effective_target = target
    else:
        await ha.call_service(
            "automation",
            "trigger",
            {"entity_id": AWAY_AUTOMATION, "skip_condition": False},
        )
        names = ["living_space", "bedroom"]
        effective_target = "both_due_to_away_priority"
    await asyncio.sleep(1)
    states = [
        summarize_state(await ha.state(THERMOSTATS[name]["climate"])) for name in names
    ]
    _audit_tool(
        "resume_thermostat_schedule",
        requested_target=target,
        effective_target=effective_target,
        presence=presence.get("state"),
    )
    return {
        "status": "completed",
        "requested_target": target,
        "effective_target": effective_target,
        "presence": presence.get("state"),
        "states": states,
    }


@mcp.tool(title="Set climate fan mode", annotations=IDEMPOTENT_WRITE)
async def set_climate_fan_mode(entity_id: str, fan_mode: str) -> dict[str, Any]:
    """Use this when the user explicitly asks to change a thermostat or HVAC fan mode."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("climate."):
        raise ValueError("entity_id must be a climate entity")
    current = await ha.state(entity_id)
    allowed = (current.get("attributes") or {}).get("fan_modes", [])
    if fan_mode not in allowed:
        raise ValueError(f"Unsupported fan mode for this entity: {fan_mode}")
    await ha.call_service(
        "climate", "set_fan_mode", {"entity_id": entity_id, "fan_mode": fan_mode}
    )
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("set_climate_fan_mode", entity_id=entity_id, fan_mode=fan_mode)
    return {"status": "completed", "state": state}


@mcp.tool(title="Set climate preset mode", annotations=IDEMPOTENT_WRITE)
async def set_climate_preset_mode(entity_id: str, preset_mode: str) -> dict[str, Any]:
    """Use this when the user explicitly asks to change a thermostat's native preset mode."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("climate."):
        raise ValueError("entity_id must be a climate entity")
    current = await ha.state(entity_id)
    allowed = (current.get("attributes") or {}).get("preset_modes", [])
    if preset_mode not in allowed:
        raise ValueError(f"Unsupported preset mode for this entity: {preset_mode}")
    await ha.call_service(
        "climate",
        "set_preset_mode",
        {"entity_id": entity_id, "preset_mode": preset_mode},
    )
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("set_climate_preset_mode", entity_id=entity_id, preset_mode=preset_mode)
    return {"status": "completed", "state": state}


async def _turn(entity_id: str, service: str) -> dict[str, Any]:
    _require_write()
    validate_entity_id(entity_id)
    domain = entity_id.split(".", 1)[0]
    if domain not in TURNABLE_DOMAINS:
        raise ValueError("This entity domain is not available through turn_on/turn_off")
    await ha.call_service(domain, service, {"entity_id": entity_id})
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool(service, entity_id=entity_id)
    return {"status": "completed", "state": state}


@mcp.tool(title="Turn on an entity", annotations=IDEMPOTENT_WRITE)
async def turn_on(entity_id: str) -> dict[str, Any]:
    """Turn on one exact, non-security Home Assistant entity."""
    return await _turn(entity_id, "turn_on")


@mcp.tool(title="Turn off an entity", annotations=IDEMPOTENT_WRITE)
async def turn_off(entity_id: str) -> dict[str, Any]:
    """Turn off one exact, non-security Home Assistant entity."""
    return await _turn(entity_id, "turn_off")


@mcp.tool(title="Activate a scene", annotations=WRITE)
async def activate_scene(entity_id: str) -> dict[str, Any]:
    """Activate one exact Home Assistant scene entity."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("scene."):
        raise ValueError("entity_id must be a scene entity")
    result = await ha.call_service("scene", "turn_on", {"entity_id": entity_id})
    _audit_tool("activate_scene", entity_id=entity_id)
    return {"status": "accepted", "result": result}


@mcp.tool(title="Control a light", annotations=IDEMPOTENT_WRITE)
async def control_light(
    entity_id: str,
    action: Literal["turn_on", "turn_off", "toggle"],
    brightness_pct: Annotated[float | None, Field(ge=0, le=100)] = None,
    rgb_color: Annotated[list[int] | None, Field(min_length=3, max_length=3)] = None,
    color_temp_kelvin: Annotated[int | None, Field(ge=1000, le=12000)] = None,
    transition: Annotated[float | None, Field(ge=0, le=300)] = None,
    effect: Annotated[str | None, Field(max_length=120)] = None,
) -> dict[str, Any]:
    """Use this when the user explicitly asks to control one exact light, including brightness or color."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("light."):
        raise ValueError("entity_id must be a light entity")
    if rgb_color is not None and any(value < 0 or value > 255 for value in rgb_color):
        raise ValueError("Every RGB channel must be between 0 and 255")
    data: dict[str, Any] = {"entity_id": entity_id}
    if brightness_pct is not None:
        data["brightness_pct"] = brightness_pct
    if rgb_color is not None:
        data["rgb_color"] = rgb_color
    if color_temp_kelvin is not None:
        data["color_temp_kelvin"] = color_temp_kelvin
    if transition is not None:
        data["transition"] = transition
    if effect is not None:
        current = await ha.state(entity_id)
        effects = (current.get("attributes") or {}).get("effect_list", [])
        if effects and effect not in effects:
            raise ValueError(f"Unsupported effect for this entity: {effect}")
        data["effect"] = effect
    if action == "turn_off" and any(
        value is not None
        for value in (brightness_pct, rgb_color, color_temp_kelvin, effect)
    ):
        raise ValueError("Brightness and color settings require turn_on or toggle")
    await ha.call_service("light", action, data)
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("control_light", entity_id=entity_id, action=action)
    return {"status": "completed", "state": state}


@mcp.tool(title="Set number entity value", annotations=IDEMPOTENT_WRITE)
async def set_number_value(entity_id: str, value: float) -> dict[str, Any]:
    """Use this when the user explicitly asks to set one number or input_number entity."""
    _require_write()
    validate_entity_id(entity_id)
    domain = entity_id.split(".", 1)[0]
    if domain not in {"number", "input_number"}:
        raise ValueError("entity_id must be a number or input_number entity")
    current = await ha.state(entity_id)
    attributes = current.get("attributes") or {}
    minimum = float(attributes.get("min", float("-inf")))
    maximum = float(attributes.get("max", float("inf")))
    if value < minimum or value > maximum:
        raise ValueError(f"value must be between {minimum:g} and {maximum:g}")
    await ha.call_service(domain, "set_value", {"entity_id": entity_id, "value": value})
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("set_number_value", entity_id=entity_id, value=value)
    return {"status": "completed", "state": state}


@mcp.tool(title="Select entity option", annotations=IDEMPOTENT_WRITE)
async def select_entity_option(entity_id: str, option: str) -> dict[str, Any]:
    """Use this when the user explicitly asks to choose an option on one select entity."""
    _require_write()
    validate_entity_id(entity_id)
    domain = entity_id.split(".", 1)[0]
    if domain not in {"select", "input_select"}:
        raise ValueError("entity_id must be a select or input_select entity")
    current = await ha.state(entity_id)
    options = (current.get("attributes") or {}).get("options", [])
    if option not in options:
        raise ValueError(f"Unsupported option for this entity: {option}")
    await ha.call_service(
        domain, "select_option", {"entity_id": entity_id, "option": option}
    )
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("select_entity_option", entity_id=entity_id, option=option)
    return {"status": "completed", "state": state}


@mcp.tool(title="Press a Home Assistant button", annotations=DESTRUCTIVE_WRITE)
async def press_button(entity_id: str, confirmed: bool = False) -> dict[str, Any]:
    """Use this only after the user explicitly confirms pressing one exact button entity."""
    _require_write()
    _require_confirmed(confirmed, "Pressing a button")
    validate_entity_id(entity_id)
    if not entity_id.startswith("button."):
        raise ValueError("entity_id must be a button entity")
    result = await ha.call_service("button", "press", {"entity_id": entity_id})
    _audit_tool("press_button", entity_id=entity_id)
    return {"status": "accepted", "entity_id": entity_id, "result": result}


@mcp.tool(title="Control a media player", annotations=WRITE)
async def control_media_player(
    entity_id: str,
    action: Literal[
        "turn_on",
        "turn_off",
        "media_play",
        "media_pause",
        "media_stop",
        "media_next_track",
        "media_previous_track",
        "volume_up",
        "volume_down",
        "volume_set",
        "volume_mute",
        "select_source",
        "media_seek",
        "repeat_set",
        "shuffle_set",
        "join",
        "unjoin",
    ],
    volume_level: Annotated[float | None, Field(ge=0, le=1)] = None,
    is_volume_muted: bool | None = None,
    source: str | None = None,
    seek_position: Annotated[float | None, Field(ge=0, le=86400)] = None,
    repeat: Literal["off", "all", "one"] | None = None,
    shuffle: bool | None = None,
    group_members: Annotated[
        list[str] | None, Field(min_length=1, max_length=8)
    ] = None,
) -> dict[str, Any]:
    """Use this when the user explicitly asks to control one exact media player."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("media_player."):
        raise ValueError("entity_id must be a media_player entity")
    current = await ha.state(entity_id)
    if current.get("state") == "unavailable":
        raise HomeAssistantError("The media player is currently unavailable")
    supported = int((current.get("attributes") or {}).get("supported_features", 0))
    required_feature = MEDIA_FEATURES.get(action)
    if supported and required_feature and supported & required_feature == 0:
        raise ValueError(f"This media player does not support {action}")
    data: dict[str, Any] = {"entity_id": entity_id}
    if action == "volume_set":
        if volume_level is None:
            raise ValueError("volume_level is required for volume_set")
        data["volume_level"] = volume_level
    elif action == "volume_mute":
        if is_volume_muted is None:
            raise ValueError("is_volume_muted is required for volume_mute")
        data["is_volume_muted"] = is_volume_muted
    elif action == "select_source":
        if not source:
            raise ValueError("source is required for select_source")
        sources = (current.get("attributes") or {}).get("source_list", [])
        if sources and source not in sources:
            raise ValueError(f"Unsupported source for this entity: {source}")
        data["source"] = source
    elif action == "media_seek":
        if seek_position is None:
            raise ValueError("seek_position is required for media_seek")
        data["seek_position"] = seek_position
    elif action == "repeat_set":
        if repeat is None:
            raise ValueError("repeat is required for repeat_set")
        data["repeat"] = repeat
    elif action == "shuffle_set":
        if shuffle is None:
            raise ValueError("shuffle is required for shuffle_set")
        data["shuffle"] = shuffle
    elif action == "join":
        if not group_members:
            raise ValueError("group_members is required for join")
        for member in group_members:
            validate_entity_id(member)
            if not member.startswith("media_player."):
                raise ValueError("Every group member must be a media_player entity")
        data["group_members"] = list(dict.fromkeys(group_members))
    await ha.call_service("media_player", action, data)
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("control_media_player", entity_id=entity_id, action=action)
    return {"status": "completed", "state": state}


@mcp.tool(title="Control a vacuum", annotations=WRITE)
async def control_vacuum(
    entity_id: str,
    action: Literal["start", "pause", "stop", "return_to_base", "locate", "clean_spot"],
) -> dict[str, Any]:
    """Use this when the user explicitly asks to control one exact vacuum entity."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("vacuum."):
        raise ValueError("entity_id must be a vacuum entity")
    await ha.call_service("vacuum", action, {"entity_id": entity_id})
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("control_vacuum", entity_id=entity_id, action=action)
    return {"status": "completed", "state": state}


@mcp.tool(title="List vacuum rooms", annotations=READ)
async def list_vacuum_rooms(entity_id: str = config.DEFAULT_VACUUM_ENTITY) -> dict[str, Any]:
    """List named rooms/segments currently advertised by one exact vacuum."""
    validate_entity_id(entity_id)
    if not entity_id.startswith("vacuum."):
        raise ValueError("entity_id must be a vacuum entity")
    state = await ha.state(entity_id)
    raw = (state.get("attributes") or {}).get("rooms", {})
    rooms = []
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict):
                room_id = value.get("id", key)
                name = value.get("name") or value.get("friendly_name") or key
                rooms.append(
                    {
                        "id": int(room_id) if str(room_id).isdigit() else room_id,
                        "name": str(name),
                    }
                )
            elif isinstance(value, list):
                for item in value[:100]:
                    if not isinstance(item, dict) or item.get("id") is None:
                        continue
                    rooms.append(
                        {
                            "id": int(item["id"])
                            if str(item["id"]).isdigit()
                            else item["id"],
                            "name": str(
                                item.get("name")
                                or item.get("friendly_name")
                                or item["id"]
                            ),
                            "map": str(key),
                        }
                    )
            else:
                room_id, name = key, value
                rooms.append(
                    {
                        "id": int(room_id) if str(room_id).isdigit() else room_id,
                        "name": str(name),
                    }
                )
    elif isinstance(raw, list):
        rooms = [
            {
                "id": int(item["id"])
                if str(item.get("id", "")).isdigit()
                else item.get("id"),
                "name": str(
                    item.get("name") or item.get("friendly_name") or item.get("id")
                ),
            }
            for item in raw[:100]
            if isinstance(item, dict) and item.get("id") is not None
        ]
    deduplicated = []
    seen_room_ids: set[str] = set()
    for room in rooms:
        marker = str(room.get("id"))
        if marker not in seen_room_ids:
            seen_room_ids.add(marker)
            deduplicated.append(room)
    rooms = deduplicated
    _audit_tool("list_vacuum_rooms", entity_id=entity_id, count=len(rooms))
    return {"entity_id": entity_id, "count": len(rooms), "rooms": rooms}


@mcp.tool(title="Clean vacuum rooms", annotations=WRITE)
async def clean_vacuum_rooms(
    room_ids: Annotated[list[int] | None, Field(min_length=1, max_length=12)] = None,
    entity_id: str = config.DEFAULT_VACUUM_ENTITY,
    room_names: Annotated[list[str] | None, Field(min_length=1, max_length=12)] = None,
    repeats: Annotated[int, Field(ge=1, le=3)] = 1,
) -> dict[str, Any]:
    """Start cleaning advertised rooms by exact ID or case-insensitive exact name."""
    _require_write()
    room_summary = await list_vacuum_rooms(entity_id)
    allowed = {
        int(item["id"])
        for item in room_summary["rooms"]
        if str(item.get("id", "")).isdigit()
    }
    requested = list(dict.fromkeys(room_ids or []))
    if room_names:
        by_name = {
            str(item.get("name", "")).casefold(): int(item["id"])
            for item in room_summary["rooms"]
            if str(item.get("id", "")).isdigit()
        }
        unknown = [name for name in room_names if name.casefold() not in by_name]
        if unknown:
            raise ValueError(f"Unknown vacuum room name(s): {', '.join(unknown)}")
        requested.extend(by_name[name.casefold()] for name in room_names)
        requested = list(dict.fromkeys(requested))
    if not requested:
        raise ValueError("At least one room ID or room name is required")
    if not set(requested).issubset(allowed):
        raise ValueError(
            "One or more room IDs are not currently advertised by the vacuum"
        )
    await ha.call_service(
        "dreame_vacuum",
        "vacuum_clean_segment",
        {"segments": requested, "repeats": repeats},
        {"entity_id": entity_id},
    )
    _audit_tool(
        "clean_vacuum_rooms", entity_id=entity_id, room_ids=requested, repeats=repeats
    )
    return {
        "status": "accepted",
        "entity_id": entity_id,
        "room_ids": requested,
        "repeats": repeats,
    }


@mcp.tool(title="Set vacuum fan speed", annotations=IDEMPOTENT_WRITE)
async def set_vacuum_fan_speed(entity_id: str, fan_speed: str) -> dict[str, Any]:
    """Set an exact vacuum fan speed after validating its advertised speed list."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("vacuum."):
        raise ValueError("entity_id must be a vacuum entity")
    current = await ha.state(entity_id)
    allowed = (current.get("attributes") or {}).get("fan_speed_list", [])
    if allowed and fan_speed not in allowed:
        raise ValueError(f"Unsupported fan speed for this vacuum: {fan_speed}")
    await ha.call_service(
        "vacuum", "set_fan_speed", {"entity_id": entity_id, "fan_speed": fan_speed}
    )
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("set_vacuum_fan_speed", entity_id=entity_id, fan_speed=fan_speed)
    return {"status": "completed", "state": state}


@mcp.tool(title="Set Nest fan timer", annotations=WRITE)
async def set_nest_fan_timer(
    entity_id: str,
    duration_minutes: Annotated[int, Field(ge=1, le=720)],
) -> dict[str, Any]:
    """Start a Google Nest thermostat fan timer for 1 to 720 minutes."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("climate."):
        raise ValueError("entity_id must be a climate entity")
    await ha.call_service(
        "nest",
        "set_fan_timer",
        {"duration": {"seconds": duration_minutes * 60}},
        {"entity_id": entity_id},
    )
    _audit_tool(
        "set_nest_fan_timer", entity_id=entity_id, duration_minutes=duration_minutes
    )
    return {
        "status": "accepted",
        "entity_id": entity_id,
        "duration_minutes": duration_minutes,
    }


@mcp.tool(title="Speak text on a media player", annotations=WRITE)
async def speak_text(
    message: Annotated[str, Field(min_length=1, max_length=1000)],
    media_player_entity_id: str,
    tts_entity_id: str = "tts.google_translate_en_com",
    language: Annotated[str | None, Field(max_length=20)] = None,
    cache: bool = True,
) -> dict[str, Any]:
    """Speak bounded text through one exact media player using one exact TTS entity."""
    _require_write()
    for entity_id, domain in (
        (media_player_entity_id, "media_player"),
        (tts_entity_id, "tts"),
    ):
        validate_entity_id(entity_id)
        if not entity_id.startswith(f"{domain}."):
            raise ValueError(f"{entity_id} must be a {domain} entity")
    data: dict[str, Any] = {
        "media_player_entity_id": media_player_entity_id,
        "message": message,
        "cache": cache,
    }
    if language:
        data["language"] = language
    await ha.call_service("tts", "speak", data, {"entity_id": tts_entity_id})
    _audit_tool(
        "speak_text",
        media_player_entity_id=media_player_entity_id,
        tts_entity_id=tts_entity_id,
    )
    return {"status": "accepted", "media_player_entity_id": media_player_entity_id}


def _validate_media_content_id(value: str) -> None:
    lowered = value.casefold()
    if any(
        marker in lowered
        for marker in (
            "/api/camera_proxy/",
            "/api/camera_proxy_stream/",
            "/api/camera_thumbnail/",
            "camera-stream",
            "camera_source",
            "wyze",
        )
    ):
        raise ValueError("Camera media is not available through this tool")
    parsed = urlsplit(value)
    if parsed.username or parsed.password:
        raise ValueError("Credential-bearing media URLs are not allowed")
    if any(
        key.casefold() in SENSITIVE_URL_QUERY_KEYS for key, _ in parse_qsl(parsed.query)
    ):
        raise ValueError("Secret-bearing media URL query parameters are not allowed")
    if parsed.scheme in {"http", "https"}:
        hostname = (parsed.hostname or "").casefold()
        if parsed.scheme != "https":
            raise ValueError("Remote media URLs must use HTTPS")
        if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(
            (".local", ".internal", ".lan")
        ):
            raise ValueError("Private-network media URLs are not allowed")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError("Private-network media URLs are not allowed")
    elif parsed.scheme and parsed.scheme not in {
        "library",
        "media-source",
        "spotify",
        "x-rincon-cpcontainer",
        "x-sonos-http",
    }:
        raise ValueError("Unsupported media content ID scheme")


@mcp.tool(title="Play media", annotations=WRITE)
async def play_media(
    entity_id: str,
    media_content_id: Annotated[str, Field(min_length=1, max_length=2000)],
    media_content_type: Annotated[str, Field(min_length=1, max_length=120)],
    enqueue: Literal["add", "next", "play", "replace"] | None = None,
) -> dict[str, Any]:
    """Play one bounded media item on one exact media player."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("media_player."):
        raise ValueError("entity_id must be a media_player entity")
    player = await ha.state(entity_id)
    supported = int((player.get("attributes") or {}).get("supported_features", 0))
    if supported and supported & MEDIA_FEATURES["play_media"] == 0:
        raise ValueError("This media player does not support play_media")
    _validate_media_content_id(media_content_id)
    data: dict[str, Any] = {
        "media_content_id": media_content_id,
        "media_content_type": media_content_type,
    }
    if enqueue:
        data["enqueue"] = enqueue
    await ha.call_service("media_player", "play_media", data, {"entity_id": entity_id})
    _audit_tool(
        "play_media", entity_id=entity_id, media_content_type=media_content_type
    )
    return {"status": "accepted", "entity_id": entity_id}


@mcp.tool(title="Browse media", annotations=READ)
async def browse_media(
    entity_id: str,
    media_content_id: Annotated[str | None, Field(max_length=2000)] = None,
    media_content_type: Annotated[str | None, Field(max_length=120)] = None,
) -> dict[str, Any]:
    """Browse media exposed by one exact media player without starting playback."""
    validate_entity_id(entity_id)
    if not entity_id.startswith("media_player."):
        raise ValueError("entity_id must be a media_player entity")
    player = await ha.state(entity_id)
    supported = int((player.get("attributes") or {}).get("supported_features", 0))
    if supported and supported & MEDIA_FEATURES["browse_media"] == 0:
        raise ValueError("This media player does not support media browsing")
    if media_content_id is not None:
        _validate_media_content_id(media_content_id)
    data = {
        key: value
        for key, value in {
            "media_content_id": media_content_id,
            "media_content_type": media_content_type,
        }.items()
        if value is not None
    }
    response = await ha.call_service_response(
        "media_player", "browse_media", data, {"entity_id": entity_id}
    )
    _audit_tool("browse_media", entity_id=entity_id)
    return {"entity_id": entity_id, "media": (response or {}).get(entity_id, response)}


@mcp.tool(title="Search media", annotations=READ)
async def search_media(
    entity_id: str,
    search_query: Annotated[str, Field(min_length=1, max_length=200)],
    media_content_id: Annotated[str | None, Field(max_length=2000)] = None,
    media_content_type: Annotated[str | None, Field(max_length=120)] = None,
) -> dict[str, Any]:
    """Search media exposed by one exact media player without starting playback."""
    validate_entity_id(entity_id)
    if not entity_id.startswith("media_player."):
        raise ValueError("entity_id must be a media_player entity")
    player = await ha.state(entity_id)
    supported = int((player.get("attributes") or {}).get("supported_features", 0))
    if supported & MEDIA_FEATURES["search_media"] == 0:
        _audit_tool("search_media", entity_id=entity_id, supported=False)
        return {
            "entity_id": entity_id,
            "supported": False,
            "reason": "entity_does_not_advertise_search_media",
            "supported_features": supported,
        }
    if media_content_id is not None:
        _validate_media_content_id(media_content_id)
    data = {"search_query": search_query}
    if media_content_id is not None:
        data["media_content_id"] = media_content_id
    if media_content_type is not None:
        data["media_content_type"] = media_content_type
    response = await ha.call_service_response(
        "media_player", "search_media", data, {"entity_id": entity_id}
    )
    _audit_tool("search_media", entity_id=entity_id)
    return {
        "entity_id": entity_id,
        "supported": True,
        "media": (response or {}).get(entity_id, response),
    }


@mcp.tool(title="Show dashboard on Google Cast", annotations=WRITE)
async def show_dashboard_on_cast(
    entity_id: str,
    dashboard_path: Annotated[str, Field(min_length=1, max_length=120)],
    view_path: Annotated[str, Field(min_length=1, max_length=120)],
) -> dict[str, Any]:
    """Display one Home Assistant dashboard view on one exact Cast media player."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("media_player."):
        raise ValueError("entity_id must be a media_player entity")
    if dashboard_path != "lovelace" and not DASHBOARD_PATH_RE.fullmatch(dashboard_path):
        raise ValueError("Invalid dashboard_path")
    if not DASHBOARD_PATH_RE.fullmatch(view_path):
        raise ValueError("Invalid view_path")
    ha_config = await ha.config()
    external_url = str(ha_config.get("external_url") or "")
    if urlsplit(external_url).scheme != "https":
        raise HomeAssistantError(
            "Casting a dashboard requires Home Assistant to have an HTTPS external_url"
        )
    dashboard = await ha.dashboard_config(
        None if dashboard_path == "lovelace" else dashboard_path
    )
    known_views = {
        str(view.get("path") or "")
        for view in dashboard.get("views", [])
        if isinstance(view, dict)
    }
    if view_path not in known_views:
        raise ValueError("view_path does not exist in this dashboard")
    await ha.call_service(
        "cast",
        "show_lovelace_view",
        {
            "entity_id": entity_id,
            "dashboard_path": dashboard_path,
            "view_path": view_path,
        },
    )
    _audit_tool(
        "show_dashboard_on_cast",
        entity_id=entity_id,
        dashboard_path=dashboard_path,
        view_path=view_path,
    )
    return {"status": "accepted", "entity_id": entity_id}


def _sprinkler_button_time(state: dict[str, Any]) -> datetime | None:
    value = state.get("state")
    if not isinstance(value, str) or value in {"", "unknown", "unavailable"}:
        return None
    try:
        return parse_rfc3339(value, "sprinkler button state")
    except ValueError:
        return None


def _sprinkler_duration(state: dict[str, Any]) -> float | None:
    try:
        value = float(state.get("state"))
    except (TypeError, ValueError):
        return None
    return value if 0 < value <= 180 else None


def _build_sprinkler_telemetry(
    state_map: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
    last_mcp_entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Infer only what HA button timestamps support; never claim physical valve state."""
    observed_commands: list[dict[str, Any]] = []
    for zone, (number_id, button_id) in SPRINKLER_ZONES.items():
        observed_at = _sprinkler_button_time(state_map[button_id])
        if observed_at is None:
            continue
        observed_commands.append(
            {
                "action": "run_zone",
                "zone": zone,
                "duration_minutes": _sprinkler_duration(state_map[number_id]),
                "observed_at": observed_at,
                "entity_id": button_id,
            }
        )
    stop_observed_at = _sprinkler_button_time(state_map[SPRINKLER_STOP])
    if stop_observed_at is not None:
        observed_commands.append(
            {
                "action": "stop_all",
                "zone": None,
                "duration_minutes": None,
                "observed_at": stop_observed_at,
                "entity_id": SPRINKLER_STOP,
            }
        )

    last_mcp_command = None
    if last_mcp_entry:
        try:
            mcp_observed_at = parse_rfc3339(
                last_mcp_entry.get("timestamp"), "audit timestamp"
            )
        except ValueError:
            mcp_observed_at = None
        tool = last_mcp_entry.get("tool")
        if mcp_observed_at is not None and tool in {
            "run_sprinkler_zone",
            "stop_sprinklers",
        }:
            last_mcp_command = {
                "action": "run_zone" if tool == "run_sprinkler_zone" else "stop_all",
                "zone": last_mcp_entry.get("zone"),
                "duration_minutes": last_mcp_entry.get("duration_minutes"),
                "observed_at": mcp_observed_at,
                "source": "mcp_audit_log",
            }

    running_state: dict[str, Any] = {
        "value": "unknown",
        "estimated_running": None,
        "confidence": "inferred",
        "reason": "no_observed_command_timestamp",
    }
    last_observed_command = None
    expected_end_at = None
    seconds_remaining_estimate = None
    if observed_commands:
        last_observed_command = max(
            observed_commands, key=lambda item: item["observed_at"]
        )
        observed_at = last_observed_command["observed_at"]
        if last_observed_command["action"] == "stop_all":
            running_state.update(
                {
                    "value": "inferred_stopped",
                    "estimated_running": False,
                    "reason": "latest_observed_command_is_stop_all",
                }
            )
        else:
            duration_minutes = last_observed_command["duration_minutes"]
            duration_source = "current_configuration_approximate"
            if (
                last_mcp_command
                and last_mcp_command["action"] == "run_zone"
                and last_mcp_command["zone"] == last_observed_command["zone"]
                and abs((last_mcp_command["observed_at"] - observed_at).total_seconds())
                <= 30
            ):
                try:
                    duration_minutes = float(last_mcp_command["duration_minutes"])
                    duration_source = "matching_mcp_audit_command"
                except (TypeError, ValueError):
                    pass
            last_observed_command["duration_minutes"] = duration_minutes
            last_observed_command["duration_source"] = duration_source
            if duration_minutes is None:
                running_state.update(
                    {
                        "value": "unknown",
                        "reason": "latest_run_duration_unavailable",
                    }
                )
            else:
                current_time = (now or datetime.now(UTC)).astimezone(UTC)
                estimated_end = observed_at + timedelta(minutes=duration_minutes)
                estimated_running = current_time < estimated_end
                expected_end_at = estimated_end.isoformat()
                seconds_remaining_estimate = max(
                    0, round((estimated_end - current_time).total_seconds())
                )
                running_state.update(
                    {
                        "value": "possibly_running" if estimated_running else "elapsed",
                        "estimated_running": estimated_running,
                        "reason": (
                            "latest_run_plus_exact_mcp_duration"
                            if duration_source == "matching_mcp_audit_command"
                            else "latest_run_plus_current_configured_duration"
                        ),
                    }
                )
        last_observed_command = {
            **last_observed_command,
            "observed_at": observed_at.isoformat(),
            "source": "home_assistant_button_state",
        }

    if last_mcp_command:
        last_mcp_command = {
            **last_mcp_command,
            "observed_at": last_mcp_command["observed_at"].isoformat(),
        }

    return {
        "telemetry": {
            "live_running_state_available": False,
            "physical_state_verified": False,
            "source": "home_assistant_button_timestamps",
            "last_observed_command": last_observed_command,
            "last_mcp_command": last_mcp_command,
            "running_state": running_state,
            "expected_end_at": expected_end_at,
            "seconds_remaining_estimate": seconds_remaining_estimate,
            "note": (
                "The integration exposes command timestamps but no live valve sensor. "
                "Running state is inferred and does not confirm physical water flow."
            ),
        }
    }


async def _sprinkler_device_id() -> str:
    """Resolve the controller's registry ID from an exact owned entity."""
    matches = [
        item
        for item in await ha.entity_registry()
        if item.get("entity_id") == SPRINKLER_STATUS and item.get("device_id")
    ]
    if len(matches) != 1:
        raise HomeAssistantError("Exactly one Wyze sprinkler controller is required")
    return str(matches[0]["device_id"])


async def _sprinkler_zone_records() -> list[dict[str, Any]]:
    entity_ids = list(SPRINKLER_ZONE_METADATA.values()) + [
        pair[0] for pair in SPRINKLER_ZONES.values()
    ]
    states = await asyncio.gather(*(ha.state(entity_id) for entity_id in entity_ids))
    state_map = {state["entity_id"]: state for state in states}
    records = []
    for zone, metadata_id in SPRINKLER_ZONE_METADATA.items():
        metadata = state_map[metadata_id]
        attributes = dict(metadata.get("attributes") or {})
        number_id = SPRINKLER_ZONES.get(zone, (None, None))[0]
        duration = state_map.get(str(number_id), {}).get("state")
        try:
            configured_duration = float(duration)
        except (TypeError, ValueError):
            configured_duration = None
        records.append(
            {
                "zone": zone,
                "name": attributes.get("name"),
                "enabled": attributes.get("enabled") is True,
                "configured_duration_minutes": configured_duration,
                "smart_duration_seconds": attributes.get("smart_duration"),
                "crop_type": attributes.get("crop_type"),
                "exposure_type": attributes.get("exposure_type"),
                "nozzle_type": attributes.get("nozzle_type"),
                "slope_type": attributes.get("slope_type"),
                "soil_type": attributes.get("soil_type"),
                "last_updated": metadata.get("last_updated"),
            }
        )
    return records


@mcp.tool(title="Get sprinkler summary", annotations=READ)
async def get_sprinkler_summary() -> dict[str, Any]:
    """Read live controller state, active-zone timing, and all configured zones."""
    status, active, remaining, last, zones = await asyncio.gather(
        ha.state(SPRINKLER_STATUS),
        ha.state(SPRINKLER_ACTIVE_ZONE),
        ha.state(SPRINKLER_REMAINING),
        ha.state(SPRINKLER_LAST_WATERING),
        _sprinkler_zone_records(),
    )
    status_attributes = dict(status.get("attributes") or {})
    _audit_tool("get_sprinkler_summary")
    return {
        "controller": summarize_state(status),
        "active_zone": summarize_state(active),
        "remaining": summarize_state(remaining),
        "last_watering": summarize_state(last),
        "zones": zones,
        "telemetry": {
            "live_running_state_available": True,
            "physical_state_verified": bool(
                status_attributes.get("physical_state_verified", False)
            ),
            "source": status_attributes.get("source"),
            "observed_at": status_attributes.get("observed_at"),
            "partial_update": bool(status_attributes.get("partial_update", False)),
            "endpoint_errors": status_attributes.get("endpoint_errors") or [],
            "note": (
                "State is read from Wyze cloud controller telemetry and does not prove "
                "physical water flow."
            ),
        },
    }


@mcp.tool(title="List sprinkler zones", annotations=READ)
async def list_sprinkler_zones() -> dict[str, Any]:
    """List exact sprinkler zones, enabled state, durations, and soil metadata."""
    zones = await _sprinkler_zone_records()
    _audit_tool("list_sprinkler_zones", count=len(zones))
    return {"count": len(zones), "zones": zones}


@mcp.tool(title="Get sprinkler configuration", annotations=READ)
async def get_sprinkler_configuration() -> dict[str, Any]:
    """Read controller wiring, sensors, notifications, schedules, and skip settings."""
    state = await ha.state(SPRINKLER_CONFIGURATION)
    _audit_tool("get_sprinkler_configuration")
    return summarize_state(state)


@mcp.tool(title="Get sprinkler watering history", annotations=READ)
async def get_sprinkler_history(
    limit: Annotated[int, Field(ge=1, le=10)] = 10,
) -> dict[str, Any]:
    """Read the bounded recent and upcoming controller schedule-run history."""
    state = await ha.state(SPRINKLER_LAST_WATERING)
    runs = list((state.get("attributes") or {}).get("recent_runs") or [])[:limit]
    _audit_tool("get_sprinkler_history", count=len(runs))
    return {
        "last_watering": state.get("state"),
        "count": len(runs),
        "runs": runs,
        "last_updated": state.get("last_updated"),
    }


@mcp.tool(title="Refresh sprinkler telemetry", annotations=IDEMPOTENT_WRITE)
async def refresh_sprinkler() -> dict[str, Any]:
    """Force a bounded Wyze status, metadata, configuration, and history refresh."""
    _require_write()
    device_id = await _sprinkler_device_id()
    await ha.call_service("wyzeapi", "refresh_sprinkler", {"device_id": [device_id]})
    status = await ha.state(SPRINKLER_STATUS)
    _audit_tool("refresh_sprinkler")
    return {"status": "completed", "controller": summarize_state(status)}


@mcp.tool(title="Run sprinkler zone", annotations=DESTRUCTIVE_WRITE)
async def run_sprinkler_zone(
    zone: Annotated[int, Field(strict=True, ge=1, le=8)],
    duration_minutes: Annotated[float, Field(ge=1, le=180)],
    confirmed: bool = False,
) -> dict[str, Any]:
    """Start one enabled zone only after explicit current-turn confirmation."""
    _require_write()
    _require_confirmed(confirmed, "Starting a sprinkler zone")
    zones = {item["zone"]: item for item in await _sprinkler_zone_records()}
    if zone not in zones or not zones[zone]["enabled"]:
        raise ValueError("zone must be one currently enabled sprinkler zone")
    device_id = await _sprinkler_device_id()
    await ha.call_service(
        "wyzeapi",
        "run_sprinkler_zone",
        {
            "device_id": [device_id],
            "zone": zone,
            "duration_minutes": duration_minutes,
        },
    )
    _audit_tool("run_sprinkler_zone", zone=zone, duration_minutes=duration_minutes)
    return {
        "status": "provider_accepted",
        "zone": zone,
        "duration_minutes": duration_minutes,
        "physical_state_verified": False,
    }


@mcp.tool(title="Run sprinkler sequence", annotations=DESTRUCTIVE_WRITE)
async def run_sprinkler_sequence(
    zones: Annotated[list[SprinklerSequenceEntry], Field(min_length=1, max_length=8)],
    confirmed: bool = False,
) -> dict[str, Any]:
    """Start an ordered, bounded set of enabled zones after explicit confirmation."""
    _require_write()
    _require_confirmed(confirmed, "Starting a sprinkler sequence")
    requested = [item.model_dump() for item in zones]
    zone_numbers = [item["zone"] for item in requested]
    if len(zone_numbers) != len(set(zone_numbers)):
        raise ValueError("sprinkler sequence zones must not be duplicated")
    if sum(float(item["duration_minutes"]) for item in requested) > 180:
        raise ValueError(
            "total sprinkler sequence duration must not exceed 180 minutes"
        )
    available = {item["zone"]: item for item in await _sprinkler_zone_records()}
    if any(
        zone not in available or not available[zone]["enabled"] for zone in zone_numbers
    ):
        raise ValueError("every sequence zone must currently be enabled")
    device_id = await _sprinkler_device_id()
    await ha.call_service(
        "wyzeapi",
        "run_sprinkler_sequence",
        {"device_id": [device_id], "zones": requested},
    )
    _audit_tool("run_sprinkler_sequence", zones=zone_numbers)
    return {
        "status": "provider_accepted",
        "zones": requested,
        "physical_state_verified": False,
    }


@mcp.tool(title="Stop all sprinklers", annotations=IDEMPOTENT_WRITE)
async def stop_sprinklers() -> dict[str, Any]:
    """Stop all sprinkler zones; safe and idempotent even when no zone is running."""
    _require_write()
    device_id = await _sprinkler_device_id()
    await ha.call_service("wyzeapi", "stop_sprinkler", {"device_id": [device_id]})
    _audit_tool("stop_sprinklers")
    return {"status": "accepted"}


@mcp.tool(title="Add to-do item", annotations=WRITE)
async def add_todo_item(
    item: Annotated[str, Field(min_length=1, max_length=500)],
    entity_id: str = "todo.shopping_list",
    due_date: str | None = None,
    due_datetime: str | None = None,
    description: Annotated[str | None, Field(max_length=2000)] = None,
) -> dict[str, Any]:
    """Use this when the user explicitly asks to add one item to an exact Home Assistant to-do list."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("todo."):
        raise ValueError("entity_id must be a todo entity")
    if due_date and due_datetime:
        raise ValueError("Provide due_date or due_datetime, not both")
    data: dict[str, Any] = {"item": item}
    for key, value in {
        "due_date": due_date,
        "due_datetime": due_datetime,
        "description": description,
    }.items():
        if value is not None:
            data[key] = value
    result = await ha.call_service("todo", "add_item", data, {"entity_id": entity_id})
    _audit_tool("add_todo_item", entity_id=entity_id)
    return {"status": "completed", "entity_id": entity_id, "result": result}


@mcp.tool(title="Update to-do item", annotations=IDEMPOTENT_WRITE)
async def update_todo_item(
    item: Annotated[str, Field(min_length=1, max_length=500)],
    entity_id: str = "todo.shopping_list",
    rename: Annotated[str | None, Field(max_length=500)] = None,
    status: Literal["needs_action", "completed"] | None = None,
    due_date: str | None = None,
    due_datetime: str | None = None,
    description: Annotated[str | None, Field(max_length=2000)] = None,
) -> dict[str, Any]:
    """Use this when the user explicitly asks to edit or complete one exact to-do item."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("todo."):
        raise ValueError("entity_id must be a todo entity")
    if due_date and due_datetime:
        raise ValueError("Provide due_date or due_datetime, not both")
    changes = {
        "rename": rename,
        "status": status,
        "due_date": due_date,
        "due_datetime": due_datetime,
        "description": description,
    }
    if all(value is None for value in changes.values()):
        raise ValueError("At least one to-do item change is required")
    data = {
        "item": item,
        **{key: value for key, value in changes.items() if value is not None},
    }
    result = await ha.call_service(
        "todo", "update_item", data, {"entity_id": entity_id}
    )
    _audit_tool("update_todo_item", entity_id=entity_id)
    return {"status": "completed", "entity_id": entity_id, "result": result}


@mcp.tool(title="Remove to-do item", annotations=DESTRUCTIVE_WRITE)
async def remove_todo_item(
    item: Annotated[str, Field(min_length=1, max_length=500)],
    entity_id: str = "todo.shopping_list",
    confirmed: bool = False,
) -> dict[str, Any]:
    """Use this only after the user explicitly confirms removing one exact to-do item."""
    _require_write()
    _require_confirmed(confirmed, "Removing a to-do item")
    validate_entity_id(entity_id)
    if not entity_id.startswith("todo."):
        raise ValueError("entity_id must be a todo entity")
    result = await ha.call_service(
        "todo", "remove_item", {"item": item}, {"entity_id": entity_id}
    )
    _audit_tool("remove_todo_item", entity_id=entity_id)
    return {"status": "completed", "entity_id": entity_id, "result": result}


@mcp.tool(title="Control a cover or garage door", annotations=DESTRUCTIVE_WRITE)
async def control_cover(
    entity_id: str,
    action: Literal["open", "close", "stop", "set_position"],
    position: Annotated[int | None, Field(ge=0, le=100)] = None,
    confirmed: bool = False,
) -> dict[str, Any]:
    """Use this only for an exact cover; garage, gate, and door movement requires explicit confirmation."""
    _require_write()
    validate_entity_id(entity_id)
    if not entity_id.startswith("cover."):
        raise ValueError("entity_id must be a cover entity")
    current = await ha.state(entity_id)
    device_class = (current.get("attributes") or {}).get("device_class")
    if device_class in {"garage", "gate", "door"} and action != "stop":
        _require_confirmed(confirmed, f"Moving the {device_class}")
    services = {
        "open": "open_cover",
        "close": "close_cover",
        "stop": "stop_cover",
        "set_position": "set_cover_position",
    }
    data: dict[str, Any] = {"entity_id": entity_id}
    if action == "set_position":
        if position is None:
            raise ValueError("position is required for set_position")
        data["position"] = position
    await ha.call_service("cover", services[action], data)
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("control_cover", entity_id=entity_id, action=action)
    return {"status": "completed", "state": state}


@mcp.tool(title="Control a siren", annotations=DESTRUCTIVE_WRITE)
async def control_siren(
    entity_id: str,
    action: Literal["turn_on", "turn_off"],
    confirmed: bool = False,
    tone: str | None = None,
    duration: Annotated[int | None, Field(ge=1, le=600)] = None,
    volume_level: Annotated[float | None, Field(ge=0, le=1)] = None,
) -> dict[str, Any]:
    """Use this only after the user explicitly confirms controlling one exact siren."""
    _require_write()
    _require_confirmed(confirmed, "Controlling a siren")
    validate_entity_id(entity_id)
    if not entity_id.startswith("siren."):
        raise ValueError("entity_id must be a siren entity")
    data: dict[str, Any] = {"entity_id": entity_id}
    if action == "turn_on":
        for key, value in {
            "tone": tone,
            "duration": duration,
            "volume_level": volume_level,
        }.items():
            if value is not None:
                data[key] = value
    await ha.call_service("siren", action, data)
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("control_siren", entity_id=entity_id, action=action)
    return {"status": "completed", "state": state}


@mcp.tool(title="Control a lock", annotations=DESTRUCTIVE_WRITE)
async def control_lock(
    entity_id: str,
    action: Literal["lock", "unlock", "open"],
    confirmed: bool = False,
) -> dict[str, Any]:
    """Use this only after the user explicitly confirms locking, unlocking, or opening one exact lock."""
    _require_write()
    _require_confirmed(confirmed, f"Lock action {action}")
    validate_entity_id(entity_id)
    if not entity_id.startswith("lock."):
        raise ValueError("entity_id must be a lock entity")
    await ha.call_service("lock", action, {"entity_id": entity_id})
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("control_lock", entity_id=entity_id, action=action)
    return {"status": "completed", "state": state}


@mcp.tool(title="Send mobile notification", annotations=WRITE)
async def send_mobile_notification(
    message: Annotated[str, Field(min_length=1, max_length=1000)],
    title: Annotated[str | None, Field(max_length=200)] = None,
    url: Annotated[str | None, Field(max_length=500)] = None,
    attachment_url: Annotated[str | None, Field(max_length=500)] = None,
    actions: Annotated[list[NotificationLinkAction] | None, Field(max_length=3)] = None,
) -> dict[str, Any]:
    """Send a notification with optional safe in-HA links, attachment, and link-only actions."""
    _require_write()
    data: dict[str, Any] = {"message": message}
    if title:
        data["title"] = title
    notification_data: dict[str, Any] = {}
    if url:
        if not url.startswith("/") or url.startswith("//"):
            raise ValueError("url must be a relative Home Assistant path")
        notification_data["url"] = url
    if attachment_url:
        if not attachment_url.startswith(("/local/", "/media/local/")):
            raise ValueError(
                "attachment_url must be a safe /local/ or /media/local/ path"
            )
        notification_data["image"] = attachment_url
    if actions:
        rendered = []
        for action in actions:
            if not action.url.startswith("/") or action.url.startswith("//"):
                raise ValueError(
                    "Every notification action URL must be a relative Home Assistant path"
                )
            rendered.append({"action": "URI", "title": action.title, "uri": action.url})
        notification_data["actions"] = rendered
    if notification_data:
        data["data"] = notification_data
    result = await ha.call_service("notify", config.MOBILE_NOTIFY_SERVICE, data)
    _audit_tool("send_mobile_notification", title=title)
    return {"status": "accepted", "result": result}


def _validate_automation_config(automation: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(automation, dict):
        raise ValueError("automation must be an object")
    allowed = {
        "alias",
        "description",
        "triggers",
        "conditions",
        "actions",
        "mode",
        "max",
        "max_exceeded",
        "variables",
    }
    unknown = set(automation) - allowed
    if unknown:
        raise ValueError(f"Unsupported automation fields: {', '.join(sorted(unknown))}")
    if not isinstance(automation.get("alias"), str) or not automation["alias"].strip():
        raise ValueError("automation.alias is required")
    if not isinstance(automation.get("triggers"), list) or not automation["triggers"]:
        raise ValueError("automation.triggers must be a non-empty list")
    if not isinstance(automation.get("actions"), list) or not automation["actions"]:
        raise ValueError("automation.actions must be a non-empty list")
    _bounded_object(automation, "automation", 65_536)
    if redact_sensitive(automation) != automation:
        raise ValueError(
            "automation must not contain credentials or secret-bearing fields"
        )
    _validate_automation_actions(automation["actions"])
    result = dict(automation)
    result.setdefault("conditions", [])
    result.setdefault("mode", "single")
    return result


def _validate_automation_actions(value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _validate_automation_actions(item)
        return
    if not isinstance(value, dict):
        return
    service = value.get("action", value.get("service"))
    if service is not None:
        if not isinstance(service, str) or "{{" in service or "{%" in service:
            raise ValueError(
                "Automation action services must be literal domain.service names"
            )
        if "." not in service:
            raise ValueError("Automation action service must include its domain")
        domain, name = service.split(".", 1)
        if not SERVICE_PART_RE.fullmatch(domain) or not SERVICE_PART_RE.fullmatch(name):
            raise ValueError("Invalid automation action service")
        if domain in AUTOMATION_BLOCKED_DOMAINS:
            raise ValueError(
                f"Automation actions in the {domain} domain are not exposed"
            )
        allowed_services = ALLOWED_SERVICES.get(
            domain, set()
        ) | AUTOMATION_EXTRA_SERVICES.get(domain, set())
        if name not in allowed_services:
            raise ValueError("That automation action service is not allowlisted")
        target = value.get("target")
        if domain != "notify" and target is None:
            raise ValueError(
                "Automation entity actions require an exact target.entity_id"
            )
        if target is not None:
            if not isinstance(target, dict) or set(target) != {"entity_id"}:
                raise ValueError("Automation actions may target only exact entity IDs")
            entity_ids = _entity_ids(target)
            expected_domain = AUTOMATION_TARGET_DOMAIN.get(domain, domain)
            if any(
                entity_id.split(".", 1)[0] != expected_domain
                for entity_id in entity_ids
            ):
                raise ValueError(
                    "Automation action target domain must match its service domain"
                )
        data = value.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("Automation action data must be an object")
        if _contains_target_key(data):
            raise ValueError("Automation targets must use target.entity_id, not data")
    for item in value.values():
        _validate_automation_actions(item)


@mcp.tool(title="Create a Home Assistant automation", annotations=WRITE)
async def create_automation(
    automation_id: str, automation: dict[str, Any], confirmed: bool = False
) -> dict[str, Any]:
    """Create one validated automation after backing up relevant Home Assistant configuration."""
    _require_write()
    _require_confirmed(confirmed, "Creating an automation")
    validate_automation_id(automation_id)
    validated = _validate_automation_config(automation)
    existing = await list_automations()
    existing_ids = {
        str((item.get("attributes") or {}).get("id"))
        for item in existing["automations"]
    }
    if automation_id in existing_ids:
        raise ValueError("Automation already exists; use update_automation")
    backup = ha.backup_automations("create-automation")
    result = await ha.save_automation_config(automation_id, validated)
    _audit_tool("create_automation", automation_id=automation_id, backup=backup)
    return {
        "status": "completed",
        "automation_id": automation_id,
        "backup": backup,
        "result": result,
    }


@mcp.tool(title="Update a Home Assistant automation", annotations=WRITE)
async def update_automation(
    automation_id: str, automation: dict[str, Any], confirmed: bool = False
) -> dict[str, Any]:
    """Replace one automation configuration after backing up relevant Home Assistant files."""
    _require_write()
    _require_confirmed(confirmed, "Updating an automation")
    validate_automation_id(automation_id)
    validated = _validate_automation_config(automation)
    await _resolve_automation(automation_id)
    backup = ha.backup_automations("update-automation")
    result = await ha.save_automation_config(automation_id, validated)
    _audit_tool("update_automation", automation_id=automation_id, backup=backup)
    return {
        "status": "completed",
        "automation_id": automation_id,
        "backup": backup,
        "result": result,
    }


@mcp.tool(title="Enable a Home Assistant automation", annotations=IDEMPOTENT_WRITE)
async def enable_automation(identifier: str) -> dict[str, Any]:
    """Enable one exact Home Assistant automation and verify its resulting state."""
    _require_write()
    entity_id, _ = await _resolve_automation(identifier)
    await ha.call_service("automation", "turn_on", {"entity_id": entity_id})
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("enable_automation", entity_id=entity_id)
    return {"status": "completed", "state": state}


@mcp.tool(title="Disable a Home Assistant automation", annotations=IDEMPOTENT_WRITE)
async def disable_automation(identifier: str) -> dict[str, Any]:
    """Disable one exact Home Assistant automation and verify its resulting state."""
    _require_write()
    entity_id, _ = await _resolve_automation(identifier)
    await ha.call_service("automation", "turn_off", {"entity_id": entity_id})
    await asyncio.sleep(1)
    state = summarize_state(await ha.state(entity_id))
    _audit_tool("disable_automation", entity_id=entity_id)
    return {"status": "completed", "state": state}


@mcp.tool(title="Trigger Home Assistant automation", annotations=DESTRUCTIVE_WRITE)
async def trigger_automation(
    identifier: str,
    skip_conditions: bool = False,
    confirmed: bool = False,
) -> dict[str, Any]:
    """Trigger one exact automation only after explicit current-turn confirmation."""
    _require_write()
    _require_confirmed(confirmed, "Triggering an automation")
    entity_id, _ = await _resolve_automation(identifier)
    result = await ha.call_service(
        "automation",
        "trigger",
        {"entity_id": entity_id, "skip_condition": skip_conditions},
    )
    _audit_tool(
        "trigger_automation", entity_id=entity_id, skip_conditions=skip_conditions
    )
    return {"status": "accepted", "entity_id": entity_id, "result": result}


class RateLimiter:
    def __init__(self) -> None:
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window: int = 60) -> bool:
        now = time.monotonic()
        queue = self.events[key]
        while queue and queue[0] < now - window:
            queue.popleft()
        if len(queue) >= limit:
            return False
        queue.append(now)
        return True


class SecurityMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app
        self.rate_limiter = RateLimiter()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        path = scope.get("path", "")
        request_id = str(uuid.uuid4())
        client_ip = (headers.get(b"cf-connecting-ip") or b"unknown").decode(
            "utf-8", "replace"
        )[:64]
        peer_host = str((scope.get("client") or ("", 0))[0])
        trusted_local_tunnel = peer_host in {"127.0.0.1", "::1"}
        if path != "/healthz" and not trusted_local_tunnel:
            supplied = (headers.get(b"x-origin-shared-secret") or b"").decode(
                "utf-8", "replace"
            )
            if not hmac.compare_digest(supplied, config.ORIGIN_SHARED_SECRET):
                await _send_json(send, 403, {"error": "forbidden"})
                return
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > 1_048_576:
                    await _send_json(send, 413, {"error": "request_too_large"})
                    return
            except ValueError:
                await _send_json(send, 400, {"error": "invalid_content_length"})
                return
        limit = 10 if path == "/oauth/authorize/decision" else 120
        if not self.rate_limiter.allow(f"{client_ip}:{path}", limit):
            await _send_json(send, 429, {"error": "rate_limited"})
            return
        token_handle = None
        if path == "/mcp":
            authorization = (headers.get(b"authorization") or b"").decode(
                "utf-8", "replace"
            )
            if not authorization.startswith("Bearer "):
                await _send_json(
                    send,
                    401,
                    {"error": "unauthorized"},
                    [
                        (
                            b"www-authenticate",
                            f'Bearer resource_metadata="{config.PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"'.encode(),
                        )
                    ],
                )
                return
            claims = oauth.verify_access_token(authorization[7:])
            if claims is None:
                await _send_json(
                    send,
                    401,
                    {"error": "invalid_token"},
                    [(b"www-authenticate", b'Bearer error="invalid_token"')],
                )
                return
            token_handle = claims_context.set(claims)
        status_holder = {"status": 500}

        async def wrapped_send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                message.setdefault("headers", []).append(
                    (b"x-request-id", request_id.encode())
                )
            await send(message)

        started = time.monotonic()
        try:
            await self.app(scope, receive, wrapped_send)
        except (
            HomeAssistantError,
            SolarEdgeError,
            SolarEdgePortalError,
            ValueError,
            PermissionError,
        ) as exc:
            LOGGER.warning(
                "request_failed request_id=%s error_type=%s",
                request_id,
                type(exc).__name__,
            )
            await _send_json(send, 400, {"error": str(exc), "request_id": request_id})
            status_holder["status"] = 400
        except Exception:
            LOGGER.exception("unhandled_request_error request_id=%s", request_id)
            await _send_json(
                send, 500, {"error": "internal_error", "request_id": request_id}
            )
            status_holder["status"] = 500
        finally:
            if token_handle is not None:
                claims_context.reset(token_handle)
            audit.write(
                "http_request",
                request_id=request_id,
                method=scope.get("method"),
                path=path,
                status=status_holder["status"],
                duration_ms=round((time.monotonic() - started) * 1000),
            )


async def _send_json(
    send: Any,
    status: int,
    body: dict[str, Any],
    headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    import json

    data = json.dumps(body, separators=(",", ":")).encode()
    response_headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(data)).encode()),
    ]
    if headers:
        response_headers.extend(headers)
    await send(
        {"type": "http.response.start", "status": status, "headers": response_headers}
    )
    await send({"type": "http.response.body", "body": data})


async def health(_: Request) -> Response:
    try:
        ha_config = await ha.config()
        return JSONResponse(
            {
                "status": "ok",
                "service": "ha-chatgpt-mcp",
                "service_version": SERVER_VERSION,
                "home_assistant": {
                    "reachable": True,
                    "version": ha_config.get("version"),
                },
            }
        )
    except Exception:
        return JSONResponse(
            {
                "status": "degraded",
                "service": "ha-chatgpt-mcp",
                "service_version": SERVER_VERSION,
                "home_assistant": {"reachable": False},
            },
            status_code=503,
        )


async def auth_metadata(_: Request) -> Response:
    return JSONResponse(oauth.authorization_metadata())


async def resource_metadata(_: Request) -> Response:
    return JSONResponse(oauth.resource_metadata())


async def register(request: Request) -> Response:
    return await oauth.register(request)


async def authorize(request: Request) -> Response:
    return await oauth.authorize(request)


async def authorize_decision(request: Request) -> Response:
    return await oauth.authorize_decision(request)


async def token(request: Request) -> Response:
    return await oauth.token(request)


async def solaredge_callback(request: Request) -> Response:
    if solaredge_oauth is None:
        return HTMLResponse(
            "<h1>SolarEdge connection unavailable</h1><p>The server is not configured.</p>",
            status_code=503,
        )
    code = request.query_params.get("code", "")
    site_id = request.query_params.get("site_id", "")
    state = request.query_params.get("state", "")
    try:
        await solaredge_oauth.handle_callback(code, site_id, state)
    except (SolarEdgeAuthorizationError, ValueError):
        LOGGER.warning("solaredge_oauth_callback_failed")
        return HTMLResponse(
            "<h1>SolarEdge connection failed</h1>"
            "<p>The authorization was invalid or expired. Close this page and try again.</p>",
            status_code=400,
        )
    audit.write("solaredge_authorized")
    return HTMLResponse(
        "<h1>SolarEdge connected</h1>"
        "<p>Read-only site and device access is now active. You may close this page.</p>"
    )


def _solaredge_bridge_allowed(request: Request) -> bool:
    peer = request.client.host if request.client else ""
    supplied = request.headers.get("x-solaredge-bridge-secret", "")
    return (
        peer in {"127.0.0.1", "::1"}
        and bool(config.SOLAREDGE_BRIDGE_SECRET)
        and hmac.compare_digest(supplied, str(config.SOLAREDGE_BRIDGE_SECRET))
    )


async def internal_solaredge_authorize(request: Request) -> Response:
    if not _solaredge_bridge_allowed(request) or solaredge_oauth is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    authorization = solaredge_oauth.begin_authorization()
    audit.write("solaredge_authorization_started")
    return JSONResponse(
        {
            "authorization_url": authorization["authorization_url"],
            "expires_at": authorization["expires_at"],
        }
    )


async def internal_solaredge_snapshot(request: Request) -> Response:
    if not _solaredge_bridge_allowed(request) or solaredge_portal is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    try:
        snapshot = await _build_solaredge_bridge_snapshot()
    except SolarEdgePortalError:
        LOGGER.warning("solaredge_portal_snapshot_failed")
        return JSONResponse(
            {
                "connected": False,
                "provider": "solaredge_monitoring_portal",
                "observed_at": datetime.now(UTC).isoformat(),
                "site": {},
                "completeness": {},
            },
            status_code=503,
        )
    async with _solaredge_snapshot_filter_lock:
        snapshot, filter_action = _solaredge_snapshot_filter.apply(snapshot)
    if filter_action == "suppressed_first_near_zero":
        LOGGER.warning("solaredge_bridge_transient_near_zero_suppressed")
    elif filter_action == "confirmed_near_zero":
        LOGGER.warning("solaredge_bridge_near_zero_confirmed")
    elif filter_action == "recovered_after_suppression":
        LOGGER.info("solaredge_bridge_recovered_after_suppressed_snapshot")
    return JSONResponse(snapshot)


transport_security = TransportSecuritySettings(
    allowed_hosts=[
        "127.0.0.1",
        "127.0.0.1:*",
        "localhost",
        "localhost:*",
        *config.MCP_ALLOWED_HOSTS,
    ],
    allowed_origins=["https://chatgpt.com", "https://platform.openai.com"],
)
mcp_app = mcp.streamable_http_app(transport_security=transport_security)


@asynccontextmanager
async def lifespan(_: Starlette) -> AsyncIterator[None]:
    await ha.start()
    oauth.store.cleanup()
    capability_sync.start(ha)
    async with mcp.session_manager.run():
        yield
    await capability_sync.close()
    if solaredge is not None:
        await solaredge.close()
    if solaredge_portal is not None:
        await solaredge_portal.close()
    await ha.close()


inner_app = Starlette(
    routes=[
        Route("/healthz", health, methods=["GET"]),
        Route(
            "/.well-known/oauth-authorization-server", auth_metadata, methods=["GET"]
        ),
        Route("/.well-known/openid-configuration", auth_metadata, methods=["GET"]),
        Route(
            "/.well-known/oauth-protected-resource", resource_metadata, methods=["GET"]
        ),
        Route(
            "/.well-known/oauth-protected-resource/mcp",
            resource_metadata,
            methods=["GET"],
        ),
        Route("/oauth/register", register, methods=["POST"]),
        Route("/oauth/authorize", authorize, methods=["GET"]),
        Route("/oauth/authorize/decision", authorize_decision, methods=["POST"]),
        Route("/oauth/token", token, methods=["POST"]),
        Route("/solaredge/oauth/callback", solaredge_callback, methods=["GET"]),
        Route(
            "/internal/solaredge/authorize",
            internal_solaredge_authorize,
            methods=["POST"],
        ),
        Route(
            "/internal/solaredge/snapshot",
            internal_solaredge_snapshot,
            methods=["GET"],
        ),
        Mount("/", app=mcp_app),
    ],
    lifespan=lifespan,
)
app = SecurityMiddleware(inner_app)
