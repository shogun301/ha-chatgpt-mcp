from __future__ import annotations

import os
import re
from pathlib import Path


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required setting: {name}")
    return value


def _secret_file(name: str) -> str:
    path = Path(_required(name))
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"Secret file is empty: {path}")
    return value


def _optional(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


_ENTITY_ID_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")


def _optional_entity_id(name: str, domain: str) -> str | None:
    value = _optional(name)
    if value is None:
        return None
    if not _ENTITY_ID_RE.fullmatch(value) or not value.startswith(f"{domain}."):
        raise RuntimeError(f"{name} must be one exact {domain} entity ID")
    return value


def _optional_secret_file(name: str) -> str | None:
    raw_path = _optional(name)
    if raw_path is None:
        return None
    path = Path(raw_path)
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"Secret file is empty: {path}")
    return value


PUBLIC_BASE_URL = _required("PUBLIC_BASE_URL").rstrip("/")
MCP_RESOURCE = f"{PUBLIC_BASE_URL}/mcp"
FRONTEND_PUBLIC_URL = _required("FRONTEND_PUBLIC_URL").rstrip("/")
MCP_LOCAL_BASE_URL = (
    os.environ.get("MCP_LOCAL_BASE_URL", "http://127.0.0.1:8000").strip()
    or "http://127.0.0.1:8000"
).rstrip("/")
MCP_DISPLAY_NAME = _optional("MCP_DISPLAY_NAME") or "Home Assistant MCP"
OAUTH_SUBJECT = _optional("OAUTH_SUBJECT") or "home-assistant-mcp"
PRESENCE_ENTITY = _optional("PRESENCE_ENTITY") or "person.primary_resident"
MOBILE_NOTIFY_SERVICE = _optional("MOBILE_NOTIFY_SERVICE") or "mobile_app_primary_phone"
DEFAULT_VACUUM_ENTITY = _optional("DEFAULT_VACUUM_ENTITY") or "vacuum.primary_vacuum"
SPRINKLER_ENTITY_PREFIX = _optional("SPRINKLER_ENTITY_PREFIX") or "sprinkler_controller"
SPRINKLER_ZONE_ENTITY_PREFIX = (
    _optional("SPRINKLER_ZONE_ENTITY_PREFIX") or f"{SPRINKLER_ENTITY_PREFIX}_zone"
)
try:
    SPRINKLER_ZONE_COUNT = int(_optional("SPRINKLER_ZONE_COUNT") or "8")
except ValueError as exc:
    raise RuntimeError(
        "SPRINKLER_ZONE_COUNT must be an integer from 1 through 8"
    ) from exc
if not 1 <= SPRINKLER_ZONE_COUNT <= 8:
    raise RuntimeError("SPRINKLER_ZONE_COUNT must be an integer from 1 through 8")
AUTOMATION_DAILY_FORECAST_ENTITY = _optional_entity_id(
    "AUTOMATION_DAILY_FORECAST_ENTITY", "weather"
)
LIVING_CLIMATE_ENTITY = (
    _optional("LIVING_CLIMATE_ENTITY") or "climate.living_space_thermostat"
)
LIVING_SCHEDULE_ID = _optional("LIVING_SCHEDULE_ID") or "living_space_schedule"
LIVING_AUTOMATION_ENTITY = (
    _optional("LIVING_AUTOMATION_ENTITY")
    or "automation.living_space_thermostat_follow_schedule"
)
BEDROOM_CLIMATE_ENTITY = (
    _optional("BEDROOM_CLIMATE_ENTITY") or "climate.bedroom_thermostat"
)
BEDROOM_SCHEDULE_ID = _optional("BEDROOM_SCHEDULE_ID") or "bedroom_schedule"
BEDROOM_AUTOMATION_ENTITY = (
    _optional("BEDROOM_AUTOMATION_ENTITY")
    or "automation.bedroom_thermostat_follow_schedule"
)
AWAY_AUTOMATION_ENTITY = (
    _optional("AWAY_AUTOMATION_ENTITY") or "automation.thermostats_away"
)
MCP_ALLOWED_HOSTS = tuple(
    host.strip()
    for host in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",")
    if host.strip()
)
HA_BASE_URL = _required("HA_BASE_URL").rstrip("/")
HA_TOKEN = _secret_file("HA_TOKEN_FILE")
OAUTH_PASSWORD_HASH = _secret_file("OAUTH_PASSWORD_HASH_FILE")
JWT_SECRET = _secret_file("JWT_SECRET_FILE")
ORIGIN_SHARED_SECRET = _secret_file("ORIGIN_SHARED_SECRET_FILE")
DATABASE_PATH = Path(_required("DATABASE_PATH"))
AUDIT_LOG_PATH = Path(_required("AUDIT_LOG_PATH"))
HA_CONFIG_PATH = Path(_required("HA_CONFIG_PATH"))
BACKUP_PATH = Path(_required("BACKUP_PATH"))
CAPABILITY_SYNC_PATH = DATABASE_PATH.parent / "ha-capability-sync.json"
HOST_DIAGNOSTICS_PATH = Path(
    os.environ.get("HOST_DIAGNOSTICS_PATH", "/host-diagnostics").strip()
    or "/host-diagnostics"
)
SOLAREDGE_CLIENT_ID = _optional_secret_file("SOLAREDGE_CLIENT_ID_FILE")
SOLAREDGE_CLIENT_SECRET = _optional_secret_file("SOLAREDGE_CLIENT_SECRET_FILE")
SOLAREDGE_TOKEN_KEY = _optional_secret_file("SOLAREDGE_TOKEN_KEY_FILE")
SOLAREDGE_BRIDGE_SECRET = _optional_secret_file("SOLAREDGE_BRIDGE_SECRET_FILE")
_solaredge_token_store = _optional("SOLAREDGE_TOKEN_STORE_PATH")
SOLAREDGE_TOKEN_STORE_PATH = (
    Path(_solaredge_token_store) if _solaredge_token_store else None
)
SOLAREDGE_REDIRECT_URI = _optional("SOLAREDGE_REDIRECT_URI")
_solaredge_portal_username_file = _optional("SOLAREDGE_PORTAL_USERNAME_FILE")
_solaredge_portal_password_file = _optional("SOLAREDGE_PORTAL_PASSWORD_FILE")
_solaredge_portal_site_id_file = _optional("SOLAREDGE_PORTAL_SITE_ID_FILE")
SOLAREDGE_PORTAL_USERNAME_FILE = (
    Path(_solaredge_portal_username_file) if _solaredge_portal_username_file else None
)
SOLAREDGE_PORTAL_PASSWORD_FILE = (
    Path(_solaredge_portal_password_file) if _solaredge_portal_password_file else None
)
SOLAREDGE_PORTAL_SITE_ID_FILE = (
    Path(_solaredge_portal_site_id_file) if _solaredge_portal_site_id_file else None
)
SOLAREDGE_PORTAL_TIMEZONE = _optional("SOLAREDGE_PORTAL_TIMEZONE")
