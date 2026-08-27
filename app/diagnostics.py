from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import ssl
import time
from collections.abc import Iterable, Mapping
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp


MAX_WINDOW = timedelta(hours=168)
DEFAULT_WINDOW_HOURS = 24
MAX_RESULTS = 200
MAX_CURRENT_BYTES = 256 * 1024
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_JSONL_LINE_BYTES = 64 * 1024
MAX_JSONL_LINES = 50_000
MAX_TEXT_LENGTH = 512
FRESH_AFTER = timedelta(minutes=3)

EXTERNAL_FRONTEND = os.environ.get(
    "FRONTEND_PUBLIC_URL", "https://ha.example.com"
).rstrip("/")
_PUBLIC_MCP_BASE = os.environ.get(
    "PUBLIC_BASE_URL", "https://mcp.example.com"
).rstrip("/")
_LOCAL_MCP_BASE = os.environ.get(
    "MCP_LOCAL_BASE_URL", "http://127.0.0.1:8000"
).rstrip("/")
LOCAL_FRONTEND = os.environ.get("HA_BASE_URL", "http://127.0.0.1:8123").rstrip("/")
EXTERNAL_MCP = f"{_PUBLIC_MCP_BASE}/mcp"
LOCAL_MCP = f"{_LOCAL_MCP_BASE}/mcp"
EXTERNAL_MCP_HEALTH = f"{_PUBLIC_MCP_BASE}/healthz"
LOCAL_MCP_HEALTH = f"{_LOCAL_MCP_BASE}/healthz"


class DiagnosticError(ValueError):
    """A safe validation or collector-read failure."""


class Component(StrEnum):
    HOME_ASSISTANT = "home_assistant"
    MCP = "mcp"
    DOCKER = "docker"
    KERNEL = "kernel"
    CGROUP = "cgroup"
    SYSTEMD = "systemd"
    CLOUDFLARE_TUNNEL = "cloudflare_tunnel"
    WIREGUARD = "wireguard"
    REVERSE_PROXY = "reverse_proxy"
    ENDPOINT_PROBE = "endpoint_probe"


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Cause(StrEnum):
    OOM_KILL = "oom_kill"
    PROCESS_CRASH = "process_crash"
    OPERATOR_RESTART = "operator_restart"
    DEPLOYMENT_RESTART = "deployment_restart"
    HOST_REBOOT = "host_reboot"
    DOCKER_RESTART = "docker_restart"
    WATCHDOG_RESTART = "watchdog_restart"
    TUNNEL_FAILURE = "tunnel_failure"
    ENDPOINT_FAILURE = "endpoint_failure"
    UNKNOWN = "unknown"


COMPONENTS = frozenset(item.value for item in Component)
SEVERITIES = frozenset(item.value for item in Severity)
CAUSES = frozenset(item.value for item in Cause)

_RFC3339_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$"
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|_)(?:access_?token|refresh_?token|api_?key|authorization|auth|cookie|"
    r"credential|password|passwd|secret|private_?key|signature|signed_?url|"
    r"environment|env|username|user|account_?id|instance_?id|subnet_?id|"
    r"security_?group|resource_?id|public_?ip|private_?ip|ip_?address|mac|"
    r"hostname|host_?id)(?:$|_)",
    re.IGNORECASE,
)
_RAW_KEY_RE = re.compile(
    r"(?:raw|log|journal|trace|stack|stdout|stderr|exception|provider_?response|"
    r"provider_?(?:error|text)|(?:error|details?|message)$|"
    r"response_?body|request_?body|headers?|process_?args|cmdline|command|"
    r"executable|config(?:uration)?_?contents?|file_?contents?)",
    re.IGNORECASE,
)
_URL_QUERY_RE = re.compile(r"\b(https?://[^\s?#]+)(?:\?[^\s#]*)?(?:#[^\s]*)?", re.I)
_AUTH_RE = re.compile(
    r"(?i)\b(?:authorization\s*:\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+\-/=]+"
)
_COOKIE_RE = re.compile(r"(?i)\b(?:set-)?cookie\s*:\s*[^\r\n]+")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:access[_-]?token|refresh[_-]?token|token|api[_-]?key|password|"
    r"passwd|secret|signature|sig|code)\s*[=:]\s*[^\s,;&]+"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_MAC_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_CANDIDATE_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_AWS_ACCOUNT_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_AWS_ARN_RE = re.compile(r"\barn:aws(?:-[a-z]+)?:[^\s,]+", re.I)
_AWS_RESOURCE_RE = re.compile(
    r"\b(?:i|ami|subnet|sg|vpc|eni|vol|snap|rtb|igw|nat|eipalloc)-[0-9a-f]{8,17}\b",
    re.I,
)
_WINDOWS_HOME_RE = re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+(?:\\[^\s,;]*)?")
_UNIX_HOME_RE = re.compile(r"(?i)(?<!\w)/(?:home|Users)/[^/\s]+(?:/[^\s,;]*)?")
_USERNAME_RE = re.compile(r"(?i)\b(?:user(?:name)?|login)\s*[=:]\s*[^\s,;]+")

_EVENT_KEYS = frozenset(
    {
        "timestamp",
        "component",
        "severity",
        "event_type",
        "summary",
        "exit_code",
        "signal",
        "counter",
        "http_status",
        "evidence_source",
        "complete",
        "truncated",
        "inferred",
        "cause",
        "initiator",
        "container",
        "boot_changed",
    }
)
_EVIDENCE_SOURCES = frozenset(
    {
        "collector_state",
        "container_state",
        "docker_event",
        "docker_journal",
        "systemd_journal",
        "kernel_journal",
        "cgroup_counter",
        "endpoint_probe",
        "deployment_marker",
        "historical_snapshot",
    }
)
_FIXED_EVENT_SUMMARIES = {
    "container_start": "The monitored container started.",
    "container_stop": "The monitored container stopped.",
    "container_exit": "The monitored container exited.",
    "container_restart": "The monitored container restarted.",
    "process_crash": "The monitored process exited unexpectedly.",
    "oom_kill": "Direct evidence recorded an out-of-memory kill.",
    "memory_oom": "Direct evidence recorded a memory out-of-memory event.",
    "cgroup_oom_kill": "The fixed cgroup counter recorded an out-of-memory kill.",
    "host_boot": "The host boot identity changed.",
    "host_reboot": "Direct evidence recorded a host reboot.",
    "host_shutdown": "Direct evidence recorded a host shutdown.",
    "docker_restart": "Direct evidence recorded a Docker restart.",
    "daemon_restart": "Direct evidence recorded a service daemon restart.",
    "deployment": "A deployment marker was recorded.",
    "deployment_restart": "A deployment marker established the restart.",
    "operator_restart": "An audit marker established an operator restart.",
    "watchdog_restart": "A watchdog action marker established the restart.",
    "disconnect": "The fixed Cloudflare tunnel disconnected.",
    "reconnect": "The fixed Cloudflare tunnel reconnected.",
    "tunnel_failure": "The fixed Cloudflare tunnel was unavailable.",
    "route_unavailable": "A fixed external route was unavailable.",
    "endpoint_failure": "A fixed endpoint probe failed.",
    "probe_failure": "A fixed endpoint probe failed.",
    "source_unavailable": "A required diagnostic evidence source was unavailable.",
}


def format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_utc(value: str, *, field: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not _RFC3339_UTC_RE.fullmatch(value):
        raise DiagnosticError(f"{field} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DiagnosticError(f"{field} must be an RFC 3339 UTC timestamp") from exc
    if parsed.utcoffset() != timedelta(0):
        raise DiagnosticError(f"{field} must be UTC")
    return parsed.astimezone(UTC)


def validate_window(
    *,
    since_hours: float | None = None,
    start: str | None = None,
    end: str | None = None,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    explicit = start is not None or end is not None
    if since_hours is not None and explicit:
        raise DiagnosticError("since_hours cannot be combined with start or end")
    if explicit:
        if start is None or end is None:
            raise DiagnosticError("start and end must be supplied together")
        start_at, end_at = parse_utc(start, field="start"), parse_utc(end, field="end")
    else:
        hours = DEFAULT_WINDOW_HOURS if since_hours is None else since_hours
        if isinstance(hours, bool) or not isinstance(hours, (int, float)):
            raise DiagnosticError("since_hours must be a number")
        if hours <= 0 or hours > MAX_WINDOW.total_seconds() / 3600:
            raise DiagnosticError("since_hours must be greater than 0 and no more than 168")
        end_at, start_at = current, current - timedelta(hours=float(hours))
    if end_at <= start_at:
        raise DiagnosticError("end must be after start")
    if end_at > current + timedelta(seconds=1):
        raise DiagnosticError("end cannot be in the future")
    if end_at - start_at > MAX_WINDOW:
        raise DiagnosticError("diagnostic window cannot exceed 168 hours")
    return start_at, end_at


def validate_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RESULTS:
        raise DiagnosticError("limit must be an integer from 1 through 200")
    return limit


def _redact_ip_candidates(text: str) -> str:
    def ipv4(match: re.Match[str]) -> str:
        try:
            ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)
        return "[REDACTED_IP]"

    def ipv6(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        return "[REDACTED_IP]"

    return _IPV6_CANDIDATE_RE.sub(ipv6, _IPV4_RE.sub(ipv4, text))


def sanitize_text(value: str, *, max_length: int = MAX_TEXT_LENGTH) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = _AUTH_RE.sub("[REDACTED_AUTH]", text)
    text = _COOKIE_RE.sub("[REDACTED_COOKIE]", text)
    text = _JWT_RE.sub("[REDACTED_TOKEN]", text)
    text = _SECRET_ASSIGNMENT_RE.sub("[REDACTED_SECRET]", text)
    text = _URL_QUERY_RE.sub(lambda match: match.group(1), text)
    text = _MAC_RE.sub("[REDACTED_MAC]", text)
    text = _redact_ip_candidates(text)
    text = _AWS_ARN_RE.sub("[REDACTED_AWS_RESOURCE]", text)
    text = _AWS_RESOURCE_RE.sub("[REDACTED_AWS_RESOURCE]", text)
    text = _AWS_ACCOUNT_RE.sub("[REDACTED_AWS_ACCOUNT]", text)
    text = _WINDOWS_HOME_RE.sub("[REDACTED_HOME_PATH]", text)
    text = _UNIX_HOME_RE.sub("[REDACTED_HOME_PATH]", text)
    text = _USERNAME_RE.sub("[REDACTED_USERNAME]", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_length:
        return text[: max_length - 14] + "...[truncated]"
    return text


def sanitize(value: Any, *, _key: str | None = None) -> Any:
    """Recursively redact defense-in-depth data from collector-owned structures."""
    if _key and (_SENSITIVE_KEY_RE.search(_key) or _RAW_KEY_RE.search(_key)):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:MAX_RESULTS]:
            key = sanitize_text(str(raw_key), max_length=80)
            result[key] = sanitize(item, _key=str(raw_key))
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize(item, _key=_key) for item in value[:MAX_RESULTS]]
    if isinstance(value, str):
        return sanitize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return "[REDACTED_UNSUPPORTED]"


class DiagnosticsReader:
    """Read a fixed, sanitized collector export and run fixed read-only probes."""

    def __init__(self, export_directory: Path | str) -> None:
        directory = Path(export_directory)
        if not directory.is_absolute():
            raise DiagnosticError("diagnostic export directory must be absolute")
        self._directory = directory.resolve(strict=False)

    def _fixed_file(self, name: str) -> Path:
        if not re.fullmatch(
            r"(?:current\.json|(?:events|samples)-\d{4}-\d{2}-\d{2}\.jsonl)", name
        ):
            raise DiagnosticError("invalid diagnostic export filename")
        path = self._directory / name
        if path.is_symlink() or path.resolve(strict=False).parent != self._directory:
            raise DiagnosticError("diagnostic export file is unavailable")
        return path

    def _read_current(self) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        path = self._fixed_file("current.json")
        metadata = {
            "available": False,
            "complete": False,
            "truncated": False,
            "reason": "missing",
        }
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_CURRENT_BYTES + 1)
        except (FileNotFoundError, OSError):
            return None, metadata
        if len(raw) > MAX_CURRENT_BYTES:
            metadata.update(reason="oversized", truncated=True)
            return None, metadata
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            metadata.update(reason="malformed")
            return None, metadata
        if not isinstance(decoded, dict):
            metadata.update(reason="malformed")
            return None, metadata
        metadata.update(available=True, complete=True, reason=None)
        return decoded, metadata

    @staticmethod
    def _days(start: datetime, end: datetime) -> Iterable[date]:
        cursor = start.date()
        final = end.date()
        while cursor <= final:
            yield cursor
            cursor += timedelta(days=1)

    @staticmethod
    def _source_group_complete(value: Any) -> bool:
        if not isinstance(value, Mapping):
            return False
        for key, item in value.items():
            if key in {"window_start", "window_end", "events"}:
                continue
            if isinstance(item, Mapping):
                if not DiagnosticsReader._source_group_complete(item):
                    return False
            elif key == "available" and item is not True:
                return False
            elif key == "truncated" and item is not False:
                return False
        return True

    def _event_coverage(self) -> tuple[datetime, datetime] | None:
        snapshot, metadata = self._read_current()
        if snapshot is None or not metadata["complete"]:
            return None
        collector = snapshot.get("collector")
        if not isinstance(collector, Mapping):
            return None
        historical = collector.get("historical_backfill")
        if not isinstance(historical, Mapping):
            return None
        if historical.get("completed") is not True or historical.get("complete") is not True:
            return None
        try:
            coverage_start = parse_utc(historical.get("window_start"), field="window_start")
            historical_end = parse_utc(historical.get("window_end"), field="window_end")
        except DiagnosticError:
            return None
        coverage_end = historical_end
        incremental = collector.get("incremental_sources")
        required_incremental = {
            "docker_events",
            "journald",
            "cloudflared_logs",
            "reverse_proxy_logs",
        }
        if (
            collector.get("status") == "healthy"
            and isinstance(incremental, Mapping)
            and required_incremental <= set(incremental)
            and self._source_group_complete(incremental)
        ):
            snapshot_at = self._snapshot_observed_at(snapshot)
            if snapshot_at is not None:
                coverage_end = max(coverage_end, snapshot_at + FRESH_AFTER)
        return coverage_start, coverage_end

    def _read_jsonl(
        self, prefix: str, start: datetime, end: datetime
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        records: list[dict[str, Any]] = []
        sources: list[dict[str, Any]] = []
        total_lines = 0
        event_coverage = self._event_coverage() if prefix == "events" else None
        for day in self._days(start, end):
            name = f"{prefix}-{day.isoformat()}.jsonl"
            path = self._fixed_file(name)
            source = {"date": day.isoformat(), "available": False, "complete": False}
            try:
                size = path.stat().st_size
                handle = path.open("rb")
            except (FileNotFoundError, OSError):
                day_start = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
                requested_start = max(start, day_start)
                requested_end = min(end, day_start + timedelta(days=1))
                covered = bool(
                    event_coverage
                    and event_coverage[0] <= requested_start
                    and event_coverage[1] >= requested_end
                )
                if covered:
                    source.update(
                        available=True,
                        complete=True,
                        truncated=False,
                        reason="no_records_in_covered_window",
                    )
                else:
                    source["reason"] = "missing_or_outside_collector_coverage"
                sources.append(source)
                continue
            source["available"] = True
            source["truncated"] = size > MAX_LEDGER_BYTES
            malformed = 0
            oversized_lines = 0
            bytes_read = 0
            with handle:
                for raw_line in handle:
                    if total_lines >= MAX_JSONL_LINES or bytes_read + len(raw_line) > MAX_LEDGER_BYTES:
                        source["truncated"] = True
                        break
                    bytes_read += len(raw_line)
                    total_lines += 1
                    if len(raw_line) > MAX_JSONL_LINE_BYTES:
                        oversized_lines += 1
                        continue
                    try:
                        item = json.loads(raw_line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        malformed += 1
                        continue
                    if not isinstance(item, dict):
                        malformed += 1
                        continue
                    timestamp = item.get("timestamp") or item.get("observed_at")
                    try:
                        observed = parse_utc(timestamp)
                    except DiagnosticError:
                        malformed += 1
                        continue
                    if start <= observed <= end:
                        records.append(item)
            source["complete"] = not source.get("truncated", False) and malformed == 0 and oversized_lines == 0
            source["malformed_records"] = malformed
            source["oversized_records"] = oversized_lines
            sources.append(source)
        return records, {
            "available": any(source["available"] for source in sources),
            "complete": bool(sources) and all(source["complete"] for source in sources),
            "truncated": any(source.get("truncated", False) for source in sources),
            "files": sources,
        }

    @staticmethod
    def _snapshot_observed_at(snapshot: Mapping[str, Any]) -> datetime | None:
        value = snapshot.get("observed_at") or snapshot.get("timestamp")
        try:
            return parse_utc(value)
        except DiagnosticError:
            return None

    def get_current_health(self, *, now: datetime | None = None) -> dict[str, Any]:
        observed_now = (now or datetime.now(UTC)).astimezone(UTC)
        snapshot, source = self._read_current()
        result: dict[str, Any] = {
            "observed_at": format_utc(observed_now),
            "collector": source,
            "fresh": False,
            "freshness_seconds": None,
            "complete": False,
            "unavailable_sources": ["collector_snapshot"],
        }
        if snapshot is None:
            return result
        snapshot_at = self._snapshot_observed_at(snapshot)
        if snapshot_at is None:
            result["collector"] = {**source, "complete": False, "reason": "invalid_timestamp"}
            return result
        age = max(0.0, (observed_now - snapshot_at).total_seconds())
        evidence = snapshot.get("evidence")
        evidence = evidence if isinstance(evidence, Mapping) else {}
        unavailable = evidence.get(
            "unavailable_sources", snapshot.get("unavailable_sources", [])
        )
        if not isinstance(unavailable, list):
            unavailable = ["collector_metadata"]
        result.update(
            {
                "snapshot_observed_at": format_utc(snapshot_at),
                "fresh": age <= FRESH_AFTER.total_seconds(),
                "freshness_seconds": round(age, 3),
                "complete": bool(
                    evidence.get("complete", snapshot.get("complete", True))
                )
                and source["complete"],
                "unavailable_sources": sanitize(unavailable),
                "health": sanitize(snapshot),
            }
        )
        if not result["fresh"]:
            result["collector"]["reason"] = "stale"
            result["complete"] = False
        return result

    @staticmethod
    def _normalize_event(raw: Mapping[str, Any]) -> dict[str, Any] | None:
        component = str(raw.get("component", ""))
        severity = str(raw.get("severity", ""))
        if component not in COMPONENTS or severity not in SEVERITIES:
            return None
        try:
            timestamp = format_utc(parse_utc(raw.get("timestamp")))
        except DiagnosticError:
            return None
        event = {key: raw[key] for key in _EVENT_KEYS if key in raw}
        event.update(timestamp=timestamp, component=component, severity=severity)
        event_type = sanitize_text(str(raw.get("event_type", "unknown")), max_length=80)
        event["event_type"] = event_type
        event["summary"] = _FIXED_EVENT_SUMMARIES.get(
            event_type, "A bounded diagnostic event was recorded."
        )
        evidence_source = str(raw.get("evidence_source", "collector_state"))
        event["evidence_source"] = (
            evidence_source
            if evidence_source in _EVIDENCE_SOURCES
            else "collector_state"
        )
        cause = str(raw.get("cause", Cause.UNKNOWN.value))
        event["cause"] = cause if cause in CAUSES else Cause.UNKNOWN.value
        event.setdefault("complete", True)
        event.setdefault("truncated", False)
        event.setdefault("inferred", False)
        return sanitize(event)

    @staticmethod
    def _normalize_filter(values: Iterable[str] | None, allowed: frozenset[str], name: str) -> set[str] | None:
        if values is None:
            return None
        normalized = {str(value) for value in values}
        if not normalized or not normalized <= allowed:
            raise DiagnosticError(f"{name} contains an unsupported value")
        return normalized

    def get_diagnostic_events(
        self,
        *,
        since_hours: float | None = None,
        start: str | None = None,
        end: str | None = None,
        components: Iterable[str] | None = None,
        severities: Iterable[str] | None = None,
        limit: int = 100,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        start_at, end_at = validate_window(
            since_hours=since_hours, start=start, end=end, now=now
        )
        limit = validate_limit(limit)
        component_filter = self._normalize_filter(components, COMPONENTS, "components")
        severity_filter = self._normalize_filter(severities, SEVERITIES, "severities")
        raw, source = self._read_jsonl("events", start_at, end_at)
        events = [event for item in raw if (event := self._normalize_event(item)) is not None]
        if component_filter is not None:
            events = [event for event in events if event["component"] in component_filter]
        if severity_filter is not None:
            events = [event for event in events if event["severity"] in severity_filter]
        events.sort(key=lambda event: event["timestamp"], reverse=True)
        truncated = len(events) > limit or source["truncated"]
        return {
            "window": {"start": format_utc(start_at), "end": format_utc(end_at)},
            "filters": {
                "components": sorted(component_filter) if component_filter else None,
                "severities": sorted(severity_filter) if severity_filter else None,
            },
            "events": events[:limit],
            "count": min(len(events), limit),
            "truncated": truncated,
            "source": sanitize(source),
        }

    @staticmethod
    def _established_cause(event: Mapping[str, Any], all_events: list[Mapping[str, Any]]) -> str:
        cause = str(event.get("cause", ""))
        if cause in CAUSES and cause != Cause.UNKNOWN.value and not event.get("inferred", False):
            return cause
        event_type = str(event.get("event_type", "")).lower()
        component = str(event.get("component", ""))
        if event.get("boot_changed") is True or event_type in {"host_boot", "host_reboot"}:
            return Cause.HOST_REBOOT.value
        if event_type in {"oom_kill", "memory_oom", "cgroup_oom_kill"}:
            return Cause.OOM_KILL.value
        if event_type in {"docker_restart", "daemon_restart"} and component == Component.DOCKER.value:
            return Cause.DOCKER_RESTART.value
        if event_type in {"deployment_restart", "deployment"}:
            return Cause.DEPLOYMENT_RESTART.value
        if event_type == "operator_restart" and event.get("initiator") == "operator_audit":
            return Cause.OPERATOR_RESTART.value
        if event_type == "watchdog_restart" and event.get("initiator") == "watchdog":
            return Cause.WATCHDOG_RESTART.value
        if component == Component.CLOUDFLARE_TUNNEL.value and event_type in {
            "disconnect", "tunnel_failure", "route_unavailable"
        }:
            return Cause.TUNNEL_FAILURE.value
        if component == Component.ENDPOINT_PROBE.value and event_type in {
            "endpoint_failure", "probe_failure"
        }:
            return Cause.ENDPOINT_FAILURE.value
        exit_code = event.get("exit_code")
        if exit_code == 137:
            event_at = event.get("timestamp")
            for candidate in all_events:
                if str(candidate.get("event_type", "")).lower() not in {
                    "oom_kill", "memory_oom", "cgroup_oom_kill"
                }:
                    continue
                try:
                    distance = abs(
                        (parse_utc(candidate.get("timestamp")) - parse_utc(event_at)).total_seconds()
                    )
                except DiagnosticError:
                    continue
                if distance <= 120:
                    return Cause.OOM_KILL.value
            return Cause.UNKNOWN.value
        if isinstance(exit_code, int) and exit_code != 0:
            return Cause.PROCESS_CRASH.value
        return Cause.UNKNOWN.value

    def get_restart_outage_diagnostics(
        self,
        *,
        since_hours: float | None = None,
        start: str | None = None,
        end: str | None = None,
        limit: int = 100,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        start_at, end_at = validate_window(
            since_hours=since_hours, start=start, end=end, now=now
        )
        limit = validate_limit(limit)
        raw_events, event_source = self._read_jsonl("events", start_at, end_at)
        events = [event for item in raw_events if (event := self._normalize_event(item)) is not None]
        relevant_types = (
            "start", "stop", "restart", "exit", "crash", "oom", "boot", "shutdown",
            "deployment", "watchdog", "disconnect", "reconnect", "failure", "unavailable",
        )
        relevant = [
            event for event in events
            if any(token in str(event["event_type"]).lower() for token in relevant_types)
        ]
        relevant.sort(key=lambda event: event["timestamp"], reverse=True)
        for event in relevant:
            event["cause"] = self._established_cause(event, events)
        samples, sample_source = self._read_jsonl("samples", start_at, end_at)
        safe_samples = [sanitize(sample) for sample in samples[-min(limit, 60):]]
        unavailable: list[str] = []
        if not event_source["available"]:
            unavailable.append("event_ledger")
        if not sample_source["available"]:
            unavailable.append("resource_samples")
        return {
            "window": {"start": format_utc(start_at), "end": format_utc(end_at)},
            "events": relevant[:limit],
            "resource_samples": safe_samples,
            "event_count": min(len(relevant), limit),
            "sample_count": len(safe_samples),
            "truncated": len(relevant) > limit or event_source["truncated"] or sample_source["truncated"],
            "complete": event_source["complete"] and sample_source["complete"],
            "unavailable_sources": unavailable,
            "sources": {"events": sanitize(event_source), "samples": sanitize(sample_source)},
        }

    async def _dns_probe(self, host: str, port: int = 443) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, port, type=0), timeout=3
            )
        except (OSError, TimeoutError):
            return {"success": False, "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
        return {"success": True, "latency_ms": round((time.perf_counter() - started) * 1000, 1)}

    async def _tls_probe(self, host: str, *, now: datetime) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, 443, ssl=ssl.create_default_context(), server_hostname=host
                ), timeout=5
            )
            del reader
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert() if ssl_object is not None else {}
            expires_raw = certificate.get("notAfter")
            expires_at = (
                datetime.fromtimestamp(ssl.cert_time_to_seconds(expires_raw), UTC)
                if expires_raw else None
            )
            writer.close()
            await writer.wait_closed()
        except (OSError, TimeoutError, ssl.SSLError, ValueError):
            return {"valid": False, "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
        return {
            "valid": bool(expires_at and expires_at > now),
            "expires_at": format_utc(expires_at) if expires_at else None,
            "days_remaining": int((expires_at - now).total_seconds() // 86400) if expires_at else None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    async def _http_probe(self, url: str, expected: set[int]) -> dict[str, Any]:
        started = time.perf_counter()
        timeout = aiohttp.ClientTimeout(total=7, connect=3)
        try:
            async with aiohttp.ClientSession(
                timeout=timeout, raise_for_status=False, cookie_jar=aiohttp.DummyCookieJar()
            ) as session:
                async with session.get(url, allow_redirects=False) as response:
                    status = response.status
                    await response.content.read(1024)
        except (aiohttp.ClientError, TimeoutError):
            return {"reachable": False, "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
        return {
            "reachable": True,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "http_status": status,
            "expected_response": status in expected,
        }

    async def _ha_bootstrap_probe(self, origin: str) -> dict[str, Any]:
        if origin not in {EXTERNAL_FRONTEND, LOCAL_FRONTEND}:
            raise DiagnosticError("unsupported fixed Home Assistant origin")
        started = time.perf_counter()
        timeout = aiohttp.ClientTimeout(total=7, connect=3)
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                raise_for_status=False,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                async with session.get(origin + "/", allow_redirects=False) as response:
                    status = response.status
                    body = (await response.content.read(16 * 1024)).decode(
                        "utf-8", "replace"
                    ).lower()
        except (aiohttp.ClientError, TimeoutError):
            return {
                "reachable": False,
                "bootstrap_marker": False,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            }
        marker = any(
            item in body
            for item in ("<home-assistant", "home-assistant", "frontend_latest")
        )
        return {
            "reachable": True,
            "http_status": status,
            "expected_response": status == 200,
            "bootstrap_marker": status == 200 and marker,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    async def _mcp_protocol_probe(self, url: str) -> dict[str, Any]:
        if url not in {EXTERNAL_MCP, LOCAL_MCP}:
            raise DiagnosticError("unsupported fixed MCP route")
        started = time.perf_counter()
        timeout = aiohttp.ClientTimeout(total=7, connect=3)
        initialize = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "fixed-diagnostic-probe", "version": "1"},
            },
        }
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                raise_for_status=False,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                async with session.post(
                    url,
                    json=initialize,
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                    },
                    allow_redirects=False,
                ) as response:
                    status = response.status
                    challenge_present = response.headers.get(
                        "WWW-Authenticate", ""
                    ).lower().startswith("bearer")
                    await response.content.read(1024)
        except (aiohttp.ClientError, TimeoutError):
            return {
                "reachable": False,
                "expected_authentication_response": False,
                "protocol_auth_reachable": False,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            }
        expected = status == 401 and challenge_present
        return {
            "reachable": True,
            "http_status": status,
            "www_authenticate_present": challenge_present,
            "expected_authentication_response": expected,
            "protocol_auth_reachable": expected,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    async def _websocket_greeting_probe(self, origin: str) -> dict[str, Any]:
        if origin not in {EXTERNAL_FRONTEND, LOCAL_FRONTEND}:
            raise DiagnosticError("unsupported fixed Home Assistant origin")
        timeout = aiohttp.ClientTimeout(total=7, connect=3)
        started = time.perf_counter()
        try:
            async with aiohttp.ClientSession(
                timeout=timeout, cookie_jar=aiohttp.DummyCookieJar()
            ) as session:
                async with session.ws_connect(
                    f"{origin.replace('https://', 'wss://').replace('http://', 'ws://')}/api/websocket",
                    autoclose=True,
                    heartbeat=None,
                ) as websocket:
                    message = await asyncio.wait_for(websocket.receive_json(), timeout=3)
                    valid = isinstance(message, dict) and message.get("type") == "auth_required"
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, TypeError):
            return {"reachable": False, "safe_greeting": False}
        return {
            "reachable": True,
            "safe_greeting": valid,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    async def get_fixed_route_health(self, *, now: datetime | None = None) -> dict[str, Any]:
        observed = (now or datetime.now(UTC)).astimezone(UTC)
        current, current_source = self._read_current()
        frontend_host = urlsplit(EXTERNAL_FRONTEND).hostname or ""
        mcp_host = urlsplit(EXTERNAL_MCP).hostname or ""
        (
            frontend_dns,
            frontend_tls,
            frontend_external_bootstrap,
            frontend_local_bootstrap,
            frontend_external_websocket,
            frontend_local_websocket,
            mcp_dns,
            mcp_tls,
            mcp_external_protocol,
            mcp_local_protocol,
            mcp_external_health,
            mcp_local_health,
        ) = await asyncio.gather(
            self._dns_probe(frontend_host),
            self._tls_probe(frontend_host, now=observed),
            self._ha_bootstrap_probe(EXTERNAL_FRONTEND),
            self._ha_bootstrap_probe(LOCAL_FRONTEND),
            self._websocket_greeting_probe(EXTERNAL_FRONTEND),
            self._websocket_greeting_probe(LOCAL_FRONTEND),
            self._dns_probe(mcp_host),
            self._tls_probe(mcp_host, now=observed),
            self._mcp_protocol_probe(EXTERNAL_MCP),
            self._mcp_protocol_probe(LOCAL_MCP),
            self._http_probe(EXTERNAL_MCP_HEALTH, {200}),
            self._http_probe(LOCAL_MCP_HEALTH, {200}),
        )
        tunnel = None
        if current is not None:
            containers = current.get("containers")
            container_tunnel = (
                containers.get("cloudflare_tunnel")
                if isinstance(containers, Mapping)
                else None
            )
            tunnel = (
                current.get("tunnel")
                or current.get("cloudflare_tunnel")
                or container_tunnel
            )
        return {
            "observed_at": format_utc(observed),
            "fixed_routes_only": True,
            "routes": {
                "home_assistant_frontend": {
                    "external_route": EXTERNAL_FRONTEND,
                    "dns": frontend_dns,
                    "tls": frontend_tls,
                    "external": {
                        "frontend": frontend_external_bootstrap,
                        "websocket": frontend_external_websocket,
                    },
                    "local_origin": {
                        "name": "home_assistant_local",
                        "frontend": frontend_local_bootstrap,
                        "websocket": frontend_local_websocket,
                    },
                },
                "mcp": {
                    "external_route": EXTERNAL_MCP,
                    "dns": mcp_dns,
                    "tls": mcp_tls,
                    "external": {
                        "protocol": mcp_external_protocol,
                        "health": mcp_external_health,
                    },
                    "local_origin": {
                        "name": "mcp_local",
                        "protocol": mcp_local_protocol,
                        "health": mcp_local_health,
                    },
                },
            },
            "cloudflare_tunnel": sanitize(tunnel) if tunnel is not None else {
                "available": False, "reason": "collector_source_unavailable"
            },
            "collector_source": sanitize(current_source),
        }


__all__ = [
    "Cause",
    "Component",
    "DiagnosticError",
    "DiagnosticsReader",
    "Severity",
    "format_utc",
    "parse_utc",
    "sanitize",
    "sanitize_text",
    "validate_limit",
    "validate_window",
]
