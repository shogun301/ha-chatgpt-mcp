#!/usr/bin/env python3
"""Root-owned, fixed-scope Home Assistant host diagnostics collector.

The internet-facing MCP process reads only the sanitized files in ``export_dir``.
This process has no listener and accepts no URLs, paths, command strings, service
names, or container names from callers.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import errno
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Union

try:
    import fcntl
except ImportError:  # pragma: no cover - production is Linux; keeps local tests importable
    fcntl = None  # type: ignore[assignment]

SCHEMA_VERSION = 1
INTERVAL_SECONDS = 60
RETENTION_DAYS = 8
MAX_HISTORY_DAYS = 8
MAX_LEDGER_FILE_BYTES = 7 * 256 * 1024
MAX_EXPORT_BYTES = 32 * 1024 * 1024
MAX_CURRENT_BYTES = 256 * 1024
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_COMMAND_BYTES = 1024 * 1024
MAX_BACKFILL_LINES = 20_000
SOURCE_COMMAND_TIMEOUT_SECONDS = 5
EXPORT_GID = 10001
COMPONENTS = {
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
}
CAUSES = {
    "oom_kill",
    "process_crash",
    "operator_restart",
    "deployment_restart",
    "host_reboot",
    "docker_restart",
    "watchdog_restart",
    "tunnel_failure",
    "endpoint_failure",
    "unknown",
}
SEVERITIES = {"info", "warning", "error", "critical"}
CONTAINERS = {
    "home_assistant": "homeassistant",
    "mcp": "ha-chatgpt-mcp",
    "cloudflare_tunnel": "ha-chatgpt-cloudflared",
    "reverse_proxy": "caddy",
}


def _configured_url(name: str, default: str) -> str:
    value = (os.environ.get(name) or default).strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError(f"{name} must be an absolute HTTP(S) URL")
    return value


LOCAL_HA_URL = _configured_url("HA_LOCAL_URL", "http://127.0.0.1:8123")
LOCAL_MCP_URL = _configured_url("MCP_LOCAL_BASE_URL", "http://127.0.0.1:8000")
PUBLIC_FRONTEND_URL = _configured_url(
    "FRONTEND_PUBLIC_URL", "https://ha.example.com"
)
PUBLIC_MCP_URL = _configured_url("PUBLIC_BASE_URL", "https://mcp.example.com")
LOCAL_HA_HOST = urllib.parse.urlsplit(LOCAL_HA_URL).hostname or "127.0.0.1"
PUBLIC_FRONTEND_HOST = urllib.parse.urlsplit(PUBLIC_FRONTEND_URL).hostname or ""
PUBLIC_MCP_HOST = urllib.parse.urlsplit(PUBLIC_MCP_URL).hostname or ""

_BEARER = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_AWS_IDS = re.compile(
    r"(?i)\b(?:arn:aws:[^\s\]\[\"']+|\d{12}|i-[0-9a-f]{8,17}|subnet-[0-9a-f]{8,17}|sg-[0-9a-f]{8,17})\b"
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE = re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,8}[0-9a-f]{0,4}(?![\w:])")
_MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_HOME_PATH = re.compile(r"(?i)(?:/home/[^/\s]+|/Users/[^/\s]+|[A-Z]:\\Users\\[^\\\s]+)")
_URL_USERINFO = re.compile(r"(?i)(https?://)[^/@\s]+@")
_QUERY = re.compile(r"(?i)(https?://[^\s?#]+)(?:\?[^\s#]*)?(?:#[^\s]*)?")
_SECRET_ASSIGN = re.compile(
    r"(?i)\b(?:authorization|cookie|set-cookie|password|passwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key|ssid|bssid)\s*[:=]\s*[^\s,;]+"
)
_ENV_ASSIGN = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\s*=\s*[^\s,;]+")
_TRACE = re.compile(r"(?is)Traceback \(most recent call last\):.*")
_PREFIXED_TOKEN = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,})\b")
_HIGH_ENTROPY = re.compile(r"\b(?=[A-Za-z0-9_+/=-]{32,}\b)(?=[^\s]*[A-Za-z])(?=[^\s]*\d)[A-Za-z0-9_+/=-]+\b")
_PRIVATE_KEY = re.compile(r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
_OAUTH_PARAM = re.compile(r"(?i)\b(?:code|state|code_verifier|refresh_token|access_token)\s*[:=]\s*[^\s,;&]+")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def rfc3339(value: Optional[Union[dt.datetime, float, int, str]] = None) -> str:
    if value is None:
        value = utc_now()
    if isinstance(value, (float, int)):
        value = dt.datetime.fromtimestamp(value, dt.timezone.utc)
    if isinstance(value, str):
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        value = parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sanitize_text(value: object, limit: int = 320) -> str:
    """Defense-in-depth sanitizer for any source-derived text."""
    text = str(value).replace("\x00", " ").replace("\r", " ").replace("\n", " ")
    text = _TRACE.sub("[REDACTED_TRACE]", text)
    text = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _BEARER.sub("[REDACTED_AUTH]", text)
    text = _JWT.sub("[REDACTED_TOKEN]", text)
    text = _AWS_KEY.sub("[REDACTED_AWS_KEY]", text)
    text = _AWS_IDS.sub("[REDACTED_AWS_ID]", text)
    text = _PREFIXED_TOKEN.sub("[REDACTED_TOKEN]", text)
    text = _HIGH_ENTROPY.sub("[REDACTED_SECRET_VALUE]", text)
    text = _MAC.sub("[REDACTED_MAC]", text)
    text = _IPV4.sub("[REDACTED_IP]", text)
    def redact_ipv6(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            return "[REDACTED_IP]" if ipaddress.ip_address(candidate).version == 6 else candidate
        except ValueError:
            return candidate
    text = _IPV6_CANDIDATE.sub(redact_ipv6, text)
    text = _HOME_PATH.sub("[REDACTED_HOME]", text)
    text = _URL_USERINFO.sub(r"\1[REDACTED_USERINFO]@", text)
    text = _QUERY.sub(r"\1?[REDACTED_QUERY]", text)
    text = _SECRET_ASSIGN.sub("[REDACTED_SECRET]", text)
    text = _OAUTH_PARAM.sub("[REDACTED_OAUTH]", text)
    text = _ENV_ASSIGN.sub("[REDACTED_ENV]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def sanitize_tree(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_tree(v) for v in value]
    if isinstance(value, dict):
        blocked = {"ip", "address", "username", "environment", "env", "args", "headers", "url"}
        return {
            str(k): sanitize_tree(v)
            for k, v in value.items()
            if str(k).lower() not in blocked
        }
    return value


@dataclass(frozen=True)
class CollectorConfig:
    export_dir: Path = Path("/var/lib/ha-host-diagnostics/export")
    state_dir: Path = Path("/var/lib/ha-host-diagnostics/state")
    interval_seconds: int = INTERVAL_SECONDS
    retention_days: int = RETENTION_DAYS
    export_gid: int = EXPORT_GID
    require_root: bool = True


class CommandRunner:
    """Executes only argv assembled from constants in this module."""

    _TIME = re.compile(r"20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
    _UNITS = {
        "docker.service",
        "wg-quick@wg0.service",
        "home-assistant-watchdog.service",
    }
    _PROPERTIES = "--property=ActiveState,SubState,ActiveEnterTimestampMonotonic,NRestarts,ExecMainStatus"

    @classmethod
    def _allowed(cls, argv: Sequence[str]) -> bool:
        args = tuple(argv)
        names = set(CONTAINERS.values())
        if len(args) == 3 and args[:2] == ("docker", "inspect") and args[2] in names:
            return True
        if len(args) == 6 and args[:5] == ("docker", "stats", "--no-stream", "--format", "{{json .}}") and args[5] in names:
            return True
        if (
            len(args) == 12
            and args[:3] == ("docker", "events", "--since")
            and cls._TIME.fullmatch(args[3])
            and args[4] == "--until"
            and cls._TIME.fullmatch(args[5])
            and args[6:10] == ("--filter", "type=container", "--filter", args[9])
            and args[9].startswith("container=")
            and args[9][10:] in names
            and args[10:] == ("--format", "{{json .}}")
        ):
            return True
        if (
            len(args) == 8
            and args[:3] == ("docker", "logs", "--since")
            and cls._TIME.fullmatch(args[3])
            and args[4] == "--until"
            and cls._TIME.fullmatch(args[5])
            and args[6] == "--timestamps"
            and args[7] in {CONTAINERS["cloudflare_tunnel"], CONTAINERS["reverse_proxy"]}
        ):
            return True
        if len(args) == 5 and args[:2] == ("systemctl", "show") and args[2] in cls._UNITS and args[3:] == (cls._PROPERTIES, "--no-pager"):
            return True
        journal_tail = ("--output=json", "--no-pager")
        if len(args) == 8 and args[:2] == ("journalctl", "--kernel") and args[2] == "--since" and cls._TIME.fullmatch(args[3]) and args[4] == "--until" and cls._TIME.fullmatch(args[5]) and args[6:] == journal_tail:
            return True
        if len(args) == 9 and args[:2] == ("journalctl", "--unit") and args[2] in cls._UNITS and args[3] == "--since" and cls._TIME.fullmatch(args[4]) and args[5] == "--until" and cls._TIME.fullmatch(args[6]) and args[7:] == journal_tail:
            return True
        if len(args) == 9 and args[:3] == ("journalctl", "--identifier", "systemd-shutdown") and args[3] == "--since" and cls._TIME.fullmatch(args[4]) and args[5] == "--until" and cls._TIME.fullmatch(args[6]) and args[7:] == journal_tail:
            return True
        return False

    def run(self, argv: Sequence[str], timeout: float = 12.0) -> tuple[int, str]:
        if not self._allowed(argv):
            raise ValueError("command is not in the fixed diagnostics allowlist")
        try:
            proc = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            assert proc.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            data = bytearray()
            deadline = time.monotonic() + timeout
            while len(data) <= MAX_COMMAND_BYTES and time.monotonic() < deadline:
                ready = selector.select(min(0.25, max(0.0, deadline - time.monotonic())))
                if ready:
                    chunk = os.read(proc.stdout.fileno(), min(65536, MAX_COMMAND_BYTES + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                elif proc.poll() is not None:
                    break
            if proc.poll() is None:
                proc.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=1)
            if proc.poll() is None:
                proc.kill()
            return int(proc.wait()), bytes(data[:MAX_COMMAND_BYTES]).decode("utf-8", "replace")
        except (FileNotFoundError, OSError):
            return 127, ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _json_load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


class Collector:
    def __init__(self, config: Optional[CollectorConfig] = None, runner: Optional[CommandRunner] = None):
        self.config = config or CollectorConfig()
        self.runner = runner or CommandRunner()
        self._stop = False
        self._lock_handle: Any = None
        self._ensure_dirs()
        self.state_path = self.config.state_dir / "state.json"
        self.secret_path = self.config.state_dir / "identity.key"
        self.state: dict[str, Any] = _json_load(self.state_path, {})
        self.identity_secret = self._load_identity_secret()

    def _ensure_dirs(self) -> None:
        if self.config.require_root and hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PermissionError("collector must run as root")
        for path, mode in ((self.config.state_dir, 0o700), (self.config.export_dir, 0o750)):
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, mode)
        if self.config.require_root:
            os.chown(self.config.state_dir, 0, 0)
            os.chown(self.config.export_dir, 0, self.config.export_gid)
            state_stat, export_stat = self.config.state_dir.stat(), self.config.export_dir.stat()
            if (state_stat.st_uid, state_stat.st_gid, state_stat.st_mode & 0o777) != (0, 0, 0o700):
                raise PermissionError("state directory permissions are not root:root 0700")
            if (export_stat.st_uid, export_stat.st_gid, export_stat.st_mode & 0o777) != (0, self.config.export_gid, 0o750):
                raise PermissionError("export directory permissions are not root:10001 0750")

    def _load_identity_secret(self) -> bytes:
        try:
            raw = self.secret_path.read_bytes()
            if len(raw) == 32:
                return raw
        except OSError:
            pass
        raw = secrets.token_bytes(32)
        self._atomic_bytes(self.secret_path, raw, 0o600, gid=0)
        return raw

    def _identity(self, raw: object) -> Optional[str]:
        if not raw:
            return None
        return "run_" + hashlib.sha256(self.identity_secret + str(raw).encode()).hexdigest()[:20]

    def _atomic_bytes(self, path: Path, payload: bytes, mode: int, gid: Optional[int] = None) -> None:
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, mode)
            if gid is not None and self.config.require_root:
                os.chown(tmp_name, 0, gid)
            os.replace(tmp_name, path)
            with contextlib.suppress(OSError):
                dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)

    def _atomic_json(self, path: Path, value: Any, *, public: bool) -> None:
        payload = json.dumps(sanitize_tree(value), sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if path.name == "current.json" and len(payload) > MAX_CURRENT_BYTES:
            raise ValueError("current snapshot exceeds hard cap")
        if path == self.state_path and len(payload) > MAX_STATE_BYTES:
            raise ValueError("collector state exceeds hard cap")
        self._atomic_bytes(path, payload, 0o640 if public else 0o600, self.config.export_gid if public else 0)

    def _save_state(self) -> None:
        self._atomic_json(self.state_path, self.state, public=False)

    def _append(self, kind: str, value: dict[str, Any], when: Optional[str] = None) -> bool:
        day = (when or value.get("timestamp") or rfc3339())[:10]
        path = self.config.export_dir / f"{kind}-{day}.jsonl"
        payload = json.dumps(sanitize_tree(value), sort_keys=True, separators=(",", ":")).encode() + b"\n"
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if size + len(payload) > MAX_LEDGER_FILE_BYTES:
            self.state.setdefault("truncation", {})[f"{kind}-{day}"] = True
            return False
        aggregate = 0
        for existing in self.config.export_dir.iterdir():
            if existing.is_file() and (existing.suffix in {".json", ".jsonl"}):
                with contextlib.suppress(OSError):
                    aggregate += existing.stat().st_size
        if aggregate + len(payload) > MAX_EXPORT_BYTES:
            self.state.setdefault("truncation", {})["aggregate"] = True
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags, 0o640)
        try:
            os.write(fd, payload)
            os.fsync(fd)
            os.fchmod(fd, 0o640)
            if self.config.require_root:
                os.fchown(fd, 0, self.config.export_gid)
        finally:
            os.close(fd)
        return True

    def event(
        self,
        timestamp: str,
        component: str,
        severity: str,
        event_type: str,
        summary: str,
        source: str,
        *,
        cause: str = "unknown",
        complete: bool = True,
        inferred: bool = False,
        exit_code: Optional[int] = None,
        signal_name: Optional[str] = None,
        counter: Optional[int] = None,
        http_status: Optional[int] = None,
        run_identity: Optional[str] = None,
        run_started_at: Optional[str] = None,
        run_finished_at: Optional[str] = None,
        historical: bool = False,
    ) -> dict[str, Any]:
        if component not in COMPONENTS or severity not in SEVERITIES or cause not in CAUSES:
            raise ValueError("invalid fixed event enum")
        record = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": rfc3339(timestamp),
            "component": component,
            "severity": severity,
            "event_type": re.sub(r"[^a-z0-9_]+", "_", event_type.lower())[:64],
            "summary": sanitize_text(summary),
            "evidence_source": source,
            "cause": cause,
            "complete": bool(complete),
            "truncated": False,
            "inferred": bool(inferred),
            "historical": bool(historical),
        }
        optional = {
            "exit_code": exit_code,
            "signal": signal_name,
            "counter": counter,
            "http_status": http_status,
            "run_identity": run_identity,
            "run_started_at": run_started_at,
            "run_finished_at": run_finished_at,
        }
        record.update({k: v for k, v in optional.items() if v is not None})
        if not self._append("events", record, timestamp):
            record["truncated"] = True
        return record

    def acquire_lock(self) -> None:
        lock_path = self.config.state_dir / "collector.lock"
        self._lock_handle = lock_path.open("a+b")
        if fcntl is not None:
            try:
                fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise RuntimeError("collector already running") from exc
                raise

    def _boot(self) -> dict[str, Any]:
        boot_id = ""
        with contextlib.suppress(OSError):
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        uptime = None
        with contextlib.suppress(OSError, ValueError):
            uptime = float(Path("/proc/uptime").read_text().split()[0])
        boot_time = rfc3339(time.time() - uptime) if uptime is not None else None
        return {"identity": self._identity(boot_id), "uptime_seconds": uptime, "boot_time": boot_time}

    def _host_metrics(self) -> tuple[dict[str, Any], list[str]]:
        unavailable: list[str] = []
        result: dict[str, Any] = {"cpu_percent": None, "memory": {}, "swap": {}, "load": {}, "disk": {}}
        try:
            fields: dict[str, int] = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                name, raw = line.split(":", 1)
                fields[name] = int(raw.strip().split()[0]) * 1024
            total, available = fields.get("MemTotal", 0), fields.get("MemAvailable", 0)
            swap_total, swap_free = fields.get("SwapTotal", 0), fields.get("SwapFree", 0)
            result["memory"] = {
                "total_bytes": total,
                "available_bytes": available,
                "used_percent": round((total - available) * 100 / total, 2) if total else None,
            }
            result["swap"] = {
                "total_bytes": swap_total,
                "used_bytes": swap_total - swap_free,
                "used_percent": round((swap_total - swap_free) * 100 / swap_total, 2) if swap_total else 0.0,
            }
        except (OSError, ValueError):
            unavailable.append("proc_meminfo")
        try:
            parts = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
            values = [int(v) for v in parts]
            idle, total = values[3] + (values[4] if len(values) > 4 else 0), sum(values)
            old = self.state.get("cpu_ticks")
            if isinstance(old, list) and total > old[1]:
                result["cpu_percent"] = round(100 * (1 - (idle - old[0]) / (total - old[1])), 2)
            self.state["cpu_ticks"] = [idle, total]
        except (OSError, ValueError, IndexError, ZeroDivisionError):
            unavailable.append("proc_stat")
        try:
            one, five, fifteen = os.getloadavg()
            result["load"] = {"one": one, "five": five, "fifteen": fifteen}
        except OSError:
            unavailable.append("loadavg")
        for label, path in (("root", Path("/")), ("docker", Path("/var/lib/docker"))):
            try:
                stat = os.statvfs(path)
                result["disk"][label] = {
                    "total_bytes": stat.f_blocks * stat.f_frsize,
                    "available_bytes": stat.f_bavail * stat.f_frsize,
                    "used_percent": round(100 * (stat.f_blocks - stat.f_bfree) / stat.f_blocks, 2) if stat.f_blocks else None,
                    "inode_total": stat.f_files,
                    "inode_available": stat.f_favail,
                    "inode_used_percent": round(100 * (stat.f_files - stat.f_ffree) / stat.f_files, 2) if stat.f_files else None,
                }
            except OSError:
                unavailable.append(f"statvfs_{label}")
        return result, unavailable

    def _inspect(self, name: str) -> tuple[Optional[dict[str, Any]], bool]:
        rc, out = self.runner.run(("docker", "inspect", name))
        if rc != 0:
            return None, False
        try:
            value = json.loads(out)[0]
            return value, True
        except (ValueError, IndexError, TypeError):
            return None, False

    def _stats(self, name: str) -> Optional[dict[str, Any]]:
        rc, out = self.runner.run(("docker", "stats", "--no-stream", "--format", "{{json .}}", name))
        if rc != 0:
            return None
        try:
            raw = json.loads(out.splitlines()[0])
        except (ValueError, IndexError):
            return None
        def pct(key: str) -> Optional[float]:
            match = re.match(r"([0-9.]+)%", str(raw.get(key, "")))
            return float(match.group(1)) if match else None
        def byte_size(value: str) -> Optional[int]:
            match = re.fullmatch(r"\s*([0-9.]+)\s*([KMGT]?i?B)\s*", value, re.I)
            if not match:
                return None
            units = {"B": 1, "KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4,
                     "KIB": 1024, "MIB": 1024**2, "GIB": 1024**3, "TIB": 1024**4}
            return int(float(match.group(1)) * units[match.group(2).upper()])
        usage, separator, limit = str(raw.get("MemUsage", "")).partition("/")
        return {
            "cpu_percent": pct("CPUPerc"),
            "memory_percent": pct("MemPerc"),
            "memory_current_bytes": byte_size(usage),
            "memory_limit_bytes": byte_size(limit) if separator else None,
        }

    def _cgroup(self, inspect: Mapping[str, Any]) -> tuple[dict[str, int], bool]:
        raw_id = str(inspect.get("Id", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", raw_id):
            return {}, False
        paths = (
            Path(f"/sys/fs/cgroup/system.slice/docker-{raw_id}.scope/memory.events"),
            Path(f"/sys/fs/cgroup/docker/{raw_id}/memory.events"),
        )
        for path in paths:
            try:
                values = {}
                for line in path.read_text().splitlines():
                    key, raw = line.split()
                    if key in {"low", "high", "max", "oom", "oom_kill", "oom_group_kill"}:
                        values[key] = int(raw)
                return values, True
            except (OSError, ValueError):
                continue
        return {}, False

    @staticmethod
    def _exit_signal(exit_code: Optional[int]) -> Optional[str]:
        if exit_code is not None and 128 < exit_code <= 192:
            number = exit_code - 128
            portable = {9: "SIGKILL", 15: "SIGTERM", 2: "SIGINT", 6: "SIGABRT", 11: "SIGSEGV"}
            if number in portable:
                return portable[number]
            with contextlib.suppress(ValueError):
                return signal.Signals(number).name
            return f"SIG{number}"
        return None

    def _container_state(self, component: str, name: str, now: str) -> tuple[dict[str, Any], list[str]]:
        inspect, ok = self._inspect(name)
        if not ok or inspect is None:
            return {"available": False, "component": component}, [f"docker_inspect_{component}"]
        raw_state = inspect.get("State") or {}
        host = inspect.get("HostConfig") or {}
        raw_id = inspect.get("Id")
        run_identity = self._identity(raw_id)
        cgroup, cgroup_ok = self._cgroup(inspect)
        stats = self._stats(name)
        exit_code = raw_state.get("ExitCode") if isinstance(raw_state.get("ExitCode"), int) else None
        state = {
            "available": True,
            "component": component,
            "run_identity": run_identity,
            "running": bool(raw_state.get("Running")),
            "status": str(raw_state.get("Status", "unknown"))[:32],
            "health": str((raw_state.get("Health") or {}).get("Status", "not_configured"))[:32],
            "started_at": raw_state.get("StartedAt") or None,
            "finished_at": raw_state.get("FinishedAt") or None,
            "exit_code": exit_code,
            "signal": self._exit_signal(exit_code),
            "error": sanitize_text(raw_state.get("Error") or "") or None,
            "oom_killed_current_run": bool(raw_state.get("OOMKilled")),
            "restart_count": int(inspect.get("RestartCount") or 0),
            "restart_policy": str((host.get("RestartPolicy") or {}).get("Name") or "none")[:32],
            "limits": {
                "memory_bytes": int(host.get("Memory") or 0),
                "memory_swap_bytes": int(host.get("MemorySwap") or 0),
                "nano_cpus": int(host.get("NanoCpus") or 0),
                "pids_limit": host.get("PidsLimit"),
            },
            "resource_usage": stats,
            "cgroup_memory_events": cgroup,
        }
        previous = (self.state.setdefault("containers", {})).get(component)
        if previous and (previous.get("run_identity") != run_identity or previous.get("running") != state["running"]):
            stopped_now = bool(previous.get("running")) and not state["running"] and previous.get("run_identity") == run_identity
            evidence = state if stopped_now else previous
            evidenced_exit = evidence.get("exit_code")
            oom_direct = bool(evidence.get("oom_killed_current_run")) or int(evidence.get("cgroup_memory_events", {}).get("oom_kill", 0)) > 0
            if evidenced_exit == 137 and oom_direct:
                cause = "oom_kill"
            elif isinstance(evidenced_exit, int) and 0 < evidenced_exit < 128:
                cause = "process_crash"
            else:
                cause = "unknown"
            severity = "error" if evidenced_exit not in (None, 0, 143) else "info"
            self.event(
                now,
                component,
                severity,
                "container_run_transition",
                f"{component} container run changed; bounded lifecycle evidence preserved",
                "docker_inspect_delta",
                cause=cause,
                complete=True,
                exit_code=evidenced_exit,
                signal_name=self._exit_signal(evidenced_exit),
                run_identity=evidence.get("run_identity"),
                run_started_at=evidence.get("started_at"),
                run_finished_at=evidence.get("finished_at"),
            )
        if previous and previous.get("run_identity") == run_identity:
            old_cgroup = previous.get("cgroup_memory_events") or {}
            for counter_name in ("high", "max", "oom", "oom_kill", "oom_group_kill"):
                delta = int(cgroup.get(counter_name, 0)) - int(old_cgroup.get(counter_name, 0))
                if delta > 0:
                    direct_oom = counter_name in {"oom_kill", "oom_group_kill"}
                    self.event(
                        now, "cgroup", "critical" if direct_oom else "warning",
                        f"memory_{counter_name}", f"{component} cgroup memory counter increased",
                        "cgroup_memory_events_delta", cause="oom_kill" if direct_oom else "unknown",
                        counter=delta, run_identity=run_identity,
                    )
        self.state["containers"][component] = state
        unavailable = []
        if stats is None:
            unavailable.append(f"docker_stats_{component}")
        if not cgroup_ok:
            unavailable.append(f"cgroup_{component}")
        return state, unavailable

    def _probe_http(self, url: str, *, method: str = "GET", body: Optional[bytes] = None) -> dict[str, Any]:
        started = time.monotonic()
        request = urllib.request.Request(
            url,
            method=method,
            data=body,
            headers={"User-Agent": "ha-host-diagnostics/1", "Content-Type": "application/json"},
        )
        opener = urllib.request.build_opener(NoRedirect)
        try:
            response = opener.open(request, timeout=5)
            status = response.status
            response.read(512)
            reachable = True
        except urllib.error.HTTPError as exc:
            status = exc.code
            reachable = True
            with contextlib.suppress(Exception):
                exc.read(512)
        except (urllib.error.URLError, TimeoutError, OSError):
            status, reachable = None, False
        return {"reachable": reachable, "status": status, "latency_ms": round((time.monotonic() - started) * 1000, 1)}

    def _probe_dns(self, hostname: str) -> bool:
        try:
            socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
            return True
        except OSError:
            return False

    def _probe_tls(self, hostname: str) -> dict[str, Any]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=hostname) as wrapped:
                    cert = wrapped.getpeercert()
            expiry = cert.get("notAfter")
            expires_at = rfc3339(ssl.cert_time_to_seconds(expiry)) if expiry else None
            days = round((ssl.cert_time_to_seconds(expiry) - time.time()) / 86400, 1) if expiry else None
            return {"valid": True, "expires_at": expires_at, "days_remaining": days}
        except (OSError, ssl.SSLError, ValueError):
            return {"valid": False, "expires_at": None, "days_remaining": None}

    def _probe_websocket(self, host: str, *, tls: bool) -> dict[str, Any]:
        started = time.monotonic()
        try:
            conn: http.client.HTTPConnection
            conn = http.client.HTTPSConnection(host, 443, timeout=5) if tls else http.client.HTTPConnection(host, 8123, timeout=5)
            conn.request(
                "GET",
                "/api/websocket",
                headers={
                    "Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": "aGFfZGlhZ25vc3RpY3NfMQ==",
                    "Origin": f"https://{host}" if tls else "http://localhost",
                },
            )
            response = conn.getresponse()
            status = response.status
            response.read(256)
            conn.close()
            return {"reachable": True, "status": status, "upgrade_accepted": status == 101, "latency_ms": round((time.monotonic() - started) * 1000, 1)}
        except (OSError, http.client.HTTPException, ssl.SSLError):
            return {"reachable": False, "status": None, "upgrade_accepted": False, "latency_ms": round((time.monotonic() - started) * 1000, 1)}

    def _probes(self) -> dict[str, Any]:
        initialize = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
        routes = {
            "local_home_assistant": {
                "scope": "local_origin",
                "http": self._probe_http(f"{LOCAL_HA_URL}/"),
                "websocket": self._probe_websocket(LOCAL_HA_HOST, tls=False),
            },
            "public_frontend": {
                "scope": "ha_frontend_route",
                "dns_resolved": self._probe_dns(PUBLIC_FRONTEND_HOST),
                "tls": self._probe_tls(PUBLIC_FRONTEND_HOST),
                "bootstrap": self._probe_http(f"{PUBLIC_FRONTEND_URL}/"),
                "websocket": self._probe_websocket(PUBLIC_FRONTEND_HOST, tls=True),
            },
            "local_mcp": {
                "scope": "local_origin",
                "health": self._probe_http(f"{LOCAL_MCP_URL}/healthz"),
                "protocol_auth_gate": self._probe_http(f"{LOCAL_MCP_URL}/mcp", method="POST", body=initialize),
            },
            "public_mcp": {
                "scope": "mcp_public_route",
                "dns_resolved": self._probe_dns(PUBLIC_MCP_HOST),
                "tls": self._probe_tls(PUBLIC_MCP_HOST),
                "health": self._probe_http(f"{PUBLIC_MCP_URL}/healthz"),
                "protocol_auth_gate": self._probe_http(f"{PUBLIC_MCP_URL}/mcp", method="POST", body=initialize),
            },
        }
        return routes

    def _systemd_state(self) -> tuple[dict[str, Any], list[str]]:
        result: dict[str, Any] = {}
        unavailable: list[str] = []
        units = {
            "docker": "docker.service",
            "wireguard": "wg-quick@wg0.service",
            "watchdog": "home-assistant-watchdog.service",
        }
        properties = "ActiveState,SubState,ActiveEnterTimestampMonotonic,NRestarts,ExecMainStatus"
        try:
            uptime = float(Path("/proc/uptime").read_text().split()[0])
            boot_epoch = time.time() - uptime
        except (OSError, ValueError, IndexError):
            boot_epoch = None
        for component, unit in units.items():
            rc, out = self.runner.run(("systemctl", "show", unit, f"--property={properties}", "--no-pager"))
            if rc != 0:
                result[component] = {"available": False}
                unavailable.append(f"systemd_{component}")
                continue
            raw: dict[str, str] = {}
            for line in out.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    raw[key] = value
            active_since = None
            try:
                monotonic_usec = int(raw.get("ActiveEnterTimestampMonotonic") or 0)
                if boot_epoch is not None and monotonic_usec > 0:
                    active_since = rfc3339(boot_epoch + monotonic_usec / 1_000_000)
            except ValueError:
                pass
            result[component] = {
                "available": True,
                "active_state": raw.get("ActiveState") or "unknown",
                "sub_state": raw.get("SubState") or "unknown",
                "active_since": active_since,
                "restart_count": int(raw.get("NRestarts") or 0),
                "main_exit_status": int(raw.get("ExecMainStatus") or 0),
            }
        return result, unavailable

    def _cloudflare_metrics(self) -> tuple[dict[str, Any], list[str]]:
        probe = self._probe_http("http://127.0.0.1:49312/metrics")
        if not probe.get("reachable") or probe.get("status") != 200:
            return {"available": False, "connected_replicas": None}, ["cloudflared_metrics"]
        request = urllib.request.Request("http://127.0.0.1:49312/metrics", headers={"User-Agent": "ha-host-diagnostics/1"})
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                body = response.read(128 * 1024).decode("ascii", "replace")
        except (OSError, urllib.error.URLError, TimeoutError):
            return {"available": False, "connected_replicas": None}, ["cloudflared_metrics"]
        values = []
        for line in body.splitlines():
            if re.fullmatch(r"cloudflared_tunnel_ha_connections(?:\{[^}]{0,512}\})?\s+[0-9.]+", line):
                with contextlib.suppress(ValueError):
                    values.append(float(line.rsplit(None, 1)[1]))
        if not values:
            return {"available": False, "connected_replicas": None}, ["cloudflared_metrics_value"]
        return {"available": True, "connected_replicas": int(sum(values)), "latency_ms": probe.get("latency_ms")}, []

    @staticmethod
    def _route_ok(name: str, probe: Mapping[str, Any]) -> bool:
        if name.endswith("home_assistant"):
            return bool(
                (probe.get("http") or {}).get("status") == 200
                and (probe.get("websocket") or {}).get("status") == 101
            )
        if name == "public_frontend":
            return bool(
                probe.get("dns_resolved")
                and (probe.get("tls") or {}).get("valid")
                and (probe.get("bootstrap") or {}).get("status") == 200
                and (probe.get("websocket") or {}).get("status") == 101
            )
        if name == "local_mcp":
            return bool(
                (probe.get("health") or {}).get("status") == 200
                and (probe.get("protocol_auth_gate") or {}).get("status") in {401, 403}
            )
        return bool(
            probe.get("dns_resolved")
            and (probe.get("tls") or {}).get("valid")
            and (probe.get("health") or {}).get("status") == 200
            and (probe.get("protocol_auth_gate") or {}).get("status") in {401, 403}
        )

    def _record_probe_transitions(self, probes: Mapping[str, Any], now: str) -> None:
        old = self.state.setdefault("probe_states", {})
        for name, probe in probes.items():
            ok = self._route_ok(name, probe)
            if name in old and old[name] != ok:
                self.event(
                    now,
                    "endpoint_probe",
                    "info" if ok else "error",
                    "endpoint_recovered" if ok else "endpoint_failed",
                    f"fixed route {name} {'recovered' if ok else 'failed'}",
                    "fixed_endpoint_probe",
                    cause="unknown" if ok else "endpoint_failure",
                    complete=True,
                )
            old[name] = ok

    def _detect_boot_change(self, boot: Mapping[str, Any], now: str) -> None:
        old = self.state.get("boot_identity")
        if old and old != boot.get("identity"):
            self.event(now, "kernel", "warning", "host_boot", "host boot identity changed", "proc_boot_id", cause="host_reboot")
        self.state["boot_identity"] = boot.get("identity")

    def _source_lines(self, argv: Sequence[str]) -> tuple[list[str], bool, bool]:
        rc, out = self.runner.run(argv, timeout=SOURCE_COMMAND_TIMEOUT_SECONDS)
        lines = out.splitlines()
        truncated = len(lines) > MAX_BACKFILL_LINES or len(out.encode("utf-8")) >= MAX_COMMAND_BYTES
        return lines[-MAX_BACKFILL_LINES:], rc == 0, truncated

    @staticmethod
    def _docker_time(raw: Mapping[str, Any]) -> Optional[str]:
        for key in ("timeNano", "TimeNano"):
            if isinstance(raw.get(key), int):
                return rfc3339(raw[key] / 1_000_000_000)
        for key in ("time", "Time"):
            if isinstance(raw.get(key), (int, float)):
                return rfc3339(raw[key])
        return None

    def _backfill_docker(self, since: str, until: str) -> dict[str, Any]:
        count, available, any_truncated = 0, True, False
        seen: set[str] = set(self.state.get("backfill_event_keys", []))
        for component, name in CONTAINERS.items():
            lines, ok, truncated = self._source_lines((
                "docker", "events", "--since", since, "--until", until,
                "--filter", "type=container", "--filter", f"container={name}", "--format", "{{json .}}",
            ))
            available &= ok
            any_truncated |= truncated
            for line in lines:
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                action = str(raw.get("Action") or raw.get("status") or "").lower()
                if action not in {"start", "stop", "die", "restart", "kill", "oom", "health_status: unhealthy", "health_status: healthy"}:
                    continue
                timestamp = self._docker_time(raw)
                if not timestamp:
                    continue
                attrs = ((raw.get("Actor") or {}).get("Attributes") or {})
                raw_identity = (raw.get("Actor") or {}).get("ID") or raw.get("id") or raw.get("ID")
                run_identity = self._identity(raw_identity)
                run_starts = self.state.setdefault("historical_run_starts", {})
                exit_raw = attrs.get("exitCode") or attrs.get("exitcode")
                try:
                    exit_code = int(exit_raw) if exit_raw is not None else None
                except (TypeError, ValueError):
                    exit_code = None
                key = hashlib.sha256(f"{timestamp}|{component}|{action}|{exit_code}".encode()).hexdigest()[:24]
                if key in seen:
                    continue
                if action == "start" and run_identity:
                    run_starts[run_identity] = timestamp
                run_started_at = run_starts.get(run_identity) if run_identity else None
                run_finished_at = timestamp if action in {"die", "stop", "kill", "oom"} else None
                if action == "oom":
                    cause = "oom_kill"
                elif action == "die" and isinstance(exit_code, int) and 0 < exit_code < 128:
                    cause = "process_crash"
                else:
                    cause = "unknown"
                severity = "error" if action in {"die", "oom", "health_status: unhealthy"} else "info"
                self.event(
                    timestamp, component, severity, f"container_{action.replace(': ', '_')}",
                    f"historical Docker lifecycle event for {component}: {action}", "docker_events",
                    cause=cause, complete=ok and not truncated, inferred=False, exit_code=exit_code,
                    signal_name=self._exit_signal(exit_code), historical=True, run_identity=run_identity,
                    run_started_at=run_started_at, run_finished_at=run_finished_at,
                )
                if run_finished_at and run_identity:
                    run_starts.pop(run_identity, None)
                seen.add(key)
                count += 1
        self.state["backfill_event_keys"] = sorted(seen)[-5000:]
        starts = self.state.get("historical_run_starts", {})
        self.state["historical_run_starts"] = dict(
            sorted(
                ((key, value) for key, value in starts.items() if isinstance(value, str) and value >= since),
                key=lambda item: item[1],
                reverse=True,
            )[:64]
        )
        return {"available": available, "truncated": any_truncated, "events": count}

    def _backfill_journal(self, since: str, until: str) -> dict[str, Any]:
        count = 0
        sources: dict[str, Any] = {}
        seen = set(self.state.get("backfill_event_keys", []))
        specs = {
            "kernel": ("journalctl", "--kernel", "--since", since, "--until", until, "--output=json", "--no-pager"),
            "docker": ("journalctl", "--unit", "docker.service", "--since", since, "--until", until, "--output=json", "--no-pager"),
            "systemd": ("journalctl", "--identifier", "systemd-shutdown", "--since", since, "--until", until, "--output=json", "--no-pager"),
            "watchdog": ("journalctl", "--unit", "home-assistant-watchdog.service", "--since", since, "--until", until, "--output=json", "--no-pager"),
        }
        for source, argv in specs.items():
            lines, ok, truncated = self._source_lines(argv)
            sources[source] = {"available": ok, "truncated": truncated}
            for line in lines:
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                message = str(raw.get("MESSAGE") or "")
                lower = message.lower()
                component, event_type, summary, cause, severity = source, None, None, "unknown", "warning"
                if source == "kernel" and ("out of memory" in lower or "oom-kill" in lower or "killed process" in lower):
                    event_type, summary, cause, severity = "kernel_oom", "kernel recorded direct out-of-memory evidence", "oom_kill", "critical"
                elif source == "kernel" and any(p in lower for p in ("linux version", "command line:")):
                    event_type, summary, cause, severity = "host_boot_evidence", "kernel journal contains host boot evidence", "host_reboot", "info"
                elif source == "docker" and ("starting up" in lower or "daemon has completed initialization" in lower):
                    event_type, summary, cause, severity = "docker_start", "Docker service startup recorded", "unknown", "info"
                elif source == "docker" and any(p in lower for p in ("daemon shutdown", "stopping event stream")):
                    event_type, summary = "docker_stop", "Docker service shutdown recorded"
                elif source == "systemd" and any(p in lower for p in ("syncing filesystems", "sending sigterm", "powering off", "rebooting")):
                    event_type, summary, severity = "host_shutdown", "systemd shutdown evidence recorded", "info"
                elif source == "watchdog" and "failed three checks; restarting" in lower:
                    component, event_type, summary, cause = "systemd", "watchdog_restart_action", "fixed resilience watchdog restart action recorded", "watchdog_restart"
                elif source == "watchdog" and any(p in lower for p in ("failed check", "check failure", "check failed")):
                    component, event_type, summary = "systemd", "watchdog_check_failure", "fixed resilience watchdog check failure recorded"
                if not event_type:
                    continue
                raw_ts = raw.get("__REALTIME_TIMESTAMP")
                try:
                    timestamp = rfc3339(int(raw_ts) / 1_000_000)
                except (TypeError, ValueError):
                    continue
                key = hashlib.sha256(f"{timestamp}|{component}|{event_type}".encode()).hexdigest()[:24]
                if key in seen:
                    continue
                self.event(timestamp, component, severity, event_type, summary or event_type, "systemd_journal", cause=cause, complete=ok and not truncated, historical=True)
                seen.add(key)
                count += 1
        self.state["backfill_event_keys"] = sorted(seen)[-5000:]
        sources["events"] = count
        return sources

    def _backfill_cloudflared(self, since: str, until: str) -> dict[str, Any]:
        lines, ok, truncated = self._source_lines(("docker", "logs", "--since", since, "--until", until, "--timestamps", CONTAINERS["cloudflare_tunnel"]))
        seen = set(self.state.get("backfill_event_keys", []))
        count = 0
        for line in lines:
            lower = line.lower()
            event_type = None
            severity, cause = "warning", "tunnel_failure"
            if any(p in lower for p in ("connection terminated", "failed to serve tunnel", "unable to establish", "quic connection")) and any(p in lower for p in ("error", "failed", "terminated", "timeout")):
                event_type, summary = "tunnel_disconnected", "Cloudflare tunnel log recorded a connection failure"
            elif any(p in lower for p in ("registered tunnel connection", "connection registered")):
                event_type, summary, severity, cause = "tunnel_connected", "Cloudflare tunnel connection registered", "info", "unknown"
            if not event_type:
                continue
            match = re.search(r"\b(20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\b", line)
            if not match:
                continue
            timestamp = rfc3339(match.group(1))
            key = hashlib.sha256(f"{timestamp}|cloudflare|{event_type}".encode()).hexdigest()[:24]
            if key in seen:
                continue
            self.event(timestamp, "cloudflare_tunnel", severity, event_type, summary, "cloudflared_classification", cause=cause, complete=ok and not truncated, historical=True)
            seen.add(key)
            count += 1
        self.state["backfill_event_keys"] = sorted(seen)[-5000:]
        return {"available": ok, "truncated": truncated, "events": count}

    def _backfill_reverse_proxy(self, since: str, until: str) -> dict[str, Any]:
        lines, ok, truncated = self._source_lines((
            "docker", "logs", "--since", since, "--until", until,
            "--timestamps", CONTAINERS["reverse_proxy"],
        ))
        seen = set(self.state.get("backfill_event_keys", []))
        count = 0
        for line in lines:
            lower = line.lower()
            if any(p in lower for p in ("connection refused", "upstream reset", "upstream timed out", "dial tcp")):
                event_type, summary, severity, cause = "reverse_proxy_upstream_failure", "reverse proxy recorded a fixed-origin upstream failure", "error", "endpoint_failure"
            elif any(p in lower for p in ("shutting down", "stopping server", "graceful shutdown")):
                event_type, summary, severity, cause = "reverse_proxy_stop", "reverse proxy shutdown recorded", "info", "unknown"
            else:
                continue
            match = re.search(r"\b(20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\b", line)
            if not match:
                continue
            timestamp = rfc3339(match.group(1))
            key = hashlib.sha256(f"{timestamp}|reverse_proxy|{event_type}".encode()).hexdigest()[:24]
            if key in seen:
                continue
            self.event(timestamp, "reverse_proxy", severity, event_type, summary, "reverse_proxy_classification", cause=cause, complete=ok and not truncated, historical=True)
            seen.add(key)
            count += 1
        self.state["backfill_event_keys"] = sorted(seen)[-5000:]
        return {"available": ok, "truncated": truncated, "events": count}

    def backfill_once(self, now: str) -> dict[str, Any]:
        prior = self.state.get("historical_backfill")
        if isinstance(prior, dict) and prior.get("completed"):
            return prior
        until_dt = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
        since = rfc3339(until_dt - dt.timedelta(days=MAX_HISTORY_DAYS))
        result = {
            "attempted_at": now,
            "window_start": since,
            "window_end": now,
            "bounded_days": MAX_HISTORY_DAYS,
            "docker_events": self._backfill_docker(since, now),
            "journald": self._backfill_journal(since, now),
            "cloudflared_logs": self._backfill_cloudflared(since, now),
            "reverse_proxy_logs": self._backfill_reverse_proxy(since, now),
            "completed": True,
        }
        journal_sources = ("kernel", "docker", "systemd", "watchdog")
        result["complete"] = bool(
            result["docker_events"].get("available") and not result["docker_events"].get("truncated")
            and all(result["journald"].get(source, {}).get("available") and not result["journald"].get(source, {}).get("truncated") for source in journal_sources)
            and result["cloudflared_logs"].get("available") and not result["cloudflared_logs"].get("truncated")
            and result["reverse_proxy_logs"].get("available") and not result["reverse_proxy_logs"].get("truncated")
        )
        self.state["historical_backfill"] = result
        return result

    def collect_incremental(self, now: str) -> dict[str, Any]:
        now_dt = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
        prior = self.state.get("source_cursor")
        try:
            prior_dt = dt.datetime.fromisoformat(str(prior).replace("Z", "+00:00"))
        except ValueError:
            prior_dt = now_dt - dt.timedelta(minutes=2)
        floor = now_dt - dt.timedelta(days=MAX_HISTORY_DAYS)
        since_dt = max(floor, prior_dt - dt.timedelta(minutes=2))
        since = rfc3339(since_dt)
        result = {
            "window_start": since,
            "window_end": now,
            "docker_events": self._backfill_docker(since, now),
            "journald": self._backfill_journal(since, now),
            "cloudflared_logs": self._backfill_cloudflared(since, now),
            "reverse_proxy_logs": self._backfill_reverse_proxy(since, now),
        }
        self.state["source_cursor"] = now
        return result

    def _retention(self, now: str) -> dict[str, Any]:
        cutoff = dt.datetime.fromisoformat(now.replace("Z", "+00:00")).date() - dt.timedelta(days=self.config.retention_days - 1)
        files: list[tuple[Path, int]] = []
        removed = 0
        for path in self.config.export_dir.glob("*.jsonl"):
            match = re.fullmatch(r"(?:events|samples)-(\d{4}-\d{2}-\d{2})\.jsonl", path.name)
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if not match:
                continue
            try:
                day = dt.date.fromisoformat(match.group(1))
            except ValueError:
                continue
            if day < cutoff:
                with contextlib.suppress(OSError):
                    path.unlink()
                    removed += 1
            else:
                files.append((path, size))
        total = sum(size for _, size in files)
        truncation = self.state.get("truncation", {})
        self.state["truncation"] = {
            key: value
            for key, value in truncation.items()
            if key == "aggregate" or not re.search(r"\d{4}-\d{2}-\d{2}$", key)
            or dt.date.fromisoformat(key[-10:]) >= cutoff
        }
        return {"retention_days": self.config.retention_days, "hard_cap_bytes": MAX_EXPORT_BYTES, "current_bytes": total, "removed_files": removed}

    def once(self, *, defer_history: bool = False) -> dict[str, Any]:
        now = rfc3339()
        # Expire only out-of-window segments before any new append so an old
        # segment cannot spuriously consume the aggregate budget at UTC rollover.
        self._retention(now)
        prior_backfill = self.state.get("historical_backfill")
        if defer_history and not (isinstance(prior_backfill, dict) and prior_backfill.get("completed")):
            backfill = {
                "attempted_at": None,
                "bounded_days": MAX_HISTORY_DAYS,
                "completed": False,
                "complete": False,
                "deferred_until_next_cycle": True,
            }
            incremental = {
                "window_start": now,
                "window_end": now,
                "deferred_until_next_cycle": True,
            }
            self.state["source_cursor"] = now
        else:
            backfill = self.backfill_once(now)
            incremental = self.collect_incremental(now)
        boot = self._boot()
        self._detect_boot_change(boot, now)
        metrics, unavailable = self._host_metrics()
        containers: dict[str, Any] = {}
        for component, name in CONTAINERS.items():
            value, missing = self._container_state(component, name, now)
            containers[component] = value
            unavailable.extend(missing)
        probes = self._probes()
        self._record_probe_transitions(probes, now)
        systemd, missing_systemd = self._systemd_state()
        unavailable.extend(missing_systemd)
        cloudflare_metrics, missing_metrics = self._cloudflare_metrics()
        unavailable.extend(missing_metrics)
        sample = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": now,
            "host": {"boot": boot, "resources": metrics},
            "containers": containers,
            "fixed_routes": probes,
            "systemd": systemd,
            "cloudflare_tunnel": cloudflare_metrics,
        }
        ledger_sample = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": now,
            "host": {
                "boot_identity": boot.get("identity"),
                "cpu_percent": metrics.get("cpu_percent"),
                "memory_used_percent": (metrics.get("memory") or {}).get("used_percent"),
                "swap_used_percent": (metrics.get("swap") or {}).get("used_percent"),
                "load_one": (metrics.get("load") or {}).get("one"),
                "root_disk_used_percent": ((metrics.get("disk") or {}).get("root") or {}).get("used_percent"),
            },
            "containers": {
                component: {
                    "run_identity": value.get("run_identity"),
                    "running": value.get("running"),
                    "restart_count": value.get("restart_count"),
                    "memory_current_bytes": (value.get("resource_usage") or {}).get("memory_current_bytes"),
                    "oom_kill": (value.get("cgroup_memory_events") or {}).get("oom_kill"),
                }
                for component, value in containers.items()
            },
            "routes_ok": {name: self._route_ok(name, value) for name, value in probes.items()},
            "cloudflare_connected_replicas": cloudflare_metrics.get("connected_replicas"),
        }
        self._append("samples", ledger_sample, now)
        retention = self._retention(now)
        current = {
            **sample,
            "collector": {
                "status": "healthy",
                "observed_at": now,
                "interval_seconds": self.config.interval_seconds,
                "fresh_for_seconds": self.config.interval_seconds * 3,
                "retention": retention,
                "historical_backfill": backfill,
                "incremental_sources": incremental,
            },
            "evidence": {
                "complete": not unavailable and bool(backfill.get("complete")),
                "unavailable_sources": sorted(set(unavailable)),
                "truncated_sources": sorted(k for k, value in self.state.get("truncation", {}).items() if value),
            },
        }
        self._atomic_json(self.config.export_dir / "current.json", current, public=True)
        self.state["last_success"] = now
        self._save_state()
        return current

    def mark_deployment(self, version: str, phase: str) -> dict[str, Any]:
        if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?", version):
            raise ValueError("version must be semantic version syntax")
        now = rfc3339()
        if phase not in {"started", "completed", "rolled_back"}:
            raise ValueError("invalid deployment phase")
        marker = self.event(now, "mcp", "info", f"deployment_{phase}", f"MCP deployment {phase}; version {version}", "collector_deployment_marker", cause="unknown")
        if marker.get("truncated"):
            raise RuntimeError("deployment marker ledger is full")
        return marker

    def validate(self) -> dict[str, Any]:
        redaction_fixture = (
            "Bearer fake-token " + "AKIA" + "ABCDEFGHIJKLMNOP 192.0.2.1 2001:db8::1 "
            "00:11:22:33:44:55 /home/alice/x https://user:pass@example.test/x?token=fake"
        )
        sanitized = sanitize_text(redaction_fixture, limit=2048)
        redaction_ok = not any(
            item in sanitized
            for item in ("fake-token", "AKIA", "192.0.2.1", "2001:db8", "00:11:22", "alice", "user:pass", "token=fake")
        )
        checks = {
            "no_listener": True,
            "fixed_containers": sorted(CONTAINERS),
            "fixed_routes": ["ha_frontend_route", "mcp_public_route", "local_origin"],
            "export_directory_exists": self.config.export_dir.is_dir(),
            "state_directory_exists": self.config.state_dir.is_dir(),
            "retention_at_least_eight_days": self.config.retention_days >= 8,
            "hard_caps_enabled": MAX_LEDGER_FILE_BYTES > 0 and MAX_EXPORT_BYTES > 0,
            "current_snapshot_cap_bytes": MAX_CURRENT_BYTES,
            "state_cap_bytes": MAX_STATE_BYTES,
            "python_3_9_compatible_runtime": sys.version_info >= (3, 9),
            "redaction_self_test": redaction_ok,
            "timestamps_preserved_self_test": sanitize_text("2026-08-24T19:53:06Z") == "2026-08-24T19:53:06Z",
            "websocket_key_is_16_bytes": len(base64.b64decode("aGFfZGlhZ25vc3RpY3NfMQ==")) == 16,
        }
        current = _json_load(self.config.export_dir / "current.json", None)
        checks["current_schema_valid_or_not_yet_created"] = current is None or (
            isinstance(current, dict) and current.get("schema_version") == SCHEMA_VERSION
        )
        return {"ok": all(v for v in checks.values() if isinstance(v, bool)), "checks": checks}

    def run(self) -> None:
        self.acquire_lock()
        self._stop = False
        def stop(_signum: int, _frame: Any) -> None:
            self._stop = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while not self._stop:
            started = time.monotonic()
            try:
                publish_readiness_first = not (self.config.export_dir / "current.json").is_file()
                self.once(defer_history=publish_readiness_first)
            except Exception as exc:
                # Never export exception text; error class is bounded and source-free.
                print(f"collector iteration failed ({type(exc).__name__})", file=sys.stderr, flush=True)
                self.event(rfc3339(), "systemd", "error", "collector_iteration_failed", f"collector iteration failed ({type(exc).__name__})", "collector_runtime", complete=False)
            remaining = self.config.interval_seconds - (time.monotonic() - started)
            deadline = time.monotonic() + max(0.0, remaining)
            while not self._stop and time.monotonic() < deadline:
                time.sleep(min(1.0, deadline - time.monotonic()))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fixed-scope Home Assistant host diagnostics collector")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("run")
    sub.add_parser("once")
    sub.add_parser("validate")
    marker = sub.add_parser("mark-deployment")
    marker.add_argument("--version", required=True)
    marker.add_argument("--phase", required=True, choices=("started", "completed", "rolled_back"))
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    collector = Collector()
    if args.action == "run":
        collector.run()
    elif args.action == "once":
        collector.acquire_lock()
        collector.once()
    elif args.action == "validate":
        print(json.dumps(collector.validate(), sort_keys=True))
    elif args.action == "mark-deployment":
        collector.mark_deployment(args.version, args.phase)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
