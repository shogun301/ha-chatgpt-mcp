from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .ha_client import HomeAssistantClient

LOGGER = logging.getLogger("ha_chatgpt_mcp.capability_sync")
MIN_INTERVAL_SECONDS = 60
MAX_STATE_BYTES = 512_000


def _normalize_services(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reduce HA's service registry to a stable, non-sensitive compatibility contract."""
    normalized: list[dict[str, Any]] = []
    for domain_entry in raw:
        domain = str(domain_entry.get("domain") or "")
        services = domain_entry.get("services") or {}
        if not domain or not isinstance(services, dict):
            continue
        for service, detail in services.items():
            if not isinstance(detail, dict):
                detail = {}
            fields = detail.get("fields") or {}
            normalized.append(
                {
                    "domain": domain,
                    "service": str(service),
                    "fields": sorted(str(field) for field in fields),
                    "required_fields": sorted(
                        str(field)
                        for field, schema in fields.items()
                        if isinstance(schema, dict) and schema.get("required") is True
                    ),
                }
            )
    return sorted(normalized, key=lambda item: (item["domain"], item["service"]))


def _fingerprint(inventory: list[dict[str, Any]]) -> str:
    payload = json.dumps(inventory, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def _key(item: dict[str, Any]) -> str:
    return f"{item['domain']}.{item['service']}"


def _diff(
    baseline: list[dict[str, Any]], current: list[dict[str, Any]]
) -> dict[str, list[Any]]:
    baseline_map = {_key(item): item for item in baseline}
    current_map = {_key(item): item for item in current}
    added = sorted(set(current_map) - set(baseline_map))
    removed = sorted(set(baseline_map) - set(current_map))
    changed = [
        {
            "service": name,
            "baseline_fields": baseline_map[name]["fields"],
            "current_fields": current_map[name]["fields"],
            "baseline_required_fields": baseline_map[name]["required_fields"],
            "current_required_fields": current_map[name]["required_fields"],
        }
        for name in sorted(set(baseline_map) & set(current_map))
        if baseline_map[name] != current_map[name]
    ]
    return {"added": added, "removed": removed, "changed": changed}


class CapabilitySync:
    """Persistently detect HA service-registry drift between MCP releases."""

    def __init__(
        self,
        state_path: Path,
        release_version: str,
        interval_seconds: int = 300,
    ) -> None:
        self.state_path = state_path
        self.release_version = release_version
        self.interval_seconds = max(MIN_INTERVAL_SECONDS, interval_seconds)
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()
        self._status: dict[str, Any] = {
            "status": "starting",
            "release_version": release_version,
            "interval_seconds": self.interval_seconds,
            "last_checked": None,
            "drift": {"added": [], "removed": [], "changed": []},
        }

    def _load(self) -> dict[str, Any]:
        try:
            if self.state_path.stat().st_size > MAX_STATE_BYTES:
                raise ValueError("capability sync state exceeds the size limit")
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, json.JSONDecodeError):
            LOGGER.warning("capability_sync_state_invalid")
            return {}

    def _save(self, value: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True)
        if len(payload.encode()) > MAX_STATE_BYTES:
            raise ValueError("capability sync state exceeds the size limit")
        temporary = self.state_path.with_name(f".{self.state_path.name}.tmp")
        temporary.write_text(payload, encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.state_path)

    async def refresh(self, ha: HomeAssistantClient) -> dict[str, Any]:
        async with self._lock:
            current = _normalize_services(await ha.services())
            persisted = self._load()
            baseline = persisted.get("baseline")
            baseline_release = persisted.get("baseline_release_version")
            if baseline_release != self.release_version or not isinstance(
                baseline, list
            ):
                baseline = current
                baseline_release = self.release_version
                acknowledged_at = datetime.now(UTC).isoformat()
            else:
                acknowledged_at = persisted.get("acknowledged_at")
            drift = _diff(baseline, current)
            checked_at = datetime.now(UTC).isoformat()
            has_drift = any(drift.values())
            state = {
                "schema_version": 1,
                "baseline_release_version": baseline_release,
                "acknowledged_at": acknowledged_at,
                "baseline_fingerprint": _fingerprint(baseline),
                "current_fingerprint": _fingerprint(current),
                "last_checked": checked_at,
                "baseline": baseline,
                "current": current,
                "drift": drift,
            }
            self._save(state)
            self._status = {
                "status": "drift_detected" if has_drift else "in_sync",
                "release_version": self.release_version,
                "interval_seconds": self.interval_seconds,
                "acknowledged_at": acknowledged_at,
                "last_checked": checked_at,
                "baseline_service_count": len(baseline),
                "current_service_count": len(current),
                "baseline_fingerprint": state["baseline_fingerprint"],
                "current_fingerprint": state["current_fingerprint"],
                "drift": drift,
            }
            return dict(self._status)

    def status(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._status))

    async def _run(self, ha: HomeAssistantClient) -> None:
        while not self._stop.is_set():
            try:
                await self.refresh(ha)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - the monitor must stay alive
                LOGGER.warning(
                    "capability_sync_refresh_failed error_type=%s", type(exc).__name__
                )
                self._status = {
                    **self._status,
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "last_checked": datetime.now(UTC).isoformat(),
                }
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_seconds)
            except TimeoutError:
                pass

    def start(self, ha: HomeAssistantClient) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(
                self._run(ha), name="home-assistant-capability-sync"
            )

    async def close(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None
