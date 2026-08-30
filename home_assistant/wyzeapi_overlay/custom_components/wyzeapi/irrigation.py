"""Shared coordinator and service helpers for Wyze sprinklers."""
# SPDX-License-Identifier: Apache-2.0
# Derived from SecKatie/ha-wyzeapi; modified for normalized sprinkler access.

from __future__ import annotations

import asyncio
import copy
import logging
import math
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from homeassistant.config_entries import ConfigEntryNotReady, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)
from wyzeapy.const import APP_INFO, OLIVE_APP_ID, PHONE_ID
from wyzeapy.crypto import olive_create_signature
from wyzeapy.exceptions import AccessTokenError
from wyzeapy.services.irrigation_service import Irrigation, IrrigationService
from wyzeapy.utils import check_for_errors_iot

from .const import DOMAIN, IRRIGATION_COORDINATORS
from .irrigation_data import (
    apply_coordinator_state,
    normalize_schedule_runs_response,
    normalize_schedules_response,
    normalize_snapshot,
    reconcile_command_status,
    sprinkler_capabilities,
    validate_sequence,
)

_LOGGER = logging.getLogger(__name__)

DEVICE_INFO_URL = "https://wyze-lockwood-service.wyzecam.com/plugin/irrigation/device_info"
SCHEDULE_RUNS_URL = "https://wyze-lockwood-service.wyzecam.com/plugin/irrigation/schedule_runs"
SCHEDULES_URL = "https://wyze-lockwood-service.wyzecam.com/plugin/irrigation/schedule"
DEVICE_INFO_KEYS = (
    "wiring,sensor,enable_schedules,notification_enable,notification_watering_begins,"
    "notification_watering_ends,notification_watering_is_skipped,skip_low_temp,skip_wind,"
    "skip_rain,skip_saturation"
)


class WyzeIrrigationCoordinator(DataUpdateCoordinator):
    """Poll one sprinkler controller with a bounded set of cloud requests."""

    def __init__(
        self,
        hass: HomeAssistant,
        service: IrrigationService,
        device: Irrigation,
        entry_id: str,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"Wyze sprinkler {device.nickname}",
            update_interval=timedelta(seconds=60),
        )
        self.service = service
        self.device = device
        self.entry_id = entry_id
        self._slow_refresh_count = 0
        self._iot_response: dict[str, Any] = {}
        self._zone_response: dict[str, Any] = {}
        self._info_response: dict[str, Any] = {}
        self._schedule_response: dict[str, Any] = {}
        self._command_lock = asyncio.Lock()
        self._managed_run_task: asyncio.Task[None] | None = None
        self._logical_run: dict[str, Any] | None = None
        self._logical_generation = 0
        self._logical_deadline_monotonic: float | None = None
        self._failed_endpoints: set[str] = set()
        self._known_zone_numbers: set[int] | None = None
        self._command_pending_until = 0.0
        self._command_status: dict[str, Any] = {
            "state": "idle",
            "evidence_type": "commanded",
            "physical_state_verified": False,
        }

    @property
    def enabled_zone_numbers(self) -> set[int]:
        return {
            int(zone["zone_number"])
            for zone in (self.data or {}).get("zones", [])
            if zone.get("enabled") is True
            and zone.get("zone_number") is not None
        }

    @property
    def response_identity(self) -> dict[str, Any]:
        """Return stable controller identity fields for service responses."""
        return {
            "controller_id": self.device.mac,
            "controller_name": self.device.nickname,
        }

    def sprinkler_snapshot(self) -> dict[str, Any]:
        """Return the current coordinator snapshot without a network request."""
        return {
            "supported": True,
            **self.response_identity,
            "snapshot": copy.deepcopy(self.data or {}),
            "logical_run": self.logical_run_snapshot(),
            "source": "coordinator_cache",
            "network_request_performed": False,
        }

    def _logical_remaining_seconds(self) -> int | None:
        """Return the current logical-zone remainder from a monotonic deadline."""
        if self._logical_run is None:
            return None
        remaining = self._logical_run.get("current_zone_remaining_seconds")
        if (
            self._logical_run.get("state") == "running"
            and self._logical_deadline_monotonic is not None
        ):
            remaining = max(
                math.ceil(self._logical_deadline_monotonic - time.monotonic()), 0
            )
        return int(remaining) if remaining is not None else None

    def logical_run_snapshot(self) -> dict[str, Any]:
        """Return bounded coordinator-owned run state for entities and services."""
        if self._logical_run is None:
            return {
                "state": "idle",
                "can_pause": False,
                "can_resume": False,
                "can_stop": False,
            }
        result = copy.deepcopy(self._logical_run)
        result["current_zone_remaining_seconds"] = self._logical_remaining_seconds()
        index = int(result.get("current_index", 0))
        zones = list(result.get("zones", []))
        result["current_zone"] = copy.deepcopy(zones[index]) if index < len(zones) else None
        result["remaining_queued_zones"] = copy.deepcopy(zones[index + 1 :])
        state = result.get("state")
        result["can_pause"] = state == "running"
        result["can_resume"] = state == "paused"
        result["can_stop"] = state in {"running", "paused"}
        return result

    def _notify_logical_run_changed(self) -> None:
        """Immediately publish a private logical-state transition to entities."""
        self.async_update_listeners()

    def _clear_logical_run_locked(self) -> None:
        """Invalidate the worker and abandon every retained queued zone."""
        self._logical_generation += 1
        self._logical_deadline_monotonic = None
        self._logical_run = None

    def _logical_zone(self, run: dict[str, int]) -> dict[str, Any]:
        """Build one bounded ordered-zone record for the logical run."""
        return {
            **self._command_zone_identity(run["zone_number"]),
            "duration_seconds": run["duration"],
            "provider_duration_seconds": max(60, run["duration"]),
        }

    async def _cancel_managed_task(self, task: asyncio.Task[None] | None) -> None:
        """Cancel one HA-owned timer without allowing its queue to advance."""
        if task is None or task is asyncio.current_task() or task.done():
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def async_get_schedule_runs(self, limit: int) -> dict[str, Any]:
        """Fetch and normalize a bounded private schedule-runs response."""
        try:
            response = await self.service._get_schedule_runs(
                SCHEDULE_RUNS_URL, self.device, limit=limit
            )
            normalized = normalize_schedule_runs_response(
                response,
                list((self.data or {}).get("zones", [])),
                limit=limit,
            )
        except ConfigEntryNotReady as err:
            raise HomeAssistantError(
                f"Unable to read sprinkler schedule runs: {err}"
            ) from err
        return {**normalized, **self.response_identity}

    async def async_get_schedules(self) -> dict[str, Any]:
        """Fetch safe known fields from Wyze's private schedule GET endpoint."""
        await self.service._auth_lib.refresh_if_should()
        payload = {
            "device_id": self.device.mac,
            "nonce": str(int(time.time() * 1000)),
        }
        token = self.service._auth_lib.token.access_token
        headers = {
            "Accept-Encoding": "gzip",
            "User-Agent": "myapp",
            "appid": OLIVE_APP_ID,
            "appinfo": APP_INFO,
            "phoneid": PHONE_ID,
            "access_token": token,
            "signature2": olive_create_signature(payload, token),
        }
        try:
            response = await self.service._auth_lib.get(
                SCHEDULES_URL, headers=headers, params=payload
            )
            check_for_errors_iot(self.service, response)
            normalized = normalize_schedules_response(
                response, list((self.data or {}).get("zones", []))
            )
        except Exception as err:
            raise HomeAssistantError(
                f"Unable to read sprinkler schedules: {err}"
            ) from err
        return {**normalized, **self.response_identity}

    def sprinkler_capabilities(self) -> dict[str, Any]:
        """Return the static, no-network capability contract."""
        return {**sprinkler_capabilities(), **self.response_identity}

    def _set_command_pending(
        self, action: str, command_id: str | None = None, **details: Any
    ) -> None:
        """Record bounded local command metadata without claiming actuation."""
        issued_at = datetime.now(timezone.utc)
        self._command_pending_until = time.monotonic() + 120
        self._command_status = {
            "command_id": command_id or str(uuid.uuid4()),
            "action": action,
            "state": "pending",
            "issued_at": issued_at.isoformat(),
            "expires_at": (issued_at + timedelta(seconds=120)).isoformat(),
            "evidence_type": "commanded",
            "physical_state_verified": False,
            **copy.deepcopy(details),
        }

    def _command_zone_identity(self, zone_number: int) -> dict[str, Any]:
        """Return bounded normalized and native identity for command metadata."""
        zone = next(
            (
                item
                for item in (self.data or {}).get("zones", [])
                if item.get("zone_number") == zone_number
            ),
            {},
        )
        result = {"zone_number": zone_number}
        if zone.get("zone_id") is not None:
            result["zone_id"] = zone["zone_id"]
        if zone.get("name") is not None:
            result["zone_name"] = zone["name"]
        return result

    async def _async_update_data(self) -> dict[str, Any]:
        """Refresh status/history every minute and static metadata every 15 minutes."""
        refresh_slow = not self._zone_response or self._slow_refresh_count >= 15
        calls = [self.service.get_iot_prop(self.device)]
        labels = ["iot"]
        calls.append(
            self.service._get_schedule_runs(
                SCHEDULE_RUNS_URL, self.device, limit=10
            )
        )
        labels.append("schedule")
        if refresh_slow:
            calls.extend(
                [
                    self.service.get_zone_by_device(self.device),
                    self._async_get_device_info(),
                ]
            )
            labels.extend(["zone", "info"])

        results = await asyncio.gather(*calls, return_exceptions=True)
        successful_labels: set[str] = set()
        for label, result in zip(labels, results):
            if isinstance(result, Exception):
                log = (
                    _LOGGER.warning
                    if label not in self._failed_endpoints
                    else _LOGGER.debug
                )
                log(
                    "Wyze sprinkler %s %s refresh failed: %s",
                    self.device.nickname,
                    label,
                    result,
                )
                self._failed_endpoints.add(label)
                continue
            successful_labels.add(label)
            self._failed_endpoints.discard(label)
            setattr(self, f"_{label}_response", result)

        if "iot" not in successful_labels:
            raise UpdateFailed(
                f"No current status response for Wyze sprinkler {self.device.nickname}"
            )
        if refresh_slow and not self._zone_response:
            raise UpdateFailed(
                f"No zone inventory for Wyze sprinkler {self.device.nickname}"
            )

        if refresh_slow and "zone" in successful_labels:
            self._slow_refresh_count = 0
        elif refresh_slow:
            self._slow_refresh_count = 15
        else:
            self._slow_refresh_count += 1

        current_schedule_response = (
            self._schedule_response if "schedule" in successful_labels else {}
        )
        snapshot = normalize_snapshot(
            self._iot_response,
            self._zone_response,
            self._info_response,
            current_schedule_response,
        )
        if "schedule" not in successful_labels and self.data:
            snapshot["recent_runs"] = list(self.data.get("recent_runs", []))[:10]
            snapshot["last_run_at"] = self.data.get("last_run_at")
        self._command_status, command_pending = reconcile_command_status(
            self._command_status,
            watering=snapshot.get("watering"),
            active_zone_number=snapshot.get("active_zone_number"),
            expired=(
                self._command_pending_until > 0
                and time.monotonic() >= self._command_pending_until
            ),
        )
        if not command_pending:
            self._command_pending_until = 0.0
        snapshot = apply_coordinator_state(
            snapshot,
            command_status=self._command_status,
            partial=bool(self._failed_endpoints),
            endpoint_errors=sorted(self._failed_endpoints),
        )

        zone_numbers = {
            int(zone["zone_number"])
            for zone in snapshot.get("zones", [])
            if zone.get("zone_number") is not None
        }
        if self._known_zone_numbers is None:
            self._known_zone_numbers = zone_numbers
        elif zone_numbers != self._known_zone_numbers:
            self._known_zone_numbers = zone_numbers
            snapshot["topology_changed"] = True
            self.hass.async_create_task(
                self.hass.config_entries.async_reload(self.entry_id),
                f"Reload Wyze sprinkler topology {self.device.nickname}",
            )
        self.device.available = bool(snapshot.get("connected"))
        self.device.RSSI = snapshot.get("rssi")
        self.device.IP = snapshot.get("ip")
        self.device.ssid = snapshot.get("ssid")
        if snapshot.get("serial_number"):
            self.device.sn = snapshot["serial_number"]
        return snapshot

    async def _async_get_device_info(self) -> dict[str, Any]:
        """Call the sprinkler config endpoint with its device_id payload contract."""
        await self.service._auth_lib.refresh_if_should()
        payload = {
            "device_id": self.device.mac,
            "nonce": str(int(time.time() * 1000)),
            "keys": DEVICE_INFO_KEYS,
        }
        token = self.service._auth_lib.token.access_token
        headers = {
            "Accept-Encoding": "gzip",
            "User-Agent": "myapp",
            "appid": OLIVE_APP_ID,
            "appinfo": APP_INFO,
            "phoneid": PHONE_ID,
            "access_token": token,
            "signature2": olive_create_signature(payload, token),
        }
        response = await self.service._auth_lib.get(
            DEVICE_INFO_URL, headers=headers, params=payload
        )
        check_for_errors_iot(self.service, response)
        return response

    async def async_start_zone(
        self,
        zone_number: int,
        duration_seconds: int,
        command_id: str | None = None,
        source: str = "service",
    ) -> None:
        """Start one enabled zone as a one-zone coordinator-owned run."""
        if duration_seconds < 1 or duration_seconds > 10_800:
            raise HomeAssistantError("Duration must be between 1 second and 180 minutes")
        await self._async_start_logical_run(
            [{"zone": zone_number, "duration_seconds": duration_seconds}],
            command_id=command_id,
            source=source,
            action="start_zone",
        )

    async def _async_start_logical_run(
        self,
        zone_runs: list[dict[str, Any]],
        *,
        command_id: str | None,
        source: str,
        action: str,
    ) -> None:
        """Validate and start only the first zone of one complete logical run."""
        async with self._command_lock:
            await self.async_refresh()
            if not self.last_update_success or not (self.data or {}).get("connected"):
                raise HomeAssistantError(
                    "Current connected sprinkler status is unavailable"
                )
            if (self.data or {}).get("topology_changed"):
                raise HomeAssistantError(
                    "Sprinkler zones changed; wait for the integration reload"
                )
            if set((self.data or {}).get("endpoint_errors", [])) & {
                "iot",
                "schedule",
            }:
                raise HomeAssistantError("Current live sprinkler state is incomplete")
            try:
                runs = validate_sequence(zone_runs, self.enabled_zone_numbers)
            except ValueError as err:
                raise HomeAssistantError(str(err)) from err
            watering = (self.data or {}).get("watering")
            if (
                watering is True
                or self._command_pending_until > time.monotonic()
                or self._logical_run is not None
                or (
                    self._managed_run_task is not None
                    and not self._managed_run_task.done()
                )
            ):
                raise HomeAssistantError(
                    "A sprinkler run is already active; stop it before starting another"
                )
            if watering is None:
                raise HomeAssistantError(
                    "Current live sprinkler watering state is unavailable"
                )
            logical_zones = [self._logical_zone(run) for run in runs]
            run_id = str(uuid.uuid4())
            started_at = datetime.now(timezone.utc)
            self._logical_generation += 1
            generation = self._logical_generation
            self._logical_run = {
                "run_id": run_id,
                "state": "running",
                "zones": logical_zones,
                "current_index": 0,
                "current_zone_remaining_seconds": runs[0]["duration"],
                "source": source,
                "correlation": {
                    "initial_command_id": command_id,
                    "latest_command_id": command_id,
                },
                "started_at": started_at.isoformat(),
                "updated_at": started_at.isoformat(),
                "evidence_type": "commanded",
                "physical_state_verified": False,
            }
            first = logical_zones[0]
            try:
                await self.service.start_zone(
                    self.device,
                    int(first["zone_number"]),
                    int(first["provider_duration_seconds"]),
                )
            except Exception as err:
                self._clear_logical_run_locked()
                raise HomeAssistantError(
                    f"Unable to start zone {first['zone_number']}: {err}"
                ) from err
            self._logical_deadline_monotonic = (
                time.monotonic() + int(first["duration_seconds"])
            )
            self._set_command_pending(
                action,
                command_id=command_id,
                logical_run_id=run_id,
                source=source,
                zones=copy.deepcopy(logical_zones),
                current_zone_number=first["zone_number"],
                duration_seconds=first["duration_seconds"],
                provider_duration_seconds=first["provider_duration_seconds"],
                managed_by_home_assistant=True,
                scheduled_stop_at=(
                    datetime.now(timezone.utc)
                    + timedelta(seconds=int(first["duration_seconds"]))
                ).isoformat(),
            )
            await self.async_request_refresh()
            self._managed_run_task = self.hass.async_create_task(
                self._async_complete_managed_runs(run_id, generation),
                f"Run Home Assistant-managed Wyze sprinkler sequence {run_id}",
            )
            self._notify_logical_run_changed()

    async def async_force_full_refresh(self) -> None:
        """Refresh live state plus zone/config metadata immediately."""
        self._slow_refresh_count = 15
        await self.async_request_refresh()

    async def async_start_sequence(
        self,
        zone_runs: list[dict[str, Any]],
        command_id: str | None = None,
        source: str = "service",
    ) -> None:
        """Start an ordered run while keeping every queued zone inside HA."""
        await self._async_start_logical_run(
            zone_runs,
            command_id=command_id,
            source=source,
            action="start_sequence",
        )

    async def _async_complete_managed_runs(
        self,
        run_id: str,
        generation: int,
    ) -> None:
        """Time the active zone and advance only while the run token is current."""
        current_task = asyncio.current_task()
        try:
            while True:
                async with self._command_lock:
                    if (
                        self._logical_run is None
                        or self._logical_run.get("run_id") != run_id
                        or self._logical_run.get("state") != "running"
                        or self._logical_generation != generation
                    ):
                        return
                    remaining = self._logical_remaining_seconds()
                if remaining is None:
                    raise HomeAssistantError("Logical run has no current-zone duration")
                if remaining > 0:
                    await asyncio.sleep(remaining)
                stopped = await self._async_managed_stop(run_id, generation)
                if not stopped:
                    return
                await self._async_wait_for_idle()
                async with self._command_lock:
                    if (
                        self._logical_run is None
                        or self._logical_run.get("run_id") != run_id
                        or self._logical_run.get("state") != "running"
                        or self._logical_generation != generation
                    ):
                        return
                    next_index = int(self._logical_run["current_index"]) + 1
                    zones = self._logical_run["zones"]
                    if next_index >= len(zones):
                        self._clear_logical_run_locked()
                        self._notify_logical_run_changed()
                        return
                    zone = zones[next_index]
                    self._logical_run["current_index"] = next_index
                    self._logical_run["current_zone_remaining_seconds"] = int(
                        zone["duration_seconds"]
                    )
                    self._logical_run["updated_at"] = datetime.now(
                        timezone.utc
                    ).isoformat()
                    await self.service.start_zone(
                        self.device,
                        int(zone["zone_number"]),
                        int(zone["provider_duration_seconds"]),
                    )
                    self._logical_deadline_monotonic = (
                        time.monotonic() + int(zone["duration_seconds"])
                    )
                    correlation = self._logical_run.get("correlation", {})
                    self._set_command_pending(
                        "start_sequence",
                        command_id=correlation.get("latest_command_id"),
                        logical_run_id=run_id,
                        source=self._logical_run.get("source"),
                        zones=copy.deepcopy(zones),
                        managed_by_home_assistant=True,
                        current_zone_number=zone["zone_number"],
                        scheduled_stop_at=(
                            datetime.now(timezone.utc)
                            + timedelta(seconds=int(zone["duration_seconds"]))
                        ).isoformat(),
                    )
                    await self.async_request_refresh()
                    self._notify_logical_run_changed()
        except asyncio.CancelledError:
            raise
        except Exception as err:
            _LOGGER.error(
                "Home Assistant-timed sprinkler run failed for %s: %s",
                self.device.nickname,
                err,
            )
            async with self._command_lock:
                current = (
                    self._logical_run is not None
                    and self._logical_run.get("run_id") == run_id
                    and self._logical_generation == generation
                )
                if current:
                    self._clear_logical_run_locked()
            if current:
                try:
                    async with self._command_lock:
                        await self.service.stop_running_schedule(self.device)
                        self._set_command_pending(
                            "stop", command_id="managed-run-failure"
                        )
                        await self.async_request_refresh()
                except Exception as stop_err:
                    _LOGGER.error(
                        "Unable to stop failed Home Assistant-managed sprinkler run for %s: %s",
                        self.device.nickname,
                        stop_err,
                    )
                self._notify_logical_run_changed()
        finally:
            if self._managed_run_task is current_task:
                self._managed_run_task = None

    async def _async_managed_stop(self, run_id: str, generation: int) -> bool:
        """Stop the current zone only for the still-current logical worker."""
        async with self._command_lock:
            if (
                self._logical_run is None
                or self._logical_run.get("run_id") != run_id
                or self._logical_run.get("state") != "running"
                or self._logical_generation != generation
            ):
                return False
            await self.service.stop_running_schedule(self.device)
            correlation = self._logical_run.get("correlation", {})
            self._set_command_pending(
                "stop",
                command_id=correlation.get("latest_command_id"),
                logical_run_id=run_id,
                automatic_stop=True,
            )
            self._logical_run["current_zone_remaining_seconds"] = 0
            self._logical_deadline_monotonic = None
            await self.async_request_refresh()
            self._notify_logical_run_changed()
            return True

    async def _async_wait_for_idle(self) -> None:
        """Wait for controller-reported or completed-run-derived idle."""
        for _ in range(30):
            await self.async_refresh()
            data = self.data or {}
            if (
                self.last_update_success
                and data.get("connected") is True
                and not (set(data.get("endpoint_errors", [])) & {"iot", "schedule"})
                and data.get("watering") is False
                and data.get("active_zone_number") is None
            ):
                return
            await asyncio.sleep(1)
        raise HomeAssistantError(
            "Controller idle was not verified after the automatic stop"
        )

    async def async_pause(
        self, command_id: str | None = None, source: str = "service"
    ) -> None:
        """Pause a coordinator-owned run while retaining its complete queue."""
        async with self._command_lock:
            if self._logical_run is None or self._logical_run.get("state") != "running":
                raise HomeAssistantError("Pause is valid only while a logical run is running")
            run_id = str(self._logical_run["run_id"])
            remaining = self._logical_remaining_seconds()
            self._logical_run["current_zone_remaining_seconds"] = remaining
            self._logical_run["state"] = "paused"
            self._logical_run["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._logical_run["correlation"]["latest_command_id"] = command_id
            self._logical_run["correlation"]["latest_source"] = source
            self._logical_deadline_monotonic = None
            self._logical_generation += 1
            task = self._managed_run_task
            self._managed_run_task = None
            self._notify_logical_run_changed()
        await self._cancel_managed_task(task)
        try:
            async with self._command_lock:
                if self._logical_run is None or self._logical_run.get("run_id") != run_id:
                    raise HomeAssistantError("The logical run changed before pause completed")
                await self.service.stop_running_schedule(self.device)
                self._set_command_pending(
                    "pause",
                    command_id=command_id,
                    logical_run_id=run_id,
                    source=source,
                    current_zone_remaining_seconds=remaining,
                )
                await self.async_request_refresh()
            await self._async_wait_for_idle()
        except Exception as err:
            async with self._command_lock:
                if self._logical_run is not None and self._logical_run.get("run_id") == run_id:
                    self._clear_logical_run_locked()
            self._notify_logical_run_changed()
            if isinstance(err, HomeAssistantError):
                raise
            raise HomeAssistantError(f"Unable to pause sprinkler: {err}") from err

    async def async_resume(
        self, command_id: str | None = None, source: str = "service"
    ) -> None:
        """Resume the captured current-zone remainder, then every queued zone."""
        await self.async_refresh()
        async with self._command_lock:
            if self._logical_run is None or self._logical_run.get("state") != "paused":
                raise HomeAssistantError("Resume is valid only while a logical run is paused")
            data = self.data or {}
            if (
                not self.last_update_success
                or data.get("connected") is not True
                or data.get("watering") is not False
                or data.get("active_zone_number") is not None
                or set(data.get("endpoint_errors", [])) & {"iot", "schedule"}
            ):
                raise HomeAssistantError("Controller idle is required before resume")
            remaining = int(self._logical_run.get("current_zone_remaining_seconds") or 0)
            if remaining <= 0:
                self._logical_run["current_index"] = int(
                    self._logical_run["current_index"]
                ) + 1
            index = int(self._logical_run["current_index"])
            zones = self._logical_run["zones"]
            if index >= len(zones):
                self._clear_logical_run_locked()
                self._notify_logical_run_changed()
                return
            zone = zones[index]
            if remaining <= 0:
                remaining = int(zone["duration_seconds"])
                self._logical_run["current_zone_remaining_seconds"] = remaining
            provider_duration_seconds = max(60, remaining)
            try:
                await self.service.start_zone(
                    self.device, int(zone["zone_number"]), provider_duration_seconds
                )
            except Exception as err:
                raise HomeAssistantError(f"Unable to resume sprinkler: {err}") from err
            self._logical_run["state"] = "running"
            self._logical_run["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._logical_run["correlation"]["latest_command_id"] = command_id
            self._logical_run["correlation"]["latest_source"] = source
            self._logical_generation += 1
            generation = self._logical_generation
            run_id = str(self._logical_run["run_id"])
            self._logical_deadline_monotonic = time.monotonic() + remaining
            self._set_command_pending(
                "resume",
                command_id=command_id,
                logical_run_id=run_id,
                source=source,
                current_zone_number=zone["zone_number"],
                duration_seconds=remaining,
                provider_duration_seconds=provider_duration_seconds,
                remaining_queued_zones=copy.deepcopy(zones[index + 1 :]),
                scheduled_stop_at=(
                    datetime.now(timezone.utc) + timedelta(seconds=remaining)
                ).isoformat(),
            )
            await self.async_request_refresh()
            self._managed_run_task = self.hass.async_create_task(
                self._async_complete_managed_runs(run_id, generation),
                f"Resume Home Assistant-managed Wyze sprinkler sequence {run_id}",
            )
            self._notify_logical_run_changed()

    async def async_stop(
        self, command_id: str | None = None, source: str = "service"
    ) -> None:
        """Abandon the complete logical run and stop the current zone if needed."""
        async with self._command_lock:
            if self._logical_run is None or self._logical_run.get("state") not in {
                "running",
                "paused",
            }:
                raise HomeAssistantError(
                    "Stop is valid only while a logical run is running or paused"
                )
            was_running = self._logical_run.get("state") == "running"
            run_id = str(self._logical_run["run_id"])
            task = self._managed_run_task
            self._managed_run_task = None
            self._clear_logical_run_locked()
            self._notify_logical_run_changed()
        await self._cancel_managed_task(task)
        if not was_running:
            return
        async with self._command_lock:
            try:
                await self.service.stop_running_schedule(self.device)
            except Exception as err:
                raise HomeAssistantError(f"Unable to stop sprinkler: {err}") from err
            self._set_command_pending(
                "stop",
                command_id=command_id,
                logical_run_id=run_id,
                source=source,
            )
            await self.async_request_refresh()
        await self._async_wait_for_idle()

    async def async_shutdown(self) -> None:
        """Fail closed by abandoning every queued zone during integration unload."""
        if self._logical_run is not None:
            await self.async_stop(
                command_id="integration-unload", source="integration_unload"
            )
            return
        task = self._managed_run_task
        self._managed_run_task = None
        await self._cancel_managed_task(task)


class WyzeIrrigationCoordinatorEntity(CoordinatorEntity):
    """Base entity shared by all sprinkler platforms."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, coordinator: WyzeIrrigationCoordinator) -> None:
        super().__init__(coordinator)
        self.coordinator = coordinator

    @property
    def device_info(self) -> DeviceInfo:
        device = self.coordinator.device
        result = DeviceInfo(
            identifiers={(DOMAIN, device.mac)},
            name=device.nickname,
            manufacturer="WyzeLabs",
            model=device.product_model,
            connections={(dr.CONNECTION_NETWORK_MAC, device.mac)},
        )
        serial = (self.coordinator.data or {}).get("serial_number") or getattr(
            device, "sn", None
        )
        firmware = (self.coordinator.data or {}).get("firmware")
        if serial:
            result["serial_number"] = serial
        if firmware:
            result["sw_version"] = firmware
        return result

    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success and bool(
            (self.coordinator.data or {}).get("connected")
        )


async def async_setup_irrigation_coordinators(
    hass: HomeAssistant,
    entry_id: str,
    client: Any,
) -> None:
    """Create exactly one coordinator for each Wyze sprinkler."""
    service = await client.irrigation_service
    coordinators: dict[str, WyzeIrrigationCoordinator] = {}
    try:
        devices = await service.get_irrigations()
    except AccessTokenError as err:
        raise ConfigEntryAuthFailed(
            "Wyze authentication expired while listing sprinklers"
        ) from err
    except Exception as err:
        raise ConfigEntryNotReady(
            "Unable to list Wyze sprinkler controllers"
        ) from err
    for device in devices:
        coordinator = WyzeIrrigationCoordinator(hass, service, device, entry_id)
        coordinators[device.mac] = coordinator
        try:
            await coordinator.async_config_entry_first_refresh()
        except Exception as err:
            device.available = False
            coordinator._known_zone_numbers = set()
            _LOGGER.warning(
                "Initial sprinkler refresh failed for %s; keeping its entities unavailable while normal coordinator retries continue: %s",
                device.nickname,
                err,
            )
    hass.data[DOMAIN][entry_id][IRRIGATION_COORDINATORS] = coordinators


def irrigation_coordinators(
    hass: HomeAssistant, entry_id: str
) -> list[WyzeIrrigationCoordinator]:
    """Return sprinkler coordinators for one config entry."""
    return list(
        hass.data[DOMAIN][entry_id].get(IRRIGATION_COORDINATORS, {}).values()
    )


def coordinator_for_device_id(
    hass: HomeAssistant, device_id: str
) -> WyzeIrrigationCoordinator:
    """Resolve a Home Assistant device ID to its sprinkler coordinator."""
    registry = dr.async_get(hass)
    device = registry.async_get(device_id)
    if device is None:
        raise HomeAssistantError(f"Home Assistant device {device_id} was not found")
    identifiers = {value for domain, value in device.identifiers if domain == DOMAIN}
    for entry_id, entry_data in hass.data.get(DOMAIN, {}).items():
        if not isinstance(entry_data, dict):
            continue
        entry = hass.config_entries.async_get_entry(entry_id)
        if entry is None or entry.state is not ConfigEntryState.LOADED:
            continue
        for mac, coordinator in entry_data.get(IRRIGATION_COORDINATORS, {}).items():
            if mac in identifiers:
                return coordinator
    raise HomeAssistantError(
        "The selected device is not a Wyze sprinkler controller"
    )
