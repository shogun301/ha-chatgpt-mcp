"""Shared coordinator and service helpers for Wyze sprinklers."""
# SPDX-License-Identifier: Apache-2.0
# Derived from SecKatie/ha-wyzeapi; modified for normalized sprinkler access.

from __future__ import annotations

import asyncio
import copy
import json
import logging
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
QUICKRUN_URL = "https://wyze-lockwood-service.wyzecam.com/plugin/irrigation/quickrun"
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
            "source": "coordinator_cache",
            "network_request_performed": False,
        }

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
    ) -> None:
        """Start one enabled zone after validating safe bounds."""
        if duration_seconds < 1 or duration_seconds > 10_800:
            raise HomeAssistantError("Duration must be between 1 second and 180 minutes")
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
            if zone_number not in self.enabled_zone_numbers:
                raise HomeAssistantError(
                    f"Zone {zone_number} is not enabled on {self.device.nickname}"
                )
            if set((self.data or {}).get("endpoint_errors", [])) & {
                "iot",
                "schedule",
            }:
                raise HomeAssistantError("Current live sprinkler state is incomplete")
            watering = (self.data or {}).get("watering")
            if watering is None:
                raise HomeAssistantError(
                    "Current live sprinkler watering state is unavailable"
                )
            if (
                watering
                or self._command_pending_until > time.monotonic()
                or (
                    self._managed_run_task is not None
                    and not self._managed_run_task.done()
                )
            ):
                raise HomeAssistantError(
                    "A sprinkler run is already active; stop it before starting another"
                )
            try:
                provider_duration_seconds = max(60, duration_seconds)
                await self.service.start_zone(
                    self.device, zone_number, provider_duration_seconds
                )
            except Exception as err:
                raise HomeAssistantError(
                    f"Unable to start zone {zone_number}: {err}"
                ) from err
            self._set_command_pending(
                "start_zone",
                command_id=command_id,
                **self._command_zone_identity(zone_number),
                duration_seconds=duration_seconds,
                provider_duration_seconds=provider_duration_seconds,
                automatic_stop=duration_seconds < 60,
                scheduled_stop_at=(
                    (
                        datetime.now(timezone.utc)
                        + timedelta(seconds=duration_seconds)
                    ).isoformat()
                    if duration_seconds < 60
                    else None
                ),
            )
            await self.async_request_refresh()
            if duration_seconds < 60:
                self._managed_run_task = self.hass.async_create_task(
                    self._async_complete_managed_runs(
                        [
                            {
                                "zone_number": zone_number,
                                "duration": duration_seconds,
                            }
                        ],
                        command_id,
                        first_zone_started=True,
                    ),
                    f"Stop Wyze sprinkler zone {zone_number} after {duration_seconds} seconds",
                )

    async def async_force_full_refresh(self) -> None:
        """Refresh live state plus zone/config metadata immediately."""
        self._slow_refresh_count = 15
        await self.async_request_refresh()

    async def async_start_sequence(
        self,
        zone_runs: list[dict[str, Any]],
        command_id: str | None = None,
    ) -> None:
        """Start an ordered quick-run sequence using Wyze's native payload."""
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
            if watering is None:
                raise HomeAssistantError(
                    "Current live sprinkler watering state is unavailable"
                )
            if (
                watering
                or self._command_pending_until > time.monotonic()
                or (
                    self._managed_run_task is not None
                    and not self._managed_run_task.done()
                )
            ):
                raise HomeAssistantError(
                    "A sprinkler run is already active; stop it before starting another"
                )
            if any(run["duration"] < 60 for run in runs):
                first = runs[0]
                provider_duration_seconds = max(60, first["duration"])
                try:
                    await self.service.start_zone(
                        self.device,
                        first["zone_number"],
                        provider_duration_seconds,
                    )
                except Exception as err:
                    raise HomeAssistantError(
                        f"Unable to start zone {first['zone_number']}: {err}"
                    ) from err
                command_zones = [
                    {
                        **self._command_zone_identity(run["zone_number"]),
                        "duration_seconds": run["duration"],
                        "provider_duration_seconds": max(60, run["duration"]),
                    }
                    for run in runs
                ]
                self._set_command_pending(
                    "start_sequence",
                    command_id=command_id,
                    zones=command_zones,
                    managed_by_home_assistant=True,
                    current_zone_number=first["zone_number"],
                    scheduled_stop_at=(
                        datetime.now(timezone.utc)
                        + timedelta(seconds=first["duration"])
                    ).isoformat(),
                )
                await self.async_request_refresh()
                self._managed_run_task = self.hass.async_create_task(
                    self._async_complete_managed_runs(
                        runs, command_id, first_zone_started=True
                    ),
                    "Run Home Assistant-timed Wyze sprinkler sequence",
                )
                return
            await self.service._auth_lib.refresh_if_should()
            payload = {
                "device_id": self.device.mac,
                "nonce": str(int(time.time() * 1000)),
                "zone_runs": runs,
            }
            payload_text = json.dumps(payload, separators=(",", ":"))
            token = self.service._auth_lib.token.access_token
            headers = {
                "Accept-Encoding": "gzip",
                "Content-Type": "application/json",
                "User-Agent": "myapp",
                "appid": OLIVE_APP_ID,
                "appinfo": APP_INFO,
                "phoneid": PHONE_ID,
                "access_token": token,
                "signature2": olive_create_signature(payload_text, token),
            }
            try:
                response = await self.service._auth_lib.post(
                    QUICKRUN_URL, headers=headers, data=payload_text
                )
                check_for_errors_iot(self.service, response)
            except Exception as err:
                raise HomeAssistantError(
                    f"Unable to start sprinkler sequence: {err}"
                ) from err
            command_zones = [
                {
                    **self._command_zone_identity(run["zone_number"]),
                    "duration_seconds": run["duration"],
                }
                for run in runs
            ]
            self._set_command_pending(
                "start_sequence", command_id=command_id, zones=command_zones
            )
            await self.async_request_refresh()

    async def _async_complete_managed_runs(
        self,
        runs: list[dict[str, int]],
        command_id: str | None,
        *,
        first_zone_started: bool,
    ) -> None:
        """Time exact runs in Home Assistant and stop between every zone."""
        current_task = asyncio.current_task()
        try:
            for index, run in enumerate(runs):
                if index > 0 or not first_zone_started:
                    async with self._command_lock:
                        provider_duration_seconds = max(60, run["duration"])
                        await self.service.start_zone(
                            self.device,
                            run["zone_number"],
                            provider_duration_seconds,
                        )
                        self._set_command_pending(
                            "start_sequence",
                            command_id=command_id,
                            zones=[
                                {
                                    **self._command_zone_identity(run["zone_number"]),
                                    "duration_seconds": run["duration"],
                                    "provider_duration_seconds": provider_duration_seconds,
                                }
                            ],
                            managed_by_home_assistant=True,
                            current_zone_number=run["zone_number"],
                            scheduled_stop_at=(
                                datetime.now(timezone.utc)
                                + timedelta(seconds=run["duration"])
                            ).isoformat(),
                        )
                        await self.async_request_refresh()
                await asyncio.sleep(run["duration"])
                await self._async_managed_stop(command_id)
                await self._async_wait_for_idle()
        except asyncio.CancelledError:
            raise
        except Exception as err:
            _LOGGER.error(
                "Home Assistant-timed sprinkler run failed for %s: %s",
                self.device.nickname,
                err,
            )
            try:
                await self._async_managed_stop(command_id)
            except Exception as stop_err:
                _LOGGER.error(
                    "Unable to stop failed Home Assistant-timed sprinkler run for %s: %s",
                    self.device.nickname,
                    stop_err,
                )
        finally:
            if self._managed_run_task is current_task:
                self._managed_run_task = None

    async def _async_managed_stop(self, command_id: str | None) -> None:
        """Issue the provider stop without cancelling the task that owns the timer."""
        async with self._command_lock:
            await self.service.stop_running_schedule(self.device)
            self._set_command_pending(
                "stop",
                command_id=command_id,
                automatic_stop=True,
            )
            await self.async_request_refresh()

    async def _async_wait_for_idle(self) -> None:
        """Require controller-reported idle before advancing a managed sequence."""
        for _ in range(30):
            await self.async_refresh()
            if (self.data or {}).get("watering") is False and (
                self.data or {}
            ).get("active_zone_number") is None:
                return
            await asyncio.sleep(1)
        raise HomeAssistantError(
            "Controller idle was not verified after the automatic stop"
        )

    async def async_stop(self, command_id: str | None = None) -> None:
        """Stop the controller's currently running schedule."""
        managed_task = self._managed_run_task
        if managed_task is not None and managed_task is not asyncio.current_task():
            managed_task.cancel()
            try:
                await managed_task
            except asyncio.CancelledError:
                pass
        async with self._command_lock:
            try:
                await self.service.stop_running_schedule(self.device)
            except Exception as err:
                raise HomeAssistantError(f"Unable to stop sprinkler: {err}") from err
            self._set_command_pending("stop", command_id=command_id)
            await self.async_request_refresh()

    async def async_shutdown(self) -> None:
        """Fail closed by stopping any HA-timed run during integration unload."""
        if self._managed_run_task is not None:
            await self.async_stop(command_id="integration-unload")


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
