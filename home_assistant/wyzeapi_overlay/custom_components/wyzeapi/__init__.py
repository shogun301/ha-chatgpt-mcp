"""The Wyze Home Assistant Integration."""
# SPDX-License-Identifier: Apache-2.0
# Derived from SecKatie/ha-wyzeapi; modified for bounded sprinkler services.

from __future__ import annotations

import logging
import math
import re

from aiohttp.client_exceptions import ClientConnectorError
import voluptuous as vol
from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry, ConfigEntryNotReady, SOURCE_IMPORT
from homeassistant.const import ATTR_DEVICE_ID, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.check_config import HomeAssistantConfig
import homeassistant.helpers.config_validation as cv
from wyzeapy import Wyzeapy
from wyzeapy.exceptions import AccessTokenError
from wyzeapy.wyze_auth_lib import Token

from .const import (
    ACCESS_TOKEN,
    API_KEY,
    BULB_LOCAL_CONTROL,
    CONF_CLIENT,
    DEFAULT_LOCAL_CONTROL,
    DOMAIN,
    KEY_ID,
    REFRESH_TIME,
    REFRESH_TOKEN,
    SERVICE_GET_SPRINKLER_CAPABILITIES,
    SERVICE_GET_SPRINKLER_SCHEDULE_RUNS,
    SERVICE_GET_SPRINKLER_SCHEDULES,
    SERVICE_GET_SPRINKLER_SNAPSHOT,
    SERVICE_REFRESH_SPRINKLER,
    SERVICE_RUN_SPRINKLER_SEQUENCE,
    SERVICE_RUN_SPRINKLER_ZONE,
    SERVICE_STOP_SPRINKLER,
    WYZE_NOTIFICATION_TOGGLE,
)
from .coordinator import WyzeLockBoltCoordinator
from .irrigation import (
    async_setup_irrigation_coordinators,
    coordinator_for_device_id,
)
from .irrigation_data import duration_seconds_from_fields
from .token_manager import TokenManager

PLATFORMS = [
    "light",
    "switch",
    "fan",
    "lock",
    "climate",
    "alarm_control_panel",
    "sensor",
    "siren",
    "cover",
    "number",
    "button",
    "camera",
]  # Fixme: Re add scene
_LOGGER = logging.getLogger(__name__)


# noinspection PyUnusedLocal
async def async_setup(
    hass: HomeAssistant, config: HomeAssistantConfig, discovery_info=None
):
    # pylint: disable=unused-argument
    """Set up the WyzeApi domain."""
    if hass.config_entries.async_entries(DOMAIN):
        _LOGGER.debug(
            "Nothing to import from configuration.yaml, loading from Integrations",
        )
        return True

    # noinspection SpellCheckingInspection
    domainconfig = config.get(DOMAIN)
    # pylint: disable=logging-not-lazy
    _LOGGER.debug(
        "Importing config information for %s from configuration.yml"
        % domainconfig[CONF_USERNAME]
    )
    if hass.config_entries.async_entries(DOMAIN):
        _LOGGER.debug("Found existing config entries")
        for entry in hass.config_entries.async_entries(DOMAIN):
            if entry:
                entry_data = entry.as_dict().get("data")
                hass.config_entries.async_update_entry(
                    entry,
                    data=entry_data,
                )
                break
    else:
        _LOGGER.debug("Creating new config entry")
        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN,
                context={"source": SOURCE_IMPORT},
                data={
                    CONF_USERNAME: domainconfig[CONF_USERNAME],
                    CONF_PASSWORD: domainconfig[CONF_PASSWORD],
                    ACCESS_TOKEN: domainconfig[ACCESS_TOKEN],
                    REFRESH_TOKEN: domainconfig[REFRESH_TOKEN],
                    REFRESH_TIME: domainconfig[REFRESH_TIME],
                    KEY_ID: domainconfig[KEY_ID],
                    API_KEY: domainconfig[API_KEY],
                },
            )
        )
    return True


# noinspection DuplicatedCode
async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up Wyze Home Assistant Integration from a config entry."""

    hass.data.setdefault(DOMAIN, {})

    key_id = config_entry.data.get(KEY_ID)
    api_key = config_entry.data.get(API_KEY)

    client = await Wyzeapy.create()
    token = None
    if config_entry.data.get(ACCESS_TOKEN):
        token = Token(
            config_entry.data.get(ACCESS_TOKEN),
            config_entry.data.get(REFRESH_TOKEN),
            float(config_entry.data.get(REFRESH_TIME)),
        )
    a_tkn_manager = TokenManager(hass, config_entry)
    client.register_for_token_callback(a_tkn_manager.token_callback)
    # We should probably try/catch here to invalidate the login credentials and throw a notification if we cannot get
    # a login with the token
    try:
        await client.login(
            config_entry.data.get(CONF_USERNAME),
            config_entry.data.get(CONF_PASSWORD),
            key_id,
            api_key,
            token,
        )
    except ClientConnectorError as e:
        raise ConfigEntryNotReady("Unable to login due to network issues.") from e
    except AccessTokenError as e:
        _LOGGER.error(
            "Wyzeapi: Could not login. Please re-login through integration configuration"
        )
        _LOGGER.error(e)
        raise ConfigEntryAuthFailed("Unable to login, please re-login.") from None

    hass.data[DOMAIN][config_entry.entry_id] = {
        CONF_CLIENT: client,
        "key_id": KEY_ID,
        "api_key": API_KEY,
        "coordinators": {},
    }
    await async_setup_irrigation_coordinators(hass, config_entry.entry_id, client)
    async_register_irrigation_services(hass)
    await setup_coordinators(hass, config_entry, client)

    options_dict = {
        BULB_LOCAL_CONTROL: config_entry.options.get(
            BULB_LOCAL_CONTROL, DEFAULT_LOCAL_CONTROL
        )
    }
    hass.config_entries.async_update_entry(config_entry, options=options_dict)

    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    mac_addresses = await client.unique_device_ids

    mac_addresses.add(WYZE_NOTIFICATION_TOGGLE)

    hms_service = await client.hms_service
    hms_id = hms_service.hms_id
    if hms_id is not None:
        mac_addresses.add(hms_id)

    device_registry = dr.async_get(hass)
    for device in dr.async_entries_for_config_entry(
        device_registry, config_entry.entry_id
    ):
        for identifier in device.identifiers:
            # domain has to remain here. If it is removed the integration will remove all entities for not being in
            # the mac address list each boot.
            domain, mac = identifier
            if mac not in mac_addresses:
                _LOGGER.warning(
                    "%s is not in the mac_addresses list, removing the entry", mac
                )
                device_registry.async_remove_device(device.id)
    return True


def _single_device_id(call: ServiceCall) -> str:
    """Return exactly one targeted Home Assistant device ID."""
    value = call.data.get(ATTR_DEVICE_ID)
    device_ids = value if isinstance(value, list) else [value]
    device_ids = [item for item in device_ids if isinstance(item, str) and item]
    if len(device_ids) != 1:
        raise HomeAssistantError("Select exactly one Wyze sprinkler controller")
    return device_ids[0]


def _strict_zone_number(value) -> int:
    """Validate a zone without truncating a physical target."""
    if isinstance(value, bool):
        raise vol.Invalid("zone must be an exact integer")
    try:
        number = float(value)
    except (TypeError, ValueError) as err:
        raise vol.Invalid("zone must be an exact integer") from err
    if not number.is_integer() or number < 1 or number > 8:
        raise vol.Invalid("zone must be an exact integer from 1 through 8")
    return int(number)


def _bounded_duration(value) -> float:
    """Validate a physical watering duration."""
    if isinstance(value, bool):
        raise vol.Invalid("duration must be a number from 1 through 180")
    try:
        number = float(value)
    except (TypeError, ValueError) as err:
        raise vol.Invalid("duration must be a number from 1 through 180") from err
    if not math.isfinite(number) or number < 1 or number > 180:
        raise vol.Invalid("duration must be a number from 1 through 180")
    return number


def _bounded_duration_seconds(value) -> int:
    """Validate an exact physical watering duration in seconds."""
    try:
        return duration_seconds_from_fields({"duration_seconds": value})
    except ValueError as err:
        raise vol.Invalid(str(err)) from err


def _require_one_duration(value):
    """Require exactly one backward-compatible duration field."""
    try:
        duration_seconds_from_fields(value)
    except ValueError as err:
        raise vol.Invalid(str(err)) from err
    return value


def _bounded_history_limit(value) -> int:
    """Validate an exact schedule-run result limit."""
    if isinstance(value, bool):
        raise vol.Invalid("limit must be an exact integer from 1 through 100")
    try:
        number = float(value)
    except (TypeError, ValueError) as err:
        raise vol.Invalid("limit must be an exact integer from 1 through 100") from err
    if not number.is_integer() or number < 1 or number > 100:
        raise vol.Invalid("limit must be an exact integer from 1 through 100")
    return int(number)


def _bounded_command_id(value) -> str:
    """Validate a caller correlation ID without accepting opaque content."""
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value
    ):
        raise vol.Invalid(
            "command_id must contain 1 through 64 letters, numbers, underscores, or hyphens"
        )
    return value


def async_register_irrigation_services(hass: HomeAssistant) -> None:
    """Register bounded sprinkler commands and exact-target response services."""

    async def run_zone(call: ServiceCall) -> None:
        coordinator = coordinator_for_device_id(hass, _single_device_id(call))
        duration_seconds = duration_seconds_from_fields(call.data)
        await coordinator.async_start_zone(
            int(call.data["zone"]),
            duration_seconds,
            command_id=call.data.get("command_id"),
        )

    async def run_sequence(call: ServiceCall) -> None:
        coordinator = coordinator_for_device_id(hass, _single_device_id(call))
        await coordinator.async_start_sequence(
            call.data["zones"], command_id=call.data.get("command_id")
        )

    async def stop(call: ServiceCall) -> None:
        coordinator = coordinator_for_device_id(hass, _single_device_id(call))
        await coordinator.async_stop(command_id=call.data.get("command_id"))

    async def refresh(call: ServiceCall) -> None:
        coordinator = coordinator_for_device_id(hass, _single_device_id(call))
        await coordinator.async_force_full_refresh()

    async def get_snapshot(call: ServiceCall) -> dict:
        device_id = _single_device_id(call)
        coordinator = coordinator_for_device_id(hass, device_id)
        return {"device_id": device_id, **coordinator.sprinkler_snapshot()}

    async def get_schedule_runs(call: ServiceCall) -> dict:
        device_id = _single_device_id(call)
        coordinator = coordinator_for_device_id(hass, device_id)
        response = await coordinator.async_get_schedule_runs(call.data["limit"])
        return {"device_id": device_id, **response}

    async def get_schedules(call: ServiceCall) -> dict:
        device_id = _single_device_id(call)
        coordinator = coordinator_for_device_id(hass, device_id)
        response = await coordinator.async_get_schedules()
        return {"device_id": device_id, **response}

    async def get_capabilities(call: ServiceCall) -> dict:
        device_id = _single_device_id(call)
        coordinator = coordinator_for_device_id(hass, device_id)
        return {"device_id": device_id, **coordinator.sprinkler_capabilities()}

    device_schema = vol.All(cv.ensure_list, [cv.string])
    target_only_schema = vol.Schema({vol.Required(ATTR_DEVICE_ID): device_schema})
    if not hass.services.has_service(DOMAIN, SERVICE_RUN_SPRINKLER_ZONE):
        hass.services.async_register(
            DOMAIN,
            SERVICE_RUN_SPRINKLER_ZONE,
            run_zone,
            schema=vol.All(
                vol.Schema(
                    {
                        vol.Required(ATTR_DEVICE_ID): device_schema,
                        vol.Required("zone"): _strict_zone_number,
                        vol.Optional("duration_minutes"): _bounded_duration,
                        vol.Optional("duration_seconds"): _bounded_duration_seconds,
                        vol.Optional("command_id"): _bounded_command_id,
                    }
                ),
                _require_one_duration,
            ),
        )
        hass.services.async_register(
            DOMAIN,
            SERVICE_RUN_SPRINKLER_SEQUENCE,
            run_sequence,
            schema=vol.Schema(
                {
                    vol.Required(ATTR_DEVICE_ID): device_schema,
                    vol.Required("zones"): vol.All(
                        [
                            vol.All(
                                vol.Schema(
                                    {
                                        vol.Required("zone"): _strict_zone_number,
                                        vol.Optional(
                                            "duration_minutes"
                                        ): _bounded_duration,
                                        vol.Optional(
                                            "duration_seconds"
                                        ): _bounded_duration_seconds,
                                    },
                                    extra=vol.PREVENT_EXTRA,
                                ),
                                _require_one_duration,
                            )
                        ],
                        vol.Length(min=1, max=8),
                    ),
                    vol.Optional("command_id"): _bounded_command_id,
                }
            ),
        )
        stop_schema = vol.Schema(
            {
                vol.Required(ATTR_DEVICE_ID): device_schema,
                vol.Optional("command_id"): _bounded_command_id,
            }
        )
        hass.services.async_register(
            DOMAIN, SERVICE_STOP_SPRINKLER, stop, schema=stop_schema
        )
        hass.services.async_register(
            DOMAIN, SERVICE_REFRESH_SPRINKLER, refresh, schema=target_only_schema
        )

    response_services = (
        (SERVICE_GET_SPRINKLER_SNAPSHOT, get_snapshot, target_only_schema),
        (
            SERVICE_GET_SPRINKLER_SCHEDULE_RUNS,
            get_schedule_runs,
            vol.Schema(
                {
                    vol.Required(ATTR_DEVICE_ID): device_schema,
                    vol.Optional("limit", default=100): _bounded_history_limit,
                }
            ),
        ),
        (SERVICE_GET_SPRINKLER_SCHEDULES, get_schedules, target_only_schema),
        (
            SERVICE_GET_SPRINKLER_CAPABILITIES,
            get_capabilities,
            target_only_schema,
        ),
    )
    for service_name, handler, schema in response_services:
        if not hass.services.has_service(DOMAIN, service_name):
            hass.services.async_register(
                DOMAIN,
                service_name,
                handler,
                schema=schema,
                supports_response=SupportsResponse.ONLY,
            )


async def options_update_listener(hass: HomeAssistant, config_entry: ConfigEntry):
    """Handle options update."""
    _LOGGER.debug("Updated options")
    entry_data = config_entry.as_dict().get("data")
    hass.config_entries.async_update_entry(
        config_entry,
        data=entry_data,
    )
    _LOGGER.debug("Reload entry: " + config_entry.entry_id)
    await hass.config_entries.async_reload(config_entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
    for coordinator in entry_data.get(IRRIGATION_COORDINATORS, {}).values():
        await coordinator.async_shutdown()
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unloaded:
        return False
    hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if not hass.data.get(DOMAIN):
        for service in (
            SERVICE_RUN_SPRINKLER_ZONE,
            SERVICE_RUN_SPRINKLER_SEQUENCE,
            SERVICE_STOP_SPRINKLER,
            SERVICE_REFRESH_SPRINKLER,
            SERVICE_GET_SPRINKLER_SNAPSHOT,
            SERVICE_GET_SPRINKLER_SCHEDULE_RUNS,
            SERVICE_GET_SPRINKLER_SCHEDULES,
            SERVICE_GET_SPRINKLER_CAPABILITIES,
        ):
            hass.services.async_remove(DOMAIN, service)
    return True


async def setup_coordinators(
    hass: HomeAssistant, config_entry: ConfigEntry, client: Wyzeapy
):
    """Set up coordinators for Wyze devices that require Bluetooth."""
    # Check if Bluetooth is active and functioning
    if bluetooth.async_scanner_count(hass, connectable=True) == 0:
        _LOGGER.info(
            "Bluetooth is not active or no scanners available. Skipping WyzeLockBoltCoordinator setup."
        )
        return

    lock_service = await client.lock_service
    for lock in await lock_service.get_locks():
        if lock.product_model == "YD_BT1":
            coordinators = hass.data[DOMAIN][config_entry.entry_id].setdefault(
                "coordinators", {}
            )
            coordinators[lock.mac] = WyzeLockBoltCoordinator(
                hass, lock_service, lock
            )
            await coordinators[lock.mac].update_lock_info()
