"""Platform for sensor integration."""
# SPDX-License-Identifier: Apache-2.0
# Derived from SecKatie/ha-wyzeapi; modified to expose allowlisted zone metadata.

from collections.abc import Callable
import datetime
import json
import logging
from typing import Any

from wyzeapy import Wyzeapy
from wyzeapy.services.air_purifier_service import AirPurifier
from wyzeapy.services.camera_service import Camera
from wyzeapy.services.lock_service import Lock
from wyzeapy.services.switch_service import Switch, SwitchUsageService

from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    ATTR_ATTRIBUTION,
    PERCENTAGE,
    EntityCategory,
    UnitOfEnergy,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
import homeassistant.helpers.entity_registry as er
from homeassistant.helpers.event import (
    async_track_state_change_event,
    async_track_time_change,
)

from .const import (
    AIR_PURIFIER_UPDATED,
    CAMERA_UPDATED,
    CONF_CLIENT,
    DOMAIN,
    LOCK_UPDATED,
    RESET_BUTTON_PRESSED,
)
from .camera_status import async_get_probed_cameras
from .irrigation import (
    WyzeIrrigationCoordinator,
    WyzeIrrigationCoordinatorEntity,
    irrigation_coordinators,
)
from .irrigation_data import zone_entity_attributes
from .token_manager import token_exception_handler

_LOGGER = logging.getLogger(__name__)
ATTRIBUTION = "Data provided by Wyze"
CAMERAS_WITH_BATTERIES = ["WVOD1", "HL_WCO2", "AN_RSCW", "GW_BE1"]
OUTDOOR_PLUGS = ["WLPPO"]


@token_exception_handler
async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: Callable[[list[Any], bool], None],
) -> None:
    """This function sets up the config_entry.

    :param hass: Home Assistant instance
    :param config_entry: The current config_entry
    :param async_add_entities: This function adds entities to the config_entry
    :return:
    """
    _LOGGER.debug("""Creating new WyzeApi sensor component""")
    client: Wyzeapy = hass.data[DOMAIN][config_entry.entry_id][CONF_CLIENT]

    # Get the list of locks so that we can create lock and keypad battery sensors
    lock_service = await client.lock_service
    camera_service = await client.camera_service
    switch_usage_service = await client.switch_usage_service
    air_purifier_service = await client.air_purifier_service

    locks = await lock_service.get_locks()
    sensors = []
    for lock in locks:
        sensors.append(WyzeLockBatterySensor(lock, WyzeLockBatterySensor.LOCK_BATTERY))
        sensors.append(
            WyzeLockBatterySensor(lock, WyzeLockBatterySensor.KEYPAD_BATTERY)
        )

    cameras = await async_get_probed_cameras(hass, config_entry, camera_service)
    sensors.extend(
        [
            WyzeCameraBatterySensor(camera)
            for camera in cameras
            if camera.product_model in CAMERAS_WITH_BATTERIES
        ]
    )

    plugs = await switch_usage_service.get_switches()
    for plug in plugs:
        if plug.product_model in OUTDOOR_PLUGS:
            sensors.append(WyzePlugEnergySensor(plug, switch_usage_service))
            sensors.append(WyzePlugDailyEnergySensor(plug))

    air_purifiers = await air_purifier_service.get_air_purifiers()
    for air_purifier in air_purifiers:
        sensors.append(WyzeAirPurifierAQISensor(air_purifier))
        sensors.append(WyzeAirPurifierHourlyMaxAQISensor(air_purifier))

    # Create sensor entities for each irrigation device
    for coordinator in irrigation_coordinators(hass, config_entry.entry_id):
        sensors.extend(
            [
                WyzeIrrigationStatus(coordinator),
                WyzeIrrigationActiveZone(coordinator),
                WyzeIrrigationRemainingTime(coordinator),
                WyzeIrrigationLastRun(coordinator),
                WyzeIrrigationConfiguration(coordinator),
                WyzeIrrigationRSSI(coordinator),
                WyzeIrrigationIP(coordinator),
                WyzeIrrigationSSID(coordinator),
            ]
        )
        sensors.extend(
            WyzeIrrigationZoneMetadata(coordinator, zone)
            for zone in (coordinator.data or {}).get("zones", [])
        )

    async_add_entities(sensors, True)


class WyzeLockBatterySensor(SensorEntity):
    """Representation of a Wyze Lock or Lock Keypad Battery."""

    @property
    def enabled(self):
        """Return if the sensor is enabled."""
        return self._enabled

    LOCK_BATTERY = "lock_battery"
    KEYPAD_BATTERY = "keypad_battery"

    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_should_poll = False

    def __init__(self, lock, battery_type) -> None:
        """Initialize the sensor."""
        self._enabled = None
        self._lock = lock
        self._battery_type = battery_type
        # make the battery unavailable by default, this will be toggled after the first update from the battery entity that
        # has battery data.
        self._available = False

    @callback
    def handle_lock_update(self, lock: Lock) -> None:
        """Helper function to Enable lock when Keypad has a battery.

        Make it avaliable when either the lock battery or keypad battery exists.
        """
        self._lock = lock
        if self._lock.raw_dict.get("power") and self._battery_type == self.LOCK_BATTERY:
            self._available = True
        if (
            self._lock.raw_dict.get("keypad", {}).get("power")
            and self._battery_type == self.KEYPAD_BATTERY
        ):
            if self.enabled is False:
                self.enabled = True
            self._available = True
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Add listener on startup."""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{LOCK_UPDATED}-{self._lock.mac}",
                self.handle_lock_update,
            )
        )

    @property
    def name(self) -> str:
        """Name of the Sensor."""
        battery_type = self._battery_type.replace("_", " ").title()
        return f"{self._lock.nickname} {battery_type}"

    @property
    def unique_id(self):
        """Unique ID of the sensor."""
        return f"{self._lock.nickname}.{self._battery_type}"

    @property
    def available(self) -> bool:
        """Return if the sensor is available."""
        return self._available

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity should be enabled."""
        if self._battery_type == self.KEYPAD_BATTERY:
            # The keypad battery may not be available if the lock has no keypad
            return False
        # The battery voltage will always be available for the lock
        return True

    @property
    def device_info(self):
        """Return the device info."""
        return {
            "identifiers": {(DOMAIN, self._lock.mac)},
            "connections": {
                (
                    dr.CONNECTION_NETWORK_MAC,
                    self._lock.mac,
                )
            },
            "name": f"{self._lock.nickname}.{self._battery_type}",
        }

    @property
    def extra_state_attributes(self):
        """Return device attributes of the entity."""
        return {
            ATTR_ATTRIBUTION: ATTRIBUTION,
            "device model": f"{self._lock.product_model}.{self._battery_type}",
        }

    @property
    def native_value(self):
        """Return the state of the device."""
        if self._battery_type == self.LOCK_BATTERY:
            return str(self._lock.raw_dict.get("power"))
        if self._battery_type == self.KEYPAD_BATTERY:
            return str(self._lock.raw_dict.get("keypad", {}).get("power"))
        return 0

    @enabled.setter
    def enabled(self, value):
        self._enabled = value


class WyzeCameraBatterySensor(SensorEntity):
    """Representation of a Wyze Camera Battery."""

    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_should_poll = False

    def __init__(self, camera) -> None:
        """Initialize the sensor."""
        self._camera = camera

    @callback
    def handle_camera_update(self, camera: Camera) -> None:
        """Handle camera updates."""
        self._camera = camera
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Add listener on startup."""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{CAMERA_UPDATED}-{self._camera.mac}",
                self.handle_camera_update,
            )
        )

    @property
    def name(self) -> str:
        """Return the entity name."""
        return f"{self._camera.nickname} Battery"

    @property
    def unique_id(self):
        """Unique ID of the sensor."""
        return f"{self._camera.nickname}.battery"

    @property
    def device_info(self):
        """Return the device info."""
        return {
            "identifiers": {(DOMAIN, self._camera.mac)},
            "connections": {
                (
                    dr.CONNECTION_NETWORK_MAC,
                    self._camera.mac,
                )
            },
            "name": self._camera.nickname,
            "model": self._camera.product_model,
            "manufacturer": "WyzeLabs",
        }

    @property
    def extra_state_attributes(self):
        """Return device attributes of the entity."""
        return {
            ATTR_ATTRIBUTION: ATTRIBUTION,
            "device model": f"{self._camera.product_model}.battery",
        }

    @property
    def native_value(self):
        """Return the value of the sensor."""
        return self._camera.device_params.get("electricity")


class WyzePlugEnergySensor(RestoreSensor):
    """Respresents an Outdoor Plug Total Energy Sensor."""

    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_suggested_display_precision = 3
    _attr_should_poll = False
    _attr_name = "Total Energy Usage"
    _previous_hour = None
    _previous_value = None
    _past_hours_previous_value = None
    _current_value = 0
    _past_hours_value = 0
    _hourly_energy_usage_added = 0

    def __init__(
        self, switch: Switch, switch_usage_service: SwitchUsageService
    ) -> None:
        """Initialize an energy sensor."""
        self._switch = switch
        self._switch_usage_service = switch_usage_service
        self._switch.usage_history = None  # type: ignore[attr-defined]

    @property
    def unique_id(self):
        """Get the unique ID of the sensor."""
        return f"{self._switch.nickname}.energy-{self._switch.mac}"

    @property
    def device_info(self):
        """Return the device info."""
        return {
            "identifiers": {(DOMAIN, self._switch.mac)},
            "name": self._switch.nickname,
        }

    def update_energy(self):
        """Update the energy sensor."""
        _now = int(datetime.datetime.now(datetime.UTC).hour)
        self._hourly_energy_usage_added = 0

        if (
            self._switch.usage_history and len(self._switch.usage_history) > 0
        ):  # Confirm there is data
            _raw_data = self._switch.usage_history
            _LOGGER.debug(_raw_data)
            _current_day_list = json.loads(_raw_data[0]["data"])
            if _now == 0:  # Handle rolling to the next UTC day
                self._past_hours_value = _current_day_list[23] / 1000
                if len(_raw_data) > 1:  # New Day's value
                    _next_day_list = json.loads(_raw_data[1]["data"])
                    self._current_value = _next_day_list[_now] / 1000
                else:
                    self._current_value = 0
            else:
                self._past_hours_value = _current_day_list[_now - 1] / 1000
                self._current_value = _current_day_list[_now] / 1000

            # Set inital values to current values on startup.
            # Has to be done after we check for current or next UTC day
            if self._previous_hour is None:
                self._previous_hour = _now
            if self._past_hours_previous_value is None:
                self._past_hours_previous_value = self._past_hours_value
            if self._previous_value is None:
                self._previous_value = self._current_value

            if _now != self._previous_hour:  # New Hour
                if self._past_hours_value > self._previous_value:
                    self._hourly_energy_usage_added = (
                        self._past_hours_value - self._previous_value
                    )
                self._hourly_energy_usage_added += self._current_value
                self._previous_value = self._current_value
                self._previous_hour = _now
                self._past_hours_previous_value = self._past_hours_value

            else:  # Current Hour
                if self._current_value > self._previous_value:
                    self._hourly_energy_usage_added += round(
                        self._current_value - self._previous_value, 3
                    )
                    self._previous_value = self._current_value

                if self._past_hours_value > self._past_hours_previous_value:
                    self._hourly_energy_usage_added += round(
                        self._past_hours_value - self._past_hours_previous_value, 3
                    )
                    self._past_hours_previous_value = self._past_hours_value

            _LOGGER.debug(
                "Total Value Added to device %s is %s",
                self._switch.mac,
                self._hourly_energy_usage_added,
            )

        return self._hourly_energy_usage_added

    @callback
    def async_update_callback(self, switch: Switch):
        """Update the sensor's state."""
        self._switch = switch
        self.update_energy()
        self._attr_native_value += self._hourly_energy_usage_added
        self.async_write_ha_state()

    @callback
    def reset_energy_use(self, switch: Switch):
        """Reset the Energy Usage."""
        _LOGGER.debug("Resetting Usage of %s to 0", self._switch.nickname)
        self._switch = switch
        self._attr_native_value = 0
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Register Updater for the sensor and get previous data."""
        state = await self.async_get_last_sensor_data()
        if state:
            self._attr_native_value = state.native_value
        else:
            self._attr_native_value = 0
        self._switch.callback_function = self.async_update_callback
        self._switch_usage_service.register_updater(
            self._switch, 120
        )  # Every 2 minutes seems to work fine, probably could be longer
        await self._switch_usage_service.start_update_manager()

        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{RESET_BUTTON_PRESSED}-{self._switch.mac}",
                self.reset_energy_use,
            )
        )

    async def async_will_remove_from_hass(self) -> None:
        """Remove updater."""
        self._switch_usage_service.unregister_updater(self._switch)


class WyzePlugDailyEnergySensor(RestoreSensor):
    """Respresents an Outdoor Plug Daily Energy Sensor."""

    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_suggested_display_precision = 3
    _attr_name = "Daily Energy Usage"

    def __init__(self, switch: Switch) -> None:
        """Initialize a daily energy sensor."""
        self._switch = switch

    @property
    def unique_id(self):
        """Get the unique ID of the sensor."""
        return f"{self._switch.nickname}.daily_energy-{self._switch.mac}"

    @property
    def should_poll(self) -> bool:
        """No polling needed."""
        return False

    @property
    def device_info(self):
        """Return the device info."""
        return {
            "identifiers": {(DOMAIN, self._switch.mac)},
            "name": self._switch.nickname,
        }

    @callback
    def _update_daily_sensor(self, event):
        """Update the sensor when the total sensor updates."""
        event_data = event.data
        new_state = event_data["new_state"]
        old_state = event_data["old_state"]

        if not old_state or not new_state:
            return

        updated_energy = float(new_state.state) - float(old_state.state)
        self._attr_native_value += updated_energy
        self.async_write_ha_state()

    async def _async_reset_at_midnight(self, now: datetime) -> None:
        """Reset the daily sensor."""
        self._attr_native_value = 0
        _LOGGER.debug("Resetting daily energy sensor %s to 0", self._switch.mac)
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Get previous data and add listeners."""

        state = await self.async_get_last_sensor_data()
        if state:
            self._attr_native_value = state.native_value
        else:
            self._attr_native_value = 0

        registry = er.async_get(self.hass)
        entity_id_total_sensor = registry.async_get_entity_id(
            "sensor", DOMAIN, f"{self._switch.nickname}.energy-{self._switch.mac}"
        )

        self.async_on_remove(
            async_track_state_change_event(
                self.hass, [entity_id_total_sensor], self._update_daily_sensor
            )
        )

        self.async_on_remove(
            async_track_time_change(
                self.hass, self._async_reset_at_midnight, hour=0, minute=0, second=0
            )
        )


class WyzeIrrigationBaseSensor(WyzeIrrigationCoordinatorEntity, SensorEntity):
    """Base class for Wyze Irrigation sensors."""

    def __init__(self, coordinator: WyzeIrrigationCoordinator) -> None:
        """Initialize the irrigation base sensor."""
        super().__init__(coordinator)
        self._device = coordinator.device


class WyzeIrrigationStatus(WyzeIrrigationBaseSensor):
    """Controller connectivity and live watering status."""

    _attr_name = "Watering status"
    _attr_icon = "mdi:sprinkler-variant"

    @property
    def unique_id(self) -> str:
        return f"{self._device.mac}-watering-status"

    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success

    @property
    def native_value(self) -> str:
        data = self.coordinator.data or {}
        if data.get("connected") is None:
            return "unknown"
        if data.get("connected") is False:
            return "offline"
        if data.get("watering") is None:
            return "unknown"
        return "watering" if data["watering"] else "idle"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self.coordinator.data or {}
        return {
            "active_zone_number": data.get("active_zone_number"),
            "active_zone_name": data.get("active_zone_name"),
            "active_zone_id": data.get("active_zone_id"),
            "watering_evidence_type": data.get("watering_state", {}).get(
                "evidence_type"
            ),
            "remaining_seconds": data.get("remaining_seconds"),
            "remaining_evidence_type": data.get("remaining_evidence_type"),
            "started_at": data.get("started_at"),
            "expected_end": data.get("expected_end"),
            "expected_end_evidence_type": data.get(
                "expected_end_evidence_type"
            ),
            "iot_state": data.get("iot_state"),
            "iot_state_updated_at": data.get("iot_state_updated_at"),
            "updated_at": data.get("updated_at"),
            "partial_update": data.get("partial"),
            "endpoint_errors": data.get("endpoint_errors"),
            "source": "wyze_cloud_schedule_and_zone_state",
            "observed_at": data.get("updated_at"),
            "physical_state_verified": False,
            "command_pending": data.get("command_pending"),
            "command_status": data.get("command_status"),
        }


class WyzeIrrigationActiveZone(WyzeIrrigationBaseSensor):
    """Currently watering zone."""

    _attr_name = "Active zone"
    _attr_icon = "mdi:water-pump"

    @property
    def unique_id(self) -> str:
        return f"{self._device.mac}-active-zone"

    @property
    def native_value(self) -> str | None:
        return (self.coordinator.data or {}).get("active_zone_name")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "zone_number": (self.coordinator.data or {}).get("active_zone_number"),
            "zone_id": (self.coordinator.data or {}).get("active_zone_id"),
            "evidence_type": (self.coordinator.data or {})
            .get("watering_state", {})
            .get("evidence_type"),
        }


class WyzeIrrigationRemainingTime(WyzeIrrigationBaseSensor):
    """Remaining duration for the current run."""

    _attr_name = "Watering time remaining"
    _attr_icon = "mdi:timer-sand"
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_native_unit_of_measurement = UnitOfTime.SECONDS

    @property
    def unique_id(self) -> str:
        return f"{self._device.mac}-watering-remaining"

    @property
    def native_value(self) -> int | None:
        value = (self.coordinator.data or {}).get("remaining_seconds")
        return int(value) if value is not None else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "evidence_type": (self.coordinator.data or {}).get(
                "remaining_evidence_type"
            ),
            "physical_state_verified": False,
        }


class WyzeIrrigationLastRun(WyzeIrrigationBaseSensor):
    """Latest completed watering event plus bounded recent history."""

    _attr_name = "Last watering"
    _attr_icon = "mdi:history"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    @property
    def unique_id(self) -> str:
        return f"{self._device.mac}-last-watering"

    @property
    def native_value(self) -> datetime.datetime | None:
        value = (self.coordinator.data or {}).get("last_run_at")
        try:
            return datetime.datetime.fromisoformat(value) if value else None
        except (TypeError, ValueError):
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"recent_runs": list((self.coordinator.data or {}).get("recent_runs", []))[:10]}


class WyzeIrrigationConfiguration(WyzeIrrigationBaseSensor):
    """Read-only Wyze schedule and weather-skip configuration."""

    _attr_name = "Configuration"
    _attr_icon = "mdi:cog-outline"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def unique_id(self) -> str:
        return f"{self._device.mac}-configuration"

    @property
    def native_value(self) -> str:
        value = (self.coordinator.data or {}).get("config", {}).get("enable_schedules")
        if value in (True, 1, "1", "true", "on", "enabled"):
            return "schedules enabled"
        if value in (False, 0, "0", "false", "off", "disabled"):
            return "schedules disabled"
        return "unknown"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        config = (self.coordinator.data or {}).get("config", {})
        attributes = {}
        for key in (
            "wiring",
            "sensor",
            "enable_schedules",
            "notification_enable",
            "notification_watering_begins",
            "notification_watering_ends",
            "notification_watering_is_skipped",
            "skip_low_temp",
            "skip_wind",
            "skip_rain",
            "skip_saturation",
        ):
            value = config.get(key)
            if isinstance(value, (str, int, float, bool)) or value is None:
                attributes[key] = value
            elif value is not None:
                attributes[key] = json.dumps(value, sort_keys=True, separators=(",", ":"))[:1024]
        return attributes


class WyzeIrrigationZoneMetadata(WyzeIrrigationBaseSensor):
    """Read-only name, enablement, smart duration, and landscaping metadata."""

    _attr_icon = "mdi:sprinkler"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: WyzeIrrigationCoordinator, zone: dict[str, Any]) -> None:
        super().__init__(coordinator)
        self._zone_number = int(zone["zone_number"])
        self._initial_zone = zone

    @property
    def _zone(self) -> dict[str, Any]:
        return next(
            (
                zone
                for zone in (self.coordinator.data or {}).get("zones", [])
                if zone.get("zone_number") == self._zone_number
            ),
            self._initial_zone,
        )

    @property
    def name(self) -> str:
        return f"{self._zone.get('name') or 'Zone'} metadata"

    @property
    def unique_id(self) -> str:
        return f"{self._device.mac}-zone-{self._zone['zone_number']}-metadata"

    @property
    def native_value(self) -> str:
        return "enabled" if self._zone.get("enabled") is not False else "disabled"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return zone_entity_attributes(self._zone)


class WyzeIrrigationRSSI(WyzeIrrigationBaseSensor):
    """Representation of a Wyze Irrigation RSSI sensor."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    @property
    def name(self) -> str:
        """Return the name of the sensor."""
        return "RSSI"

    @property
    def unique_id(self) -> str:
        """Return a unique ID for the sensor."""
        return f"{self._device.mac}-rssi"

    @property
    def native_value(self) -> int:
        """Return the RSSI value."""
        return (self.coordinator.data or {}).get("rssi")

    @property
    def native_unit_of_measurement(self) -> str:
        """Return the unit of measurement."""
        return "dBm"


class WyzeIrrigationIP(WyzeIrrigationBaseSensor):
    """Representation of a Wyze Irrigation IP sensor."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    @property
    def name(self) -> str:
        """Return the name of the sensor."""
        return "IP Address"

    @property
    def unique_id(self) -> str:
        """Return a unique ID for the sensor."""
        return f"{self._device.mac}-ip"

    @property
    def native_value(self) -> str:
        """Return the IP address."""
        return (self.coordinator.data or {}).get("ip")


class WyzeIrrigationSSID(WyzeIrrigationBaseSensor):
    """Representation of a Wyze Irrigation SSID sensor."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    @property
    def name(self) -> str:
        """Return the name of the sensor."""
        return "SSID"

    @property
    def unique_id(self) -> str:
        """Return a unique ID for the sensor."""
        return f"{self._device.mac}-ssid"

    @property
    def native_value(self) -> str:
        """Return the SSID."""
        return (self.coordinator.data or {}).get("ssid")


class WyzeAirPurifierAirQualitySensor(SensorEntity):
    """Base class for Wyze Air Purifier air quality sensors."""

    _attr_attribution = ATTRIBUTION
    _attr_device_class = SensorDeviceClass.AQI
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 0

    def __init__(
        self,
        air_purifier: AirPurifier,
    ) -> None:
        """Initialize the AQI sensor."""
        self._air_purifier = air_purifier

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information about this entity."""
        device_info = DeviceInfo(
            identifiers={(DOMAIN, self._air_purifier.mac)},
            name=self._air_purifier.nickname,
            manufacturer="WyzeLabs",
            model=self._air_purifier.product_model,
        )
        if self._air_purifier.app_version:
            device_info["sw_version"] = self._air_purifier.app_version
        if self._air_purifier.sn:
            device_info["serial_number"] = self._air_purifier.sn
        if self._air_purifier.wifi_mac:
            device_info["connections"] = {
                (dr.CONNECTION_NETWORK_MAC, self._air_purifier.wifi_mac)
            }
        return device_info

    @property
    def available(self) -> bool:
        """Return the connection status of this sensor."""
        return self._air_purifier.available

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return device attributes of the entity."""
        return {
            ATTR_ATTRIBUTION: ATTRIBUTION,
            "device model": self._air_purifier.product_model,
        }

    @callback
    def handle_air_purifier_update(self, air_purifier: AirPurifier) -> None:
        """Handle air purifier updates."""
        self._air_purifier = air_purifier
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Add listener on startup."""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{AIR_PURIFIER_UPDATED}-{self._air_purifier.mac}",
                self.handle_air_purifier_update,
            )
        )


class WyzeAirPurifierAQISensor(WyzeAirPurifierAirQualitySensor):
    """Representation of a Wyze Air Purifier current AQI sensor."""

    _attr_name = "Current AQI"

    def __init__(
        self,
        air_purifier: AirPurifier,
    ) -> None:
        """Initialize the current AQI sensor."""
        super().__init__(air_purifier)
        self._attr_unique_id = f"{self._air_purifier.mac}-aqi"

    @property
    def native_value(self) -> int | None:
        """Return the current AQI value."""
        return self._air_purifier.aqi


class WyzeAirPurifierHourlyMaxAQISensor(WyzeAirPurifierAirQualitySensor):
    """Representation of a Wyze Air Purifier hourly max AQI sensor."""

    _attr_name = "Hourly Max AQI"

    def __init__(
        self,
        air_purifier: AirPurifier,
    ) -> None:
        """Initialize the hourly max AQI sensor."""
        super().__init__(air_purifier)
        self._attr_unique_id = f"{self._air_purifier.mac}-hourly-max-aqi"

    @property
    def native_value(self) -> int | None:
        """Return the hourly max AQI value."""
        return self._air_purifier.max_hourly_aqi

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return device attributes of the entity."""
        attributes = super().extra_state_attributes
        attributes.update(
            {
                "hour_start": self._timestamp_attribute(
                    self._air_purifier.max_hourly_aqi_start_time
                ),
                "hour_end": self._timestamp_attribute(
                    self._air_purifier.max_hourly_aqi_start_time,
                    offset=datetime.timedelta(hours=1),
                ),
                "sampled_until": self._timestamp_attribute(
                    self._air_purifier.max_hourly_aqi_end_time
                ),
            }
        )
        return attributes

    @staticmethod
    def _timestamp_attribute(
        timestamp: int | None, offset: datetime.timedelta | None = None
    ) -> str | None:
        """Return an ISO formatted timestamp attribute."""
        if timestamp is None:
            return None

        value = datetime.datetime.fromtimestamp(timestamp, datetime.UTC)
        if offset is not None:
            value += offset
        return value.isoformat()
