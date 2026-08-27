"""Sensor platform for SolarEdge Monitoring Bridge."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, UnitOfEnergy, UnitOfPower
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SolarEdgeBridgeConfigEntry
from .const import DOMAIN
from .coordinator import SolarEdgeBridgeCoordinator


@dataclass(frozen=True, kw_only=True)
class SolarEdgeBridgeSensorDescription(SensorEntityDescription):
    """Describe a sanitized bridge sensor."""


SENSOR_DESCRIPTIONS: tuple[SolarEdgeBridgeSensorDescription, ...] = (
    *(
        SolarEdgeBridgeSensorDescription(
            key=key,
            translation_key=key,
            device_class=SensorDeviceClass.POWER,
            native_unit_of_measurement=UnitOfPower.WATT,
            state_class=SensorStateClass.MEASUREMENT,
        )
        for key in (
            "production_power_w",
            "consumption_power_w",
            "grid_import_power_w",
            "grid_export_power_w",
            "battery_charge_power_w",
            "battery_discharge_power_w",
        )
    ),
    SolarEdgeBridgeSensorDescription(
        key="battery_state_of_energy_pct",
        translation_key="battery_state_of_energy_pct",
        device_class=SensorDeviceClass.BATTERY,
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    *(
        SolarEdgeBridgeSensorDescription(
            key=key,
            translation_key=key,
            device_class=SensorDeviceClass.ENERGY,
            native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
            state_class=SensorStateClass.TOTAL_INCREASING,
        )
        for key in (
            "production_energy_kwh",
            "consumption_energy_kwh",
            "grid_import_energy_kwh",
            "grid_export_energy_kwh",
            "battery_charge_energy_kwh",
            "battery_discharge_energy_kwh",
        )
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SolarEdgeBridgeConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up SolarEdge bridge sensors."""
    async_add_entities(
        [
            *(
                SolarEdgeBridgeSensor(entry.runtime_data, description)
                for description in SENSOR_DESCRIPTIONS
            ),
            SolarEdgeStorageOperatingPlanSensor(entry.runtime_data),
        ]
    )


def _bridge_diagnostic_attributes(
    coordinator: SolarEdgeBridgeCoordinator,
) -> dict[str, str]:
    """Return common concise, non-identifying bridge diagnostics."""
    attributes: dict[str, str] = {}
    if coordinator.data.observed_at is not None:
        attributes["observed_at"] = coordinator.data.observed_at
    if coordinator.data.provider is not None:
        attributes["provider"] = coordinator.data.provider
    return attributes


class SolarEdgeBridgeSensor(
    CoordinatorEntity[SolarEdgeBridgeCoordinator], SensorEntity
):
    """One allowlisted aggregate SolarEdge metric."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: SolarEdgeBridgeCoordinator,
        description: SolarEdgeBridgeSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{DOMAIN}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, "bridge")},
            manufacturer="SolarEdge",
            model="Monitoring API bridge",
            name="SolarEdge Monitoring",
        )

    @property
    def available(self) -> bool:
        """Return availability without surfacing incomplete or stale values."""
        return (
            super().available
            and self.coordinator.data.connected
            and self.coordinator.data.value(self.entity_description.key) is not None
        )

    @property
    def native_value(self) -> float | None:
        """Return the sanitized metric value, omitting unavailable values."""
        if not self.coordinator.data.connected:
            return None
        return self.coordinator.data.value(self.entity_description.key)

    @property
    def extra_state_attributes(self) -> dict[str, str | bool]:
        """Expose only concise, non-identifying bridge diagnostics."""
        attributes: dict[str, str | bool] = _bridge_diagnostic_attributes(
            self.coordinator
        )
        completeness = self.coordinator.data.completeness.get(
            self.entity_description.key
        )
        if completeness is not None:
            attributes["completeness"] = completeness
        return attributes


class SolarEdgeStorageOperatingPlanSensor(
    CoordinatorEntity[SolarEdgeBridgeCoordinator], SensorEntity
):
    """Provider-reported storage operating-plan status."""

    _attr_has_entity_name = True
    _attr_translation_key = "storage_operating_plan"
    _attr_unique_id = f"{DOMAIN}_storage_operating_plan"
    _attr_device_info = DeviceInfo(
        identifiers={(DOMAIN, "bridge")},
        manufacturer="SolarEdge",
        model="Monitoring API bridge",
        name="SolarEdge Monitoring",
    )

    @property
    def available(self) -> bool:
        """Return whether the provider supplied a current plan label."""
        return (
            super().available
            and self.coordinator.data.connected
            and self.coordinator.data.storage_operating_plan is not None
            and self.coordinator.data.completeness.get("storage_operating_plan")
            is not False
        )

    @property
    def native_value(self) -> str | None:
        """Return the sanitized provider plan label."""
        if not self.coordinator.data.connected:
            return None
        return self.coordinator.data.storage_operating_plan

    @property
    def extra_state_attributes(self) -> dict[str, str | bool | int]:
        """Expose bounded status only; never expose provider policy payloads."""
        attributes: dict[str, str | bool | int] = _bridge_diagnostic_attributes(
            self.coordinator
        )
        if self.coordinator.data.storage_operating_plan_active is not None:
            attributes["active"] = self.coordinator.data.storage_operating_plan_active
        if self.coordinator.data.storage_operating_plan_block_count is not None:
            attributes["block_count"] = (
                self.coordinator.data.storage_operating_plan_block_count
            )
        completeness = self.coordinator.data.completeness.get("storage_operating_plan")
        if completeness is not None:
            attributes["completeness"] = completeness
        return attributes
