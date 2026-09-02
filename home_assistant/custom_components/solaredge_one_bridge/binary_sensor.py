"""Binary sensors for SolarEdge capability, endpoint, and live-state flags."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import SolarEdgeBridgeConfigEntry
from .const import DOMAIN
from .coordinator import SolarEdgeBridgeCoordinator
from .model import BOOLEAN_KEYS


def _friendly_name(key: str) -> str:
    """Build a stable readable name for an explicitly allowlisted flag."""
    replacements = {"ac": "AC", "dc": "DC", "ev": "EV", "pv": "PV"}
    label = " ".join(replacements.get(word, word) for word in key.split("_"))
    return f"{label[:1].upper()}{label[1:]}"


BINARY_SENSOR_DESCRIPTIONS = (
    BinarySensorEntityDescription(
        key="connected",
        name="Connected",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
    ),
    *(
        BinarySensorEntityDescription(
            key=key,
            name=_friendly_name(key),
            device_class=(
                BinarySensorDeviceClass.CONNECTIVITY
                if key.startswith("endpoint_")
                else None
            ),
        )
        for key in sorted(BOOLEAN_KEYS)
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SolarEdgeBridgeConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up every allowlisted SolarEdge bridge boolean."""
    async_add_entities(
        SolarEdgeBridgeBinarySensor(entry.runtime_data, description)
        for description in BINARY_SENSOR_DESCRIPTIONS
    )


class SolarEdgeBridgeBinarySensor(
    CoordinatorEntity[SolarEdgeBridgeCoordinator], BinarySensorEntity
):
    """One allowlisted SolarEdge bridge boolean."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: SolarEdgeBridgeCoordinator,
        description: BinarySensorEntityDescription,
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
        """Keep a false flag available while omitting unsupported provider fields."""
        if self.entity_description.key == "connected":
            return super().available
        return (
            super().available
            and self.coordinator.data.connected
            and self.coordinator.data.flag(self.entity_description.key) is not None
        )

    @property
    def is_on(self) -> bool | None:
        """Return the strict provider boolean without coercion."""
        if self.entity_description.key == "connected":
            return self.coordinator.data.connected
        if not self.coordinator.data.connected:
            return None
        return self.coordinator.data.flag(self.entity_description.key)

    @property
    def extra_state_attributes(self) -> dict[str, str | bool]:
        """Expose concise non-identifying bridge diagnostics."""
        attributes: dict[str, str | bool] = {}
        if self.coordinator.data.observed_at is not None:
            attributes["observed_at"] = self.coordinator.data.observed_at
        if self.coordinator.data.provider is not None:
            attributes["provider"] = self.coordinator.data.provider
        if self.entity_description.key != "connected":
            completeness = self.coordinator.data.completeness.get(
                self.entity_description.key
            )
            if completeness is not None:
                attributes["completeness"] = completeness
        return attributes
