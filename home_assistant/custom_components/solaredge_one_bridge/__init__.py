"""SolarEdge Monitoring Bridge integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .client import SolarEdgeBridgeClient
from .const import CONF_ENDPOINT, CONF_SHARED_SECRET
from .coordinator import SolarEdgeBridgeCoordinator

PLATFORMS = [Platform.SENSOR]

type SolarEdgeBridgeConfigEntry = ConfigEntry[SolarEdgeBridgeCoordinator]


async def async_setup_entry(
    hass: HomeAssistant, entry: SolarEdgeBridgeConfigEntry
) -> bool:
    """Set up SolarEdge Monitoring Bridge from a config entry."""
    client = SolarEdgeBridgeClient(
        async_get_clientsession(hass),
        entry.data[CONF_ENDPOINT],
        entry.data[CONF_SHARED_SECRET],
    )
    coordinator = SolarEdgeBridgeCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(
    hass: HomeAssistant, entry: SolarEdgeBridgeConfigEntry
) -> bool:
    """Unload a SolarEdge Monitoring Bridge config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
