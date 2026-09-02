"""SolarEdge Monitoring Bridge integration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .client import SolarEdgeBridgeClient
from .const import CONF_ENDPOINT, CONF_SHARED_SECRET, DOMAIN
from .coordinator import SolarEdgeBridgeCoordinator
from .export_events_ha import (
    async_setup_export_event_manager,
    async_unload_export_event_manager,
)

PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR]
SERVICE_GET_FULL_DATA = "get_full_data"

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
    try:
        await async_setup_export_event_manager(hass, entry, coordinator)
    except Exception:
        await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
        raise
    if not hass.services.has_service(DOMAIN, SERVICE_GET_FULL_DATA):

        async def async_get_full_data(call: ServiceCall) -> dict:
            """Return complete privacy-filtered SolarEdge portal data on demand."""
            return await entry.runtime_data.async_get_full_data()

        hass.services.async_register(
            DOMAIN,
            SERVICE_GET_FULL_DATA,
            async_get_full_data,
            supports_response=SupportsResponse.ONLY,
        )
    return True


async def async_unload_entry(
    hass: HomeAssistant, entry: SolarEdgeBridgeConfigEntry
) -> bool:
    """Unload a SolarEdge Monitoring Bridge config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await async_unload_export_event_manager(hass, entry.entry_id)
        hass.services.async_remove(DOMAIN, SERVICE_GET_FULL_DATA)
    return unloaded
