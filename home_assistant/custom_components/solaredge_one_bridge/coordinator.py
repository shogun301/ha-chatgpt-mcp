"""Data coordinator for SolarEdge Monitoring Bridge."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import BridgeError, SolarEdgeBridgeClient
from .const import DEFAULT_UPDATE_INTERVAL, DOMAIN
from .model import SolarEdgeSnapshot

_LOGGER = logging.getLogger(__name__)


class SolarEdgeBridgeCoordinator(DataUpdateCoordinator[SolarEdgeSnapshot]):
    """Poll the local bridge without forcing integration reloads on outages."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: SolarEdgeBridgeClient,
    ) -> None:
        super().__init__(
            hass,
            logger=_LOGGER,
            name=DOMAIN,
            config_entry=entry,
            update_interval=DEFAULT_UPDATE_INTERVAL,
        )
        self._client = client

    async def async_get_full_data(self) -> dict[str, Any]:
        """Return every privacy-filtered portal surface without recorder storage."""
        return await self._client.async_get_full_data()

    async def _async_update_data(self) -> SolarEdgeSnapshot:
        try:
            return await self._client.async_get_snapshot()
        except BridgeError as err:
            # UpdateFailed marks entities unavailable and lets the coordinator use its
            # normal bounded polling cadence; it does not reload or restart HA.
            raise UpdateFailed(str(err)) from err
