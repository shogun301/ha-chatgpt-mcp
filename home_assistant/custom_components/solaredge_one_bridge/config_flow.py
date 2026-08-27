"""Config flow for SolarEdge Monitoring Bridge."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .client import (
    BridgeAuthenticationError,
    BridgeConnectionError,
    SolarEdgeBridgeClient,
    is_local_endpoint,
)
from .const import CONF_ENDPOINT, CONF_SHARED_SECRET, DEFAULT_ENDPOINT, DOMAIN


class SolarEdgeMonitoringBridgeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Configure the one supported SolarEdge Monitoring bridge."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle initial setup."""
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")
        await self.async_set_unique_id(DOMAIN)
        self._abort_if_unique_id_configured()

        errors: dict[str, str] = {}
        if user_input is not None:
            endpoint = user_input[CONF_ENDPOINT].strip()
            shared_secret = user_input[CONF_SHARED_SECRET]
            if not is_local_endpoint(endpoint):
                errors["base"] = "invalid_endpoint"
            else:
                client = SolarEdgeBridgeClient(
                    async_get_clientsession(self.hass), endpoint, shared_secret
                )
                try:
                    await client.async_get_snapshot()
                except BridgeAuthenticationError:
                    errors["base"] = "invalid_auth"
                except BridgeConnectionError:
                    errors["base"] = "cannot_connect"
                else:
                    return self.async_create_entry(
                        title="SolarEdge Monitoring",
                        data={
                            CONF_ENDPOINT: endpoint,
                            CONF_SHARED_SECRET: shared_secret,
                        },
                    )

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_ENDPOINT,
                    default=(user_input or {}).get(CONF_ENDPOINT, DEFAULT_ENDPOINT),
                ): vol.All(str, vol.Length(min=1, max=2048)),
                vol.Required(CONF_SHARED_SECRET): vol.All(str, vol.Length(min=1)),
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
