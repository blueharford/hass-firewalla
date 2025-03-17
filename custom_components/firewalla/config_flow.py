"""Config flow for Firewalla integration."""
import logging
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv

from .api import FirewallaApiClient
from .const import DOMAIN, CONF_API_TOKEN, CONF_SUBDOMAIN, DEFAULT_SUBDOMAIN

_LOGGER = logging.getLogger(__name__)

class FirewallaConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Firewalla."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        error_info = None

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            api_client = FirewallaApiClient(
                user_input[CONF_API_TOKEN],
                user_input[CONF_SUBDOMAIN],
                session
            )

            try:
                await api_client.async_check_credentials()
            except Exception as exc:
                _LOGGER.error("Authentication error: %s", exc)
                errors["base"] = "auth"
                error_info = str(exc)
            else:
                # Use a combination of subdomain and token as the unique ID
                await self.async_set_unique_id(f"{user_input[CONF_SUBDOMAIN]}_{user_input[CONF_API_TOKEN][:10]}")
                self._abort_if_unique_id_configured()
                
                return self.async_create_entry(
                    title=f"Firewalla ({user_input[CONF_SUBDOMAIN]})",
                    data=user_input,
                )

        schema = vol.Schema(
            {
                vol.Required(CONF_SUBDOMAIN, default=DEFAULT_SUBDOMAIN): str,
                vol.Required(CONF_API_TOKEN): str,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={"error_info": error_info} if error_info else None,
        )
