"""Config flow for Firewalla integration."""
import logging
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv

from .api import FirewallaApiClient
from .const import (
    DOMAIN, 
    CONF_API_TOKEN, 
    CONF_SUBDOMAIN, 
    DEFAULT_SUBDOMAIN, 
    CONF_API_KEY,
    CONF_API_SECRET,
    CONF_EMAIL,
    CONF_PASSWORD,
)

_LOGGER = logging.getLogger(__name__)

class FirewallaConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Firewalla."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            session = async_get_clientsession(self.hass)
            
            # Create API client with the provided credentials
            api_client = FirewallaApiClient(
                session=session,
                api_token=user_input.get(CONF_API_TOKEN),
                subdomain=user_input.get(CONF_SUBDOMAIN),
            )

            try:
                # Test the API connection
                auth_success = await api_client.async_check_credentials()
                
                if auth_success:
                    # Use a combination of subdomain and token as the unique ID
                    await self.async_set_unique_id(f"{user_input[CONF_SUBDOMAIN]}_{user_input.get(CONF_API_TOKEN, '')}")
                    self._abort_if_unique_id_configured()
                    
                    return self.async_create_entry(
                        title=f"Firewalla ({user_input[CONF_SUBDOMAIN]})",
                        data=user_input,
                    )
                else:
                    errors["base"] = "auth"
            except Exception as ex:
                _LOGGER.error("Error during authentication: %s", ex)
                errors["base"] = "auth"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_SUBDOMAIN, default=DEFAULT_SUBDOMAIN): str,
                    vol.Required(CONF_API_TOKEN): str,
                }
            ),
            errors=errors,
        )

