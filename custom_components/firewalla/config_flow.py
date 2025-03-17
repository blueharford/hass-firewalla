"""Config flow for Firewalla integration."""
import logging
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv
from homeassistant.const import CONF_SCAN_INTERVAL

from .api import FirewallaApiClient
from .const import (
    DOMAIN, 
    CONF_API_TOKEN, 
    CONF_SUBDOMAIN, 
    DEFAULT_SUBDOMAIN,
    DEFAULT_SCAN_INTERVAL,
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

        # Set default values
        default_values = {
            CONF_SUBDOMAIN: DEFAULT_SUBDOMAIN,
            CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
        }
        
        # If we have user input, use those values as defaults
        if user_input is not None:
            for key in default_values:
                if key in user_input:
                    default_values[key] = user_input[key]

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_SUBDOMAIN, default=default_values[CONF_SUBDOMAIN]): str,
                    vol.Required(CONF_API_TOKEN): str,
                    vol.Required(CONF_SCAN_INTERVAL, default=default_values[CONF_SCAN_INTERVAL]): int,
                }
            ),
            errors=errors,
        )

    @staticmethod
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return FirewallaOptionsFlowHandler(config_entry)


class FirewallaOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle Firewalla options."""

    def __init__(self, config_entry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SCAN_INTERVAL,
                        default=self.config_entry.options.get(
                            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                        ),
                    ): int,
                }
            ),
        )

