"""The Firewalla integration."""
import asyncio
import logging
from datetime import timedelta

import aiohttp
import async_timeout
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
import homeassistant.helpers.config_validation as cv

from .const import (
    DOMAIN,
    CONF_API_TOKEN,
    CONF_SUBDOMAIN,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SUBDOMAIN,
    COORDINATOR,
    API_CLIENT,
)
from .api import FirewallaApiClient

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_API_TOKEN): cv.string,
                vol.Optional(CONF_SUBDOMAIN, default=DEFAULT_SUBDOMAIN): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)

PLATFORMS = ["sensor", "switch", "binary_sensor"]


async def async_setup(hass: HomeAssistant, config: dict):
    """Set up the Firewalla component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up Firewalla from a config entry."""
    api_token = entry.data[CONF_API_TOKEN]
    subdomain = entry.data.get(CONF_SUBDOMAIN, DEFAULT_SUBDOMAIN)
    
    session = async_get_clientsession(hass)
    api_client = FirewallaApiClient(api_token, subdomain, session)
    
    # Verify credentials
    try:
        await api_client.async_check_credentials()
    except Exception as exc:
        _LOGGER.error("Failed to connect to Firewalla API: %s", exc)
        return False
    
    async def async_update_data():
        """Fetch data from API."""
        try:
            async with async_timeout.timeout(30):
                # Get all the data we need for the platforms
                devices = await api_client.async_get_devices()
                flows = await api_client.async_get_flows()
                alarms = await api_client.async_get_alarms()
                rules = await api_client.async_get_rules()
                
                return {
                    "devices": devices,
                    "flows": flows,
                    "alarms": alarms,
                    "rules": rules,
                }
        except Exception as err:
            raise UpdateFailed(f"Error communicating with API: {err}")
    
    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=DOMAIN,
        update_method=async_update_data,
        update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
    )
    
    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()
    
    hass.data[DOMAIN][entry.entry_id] = {
        COORDINATOR: coordinator,
        API_CLIENT: api_client,
    }
    
    for platform in PLATFORMS:
        hass.async_create_task(
            hass.config_entries.async_forward_entry_setup(entry, platform)
        )
    
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry."""
    unload_ok = all(
        await asyncio.gather(
            *[
                hass.config_entries.async_forward_entry_unload(entry, platform)
                for platform in PLATFORMS
            ]
        )
    )
    
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    
    return unload_ok

