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
from homeassistant.const import (
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
)
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import (
    DOMAIN,
    CONF_API_TOKEN,
    CONF_SUBDOMAIN,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SUBDOMAIN,
    COORDINATOR,
    API_CLIENT,
    CONF_API_KEY,
    CONF_API_SECRET,
    CONF_USE_MOCK_DATA,
    PLATFORMS,
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


async def async_setup(hass: HomeAssistant, config: dict):
    """Set up the Firewalla component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Firewalla from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    
    session = async_get_clientsession(hass)
    
    # Get the subdomain from the config entry
    subdomain = entry.data.get(CONF_SUBDOMAIN, DEFAULT_SUBDOMAIN)
    
    # Log the subdomain being used
    _LOGGER.debug("Using subdomain: %s", subdomain)
    
    client = FirewallaApiClient(
        session=session,
        email=entry.data.get(CONF_EMAIL),
        password=entry.data.get(CONF_PASSWORD),
        api_key=entry.data.get(CONF_API_KEY),
        api_secret=entry.data.get(CONF_API_SECRET),
        api_token=entry.data.get(CONF_API_TOKEN),
        subdomain=subdomain,
        use_mock_data=entry.data.get(CONF_USE_MOCK_DATA, False),
    )
    
    # Test the API connection
    if not await client.authenticate():
        raise ConfigEntryNotReady("Failed to authenticate with Firewalla API")
    
    # Create update coordinator
    async def async_update_data():
        """Fetch data from API."""
        try:
            return {"devices": await client.get_devices()}
        except Exception as err:
            raise UpdateFailed(f"Error communicating with API: {err}")

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=f"{DOMAIN}_{entry.entry_id}",
        update_method=async_update_data,
        update_interval=timedelta(seconds=entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)),
    )
    
    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()
    
    # Store the client and coordinator
    hass.data[DOMAIN][entry.entry_id] = {
        API_CLIENT: client,
        COORDINATOR: coordinator,
        "devices": {},
    }
    
    # Get initial devices
    try:
        devices = coordinator.data.get("devices", []) if coordinator.data else []
        if not devices and not entry.data.get(CONF_USE_MOCK_DATA, False):
            _LOGGER.warning("No devices found from Firewalla API. Check your network configuration.")
        
        hass.data[DOMAIN][entry.entry_id]["devices"] = {
            device["id"]: device for device in devices
        }
        _LOGGER.debug("Found %s devices from Firewalla", len(devices))
    except Exception as exc:
        _LOGGER.error("Error processing initial devices: %s", exc)
        if not entry.data.get(CONF_USE_MOCK_DATA, False):
            raise ConfigEntryNotReady("Failed to process initial device data") from exc
    
    # Set up platforms using the new async_forward_entry_setups method
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    
    # Set up update listener
    entry.async_on_unload(entry.add_update_listener(async_update_options))
    
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    
    return unload_ok

async def async_update_options(hass: HomeAssistant, entry: ConfigEntry):
    """Update options."""
    await hass.config_entries.async_reload(entry.entry_id)

