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


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Firewalla from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    
    session = async_get_clientsession(hass)
    
    client = FirewallaApiClient(
        session=session,
        email=entry.data.get(CONF_EMAIL),
        password=entry.data.get(CONF_PASSWORD),
        api_key=entry.data.get(CONF_API_KEY),
        api_secret=entry.data.get(CONF_API_SECRET),
        api_token=entry.data.get(CONF_API_TOKEN),
        subdomain=entry.data.get(CONF_SUBDOMAIN),
        use_mock_data=entry.data.get(CONF_USE_MOCK_DATA, False),
    )
    
    # Test the API connection
    if not await client.authenticate():
        raise ConfigEntryNotReady("Failed to authenticate with Firewalla API")
    
    # Store the client
    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "devices": {},
    }
    
    # Get initial devices
    try:
        devices = await client.get_devices()
        if not devices and not entry.data.get(CONF_USE_MOCK_DATA, False):
            _LOGGER.warning("No devices found from Firewalla API. Check your network configuration.")
        
        hass.data[DOMAIN][entry.entry_id]["devices"] = {
            device["id"]: device for device in devices
        }
        _LOGGER.debug("Found %s devices from Firewalla", len(devices))
    except Exception as exc:
        _LOGGER.error("Error fetching initial devices: %s", exc)
        if not entry.data.get(CONF_USE_MOCK_DATA, False):
            raise ConfigEntryNotReady("Failed to fetch initial device data") from exc
    
    # Set up platforms
    for platform in PLATFORMS:
        hass.async_create_task(
            hass.config_entries.async_forward_entry_setup(entry, platform)
        )
    
    # Set up update listener
    entry.async_on_unload(entry.add_update_listener(async_update_options))
    
    # Set up periodic data refresh
    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    
    async def async_update_data():
        """Update data from Firewalla."""
        try:
            devices = await client.get_devices()
            
            # Check for new devices
            current_devices = hass.data[DOMAIN][entry.entry_id]["devices"]
            new_devices = {}
            updated_devices = {}
            
            for device in devices:
                device_id = device["id"]
                if device_id not in current_devices:
                    new_devices[device_id] = device
                else:
                    # Check if device data has changed
                    if current_devices[device_id] != device:
                        updated_devices[device_id] = device
            
            # Update the devices dictionary
            hass.data[DOMAIN][entry.entry_id]["devices"] = {
                device["id"]: device for device in devices
            }
            
            # Log the update results
            if new_devices:
                _LOGGER.info("Found %s new devices from Firewalla", len(new_devices))
                # Notify about new devices
                async_dispatcher_send(
                    hass, 
                    f"{DOMAIN}_{entry.entry_id}_device_update", 
                    new_devices
                )
            
            if updated_devices:
                _LOGGER.debug("Updated %s existing devices from Firewalla", len(updated_devices))
            
            # Notify all entities to update
            async_dispatcher_send(hass, f"{DOMAIN}_{entry.entry_id}_update")
            
        except Exception as exc:
            _LOGGER.error("Error updating devices: %s", exc)
    
    # Create the update timer
    entry.async_on_unload(
        async_track_time_interval(
            hass, async_update_data, timedelta(seconds=scan_interval)
        )
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

async def async_update_options(hass: HomeAssistant, entry: ConfigEntry):
    """Update options."""
    await hass.config_entries.async_reload(entry.entry_id)

