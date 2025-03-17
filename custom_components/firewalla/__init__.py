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
                data = {}
                
                # Try to get devices
                devices = await api_client.async_get_devices()
                if devices is not None:
                    data["devices"] = devices
                else:
                    _LOGGER.warning("Failed to get devices from Firewalla API")
                    data["devices"] = []
                
                # Try to get flows
                flows = await api_client.async_get_flows()
                if flows is not None:
                    data["flows"] = flows
                else:
                    _LOGGER.warning("Failed to get flows from Firewalla API")
                    data["flows"] = []
                
                # Try to get alarms
                alarms = await api_client.async_get_alarms()
                if alarms is not None:
                    data["alarms"] = alarms
                else:
                    _LOGGER.warning("Failed to get alarms from Firewalla API")
                    data["alarms"] = []
                
                # Try to get rules
                rules = await api_client.async_get_rules()
                if rules is not None:
                    data["rules"] = rules
                else:
                    _LOGGER.warning("Failed to get rules from Firewalla API")
                    data["rules"] = []
                
                # Check if we got any data
                if not data or all(len(v) == 0 for v in data.values()):
                    _LOGGER.error("Failed to get any data from Firewalla API")
                    # Return empty data structure instead of failing
                    return {
                        "devices": [],
                        "flows": [],
                        "alarms": [],
                        "rules": [],
                    }
                
                return data
                
        except Exception as err:
            _LOGGER.error("Error communicating with API: %s", err)
            # Return empty data structure instead of failing
            return {
                "devices": [],
                "flows": [],
                "alarms": [],
                "rules": [],
            }
    
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
