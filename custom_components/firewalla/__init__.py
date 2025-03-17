"""The Firewalla integration."""
import logging
from datetime import timedelta

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
import homeassistant.helpers.config_validation as cv
from homeassistant.const import (
    CONF_SCAN_INTERVAL,
)
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    DOMAIN,
    CONF_API_TOKEN,
    CONF_SUBDOMAIN,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SUBDOMAIN,
    COORDINATOR,
    API_CLIENT,
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
        api_token=entry.data.get(CONF_API_TOKEN),
        subdomain=subdomain,
    )
    
    # Test the API connection
    if not await client.authenticate():
        raise ConfigEntryNotReady("Failed to authenticate with Firewalla API")
    
    # Create update coordinator
    async def async_update_data():
        """Fetch data from API."""
        try:
            # Get data from all endpoints
            boxes = await client.get_boxes()
            devices = await client.get_devices()
            rules = await client.get_rules()
            alarms = await client.get_alarms()
            flows = await client.get_flows()
            
            return {
                "boxes": boxes,
                "devices": devices,
                "rules": rules,
                "alarms": alarms,
                "flows": flows
            }
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
        "boxes": {},
        "devices": {},
        "rules": {},
        "alarms": {},
        "flows": {}
    }
    
    # Process initial data
    try:
        # Process boxes
        boxes = coordinator.data.get("boxes", []) if coordinator.data else []
        
        # Log the raw boxes data for debugging
        _LOGGER.debug("Raw boxes data: %s", boxes)
        
        # Process boxes with more robust error handling
        box_dict = {}
        for box in boxes:
            if isinstance(box, dict):
                # Check if box has an id field
                box_id = box.get("id")
                if box_id:
                    box_dict[box_id] = box
                else:
                    _LOGGER.warning("Found box without id: %s", box)
        
        hass.data[DOMAIN][entry.entry_id]["boxes"] = box_dict
        _LOGGER.debug("Found %s Firewalla boxes", len(box_dict))
        
        # Process devices
        devices = coordinator.data.get("devices", []) if coordinator.data else []
        
        # Log the raw devices data for debugging
        _LOGGER.debug("Raw devices data: %s", devices)
        
        # Process devices with more robust error handling
        device_dict = {}
        for device in devices:
            if isinstance(device, dict):
                # Check if device has an id field
                device_id = device.get("id")
                if device_id:
                    device_dict[device_id] = device
                else:
                    _LOGGER.warning("Found device without id: %s", device)
        
        hass.data[DOMAIN][entry.entry_id]["devices"] = device_dict
        _LOGGER.debug("Found %s devices from Firewalla", len(device_dict))
        
        # Process rules
        rules = coordinator.data.get("rules", []) if coordinator.data else []
        
        # Process rules with more robust error handling
        rule_dict = {}
        for rule in rules:
            if isinstance(rule, dict):
                # Check if rule has an id field
                rule_id = rule.get("id")
                if rule_id:
                    rule_dict[rule_id] = rule
                else:
                    _LOGGER.warning("Found rule without id: %s", rule)
        
        hass.data[DOMAIN][entry.entry_id]["rules"] = rule_dict
        _LOGGER.debug("Found %s rules from Firewalla", len(rule_dict))
        
        # Process alarms
        alarms = coordinator.data.get("alarms", []) if coordinator.data else []
        
        # Process alarms with more robust error handling
        alarm_dict = {}
        for alarm in alarms:
            if isinstance(alarm, dict):
                # Check if alarm has an id field
                alarm_id = alarm.get("id")
                if alarm_id:
                    alarm_dict[alarm_id] = alarm
                else:
                    _LOGGER.warning("Found alarm without id: %s", alarm)
        
        hass.data[DOMAIN][entry.entry_id]["alarms"] = alarm_dict
        _LOGGER.debug("Found %s alarms from Firewalla", len(alarm_dict))
        
        # Process flows
        flows = coordinator.data.get("flows", []) if coordinator.data else []
        
        # Process flows with more robust error handling
        flow_dict = {}
        for flow in flows:
            if isinstance(flow, dict):
                # Check if flow has an id field
                flow_id = flow.get("id")
                if flow_id:
                    flow_dict[flow_id] = flow
                else:
                    _LOGGER.warning("Found flow without id: %s", flow)
        
        hass.data[DOMAIN][entry.entry_id]["flows"] = flow_dict
        _LOGGER.debug("Found %s flows from Firewalla", len(flow_dict))
        
    except Exception as exc:
        _LOGGER.error("Error processing initial data: %s", exc, exc_info=True)
        raise ConfigEntryNotReady("Failed to process initial data") from exc
    
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

