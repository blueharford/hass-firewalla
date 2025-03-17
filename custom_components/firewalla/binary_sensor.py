"""Binary sensor platform for Firewalla integration."""
import logging
from datetime import datetime
from typing import Any, Dict

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN, 
    COORDINATOR, 
    ATTR_ALARM_ID, 
    ATTR_DEVICE_ID, 
    ATTR_NETWORK_ID,
    API_CLIENT
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    """Set up Firewalla binary sensors based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id].get(COORDINATOR)
    
    if not coordinator:
        _LOGGER.error("No coordinator found for entry %s", entry.entry_id)
        return
    
    entities = []
    
    # Add online status sensors for each device
    if coordinator.data and "devices" in coordinator.data:
        for device in coordinator.data["devices"]:
            entities.append(FirewallaOnlineSensor(coordinator, device))
    
    async_add_entities(entities)


class FirewallaOnlineSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for Firewalla device online status."""

    def __init__(self, coordinator, device):
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self.device_id = device["id"]
        self.network_id = device.get("networkId")
        self._attr_name = f"{device.get('name', 'Unknown')} Online"
        self._attr_unique_id = f"{DOMAIN}_online_{self.device_id}"
        self._attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
        
        # Set up device info
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self.device_id)},
            name=device.get("name", f"Firewalla Device {self.device_id}"),
            manufacturer="Firewalla",
            model="Network Device",
        )
        
        self._update_attributes(device)
    
    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if not self.coordinator.data or "devices" not in self.coordinator.data:
            return
            
        for device in self.coordinator.data["devices"]:
            if device["id"] == self.device_id:
                self._update_attributes(device)
                break
                
        self.async_write_ha_state()
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        # Explicitly check for online status
        self._attr_is_on = device.get("online", False)
        
        # Set additional attributes
        self._attr_extra_state_attributes = {
            ATTR_DEVICE_ID: self.device_id,
            ATTR_NETWORK_ID: self.network_id,
        }
        
        # Add last seen timestamp if available
        last_active = device.get("lastActiveTimestamp")
        if last_active:
            try:
                # Convert from milliseconds to seconds
                last_active_dt = datetime.fromtimestamp(last_active / 1000)
                self._attr_extra_state_attributes["last_seen"] = last_active_dt.isoformat()
                
                # Calculate time since last seen
                now = datetime.now()
                time_diff = now - last_active_dt
                self._attr_extra_state_attributes["last_seen_seconds_ago"] = time_diff.total_seconds()
                
                # Add human-readable format
                if time_diff.total_seconds() < 60:
                    time_str = f"{int(time_diff.total_seconds())} seconds ago"
                elif time_diff.total_seconds() < 3600:
                    time_str = f"{int(time_diff.total_seconds() / 60)} minutes ago"
                elif time_diff.total_seconds() < 86400:
                    time_str = f"{int(time_diff.total_seconds() / 3600)} hours ago"
                else:
                    time_str = f"{int(time_diff.total_seconds() / 86400)} days ago"
                self._attr_extra_state_attributes["last_seen_friendly"] = time_str
                
            except (ValueError, TypeError):
                pass
        
        # Add IP and MAC addresses if available
        for attr in ["ip", "mac"]:
            if attr in device:
                self._attr_extra_state_attributes[attr] = device[attr]

