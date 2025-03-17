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

from .const import DOMAIN, COORDINATOR, ATTR_ALARM_ID, ATTR_DEVICE_ID, ATTR_NETWORK_ID

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    """Set up Firewalla binary sensors based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id][COORDINATOR]
    
    entities = []
    
    # Add alarm binary sensors
    if coordinator.data and "alarms" in coordinator.data:
        for alarm in coordinator.data["alarms"]:
            entities.append(FirewallaAlarmBinarySensor(coordinator, alarm))
    
    # Add online status sensors for each device
    if coordinator.data and "devices" in coordinator.data:
        for device in coordinator.data["devices"]:
            entities.append(FirewallaOnlineSensor(hass, entry, device["id"], device))
    
    async_add_entities(entities)


class FirewallaAlarmBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for Firewalla alarms."""

    def __init__(self, coordinator, alarm):
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._alarm = alarm
        self._attr_unique_id = f"{DOMAIN}_alarm_{alarm.get('id', '')}"
        self._attr_name = f"Alarm: {alarm.get('name', 'Unknown')}"
        self._attr_device_class = BinarySensorDeviceClass.PROBLEM
        self._attr_icon = "mdi:alert"
        
        # Find the device this alarm belongs to
        device_id = alarm.get("device_id")
        device_name = "Unknown Device"
        device_model = "Unknown"
        
        if coordinator.data and "devices" in coordinator.data:
            for device in coordinator.data["devices"]:
                if device.get("id") == device_id:
                    device_name = device.get("name", "Unknown Device")
                    device_model = device.get("model", "Unknown")
                    break
        
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device_id or "unknown")},
            "name": device_name,
            "manufacturer": "Firewalla",
            "model": device_model,
        }

    @property
    def is_on(self):
        """Return true if the alarm is active."""
        if not self.coordinator.data or "alarms" not in self.coordinator.data:
            return False
            
        for alarm in self.coordinator.data["alarms"]:
            if alarm.get("id") == self._alarm.get("id"):
                return alarm.get("active", False)
                
        return False

    @property
    def extra_state_attributes(self):
        """Return the state attributes."""
        if not self.coordinator.data or "alarms" not in self.coordinator.data:
            return {}
            
        for alarm in self.coordinator.data["alarms"]:
            if alarm.get("id") == self._alarm.get("id"):
                return {
                    ATTR_ALARM_ID: alarm.get("id"),
                    "name": alarm.get("name"),
                    "type": alarm.get("type"),
                    "severity": alarm.get("severity"),
                    "message": alarm.get("message"),
                    "created_at": alarm.get("created_at"),
                }
                
        return {}

class FirewallaOnlineSensor(BinarySensorEntity):
    """Binary sensor for Firewalla device online status."""

    def __init__(
        self, 
        hass: HomeAssistant, 
        entry: ConfigEntry, 
        device_id: str, 
        device_data: Dict[str, Any]
    ) -> None:
        """Initialize the sensor."""
        self.hass = hass
        self.entry = entry
        self.device_id = device_id
        self.network_id = device_data.get("networkId")
        self._attr_name = f"{device_data.get('name', 'Unknown')} Online"
        self._attr_unique_id = f"{DOMAIN}_online_{device_id}"
        self._attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
        self._attr_has_entity_name = True
        self._attr_should_poll = False
        self._update_attributes(device_data)
        
        # Set up device info
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=device_data.get("name", f"Firewalla Device {device_id}"),
            manufacturer="Firewalla",
            model="Network Device",
            via_device=(DOMAIN, entry.entry_id),
        )
    
    @callback
    def _update_attributes(self, device_data: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        # Explicitly check for online status
        self._attr_is_on = device_data.get("online", False)
        
        # Set additional attributes
        self._attr_extra_state_attributes = {
            ATTR_DEVICE_ID: self.device_id,
            ATTR_NETWORK_ID: self.network_id,
        }
        
        # Add last seen timestamp if available
        last_active = device_data.get("lastActiveTimestamp")
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
            if attr in device_data:
                self._attr_extra_state_attributes[attr] = device_data[attr]

