"""Binary sensor platform for Firewalla integration."""
import logging

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, COORDINATOR, ATTR_ALARM_ID

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

