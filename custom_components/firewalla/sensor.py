"""Sensor platform for Firewalla integration."""
import logging

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, COORDINATOR, ATTR_DEVICE_ID, ATTR_DEVICE_NAME

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    """Set up Firewalla sensors based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id][COORDINATOR]
    
    entities = []
    
    # Add device sensors
    if coordinator.data and "devices" in coordinator.data:
        for device in coordinator.data["devices"]:
            entities.append(FirewallaDeviceStatusSensor(coordinator, device))
            entities.append(FirewallaDeviceConnectionsSensor(coordinator, device))
    
    # Add flow sensors
    if coordinator.data and "flows" in coordinator.data:
        for flow in coordinator.data["flows"]:
            entities.append(FirewallaFlowSensor(coordinator, flow))
    
    async_add_entities(entities)


class FirewallaBaseSensor(CoordinatorEntity, SensorEntity):
    """Base class for Firewalla sensors."""

    def __init__(self, coordinator, data):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._data = data
        self._attr_unique_id = f"{DOMAIN}_{self._get_id()}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, self._get_device_id())},
            "name": self._get_device_name(),
            "manufacturer": "Firewalla",
            "model": self._get_device_model(),
        }

    def _get_id(self):
        """Get the ID for this entity."""
        raise NotImplementedError

    def _get_device_id(self):
        """Get the device ID for this entity."""
        raise NotImplementedError

    def _get_device_name(self):
        """Get the device name for this entity."""
        raise NotImplementedError

    def _get_device_model(self):
        """Get the device model for this entity."""
        return "Unknown"


class FirewallaDeviceStatusSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device status."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(coordinator, device)
        self._attr_name = f"{device.get('name', 'Unknown')} Status"
        self._attr_icon = "mdi:router-wireless"

    def _get_id(self):
        """Get the ID for this entity."""
        return f"device_{self._data.get('id', '')}_status"

    def _get_device_id(self):
        """Get the device ID for this entity."""
        return self._data.get("id", "unknown")

    def _get_device_name(self):
        """Get the device name for this entity."""
        return self._data.get("name", "Unknown Firewalla Device")

    def _get_device_model(self):
        """Get the device model for this entity."""
        return self._data.get("model", "Unknown")

    @property
    def state(self):
        """Return the state of the sensor."""
        if not self.coordinator.data or "devices" not in self.coordinator.data:
            return "unknown"
            
        for device in self.coordinator.data["devices"]:
            if device.get("id") == self._data.get("id"):
                return device.get("status", "unknown")
                
        return "unknown"

    @property
    def extra_state_attributes(self):
        """Return the state attributes."""
        if not self.coordinator.data or "devices" not in self.coordinator.data:
            return {}
            
        for device in self.coordinator.data["devices"]:
            if device.get("id") == self._data.get("id"):
                return {
                    ATTR_DEVICE_ID: device.get("id"),
                    ATTR_DEVICE_NAME: device.get("name"),
                    "ip_address": device.get("ip"),
                    "mac_address": device.get("mac"),
                    "last_seen": device.get("last_seen"),
                }
                
        return {}


class FirewallaDeviceConnectionsSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device connections."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(coordinator, device)
        self._attr_name = f"{device.get('name', 'Unknown')} Connections"
        self._attr_icon = "mdi:connection"
        self._attr_unit_of_measurement = "connections"

    def _get_id(self):
        """Get the ID for this entity."""
        return f"device_{self._data.get('id', '')}_connections"

    def _get_device_id(self):
        """Get the device ID for this entity."""
        return self._data.get("id", "unknown")

    def _get_device_name(self):
        """Get the device name for this entity."""
        return self._data.get("name", "Unknown Firewalla Device")

    @property
    def state(self):
        """Return the state of the sensor."""
        if not self.coordinator.data or "devices" not in self.coordinator.data:
            return 0
            
        for device in self.coordinator.data["devices"]:
            if device.get("id") == self._data.get("id"):
                return device.get("connections", 0)
                
        return 0


class FirewallaFlowSensor(FirewallaBaseSensor):
    """Sensor for Firewalla flow."""

    def __init__(self, coordinator, flow):
        """Initialize the sensor."""
        super().__init__(coordinator, flow)
        self._attr_name = f"Flow {flow.get('name', 'Unknown')}"
        self._attr_icon = "mdi:network"

    def _get_id(self):
        """Get the ID for this entity."""
        return f"flow_{self._data.get('id', '')}"

    def _get_device_id(self):
        """Get the device ID for this entity."""
        return self._data.get("device_id", "unknown")

    def _get_device_name(self):
        """Get the device name for this entity."""
        if not self.coordinator.data or "devices" not in self.coordinator.data:
            return "Unknown Device"
            
        for device in self.coordinator.data["devices"]:
            if device.get("id") == self._data.get("device_id"):
                return device.get("name", "Unknown Device")
                
        return "Unknown Device"

    @property
    def state(self):
        """Return the state of the sensor."""
        if not self.coordinator.data or "flows" not in self.coordinator.data:
            return "unknown"
            
        for flow in self.coordinator.data["flows"]:
            if flow.get("id") == self._data.get("id"):
                return flow.get("status", "unknown")
                
        return "unknown"

    @property
    def extra_state_attributes(self):
        """Return the state attributes."""
        if not self.coordinator.data or "flows" not in self.coordinator.data:
            return {}
            
        for flow in self.coordinator.data["flows"]:
            if flow.get("id") == self._data.get("id"):
                return {
                    "flow_id": flow.get("id"),
                    "name": flow.get("name"),
                    "source": flow.get("source"),
                    "destination": flow.get("destination"),
                    "protocol": flow.get("protocol"),
                    "bytes_in": flow.get("bytes_in"),
                    "bytes_out": flow.get("bytes_out"),
                }
                
        return {}

