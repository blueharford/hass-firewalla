"""Sensor platform for Firewalla integration."""
import logging
from typing import Any, Dict, Optional

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfDataRate,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    COORDINATOR,
    ATTR_DEVICE_ID,
    ATTR_DEVICE_NAME,
    ATTR_NETWORK_ID,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    """Set up sensors for Firewalla devices."""
    coordinator = hass.data[DOMAIN][entry.entry_id].get(COORDINATOR)
    
    if not coordinator:
        _LOGGER.error("No coordinator found for entry %s", entry.entry_id)
        return
    
    entities = []
    
    # Add sensors for each device
    if coordinator.data and "devices" in coordinator.data:
        for device in coordinator.data["devices"]:
            if isinstance(device, dict) and "id" in device:
                entities.append(FirewallaUploadSensor(coordinator, device))
                entities.append(FirewallaDownloadSensor(coordinator, device))
                entities.append(FirewallaBlockedCountSensor(coordinator, device))
            else:
                _LOGGER.warning("Skipping device without id: %s", device)
    
    # Add sensors for each box
    if coordinator.data and "boxes" in coordinator.data:
        for box in coordinator.data["boxes"]:
            if isinstance(box, dict) and "id" in box:
                entities.append(FirewallaBoxCPUSensor(coordinator, box))
                entities.append(FirewallaBoxMemorySensor(coordinator, box))
                entities.append(FirewallaBoxTemperatureSensor(coordinator, box))
            else:
                _LOGGER.warning("Skipping box without id: %s", box)
    
    # Add flow sensors
    if coordinator.data and "flows" in coordinator.data:
        for flow in coordinator.data["flows"]:
            if isinstance(flow, dict) and "id" in flow:
                entities.append(FirewallaFlowSensor(coordinator, flow))
            else:
                _LOGGER.warning("Skipping flow without id: %s", flow)
    
    async_add_entities(entities)


class FirewallaBaseSensor(CoordinatorEntity, SensorEntity):
    """Base sensor for Firewalla devices."""

    def __init__(
        self, 
        coordinator, 
        device,
        suffix: str,
        device_class: Optional[str] = None,
        state_class: Optional[str] = None,
        unit_of_measurement: Optional[str] = None,
    ):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.device_id = device["id"]
        self.network_id = device.get("networkId")
        self._attr_name = f"{device.get('name', 'Unknown')} {suffix}"
        self._attr_unique_id = f"{DOMAIN}_{suffix.lower().replace(' ', '_')}_{self.device_id}"
        self._attr_device_class = device_class
        self._attr_state_class = state_class
        self._attr_native_unit_of_measurement = unit_of_measurement
        
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
        self._attr_extra_state_attributes = {
            ATTR_DEVICE_ID: self.device_id,
            ATTR_NETWORK_ID: self.network_id,
            ATTR_DEVICE_NAME: device.get("name", "Unknown"),
        }


class FirewallaUploadSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device upload data rate."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "Upload Rate",
            SensorDeviceClass.DATA_RATE,
            SensorStateClass.MEASUREMENT,
            UnitOfDataRate.BYTES_PER_SECOND,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get upload rate from stats if available
        stats = device.get("stats", {})
        self._attr_native_value = stats.get("upload", 0)


class FirewallaDownloadSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device download data rate."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "Download Rate",
            SensorDeviceClass.DATA_RATE,
            SensorStateClass.MEASUREMENT,
            UnitOfDataRate.BYTES_PER_SECOND,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get download rate from stats if available
        stats = device.get("stats", {})
        self._attr_native_value = stats.get("download", 0)


class FirewallaBlockedCountSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device blocked connections count."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "Blocked Count",
            None,
            SensorStateClass.TOTAL_INCREASING,
            None,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get blocked count from stats if available
        stats = device.get("stats", {})
        self._attr_native_value = stats.get("blockedCount", 0)


class FirewallaBoxBaseSensor(CoordinatorEntity, SensorEntity):
    """Base sensor for Firewalla box."""

    def __init__(
        self, 
        coordinator, 
        box,
        suffix: str,
        device_class: Optional[str] = None,
        state_class: Optional[str] = None,
        unit_of_measurement: Optional[str] = None,
    ):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.box_id = box["id"]
        self._attr_name = f"Firewalla Box {box.get('name', 'Unknown')} {suffix}"
        self._attr_unique_id = f"{DOMAIN}_box_{suffix.lower().replace(' ', '_')}_{self.box_id}"
        self._attr_device_class = device_class
        self._attr_state_class = state_class
        self._attr_native_unit_of_measurement = unit_of_measurement
        
        # Set up device info
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"box_{self.box_id}")},
            name=f"Firewalla Box {box.get('name', self.box_id)}",
            manufacturer="Firewalla",
            model=box.get("model", "Firewalla Box"),
        )
        
        self._update_attributes(box)
    
    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if not self.coordinator.data or "boxes" not in self.coordinator.data:
            return
            
        for box in self.coordinator.data["boxes"]:
            if box["id"] == self.box_id:
                self._update_attributes(box)
                break
                
        self.async_write_ha_state()
    
    @callback
    def _update_attributes(self, box: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        self._attr_extra_state_attributes = {
            "box_id": self.box_id,
            "name": box.get("name", "Unknown"),
            "model": box.get("model", "Unknown"),
            "version": box.get("version", "Unknown"),
        }


class FirewallaBoxCPUSensor(FirewallaBoxBaseSensor):
    """Sensor for Firewalla box CPU usage."""

    def __init__(self, coordinator, box):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            box,
            "CPU Usage",
            SensorDeviceClass.POWER_FACTOR,
            SensorStateClass.MEASUREMENT,
            "%",
        )
    
    @callback
    def _update_attributes(self, box: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(box)
        
        # Get CPU usage from stats if available
        stats = box.get("stats", {})
        self._attr_native_value = stats.get("cpu", 0)


class FirewallaBoxMemorySensor(FirewallaBoxBaseSensor):
    """Sensor for Firewalla box memory usage."""

    def __init__(self, coordinator, box):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            box,
            "Memory Usage",
            SensorDeviceClass.POWER_FACTOR,
            SensorStateClass.MEASUREMENT,
            "%",
        )
    
    @callback
    def _update_attributes(self, box: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(box)
        
        # Get memory usage from stats if available
        stats = box.get("stats", {})
        self._attr_native_value = stats.get("memory", 0)


class FirewallaBoxTemperatureSensor(FirewallaBoxBaseSensor):
    """Sensor for Firewalla box temperature."""

    def __init__(self, coordinator, box):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            box,
            "Temperature",
            SensorDeviceClass.TEMPERATURE,
            SensorStateClass.MEASUREMENT,
            "°C",
        )
    
    @callback
    def _update_attributes(self, box: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(box)
        
        # Get temperature from stats if available
        stats = box.get("stats", {})
        self._attr_native_value = stats.get("temperature", 0)


class FirewallaFlowSensor(CoordinatorEntity, SensorEntity):
    """Sensor for Firewalla network flow."""

    def __init__(self, coordinator, flow):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.flow_id = flow["id"]
        
        # Create a descriptive name based on source and destination
        src = flow.get("src", "unknown")
        dst = flow.get("dst", "unknown")
        self._attr_name = f"Flow {src} to {dst}"
        
        self._attr_unique_id = f"{DOMAIN}_flow_{self.flow_id}"
        self._attr_device_class = SensorDeviceClass.DATA_RATE
        self._attr_state_class = SensorStateClass.MEASUREMENT
        self._attr_native_unit_of_measurement = UnitOfDataRate.BYTES_PER_SECOND
        
        # Set up device info - associate with the box if possible
        box_id = flow.get("boxId") or flow.get("box_id")
        if box_id:
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, f"box_{box_id}")},
                name=f"Firewalla Box {box_id}",
                manufacturer="Firewalla",
                model="Firewalla Box",
            )
        
        self._update_attributes(flow)
    
    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if not self.coordinator.data or "flows" not in self.coordinator.data:
            return
            
        for flow in self.coordinator.data["flows"]:
            if flow["id"] == self.flow_id:
                self._update_attributes(flow)
                break
                
        self.async_write_ha_state()
    
    @callback
    def _update_attributes(self, flow: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        # Use the total bytes as the state value
        self._attr_native_value = flow.get("bytes", 0)
        
        # Set additional attributes
        self._attr_extra_state_attributes = {
            "flow_id": self.flow_id,
            "source": flow.get("src", "unknown"),
            "destination": flow.get("dst", "unknown"),
            "protocol": flow.get("protocol", "unknown"),
            "upload": flow.get("upload", 0),
            "download": flow.get("download", 0),
            "duration": flow.get("duration", 0),
            "timestamp": flow.get("timestamp", ""),
        }

