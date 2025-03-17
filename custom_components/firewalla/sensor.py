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
            entities.append(FirewallaUploadSensor(coordinator, device))
            entities.append(FirewallaDownloadSensor(coordinator, device))
            entities.append(FirewallaBlockedCountSensor(coordinator, device))
    
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

