"""Sensor platform for Firewalla integration."""
import logging
from typing import Any, Dict, Optional
from datetime import datetime

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfInformation,
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
                # Add MAC address sensor (which is often the id)
                entities.append(FirewallaMacAddressSensor(coordinator, device))
                
                # Add IP address sensor
                if "ip" in device:
                    entities.append(FirewallaIpAddressSensor(coordinator, device))
                
                # Add MAC vendor sensor
                if "macVendor" in device:
                    entities.append(FirewallaMacVendorSensor(coordinator, device))
                
                # Add network name sensor
                if "network" in device and isinstance(device["network"], dict):
                    entities.append(FirewallaNetworkNameSensor(coordinator, device))
                
                # Add group name sensor
                if "group" in device and isinstance(device["group"], dict):
                    entities.append(FirewallaGroupNameSensor(coordinator, device))
                
                # Add IP reservation sensor
                if "ipReserved" in device:
                    entities.append(FirewallaIpReservationSensor(coordinator, device))
                
                # Add total download sensor
                if "totalDownload" in device:
                    entities.append(FirewallaTotalDownloadSensor(coordinator, device))
                
                # Add total upload sensor
                if "totalUpload" in device:
                    entities.append(FirewallaTotalUploadSensor(coordinator, device))
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
        if "network" in device and isinstance(device["network"], dict) and "id" in device["network"]:
            self.network_id = device["network"]["id"]
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


class FirewallaMacAddressSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device MAC address."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "MAC Address",
            None,
            None,
            None,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # MAC address is often the device ID
        mac = device.get("mac", self.device_id)
        # If the ID starts with "mac:", extract just the MAC part
        if mac.startswith("mac:"):
            mac = mac[4:]
        self._attr_native_value = mac


class FirewallaIpAddressSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device IP address."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "IP Address",
            None,
            None,
            None,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get IP address
        self._attr_native_value = device.get("ip", "Unknown")


class FirewallaMacVendorSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device MAC vendor."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "MAC Vendor",
            None,
            None,
            None,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get MAC vendor
        self._attr_native_value = device.get("macVendor", "Unknown")


class FirewallaNetworkNameSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device network name."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "Network Name",
            None,
            None,
            None,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get network name from the nested network object
        network_name = "Unknown"
        if "network" in device and isinstance(device["network"], dict):
            network_name = device["network"].get("name", "Unknown")
        self._attr_native_value = network_name


class FirewallaGroupNameSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device group name."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "Group Name",
            None,
            None,
            None,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get group name from the nested group object
        group_name = "Unknown"
        if "group" in device and isinstance(device["group"], dict):
            group_name = device["group"].get("name", "Unknown")
        self._attr_native_value = group_name


class FirewallaIpReservationSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device IP reservation status."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "IP Reserved",
            None,
            None,
            None,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get IP reservation status
        ip_reserved = device.get("ipReserved", False)
        self._attr_native_value = "Yes" if ip_reserved else "No"


class FirewallaTotalDownloadSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device total download."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "Total Download",
            SensorDeviceClass.DATA_SIZE,
            SensorStateClass.TOTAL_INCREASING,
            UnitOfInformation.KILOBYTES,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get total download directly from the device object
        download_bytes = device.get("totalDownload", 0)
        
        # Convert bytes to kilobytes
        download_kb = download_bytes / 1024 if download_bytes else 0
        self._attr_native_value = round(download_kb, 2)


class FirewallaTotalUploadSensor(FirewallaBaseSensor):
    """Sensor for Firewalla device total upload."""

    def __init__(self, coordinator, device):
        """Initialize the sensor."""
        super().__init__(
            coordinator,
            device,
            "Total Upload",
            SensorDeviceClass.DATA_SIZE,
            SensorStateClass.TOTAL_INCREASING,
            UnitOfInformation.KILOBYTES,
        )
    
    @callback
    def _update_attributes(self, device: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        super()._update_attributes(device)
        
        # Get total upload directly from the device object
        upload_bytes = device.get("totalUpload", 0)
        
        # Convert bytes to kilobytes
        upload_kb = upload_bytes / 1024 if upload_bytes else 0
        self._attr_native_value = round(upload_kb, 2)


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
        src_name = "unknown"
        dst_name = "unknown"
        
        if "source" in flow and isinstance(flow["source"], dict):
            src_name = flow["source"].get("name", flow["source"].get("ip", "unknown"))
        
        if "destination" in flow and isinstance(flow["destination"], dict):
            dst_name = flow["destination"].get("name", flow["destination"].get("ip", "unknown"))
        
        self._attr_name = f"Flow {src_name} to {dst_name}"
        self._attr_unique_id = f"{DOMAIN}_flow_{self.flow_id}"
        self._attr_device_class = SensorDeviceClass.DATA_SIZE
        self._attr_state_class = SensorStateClass.MEASUREMENT
        self._attr_native_unit_of_measurement = UnitOfInformation.BYTES
        
        # Set up device info - associate with the device that generated the flow
        device_id = None
        if "device" in flow and isinstance(flow["device"], dict) and "id" in flow["device"]:
            device_id = flow["device"]["id"]
        elif "source" in flow and isinstance(flow["source"], dict) and "id" in flow["source"]:
            device_id = flow["source"]["id"]
        
        if device_id:
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, device_id)},
                name=flow.get("device", {}).get("name", f"Device {device_id}"),
                manufacturer="Firewalla",
                model="Network Device",
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
        # Use the total bytes (download + upload) as the state value
        download = flow.get("download", 0)
        upload = flow.get("upload", 0)
        self._attr_native_value = download + upload
        
        # Set additional attributes
        self._attr_extra_state_attributes = {
            "flow_id": self.flow_id,
            "protocol": flow.get("protocol", "unknown"),
            "direction": flow.get("direction", "unknown"),
            "blocked": flow.get("block", False),
            "download": download,
            "upload": upload,
            "duration": flow.get("duration", 0),
            "category": flow.get("category", "unknown"),
            "region": flow.get("region", "unknown"),
            "timestamp": flow.get("ts", ""),
        }
        
        # Add source information
        if "source" in flow and isinstance(flow["source"], dict):
            source = flow["source"]
            self._attr_extra_state_attributes["source_id"] = source.get("id", "unknown")
            self._attr_extra_state_attributes["source_ip"] = source.get("ip", "unknown")
            self._attr_extra_state_attributes["source_name"] = source.get("name", "unknown")
        
        # Add destination information
        if "destination" in flow and isinstance(flow["destination"], dict):
            destination = flow["destination"]
            self._attr_extra_state_attributes["destination_id"] = destination.get("id", "unknown")
            self._attr_extra_state_attributes["destination_ip"] = destination.get("ip", "unknown")
            self._attr_extra_state_attributes["destination_name"] = destination.get("name", "unknown")
        
        # Add device information
        if "device" in flow and isinstance(flow["device"], dict):
            device = flow["device"]
            self._attr_extra_state_attributes["device_id"] = device.get("id", "unknown")
            self._attr_extra_state_attributes["device_ip"] = device.get("ip", "unknown")
            self._attr_extra_state_attributes["device_name"] = device.get("name", "unknown")
            self._attr_extra_state_attributes["device_port"] = device.get("port", "unknown")
        
        # Add network information
        if "network" in flow and isinstance(flow["network"], dict):
            network = flow["network"]
            self._attr_extra_state_attributes["network_id"] = network.get("id", "unknown")
            self._attr_extra_state_attributes["network_name"] = network.get("name", "unknown")
        
        # Add group information
        if "group" in flow and isinstance(flow["group"], dict):
            group = flow["group"]
            self._attr_extra_state_attributes["group_id"] = group.get("id", "unknown")
            self._attr_extra_state_attributes["group_name"] = group.get("name", "unknown")
        
        # Convert timestamp to datetime if possible
        if "ts" in flow:
            try:
                ts = flow["ts"]
                if isinstance(ts, (int, float)):
                    dt = datetime.fromtimestamp(ts)
                    self._attr_extra_state_attributes["timestamp_formatted"] = dt.isoformat()
            except Exception as e:
                _LOGGER.debug("Error converting timestamp: %s", e)

