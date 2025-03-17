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
            if isinstance(device, dict) and "id" in device:
                entities.append(FirewallaOnlineSensor(coordinator, device))
            else:
                _LOGGER.warning("Skipping device without id: %s", device)
    
    # Add online status sensors for each box
    if coordinator.data and "boxes" in coordinator.data:
        for box in coordinator.data["boxes"]:
            if isinstance(box, dict) and "id" in box:
                entities.append(FirewallaBoxOnlineSensor(coordinator, box))
            else:
                _LOGGER.warning("Skipping box without id: %s", box)
    
    # Add alarm sensors
    if coordinator.data and "alarms" in coordinator.data:
        for alarm in coordinator.data["alarms"]:
            if isinstance(alarm, dict) and "id" in alarm:
                entities.append(FirewallaAlarmSensor(coordinator, alarm))
            else:
                _LOGGER.warning("Skipping alarm without id: %s", alarm)
    
    # Add rule status sensors
    if coordinator.data and "rules" in coordinator.data:
        for rule in coordinator.data["rules"]:
            if isinstance(rule, dict) and "id" in rule:
                entities.append(FirewallaRuleStatusSensor(coordinator, rule))
            else:
                _LOGGER.warning("Skipping rule without id: %s", rule)
    
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
        
        # Add IP address
        if "ip" in device:
            self._attr_extra_state_attributes["ip_address"] = device["ip"]
        
        # Add MAC address (which is often the id)
        if "mac" in device:
            self._attr_extra_state_attributes["mac_address"] = device["mac"]
        
        # Add network name
        if "networkName" in device:
            self._attr_extra_state_attributes["network_name"] = device["networkName"]
        elif "network_name" in device:
            self._attr_extra_state_attributes["network_name"] = device["network_name"]
        
        # Add group name if available
        if "groupName" in device:
            self._attr_extra_state_attributes["group_name"] = device["groupName"]
        elif "group_name" in device:
            self._attr_extra_state_attributes["group_name"] = device["group_name"]
        
        # Add IP reservation status
        if "ipReservation" in device:
            self._attr_extra_state_attributes["ip_reserved"] = device["ipReservation"]
        elif "ip_reservation" in device:
            self._attr_extra_state_attributes["ip_reserved"] = device["ip_reservation"]
        
        # Add MAC vendor information
        if "macVendor" in device:
            self._attr_extra_state_attributes["mac_vendor"] = device["macVendor"]
        elif "mac_vendor" in device:
            self._attr_extra_state_attributes["mac_vendor"] = device["mac_vendor"]
        
        # Add last seen timestamp if available
        last_active = device.get("lastActiveTimestamp") or device.get("last_active_timestamp")
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


class FirewallaBoxOnlineSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for Firewalla box online status."""

    def __init__(self, coordinator, box):
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self.box_id = box["id"]
        self._attr_name = f"Firewalla Box {box.get('name', 'Unknown')} Online"
        self._attr_unique_id = f"{DOMAIN}_box_online_{self.box_id}"
        self._attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
        
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
        # Explicitly check for online status
        self._attr_is_on = box.get("online", False)
        
        # Set additional attributes
        self._attr_extra_state_attributes = {
            "box_id": self.box_id,
            "name": box.get("name", "Unknown"),
            "model": box.get("model", "Unknown"),
            "version": box.get("version", "Unknown"),
        }
        
        # Add last seen timestamp if available
        last_active = box.get("lastActiveTimestamp")
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


class FirewallaAlarmSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for Firewalla alarms."""

    def __init__(self, coordinator, alarm):
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self.alarm_id = alarm["id"]
        
        # Get a descriptive name for the alarm
        alarm_type = alarm.get("type") or alarm.get("_type", "Unknown")
        if isinstance(alarm_type, int):
            alarm_type = f"Type {alarm_type}"
        
        self._attr_name = f"Firewalla Alarm {alarm_type}"
        self._attr_unique_id = f"{DOMAIN}_alarm_{self.alarm_id}"
        self._attr_device_class = BinarySensorDeviceClass.PROBLEM
        
        # Set up device info - associate with the box if possible
        box_id = alarm.get("boxId") or alarm.get("box_id") or alarm.get("gid")
        if box_id:
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, f"box_{box_id}")},
                name=f"Firewalla Box {box_id}",
                manufacturer="Firewalla",
                model="Firewalla Box",
            )
        
        self._update_attributes(alarm)
    
    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if not self.coordinator.data or "alarms" not in self.coordinator.data:
            return
            
        for alarm in self.coordinator.data["alarms"]:
            if alarm["id"] == self.alarm_id:
                self._update_attributes(alarm)
                break
                
        self.async_write_ha_state()
    
    @callback
    def _update_attributes(self, alarm: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        # Alarm is active if status is not 2 (cleared)
        self._attr_is_on = alarm.get("status", 1) != 2
        
        # Set additional attributes
        self._attr_extra_state_attributes = {
            ATTR_ALARM_ID: self.alarm_id,
            "type": alarm.get("type", "Unknown"),
            "message": alarm.get("message", ""),
            "timestamp": alarm.get("ts", ""),
        }
        
        # Add device info if available
        if "device" in alarm and isinstance(alarm["device"], dict):
            device = alarm["device"]
            if "id" in device:
                self._attr_extra_state_attributes[ATTR_DEVICE_ID] = device["id"]
            if "name" in device:
                self._attr_extra_state_attributes["device_name"] = device["name"]
            if "ip" in device:
                self._attr_extra_state_attributes["device_ip"] = device["ip"]
            if "mac" in device:
                self._attr_extra_state_attributes["device_mac"] = device["mac"]


class FirewallaRuleStatusSensor(CoordinatorEntity, BinarySensorEntity):
    """Binary sensor for Firewalla rule status."""

    def __init__(self, coordinator, rule):
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self.rule_id = rule["id"]
        
        # Get a descriptive name for the rule
        rule_name = rule.get("name", "")
        if not rule_name:
            # Try to create a descriptive name from the target
            if "target" in rule and isinstance(rule["target"], dict):
                target_type = rule["target"].get("type", "")
                target_value = rule["target"].get("value", "")
                if target_type and target_value:
                    rule_name = f"{target_type}:{target_value}"
                elif target_type:
                    rule_name = target_type
            
            # If still no name, use the action and direction
            if not rule_name:
                action = rule.get("action", "")
                direction = rule.get("direction", "")
                if action and direction:
                    rule_name = f"{action}_{direction}"
                elif action:
                    rule_name = action
        
        # If still no name, use the ID
        if not rule_name:
            rule_name = self.rule_id[:8]
        
        self._attr_name = f"Firewalla Rule {rule_name}"
        self._attr_unique_id = f"{DOMAIN}_rule_{self.rule_id}"
        self._attr_device_class = BinarySensorDeviceClass.RUNNING
        
        # Set up device info - associate with the box if possible
        box_id = rule.get("boxId") or rule.get("box_id") or rule.get("gid")
        if box_id:
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, f"box_{box_id}")},
                name=f"Firewalla Box {box_id}",
                manufacturer="Firewalla",
                model="Firewalla Box",
            )
        
        self._update_attributes(rule)
    
    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if not self.coordinator.data or "rules" not in self.coordinator.data:
            return
            
        for rule in self.coordinator.data["rules"]:
            if rule["id"] == self.rule_id:
                self._update_attributes(rule)
                break
                
        self.async_write_ha_state()
    
    @callback
    def _update_attributes(self, rule: Dict[str, Any]) -> None:
        """Update the entity attributes."""
        # Rule is active if status is 'active'
        self._attr_is_on = rule.get("status") == "active"
        
        # Set additional attributes
        self._attr_extra_state_attributes = {
            ATTR_RULE_ID: self.rule_id,
            "action": rule.get("action", "Unknown"),
            "direction": rule.get("direction", "Unknown"),
            "status": rule.get("status", "Unknown"),
        }
        
        # Add target information if available
        if "target" in rule and isinstance(rule["target"], dict):
            target = rule["target"]
            self._attr_extra_state_attributes["target_type"] = target.get("type", "")
            if "value" in target:
                self._attr_extra_state_attributes["target_value"] = target["value"]
        
        # Add scope information if available
        if "scope" in rule and isinstance(rule["scope"], dict):
            scope = rule["scope"]
            self._attr_extra_state_attributes["scope_type"] = scope.get("type", "")
            if "value" in scope:
                self._attr_extra_state_attributes["scope_value"] = scope["value"]
            if "port" in scope:
                self._attr_extra_state_attributes["scope_port"] = scope["port"]
        
        # Add timestamp information
        if "ts" in rule:
            self._attr_extra_state_attributes["created_at"] = rule["ts"]
        if "updateTs" in rule:
            self._attr_extra_state_attributes["updated_at"] = rule["updateTs"]

