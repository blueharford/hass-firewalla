"""Switch platform for Firewalla integration."""
import logging
from typing import Any, Dict, Optional

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    COORDINATOR,
    API_CLIENT,
    ATTR_RULE_ID,
    ATTR_BLOCKED,
    ATTR_DEVICE_ID,
    ATTR_NETWORK_ID,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    """Set up switches for Firewalla devices."""
    coordinator = hass.data[DOMAIN][entry.entry_id].get(COORDINATOR)
    client = hass.data[DOMAIN][entry.entry_id].get(API_CLIENT)
    
    if not coordinator:
        _LOGGER.error("No coordinator found for entry %s", entry.entry_id)
        return
    
    entities = []
    
    # Add block switches for each device
    if coordinator.data and "devices" in coordinator.data:
        for device in coordinator.data["devices"]:
            entities.append(FirewallaBlockSwitch(coordinator, client, device))
    
    async_add_entities(entities)


class FirewallaBlockSwitch(CoordinatorEntity, SwitchEntity):
    """Switch for blocking Firewalla devices."""

    def __init__(self, coordinator, client, device):
        """Initialize the switch."""
        super().__init__(coordinator)
        self.client = client
        self.device_id = device["id"]
        self.network_id = device.get("networkId")
        self._attr_name = f"{device.get('name', 'Unknown')} Block"
        self._attr_unique_id = f"{DOMAIN}_block_{self.device_id}"
        self._attr_entity_category = EntityCategory.CONFIG
        self._attr_is_on = device.get("blocked", False)
        
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
        self._attr_is_on = device.get("blocked", False)
        self._attr_extra_state_attributes = {
            ATTR_DEVICE_ID: self.device_id,
            ATTR_NETWORK_ID: self.network_id,
        }
    
    async def async_turn_on(self, **kwargs: Any) -> None:
        """Block the device."""
        if hasattr(self.client, "block_device"):
            if await self.client.block_device(self.device_id, self.network_id):
                self._attr_is_on = True
                self.async_write_ha_state()
                await self.coordinator.async_request_refresh()
    
    async def async_turn_off(self, **kwargs: Any) -> None:
        """Unblock the device."""
        if hasattr(self.client, "unblock_device"):
            if await self.client.unblock_device(self.device_id, self.network_id):
                self._attr_is_on = False
                self.async_write_ha_state()
                await self.coordinator.async_request_refresh()

