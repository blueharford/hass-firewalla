"""Switch platform for Firewalla integration."""
import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, COORDINATOR, API_CLIENT, ATTR_RULE_ID

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    """Set up Firewalla switches based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id][COORDINATOR]
    api_client = hass.data[DOMAIN][entry.entry_id][API_CLIENT]
    
    entities = []
    
    # Add rule switches
    if coordinator.data and "rules" in coordinator.data:
        for rule in coordinator.data["rules"]:
            entities.append(FirewallaRuleSwitch(coordinator, api_client, rule))
    
    async_add_entities(entities)


class FirewallaRuleSwitch(CoordinatorEntity, SwitchEntity):
    """Switch for enabling/disabling Firewalla rules."""

    def __init__(self, coordinator, api_client, rule):
        """Initialize the switch."""
        super().__init__(coordinator)
        self._api_client = api_client
        self._rule = rule
        self._attr_unique_id = f"{DOMAIN}_rule_{rule.get('id', '')}"
        self._attr_name = f"Rule: {rule.get('name', 'Unknown')}"
        self._attr_icon = "mdi:shield"
        
        # Find the device this rule belongs to
        device_id = rule.get("device_id")
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
        """Return true if the rule is enabled."""
        if not self.coordinator.data or "rules" not in self.coordinator.data:
            return False
            
        for rule in self.coordinator.data["rules"]:
            if rule.get("id") == self._rule.get("id"):
                return rule.get("enabled", False)
                
        return False

    @property
    def extra_state_attributes(self):
        """Return the state attributes."""
        if not self.coordinator.data or "rules" not in self.coordinator.data:
            return {}
            
        for rule in self.coordinator.data["rules"]:
            if rule.get("id") == self._rule.get("id"):
                return {
                    ATTR_RULE_ID: rule.get("id"),
                    "name": rule.get("name"),
                    "type": rule.get("type"),
                    "target": rule.get("target"),
                    "action": rule.get("action"),
                    "created_at": rule.get("created_at"),
                }
                
        return {}

    async def async_turn_on(self, **kwargs):
        """Enable the rule."""
        await self._api_client.async_toggle_rule(self._rule.get("id"), True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs):
        """Disable the rule."""
        await self._api_client.async_toggle_rule(self._rule.get("id"), False)
        await self.coordinator.async_request_refresh()

