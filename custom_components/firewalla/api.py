"""Firewalla API Client."""
import logging
import aiohttp
import asyncio
import async_timeout
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from .const import (
    DEFAULT_TIMEOUT,
    DEFAULT_API_URL,
    API_LOGIN_ENDPOINT,
    API_ORGS_ENDPOINT,
    API_NETWORKS_ENDPOINT,
    API_DEVICES_ENDPOINT,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_API_KEY,
    CONF_API_SECRET,
    CONF_API_TOKEN,
    CONF_SUBDOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class FirewallaApiClient:
    """Firewalla API client."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        email: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        api_token: Optional[str] = None,
        subdomain: Optional[str] = None,
        use_mock_data: bool = False,
    ) -> None:
        """Initialize the API client."""
        self._session = session
        self._email = email
        self._password = password
        self._api_key = api_key
        self._api_secret = api_secret
        self._api_token = api_token
        self._subdomain = subdomain
        self._use_mock_data = use_mock_data
        self._access_token = api_token  # Use api_token as access token if provided
        
        # Determine base URL based on subdomain
        if subdomain:
            self._base_url = f"https://{subdomain}.firewalla.io/api/1.0"
        else:
            self._base_url = DEFAULT_API_URL
            
        # Determine auth method
        if email and password:
            self._auth_method = "credentials"
        elif api_key and api_secret:
            self._auth_method = "api_key"
        elif api_token:
            self._auth_method = "token"
            # If using token directly, we're already authenticated
            self._access_token = api_token
        else:
            self._auth_method = None
            
        self._org_id = None
        self._token_expires_at = None
        
        _LOGGER.debug("Initialized Firewalla API client with auth method: %s", self._auth_method)

    async def authenticate(self) -> bool:
        """Authenticate with the Firewalla API."""
        if self._use_mock_data:
            _LOGGER.debug("Using mock data, skipping authentication")
            self._access_token = "mock_token"
            self._token_expires_at = datetime.now() + timedelta(hours=1)
            return True

        # If we're using a direct token, we're already authenticated
        if self._auth_method == "token" and self._access_token:
            _LOGGER.debug("Using provided API token, skipping authentication")
            return True

        if not self._auth_method:
            _LOGGER.error("No authentication method configured")
            return False

        try:
            if self._auth_method == "credentials":
                return await self._authenticate_with_credentials()
            elif self._auth_method == "api_key":
                return await self._authenticate_with_api_key()
        except Exception as exc:
            _LOGGER.error("Authentication failed: %s", exc)
            return False

    async def _api_request(self, method, endpoint, data=None):
        """Make an API request."""
        url = f"{self._base_url}/{endpoint}"
        
        try:
            async with self._session.request(
                method, url, headers=self._headers, json=data
            ) as resp:
                if resp.status != 200:
                    _LOGGER.error(
                        "Error from Firewalla API: %s %s", resp.status, await resp.text()
                    )
                    return None
                return await resp.json()
        except aiohttp.ClientError as err:
            _LOGGER.error("Error making API request: %s", err)
            return None

    async def async_check_credentials(self):
        """Check if credentials are valid."""
        # Try to get user info as a validation check
        result = await self._api_request("GET", "users/me")
        if not result:
            raise Exception("Failed to authenticate with Firewalla API")
        return True

    async def async_get_devices(self):
        """Get all devices."""
        return await self._api_request("GET", "device")

    async def async_get_flows(self):
        """Get all flows."""
        return await self._api_request("GET", "flow")

    async def async_get_alarms(self):
        """Get all alarms."""
        return await self._api_request("GET", "alarm")

    async def async_get_rules(self):
        """Get all rules."""
        return await self._api_request("GET", "rule")

    async def async_get_statistics(self):
        """Get statistics."""
        return await self._api_request("GET", "statistics")

    async def async_get_target_lists(self):
        """Get target lists."""
        return await self._api_request("GET", "target_list")

    async def async_toggle_rule(self, rule_id, enabled):
        """Enable or disable a rule."""
        data = {"enabled": enabled}
        return await self._api_request("PUT", f"rule/{rule_id}", data)

    async def get_devices(self) -> List[Dict[str, Any]]:
        """Get all devices across all networks."""
        if self._use_mock_data:
            return [
                {
                    "id": "mock_device_1",
                    "name": "Mock Device 1",
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.168.1.100",
                    "online": True,
                    "lastActiveTimestamp": int(datetime.now().timestamp() * 1000),
                    "networkId": "mock_network_1"
                },
                {
                    "id": "mock_device_2",
                    "name": "Mock Device 2",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.101",
                    "online": False,
                    "lastActiveTimestamp": int((datetime.now() - timedelta(hours=2)).timestamp() * 1000),
                    "networkId": "mock_network_1"
                }
            ]

        # Based on the example provided in the Firewalla MSP API examples
        org_id = await self.get_organization_id()
        if not org_id:
            _LOGGER.error("Cannot get devices without organization ID")
            return []

        if not await self._ensure_authenticated():
            return []

        networks = await self.get_networks()
        if not networks:
            _LOGGER.error("No networks found")
            return []

        all_devices = []
        
        for network in networks:
            network_id = network.get("id")
            if not network_id:
                continue
                
            _LOGGER.debug("Getting devices for network: %s", network_id)
            
            # Following the approach from the example code
            devices_url = f"{self._base_url}{API_DEVICES_ENDPOINT}?orgId={org_id}&networkId={network_id}"
            
            try:
                async with async_timeout.timeout(DEFAULT_TIMEOUT):
                    headers = {"Authorization": f"Bearer {self._access_token}"}
                    response = await self._session.get(devices_url, headers=headers)
                    
                    if response.status != 200:
                        response_text = await response.text()
                        _LOGGER.error(
                            "Failed to get devices for network %s with status %s: %s", 
                            network_id,
                            response.status, 
                            response_text
                        )
                        continue
                    
                    try:
                        data = await response.json()
                    except aiohttp.ContentTypeError:
                        _LOGGER.error("Devices response is not valid JSON for network %s", network_id)
                        continue
                    
                    if not data or not isinstance(data, list):
                        _LOGGER.error("Invalid devices data format for network %s", network_id)
                        continue
                    
                    # Add network ID to each device for reference
                    for device in data:
                        device["networkId"] = network_id
                        # Ensure online status is properly set
                        if "online" not in device:
                            # If online status is not explicitly set, determine from lastActiveTimestamp
                            last_active = device.get("lastActiveTimestamp")
                            if last_active:
                                # Consider device offline if last active more than 5 minutes ago
                                now = datetime.now().timestamp() * 1000
                                device["online"] = (now - last_active) < (5 * 60 * 1000)
                            else:
                                device["online"] = False
                            
                    all_devices.extend(data)
                    _LOGGER.debug("Found %s devices in network %s", len(data), network_id)
                    
            except asyncio.TimeoutError:
                _LOGGER.error("Devices request timed out for network %s", network_id)
                continue
            except Exception as exc:
                _LOGGER.error("Failed to get devices for network %s: %s", network_id, exc)
                continue
        
        _LOGGER.debug("Retrieved a total of %s devices across all networks", len(all_devices))
        return all_devices

    async def get_organization_id(self):
        """Placeholder for getting organization ID."""
        return "your_organization_id"

    async def get_networks(self):
        """Placeholder for getting networks."""
        return [{"id": "your_network_id"}]

    async def _ensure_authenticated(self):
        """Placeholder for ensuring authentication."""
        return True

