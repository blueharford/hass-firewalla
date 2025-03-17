"""Firewalla API Client."""
import logging
import aiohttp
import json

_LOGGER = logging.getLogger(__name__)


class FirewallaApiClient:
    """Firewalla API client."""

    def __init__(self, api_token, subdomain, session):
        """Initialize the API client."""
        self._api_token = api_token
        self._subdomain = subdomain
        self._session = session
        self._headers = {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",  # Explicitly request JSON response
        }
        self._base_url = f"https://{self._subdomain}.firewalla.net/api"

    async def _api_request(self, method, endpoint, data=None):
        """Make an API request."""
        url = f"{self._base_url}/{endpoint}"
        
        try:
            async with self._session.request(
                method, url, headers=self._headers, json=data
            ) as resp:
                _LOGGER.debug("API response status: %s for URL: %s", resp.status, url)
                
                # Check content type
                content_type = resp.headers.get("Content-Type", "")
                _LOGGER.debug("Content-Type: %s", content_type)
                
                # Get response text
                text = await resp.text()
                
                if resp.status != 200:
                    _LOGGER.error(
                        "Error from Firewalla API: %s %s", resp.status, text
                    )
                    return None
                
                # Try to parse as JSON
                try:
                    return json.loads(text)
                except json.JSONDecodeError as err:
                    _LOGGER.error("Failed to parse JSON response from %s: %s", endpoint, err)
                    _LOGGER.debug("Response content: %s", text[:200] + "..." if len(text) > 200 else text)
                    return None
                
        except aiohttp.ClientError as err:
            _LOGGER.error("Error making API request to %s: %s", url, err)
            return None

    async def async_check_credentials(self):
        """Check if credentials are valid.
        
        Prioritizes endpoints that are known to return JSON.
        """
        # Try /device endpoint first as it's more likely to exist and return JSON
        _LOGGER.debug("Checking authentication with /device endpoint")
        result = await self._api_request("GET", "device")
        if result is not None:
            _LOGGER.debug("Successfully authenticated with /device endpoint")
            return True
            
        # If that fails, try /flow
        _LOGGER.debug("Checking authentication with /flow endpoint")
        result = await self._api_request("GET", "flow")
        if result is not None:
            _LOGGER.debug("Successfully authenticated with /flow endpoint")
            return True
            
        # If that fails, try /alarm
        _LOGGER.debug("Checking authentication with /alarm endpoint")
        result = await self._api_request("GET", "alarm")
        if result is not None:
            _LOGGER.debug("Successfully authenticated with /alarm endpoint")
            return True
            
        # If that fails, try /rule
        _LOGGER.debug("Checking authentication with /rule endpoint")
        result = await self._api_request("GET", "rule")
        if result is not None:
            _LOGGER.debug("Successfully authenticated with /rule endpoint")
            return True
            
        # Only try /users/me as a last resort since it might not return JSON
        _LOGGER.debug("Checking authentication with /users/me endpoint")
        result = await self._api_request("GET", "users/me")
        if result is not None:
            _LOGGER.debug("Successfully authenticated with /users/me endpoint")
            return True
            
        _LOGGER.error("Failed to authenticate with any Firewalla API endpoint")
        raise Exception("Failed to authenticate with Firewalla API")

    async def async_get_devices(self):
        """Get all devices."""
        return await self._api_request("GET", "device") or []

    async def async_get_flows(self):
        """Get all flows."""
        return await self._api_request("GET", "flow") or []

    async def async_get_alarms(self):
        """Get all alarms."""
        return await self._api_request("GET", "alarm") or []

    async def async_get_rules(self):
        """Get all rules."""
        return await self._api_request("GET", "rule") or []

    async def async_get_statistics(self):
        """Get statistics."""
        return await self._api_request("GET", "statistics") or []

    async def async_get_target_lists(self):
        """Get target lists."""
        return await self._api_request("GET", "target_list") or []

    async def async_toggle_rule(self, rule_id, enabled):
        """Enable or disable a rule."""
        data = {"enabled": enabled}
        return await self._api_request("PUT", f"rule/{rule_id}", data)
