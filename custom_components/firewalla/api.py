"""Firewalla API Client."""
import logging
import aiohttp
import json
import re

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
            "Accept": "application/json",
        }
        self._base_url = f"https://{self._subdomain}.firewalla.net/api"
        _LOGGER.debug("Initialized Firewalla API client with base URL: %s", self._base_url)

    async def _api_request(self, method, endpoint, data=None, auth_test=False):
        """Make an API request."""
        url = f"{self._base_url}/{endpoint}"
        
        try:
            _LOGGER.debug("Making %s request to %s", method, url)
            
            # For authentication testing, we'll try different auth methods
            headers = self._headers
            if auth_test:
                # Try without the 'Bearer' prefix as some APIs just want the token
                headers = {
                    "Authorization": self._api_token,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                }
                _LOGGER.debug("Using simplified Authorization header for auth test")
            
            async with self._session.request(
                method, url, headers=headers, json=data
            ) as resp:
                _LOGGER.debug("API response status: %s for URL: %s", resp.status, url)
                
                # Check content type
                content_type = resp.headers.get("Content-Type", "")
                _LOGGER.debug("Content-Type: %s", content_type)
                
                # Get response text
                text = await resp.text()
                
                # For auth testing, we consider any successful response as valid
                if auth_test and resp.status == 200:
                    _LOGGER.debug("Auth test successful with status 200")
                    return {"success": True}
                
                if resp.status != 200:
                    _LOGGER.error(
                        "Error from Firewalla API: %s %s", resp.status, text[:200]
                    )
                    return None
                
                # Try to parse as JSON
                try:
                    return json.loads(text)
                except json.JSONDecodeError as err:
                    _LOGGER.error("Failed to parse JSON response from %s: %s", endpoint, err)
                    _LOGGER.debug("Response content: %s", text[:200] + "..." if len(text) > 200 else text)
                    
                    # For auth testing, check if the response contains any indication of success
                    if auth_test and ("success" in text.lower() or "welcome" in text.lower()):
                        _LOGGER.debug("Auth test successful based on response content")
                        return {"success": True}
                    
                    return None
                
        except aiohttp.ClientError as err:
            _LOGGER.error("Error making API request to %s: %s", url, err)
            return None

    async def async_check_credentials(self):
        """Check if credentials are valid."""
        # First, try to access the base URL to see if the domain is correct
        try:
            _LOGGER.debug("Testing base domain connectivity")
            async with self._session.get(
                f"https://{self._subdomain}.firewalla.net/", 
                timeout=10
            ) as resp:
                _LOGGER.debug("Base domain response: %s", resp.status)
                if resp.status != 200:
                    _LOGGER.error("Failed to connect to base domain. Check your subdomain.")
                    raise Exception(f"Failed to connect to {self._subdomain}.firewalla.net - Check your subdomain")
        except aiohttp.ClientError as err:
            _LOGGER.error("Error connecting to base domain: %s", err)
            raise Exception(f"Failed to connect to {self._subdomain}.firewalla.net - {err}")
        
        # Try different authentication approaches
        auth_methods = [
            # Standard Bearer token auth
            {"method": "GET", "endpoint": "device", "auth_test": False},
            {"method": "GET", "endpoint": "flow", "auth_test": False},
            {"method": "GET", "endpoint": "alarm", "auth_test": False},
            {"method": "GET", "endpoint": "rule", "auth_test": False},
            # Try with simplified auth header
            {"method": "GET", "endpoint": "device", "auth_test": True},
            {"method": "GET", "endpoint": "flow", "auth_test": True},
            # Try the root API endpoint
            {"method": "GET", "endpoint": "", "auth_test": False},
            {"method": "GET", "endpoint": "", "auth_test": True},
            # Last resort
            {"method": "GET", "endpoint": "users/me", "auth_test": False},
        ]
        
        for i, auth_method in enumerate(auth_methods):
            _LOGGER.debug(
                "Trying authentication method %d: %s %s (auth_test=%s)",
                i + 1,
                auth_method["method"],
                auth_method["endpoint"],
                auth_method["auth_test"]
            )
            
            result = await self._api_request(
                auth_method["method"],
                auth_method["endpoint"],
                auth_test=auth_method["auth_test"]
            )
            
            if result is not None:
                _LOGGER.debug("Authentication successful with method %d", i + 1)
                return True
        
        # If we get here, all authentication methods failed
        _LOGGER.error("Failed to authenticate with any Firewalla API endpoint")
        
        # Try to get more diagnostic information
        try:
            _LOGGER.debug("Attempting to get diagnostic information")
            async with self._session.get(
                f"https://{self._subdomain}.firewalla.net/api", 
                timeout=10
            ) as resp:
                text = await resp.text()
                _LOGGER.debug("API root response: %s, Content: %s", resp.status, text[:200])
        except Exception as err:
            _LOGGER.debug("Failed to get diagnostic information: %s", err)
        
        raise Exception("Failed to authenticate with Firewalla API. Check your API token and subdomain.")

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
