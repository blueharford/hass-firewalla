"""Firewalla API Client."""
import logging
import aiohttp

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
        }
        self._base_url = f"https://{self._subdomain}.firewalla.net/api"

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

