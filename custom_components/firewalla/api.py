"""Firewalla API Client."""
import logging
import aiohttp
import asyncio
import async_timeout
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
import json
import ssl

from .const import (
    DEFAULT_TIMEOUT,
    DEFAULT_API_URL,
    CONF_API_TOKEN,
    CONF_SUBDOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class FirewallaApiClient:
    """Firewalla API client."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        api_token: str,
        subdomain: Optional[str] = None,
    ) -> None:
        """Initialize the API client."""
        self._session = session
        self._api_token = api_token
        self._subdomain = subdomain
        
        # Use the correct URL format based on the API documentation
        if subdomain:
            self._base_url = f"https://{subdomain}.firewalla.net/v2"
            _LOGGER.debug("Using API URL: %s", self._base_url)
        else:
            self._base_url = DEFAULT_API_URL
            _LOGGER.debug("Using default API URL: %s", self._base_url)
            
        _LOGGER.debug("Initialized Firewalla API client with token authentication")

    @property
    def _headers(self) -> Dict[str, str]:
        """Get the headers for API requests."""
        headers = {"Content-Type": "application/json"}
        
        # Add authorization header with token
        if self._api_token:
            headers["Authorization"] = f"Token {self._api_token}"
            
        return headers

    async def authenticate(self) -> bool:
        """Verify authentication with the Firewalla API."""
        # Simply check if we can access the boxes endpoint
        result = await self._api_request("GET", "boxes")
        if result is not None:
            _LOGGER.info("Authentication successful with boxes endpoint")
            return True
            
        _LOGGER.error("Failed to authenticate with Firewalla API")
        return False

    async def _api_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
        """Make an API request."""
        url = f"{self._base_url}/{endpoint}"
        _LOGGER.debug("%s request to %s", method, url)
        
        # Create SSL context that ignores certificate errors
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        try:
            async with async_timeout.timeout(DEFAULT_TIMEOUT):
                # Make the request with SSL context
                response = await self._session.request(
                    method, 
                    url, 
                    headers=self._headers, 
                    params=params,
                    json=data,
                    ssl=ssl_context
                )
                
                # Check if we got HTML instead of JSON
                content_type = response.headers.get("Content-Type", "")
                if "text/html" in content_type:
                    response_text = await response.text()
                    if "<html" in response_text:
                        _LOGGER.error("Received HTML response instead of JSON. URL: %s", url)
                        return None
            
                # Handle 401 Unauthorized errors
                if response.status == 401:
                    response_text = await response.text()
                    _LOGGER.error("Unauthorized error from Firewalla API: %s", response_text)
                    return None
            
                if response.status != 200:
                    response_text = await response.text()
                    _LOGGER.error(
                        "Error from Firewalla API: %s %s", 
                        response.status, 
                        response_text
                    )
                    return None
                
                try:
                    result = await response.json()
                    _LOGGER.debug("API request successful")
                    return result
                except aiohttp.ContentTypeError:
                    response_text = await response.text()
                    _LOGGER.error("Invalid JSON response: %s", response_text)
                    return None
                
        except asyncio.TimeoutError:
            _LOGGER.error("Request to %s timed out", url)
            return None
        except aiohttp.ClientError as err:
            _LOGGER.error("Error making request to %s: %s", url, err)
            return None
        except Exception as exc:
            _LOGGER.error("Unexpected error making request to %s: %s", url, exc)
            return None

    async def async_check_credentials(self) -> bool:
        """Check if credentials are valid."""
        # Simply check if we can access the boxes endpoint
        result = await self._api_request("GET", "boxes")
        if result is not None:
            _LOGGER.info("Credential check successful with boxes endpoint")
            return True
    
        # If that fails, try the devices endpoint
        result = await self._api_request("GET", "devices")
        if result is not None:
            _LOGGER.info("Credential check successful with devices endpoint")
            return True
    
        # If all attempts fail, return failure
        _LOGGER.error("Failed to validate credentials")
        return False

    async def block_device(self, device_id: str, network_id: str) -> bool:
        """Block a device."""
        # Based on the API documentation, the endpoint is /devices/{deviceId}/block
        endpoint = f"devices/{device_id}/block"
        params = {"networkId": network_id} if network_id else None
        
        result = await self._api_request("POST", endpoint, params=params)
        return result is not None

    async def unblock_device(self, device_id: str, network_id: str) -> bool:
        """Unblock a device."""
        # Based on the API documentation, the endpoint is /devices/{deviceId}/unblock
        endpoint = f"devices/{device_id}/unblock"
        params = {"networkId": network_id} if network_id else None
        
        result = await self._api_request("POST", endpoint, params=params)
        return result is not None

    async def get_boxes(self) -> List[Dict[str, Any]]:
        """Get all Firewalla boxes."""
        try:
            # Get the boxes from the API
            boxes = await self._api_request("GET", "boxes")
            
            if not boxes or not isinstance(boxes, list):
                _LOGGER.error("No boxes found or invalid response")
                return []
            
            _LOGGER.debug("Retrieved a total of %s boxes", len(boxes))
            return boxes
                
        except Exception as exc:
            _LOGGER.error("Error getting boxes: %s", exc)
            return []

    async def get_devices(self) -> List[Dict[str, Any]]:
        """Get all devices across all networks."""
        try:
            # Based on the API documentation, get the devices
            devices = await self._api_request("GET", "devices")
            
            if not devices or not isinstance(devices, list):
                _LOGGER.error("No devices found or invalid response")
                return []
            
            # Process the devices
            for device in devices:
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
                
                # Ensure networkId is set
                if "networkId" not in device:
                    device["networkId"] = "default"
            
            _LOGGER.debug("Retrieved a total of %s devices", len(devices))
            return devices
                
        except Exception as exc:
            _LOGGER.error("Error getting devices: %s", exc)
            return []

