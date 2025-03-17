"""Firewalla API Client."""
import logging
import aiohttp
import asyncio
import async_timeout
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union
import json
import ssl

from .const import (
    DEFAULT_TIMEOUT,
    DEFAULT_API_URL,
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
    ) -> None:
        """Initialize the API client."""
        self._session = session
        self._email = email
        self._password = password
        self._api_key = api_key
        self._api_secret = api_secret
        self._api_token = api_token
        self._subdomain = subdomain
        self._access_token = api_token  # Use api_token as access token if provided
        
        # Use the correct URL format based on the API documentation
        if subdomain:
            self._base_url = f"https://{subdomain}.firewalla.net/v2"
            _LOGGER.debug("Using API URL: %s", self._base_url)
        else:
            self._base_url = DEFAULT_API_URL
            _LOGGER.debug("Using default API URL: %s", self._base_url)
            
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
            
        self._token_expires_at = None
        
        _LOGGER.debug("Initialized Firewalla API client with auth method: %s", self._auth_method)

    @property
    def _headers(self) -> Dict[str, str]:
        """Get the headers for API requests."""
        headers = {"Content-Type": "application/json"}
        
        # Add authorization header if we have a token
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
            
        return headers

    async def authenticate(self) -> bool:
        """Authenticate with the Firewalla API."""
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

    async def _authenticate_with_credentials(self) -> bool:
        """Authenticate using email and password."""
        _LOGGER.debug("Authenticating with email and password")
        
        # Based on the API documentation, the login endpoint is /auth/login
        login_url = f"{self._base_url}/auth/login"
        
        payload = {
            "email": self._email,
            "password": self._password
        }
        
        try:
            async with async_timeout.timeout(DEFAULT_TIMEOUT):
                response = await self._session.post(login_url, json=payload)
                
                if response.status != 200:
                    response_text = await response.text()
                    _LOGGER.error(
                        "Authentication failed with status %s: %s", 
                        response.status, 
                        response_text
                    )
                    return False
                
                try:
                    data = await response.json()
                except aiohttp.ContentTypeError:
                    response_text = await response.text()
                    _LOGGER.error("Authentication response is not valid JSON: %s", response_text)
                    return False
                
                # Look for token in the response
                token = None
                if "token" in data:
                    token = data["token"]
                elif "access_token" in data:
                    token = data["access_token"]
                elif "accessToken" in data:
                    token = data["accessToken"]
                elif "data" in data and "token" in data["data"]:
                    token = data["data"]["token"]
                
                if not token:
                    _LOGGER.error("No token found in authentication response")
                    return False
                
                self._access_token = token
                # Set expiration if provided, otherwise default to 1 hour
                if "expiresIn" in data:
                    self._token_expires_at = datetime.now() + timedelta(seconds=data["expiresIn"])
                elif "expires_in" in data:
                    self._token_expires_at = datetime.now() + timedelta(seconds=data["expires_in"])
                else:
                    self._token_expires_at = datetime.now() + timedelta(hours=1)
                
                _LOGGER.debug("Authentication successful")
                return True
        
        except asyncio.TimeoutError:
            _LOGGER.error("Authentication request timed out")
            return False
        except Exception as exc:
            _LOGGER.error("Authentication failed: %s", exc)
            return False

    async def _authenticate_with_api_key(self) -> bool:
        """Authenticate using API key and secret."""
        _LOGGER.debug("Authenticating with API key and secret")
        
        # Based on the API documentation, the login endpoint is /auth/login
        login_url = f"{self._base_url}/auth/login"
        
        payload = {
            "apiKey": self._api_key,
            "apiSecret": self._api_secret
        }
        
        try:
            async with async_timeout.timeout(DEFAULT_TIMEOUT):
                response = await self._session.post(login_url, json=payload)
                
                if response.status != 200:
                    response_text = await response.text()
                    _LOGGER.error(
                        "API key authentication failed with status %s: %s", 
                        response.status, 
                        response_text
                    )
                    return False
                
                try:
                    data = await response.json()
                except aiohttp.ContentTypeError:
                    response_text = await response.text()
                    _LOGGER.error("Authentication response is not valid JSON: %s", response_text)
                    return False
                
                # Look for token in the response
                token = None
                if "token" in data:
                    token = data["token"]
                elif "access_token" in data:
                    token = data["access_token"]
                elif "accessToken" in data:
                    token = data["accessToken"]
                elif "data" in data and "token" in data["data"]:
                    token = data["data"]["token"]
                
                if not token:
                    _LOGGER.error("No token found in authentication response")
                    return False
                
                self._access_token = token
                # Set expiration if provided, otherwise default to 1 hour
                if "expiresIn" in data:
                    self._token_expires_at = datetime.now() + timedelta(seconds=data["expiresIn"])
                elif "expires_in" in data:
                    self._token_expires_at = datetime.now() + timedelta(seconds=data["expires_in"])
                else:
                    self._token_expires_at = datetime.now() + timedelta(hours=1)
                
                _LOGGER.debug("API key authentication successful")
                return True
        
        except asyncio.TimeoutError:
            _LOGGER.error("Authentication request timed out")
            return False
        except Exception as exc:
            _LOGGER.error("API key authentication failed: %s", exc)
            return False

    async def _ensure_authenticated(self) -> bool:
        """Ensure the client is authenticated."""
        if not self._access_token or (
            self._token_expires_at and datetime.now() >= self._token_expires_at
        ):
            _LOGGER.debug("Token expired or not set, re-authenticating")
            return await self.authenticate()
        return True

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
        # Based on the API documentation, try to get the user info
        result = await self._api_request("GET", "user")
        if result:
            _LOGGER.info("Credential check successful")
            return True
        
        # If that fails, try to get the devices
        result = await self._api_request("GET", "devices")
        if result:
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

    async def get_devices(self) -> List[Dict[str, Any]]:
        """Get all devices across all networks."""
        # Make sure we're authenticated
        if not await self._ensure_authenticated():
            _LOGGER.error("Failed to authenticate")
            return []

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

