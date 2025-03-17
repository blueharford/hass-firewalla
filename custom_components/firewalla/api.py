"""Firewalla API Client."""
import logging
import aiohttp
import asyncio
import async_timeout
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union
import json
import ssl
import base64

from .const import (
    DEFAULT_TIMEOUT,
    DEFAULT_API_URL,
    API_LOGIN_ENDPOINT,
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
        
        # Try a completely different approach based on the subdomain
        # The subdomain might be the MSP instance name
        if subdomain:
            # Format 1: Direct API with subdomain
            self._base_url = f"https://{subdomain}.firewalla.io"
            _LOGGER.debug("Using direct subdomain URL: %s", self._base_url)
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
        
        # Try different authorization methods
        if self._access_token:
            # Method 1: Bearer token
            headers["Authorization"] = f"Bearer {self._access_token}"
            
            # Method 2: Token header
            headers["Token"] = self._access_token
            
            # Method 3: X-API-Token header
            headers["X-API-Token"] = self._access_token
            
            # Method 4: Basic auth with token as username
            auth_str = base64.b64encode(f"{self._access_token}:".encode()).decode()
            headers["Authorization"] = f"Basic {auth_str}"
            
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
        
        # Try different login endpoints
        login_endpoints = [
            "/api/v1/auth/login",
            "/api/v1/login",
            "/api/login",
            "/login"
        ]
        
        for endpoint in login_endpoints:
            login_url = f"{self._base_url}{endpoint}"
            _LOGGER.debug("Trying login endpoint: %s", login_url)
            
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
                        continue
                    
                    try:
                        data = await response.json()
                    except aiohttp.ContentTypeError:
                        response_text = await response.text()
                        _LOGGER.error("Authentication response is not valid JSON: %s", response_text)
                        continue
                    
                    # Look for token in different places
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
                        continue
                    
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
                continue
            except Exception as exc:
                _LOGGER.error("Authentication failed: %s", exc)
                continue
        
        _LOGGER.error("All authentication attempts failed")
        return False

    async def _authenticate_with_api_key(self) -> bool:
        """Authenticate using API key and secret."""
        _LOGGER.debug("Authenticating with API key and secret")
        
        # Try different login endpoints
        login_endpoints = [
            "/api/v1/auth/login",
            "/api/v1/login",
            "/api/login",
            "/login"
        ]
        
        for endpoint in login_endpoints:
            login_url = f"{self._base_url}{endpoint}"
            _LOGGER.debug("Trying login endpoint: %s", login_url)
            
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
                        continue
                    
                    try:
                        data = await response.json()
                    except aiohttp.ContentTypeError:
                        response_text = await response.text()
                        _LOGGER.error("Authentication response is not valid JSON: %s", response_text)
                        continue
                    
                    # Look for token in different places
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
                        continue
                    
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
                continue
            except Exception as exc:
                _LOGGER.error("API key authentication failed: %s", exc)
                continue
        
        _LOGGER.error("All API key authentication attempts failed")
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
        # Try different API endpoints
        api_prefixes = [
            "/api/v1",
            "/api",
            ""
        ]
        
        # Create SSL context that ignores certificate errors
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        for prefix in api_prefixes:
            url = f"{self._base_url}{prefix}/{endpoint}"
            _LOGGER.debug("%s request to %s", method, url)
            
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
                            _LOGGER.debug("Received HTML response instead of JSON. URL: %s", url)
                            continue
                    
                    if response.status != 200:
                        response_text = await response.text()
                        _LOGGER.debug(
                            "Error from Firewalla API: %s %s", 
                            response.status, 
                            response_text
                        )
                        continue
                    
                    try:
                        result = await response.json()
                        _LOGGER.debug("API request successful")
                        return result
                    except aiohttp.ContentTypeError:
                        response_text = await response.text()
                        _LOGGER.debug("Invalid JSON response: %s", response_text)
                        continue
                    
            except asyncio.TimeoutError:
                _LOGGER.debug("Request to %s timed out", url)
                continue
            except aiohttp.ClientError as err:
                _LOGGER.debug("Error making request to %s: %s", url, err)
                continue
            except Exception as exc:
                _LOGGER.debug("Unexpected error making request to %s: %s", url, exc)
                continue
        
        # If we're here, all attempts failed
        _LOGGER.error("All API request attempts failed for endpoint: %s", endpoint)
        return None

    async def async_check_credentials(self) -> bool:
        """Check if credentials are valid."""
        # Try different endpoints to check credentials
        check_endpoints = [
            "devices",
            "networks",
            "users/me",
            "user",
            "status"
        ]
        
        for endpoint in check_endpoints:
            result = await self._api_request("GET", endpoint)
            if result:
                _LOGGER.info("Credential check successful with endpoint: %s", endpoint)
                return True
        
        # If all attempts fail, return failure
        _LOGGER.error("Failed to validate credentials")
        return False

    async def block_device(self, device_id: str, network_id: str) -> bool:
        """Block a device."""
        # Try different block endpoints
        block_endpoints = [
            f"devices/{device_id}/block",
            f"device/{device_id}/block",
            f"block/{device_id}"
        ]
        
        for endpoint in block_endpoints:
            params = {"networkId": network_id} if network_id else None
            result = await self._api_request("POST", endpoint, params=params)
            if result:
                return True
        
        # If all attempts fail, return failure
        return False

    async def unblock_device(self, device_id: str, network_id: str) -> bool:
        """Unblock a device."""
        # Try different unblock endpoints
        unblock_endpoints = [
            f"devices/{device_id}/unblock",
            f"device/{device_id}/unblock",
            f"unblock/{device_id}"
        ]
        
        for endpoint in unblock_endpoints:
            params = {"networkId": network_id} if network_id else None
            result = await self._api_request("POST", endpoint, params=params)
            if result:
                return True
        
        # If all attempts fail, return failure
        return False

    async def get_devices(self) -> List[Dict[str, Any]]:
        """Get all devices across all networks."""
        # Make sure we're authenticated
        if not await self._ensure_authenticated():
            _LOGGER.error("Failed to authenticate")
            return []

        try:
            # Try different device endpoints
            device_endpoints = [
                "devices",
                "device",
                "hosts"
            ]
            
            for endpoint in device_endpoints:
                devices = await self._api_request("GET", endpoint)
                
                if devices and isinstance(devices, list) and len(devices) > 0:
                    _LOGGER.info("Successfully retrieved devices from endpoint: %s", endpoint)
                    
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
            
            # If all attempts fail, return empty list
            _LOGGER.error("Failed to retrieve devices")
            return []
                
        except Exception as exc:
            _LOGGER.error("Error getting devices: %s", exc)
            return []

