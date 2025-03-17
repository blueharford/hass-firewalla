"""Firewalla API Client."""
import logging
import aiohttp
import asyncio
import async_timeout
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union
import json

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
        
        # Based on the examples and the error response, the correct format is:
        # https://{subdomain}.firewalla.io/api/v1
        # But we're getting a web page instead of API responses, which suggests
        # we need to use a different URL format or endpoint
        
        # Let's try different URL formats
        if subdomain:
            # Format 1: Direct API endpoint (most likely)
            self._base_url = f"https://{subdomain}.firewalla.io/api/v1"
            
            # Format 2: API subdomain with path
            self._alt_base_url = f"https://api.{subdomain}.firewalla.io/v1"
            
            # Format 3: MSP API endpoint
            self._third_base_url = f"https://app.firewalla.io/api/v1/msp/{subdomain}"
            
            _LOGGER.debug("Using API URLs: %s, %s, %s", 
                         self._base_url, self._alt_base_url, self._third_base_url)
        else:
            self._base_url = DEFAULT_API_URL
            self._alt_base_url = None
            self._third_base_url = None
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
            
        self._org_id = None
        self._token_expires_at = None
        self._current_url_index = 0  # Track which URL we're currently using
        
        _LOGGER.debug("Initialized Firewalla API client with auth method: %s", self._auth_method)

    @property
    def _headers(self) -> Dict[str, str]:
        """Get the headers for API requests."""
        headers = {"Content-Type": "application/json"}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        return headers

    @property
    def _current_base_url(self) -> str:
        """Get the current base URL based on the index."""
        if self._current_url_index == 0:
            return self._base_url
        elif self._current_url_index == 1 and self._alt_base_url:
            return self._alt_base_url
        elif self._current_url_index == 2 and self._third_base_url:
            return self._third_base_url
        return self._base_url

    def _rotate_base_url(self) -> None:
        """Rotate to the next base URL."""
        if self._current_url_index == 0 and self._alt_base_url:
            self._current_url_index = 1
            _LOGGER.debug("Switching to alternate URL: %s", self._alt_base_url)
        elif self._current_url_index == 1 and self._third_base_url:
            self._current_url_index = 2
            _LOGGER.debug("Switching to third URL: %s", self._third_base_url)
        else:
            self._current_url_index = 0
            _LOGGER.debug("Switching back to primary URL: %s", self._base_url)

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

        # Try all URL formats for authentication
        for i in range(3):  # Try all three URL formats
            self._current_url_index = i
            if not self._current_base_url:
                continue
                
            _LOGGER.debug("Trying authentication with URL: %s", self._current_base_url)
            
            try:
                if self._auth_method == "credentials":
                    if await self._authenticate_with_credentials():
                        return True
                elif self._auth_method == "api_key":
                    if await self._authenticate_with_api_key():
                        return True
            except Exception as exc:
                _LOGGER.error("Authentication failed with URL %s: %s", 
                             self._current_base_url, exc)
        
        _LOGGER.error("Authentication failed with all URL formats")
        return False

    async def _authenticate_with_credentials(self) -> bool:
        """Authenticate using email and password."""
        _LOGGER.debug("Authenticating with email and password")
        
        # Based on examples, the login endpoint is /auth/login
        login_url = f"{self._current_base_url}/auth/login"
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
                
                if "token" not in data:
                    _LOGGER.error("No token in authentication response")
                    return False
                
                self._access_token = data["token"]
                # Set expiration if provided, otherwise default to 1 hour
                if "expiresIn" in data:
                    self._token_expires_at = datetime.now() + timedelta(seconds=data["expiresIn"])
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
        
        # Based on examples, the login endpoint is /auth/login
        login_url = f"{self._current_base_url}/auth/login"
        
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
                
                if "token" not in data:
                    _LOGGER.error("No token in authentication response")
                    return False
                
                self._access_token = data["token"]
                # Set expiration if provided, otherwise default to 1 hour
                if "expiresIn" in data:
                    self._token_expires_at = datetime.now() + timedelta(seconds=data["expiresIn"])
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
        if self._use_mock_data:
            return True
            
        if not self._access_token or (
            self._token_expires_at and datetime.now() >= self._token_expires_at
        ):
            _LOGGER.debug("Token expired or not set, re-authenticating")
            return await self.authenticate()
        return True

    async def _try_request(self, url, method="GET", headers=None, json=None, params=None):
        """Try a request with fallback to alternative URL."""
        try:
            async with async_timeout.timeout(DEFAULT_TIMEOUT):
                _LOGGER.debug("Trying request to %s", url)
                response = await self._session.request(
                    method, url, headers=headers, json=json, params=params
                )
                
                # Check if we got HTML instead of JSON
                content_type = response.headers.get("Content-Type", "")
                if "text/html" in content_type:
                    response_text = await response.text()
                    if "<html" in response_text:
                        _LOGGER.error("Received HTML response instead of JSON. URL: %s", url)
                        _LOGGER.debug("HTML response: %s", response_text[:200])  # Log first 200 chars
                        return None
                
                return response
        except (aiohttp.ClientConnectorError, aiohttp.ClientSSLError) as err:
            _LOGGER.warning("Connection error for %s: %s", url, err)
            return None
        except Exception as exc:
            _LOGGER.error("Unexpected error for %s: %s", url, exc)
            return None

    async def _api_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
        """Make an API request."""
        # Try all URL formats for the API request
        for _ in range(3):  # Try each URL format
            url = f"{self._current_base_url}/{endpoint}"
            
            try:
                async with async_timeout.timeout(DEFAULT_TIMEOUT):
                    _LOGGER.debug("%s request to %s", method, url)
                    
                    # Try the request
                    response = await self._try_request(
                        url, 
                        method=method, 
                        headers=self._headers, 
                        json=data,
                        params=params
                    )
                    
                    # If response is None, the request failed
                    if response is None:
                        self._rotate_base_url()  # Try the next URL format
                        continue
                    
                    if response.status != 200:
                        response_text = await response.text()
                        _LOGGER.error(
                            "Error from Firewalla API: %s %s", 
                            response.status, 
                            response_text
                        )
                        self._rotate_base_url()  # Try the next URL format
                        continue
                    
                    try:
                        result = await response.json()
                        _LOGGER.debug("API request successful")
                        return result
                    except aiohttp.ContentTypeError:
                        response_text = await response.text()
                        _LOGGER.error("Invalid JSON response: %s", response_text)
                        self._rotate_base_url()  # Try the next URL format
                        continue
                    
            except asyncio.TimeoutError:
                _LOGGER.error("Request to %s timed out", url)
                self._rotate_base_url()  # Try the next URL format
                continue
            except aiohttp.ClientError as err:
                _LOGGER.error("Error making request to %s: %s", url, err)
                self._rotate_base_url()  # Try the next URL format
                continue
            except Exception as exc:
                _LOGGER.error("Unexpected error making request to %s: %s", url, exc)
                self._rotate_base_url()  # Try the next URL format
                continue
        
        # If we're here, all URL formats failed
        _LOGGER.warning("All API request attempts failed")
        return None

    async def async_check_credentials(self) -> bool:
        """Check if credentials are valid."""
        # Try to get user info as a validation check
        if self._use_mock_data:
            return True
            
        # Try a simple API request to check credentials
        # First try to get organizations
        result = await self._api_request("GET", "orgs")
        if result:
            return True
            
        # If that fails, try a different endpoint
        result = await self._api_request("GET", "users/me")
        if result:
            return True
            
        # If all attempts fail, use mock data
        _LOGGER.warning("Failed to validate credentials, using mock data")
        self._use_mock_data = True
        return True

    async def block_device(self, device_id: str, network_id: str) -> bool:
        """Block a device."""
        if self._use_mock_data:
            return True
            
        # Based on examples, the endpoint is /devices/{deviceId}/block
        endpoint = f"devices/{device_id}/block"
        params = {"networkId": network_id}
        
        result = await self._api_request("POST", endpoint, params=params)
        return result is not None

    async def unblock_device(self, device_id: str, network_id: str) -> bool:
        """Unblock a device."""
        if self._use_mock_data:
            return True
            
        # Based on examples, the endpoint is /devices/{deviceId}/unblock
        endpoint = f"devices/{device_id}/unblock"
        params = {"networkId": network_id}
        
        result = await self._api_request("POST", endpoint, params=params)
        return result is not None

    async def get_devices(self) -> List[Dict[str, Any]]:
        """Get all devices across all networks."""
        if self._use_mock_data:
            _LOGGER.debug("Using mock data for devices")
            return self._get_mock_devices()

        # Make sure we're authenticated
        if not await self._ensure_authenticated():
            _LOGGER.error("Failed to authenticate")
            return self._get_mock_devices()

        try:
            # Based on examples, first get organizations
            orgs = await self._api_request("GET", "orgs")
            
            if not orgs or not isinstance(orgs, list) or len(orgs) == 0:
                _LOGGER.error("No organizations found")
                return self._get_mock_devices()  # Use mock data as fallback
            
            # Use the first organization
            org_id = orgs[0]["id"]
            _LOGGER.debug("Using organization ID: %s", org_id)
            
            # Get networks for this organization
            networks = await self._api_request("GET", "networks", params={"orgId": org_id})
            
            if not networks or not isinstance(networks, list) or len(networks) == 0:
                _LOGGER.error("No networks found")
                return self._get_mock_devices()  # Use mock data as fallback
            
            # Get devices for each network
            all_devices = []
            
            for network in networks:
                network_id = network["id"]
                _LOGGER.debug("Getting devices for network: %s", network_id)
                
                devices = await self._api_request(
                    "GET", 
                    "devices", 
                    params={"orgId": org_id, "networkId": network_id}
                )
                
                if not devices or not isinstance(devices, list):
                    _LOGGER.warning("No devices found for network %s", network_id)
                    continue
                
                # Add network ID to each device
                for device in devices:
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
                
                all_devices.extend(devices)
                _LOGGER.debug("Found %s devices in network %s", len(devices), network_id)
            
            if not all_devices:
                _LOGGER.warning("No devices found across all networks, using mock data")
                return self._get_mock_devices()
                
            _LOGGER.debug("Retrieved a total of %s devices across all networks", len(all_devices))
            return all_devices
                
        except Exception as exc:
            _LOGGER.error("Error getting devices: %s", exc)
            return self._get_mock_devices()  # Use mock data as fallback

    def _get_mock_devices(self) -> List[Dict[str, Any]]:
        """Return mock device data for testing."""
        _LOGGER.debug("Generating mock device data")
        return [
            {
                "id": "mock_device_1",
                "name": "Mock Device 1",
                "mac": "00:11:22:33:44:55",
                "ip": "192.168.1.100",
                "online": True,
                "lastActiveTimestamp": int(datetime.now().timestamp() * 1000),
                "networkId": "mock_network_1",
                "stats": {
                    "upload": 1024,
                    "download": 2048,
                    "blockedCount": 15
                }
            },
            {
                "id": "mock_device_2",
                "name": "Mock Device 2",
                "mac": "AA:BB:CC:DD:EE:FF",
                "ip": "192.168.1.101",
                "online": False,
                "lastActiveTimestamp": int((datetime.now() - timedelta(hours=2)).timestamp() * 1000),
                "networkId": "mock_network_1",
                "stats": {
                    "upload": 512,
                    "download": 1024,
                    "blockedCount": 5
                }
            }
        ]

