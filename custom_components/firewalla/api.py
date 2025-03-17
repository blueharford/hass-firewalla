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
                    
                    # Handle different response formats
                    if isinstance(result, dict) and "data" in result:
                        # Some endpoints return data in a "data" field
                        return result["data"]
                    
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

    async def get_boxes(self) -> List[Dict[str, Any]]:
        """Get all Firewalla boxes."""
        try:
            # Get the boxes from the API
            boxes = await self._api_request("GET", "boxes")
        
            if not boxes:
                _LOGGER.error("No boxes found or invalid response")
                return []
            
            # Check if boxes is a list
            if not isinstance(boxes, list):
                _LOGGER.error("Boxes response is not a list: %s", boxes)
                # If it's a dict with a data field, try to use that
                if isinstance(boxes, dict) and "data" in boxes:
                    boxes = boxes["data"]
                    if not isinstance(boxes, list):
                        _LOGGER.error("Boxes data is not a list: %s", boxes)
                        return []
                else:
                    # Return empty list if we can't parse the response
                    return []
        
            # Process boxes to ensure they have an id
            processed_boxes = []
            for box in boxes:
                if isinstance(box, dict):
                    # If box doesn't have an id but has a uuid, use that as id
                    if "id" not in box and "uuid" in box:
                        box["id"] = box["uuid"]
                    # If box doesn't have an id but has a name, use that as id
                    elif "id" not in box and "name" in box:
                        box["id"] = f"box_{box['name']}"
                    # If box still doesn't have an id, generate one
                    elif "id" not in box:
                        box["id"] = f"box_{len(processed_boxes)}"
                
                    processed_boxes.append(box)
        
            _LOGGER.debug("Retrieved a total of %s boxes", len(processed_boxes))
            return processed_boxes
            
        except Exception as exc:
            _LOGGER.error("Error getting boxes: %s", exc)
            return []

    async def get_devices(self) -> List[Dict[str, Any]]:
        """Get all devices across all networks."""
        try:
            # Based on the API documentation, get the devices
            devices = await self._api_request("GET", "devices")
        
            if not devices:
                _LOGGER.error("No devices found or invalid response")
                return []
            
            # Check if devices is a list
            if not isinstance(devices, list):
                _LOGGER.error("Devices response is not a list: %s", devices)
                # If it's a dict with a data field, try to use that
                if isinstance(devices, dict) and "data" in devices:
                    devices = devices["data"]
                    if not isinstance(devices, list):
                        _LOGGER.error("Devices data is not a list: %s", devices)
                        return []
                else:
                    # Return empty list if we can't parse the response
                    return []
        
            # Process the devices
            processed_devices = []
            for device in devices:
                if isinstance(device, dict):
                    # If device doesn't have an id but has a mac, use that as id
                    if "id" not in device and "mac" in device:
                        device["id"] = device["mac"]
                    # If device doesn't have an id but has an ip, use that as id
                    elif "id" not in device and "ip" in device:
                        device["id"] = device["ip"]
                    # If device still doesn't have an id, generate one
                    elif "id" not in device:
                        device["id"] = f"device_{len(processed_devices)}"
                
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
                
                    processed_devices.append(device)
        
            _LOGGER.debug("Retrieved a total of %s devices", len(processed_devices))
            return processed_devices
            
        except Exception as exc:
            _LOGGER.error("Error getting devices: %s", exc)
            return []

    async def get_rules(self) -> List[Dict[str, Any]]:
        """Get all rules."""
        rules = []
        try:
            # Get the rules from the API
            rules_response = await self._api_request("GET", "rules")
            
            if not rules_response:
                _LOGGER.warning("No rules found or endpoint not available")
                return []
                
            # Check if the response is a dictionary with a 'results' key
            if isinstance(rules_response, dict) and "results" in rules_response:
                rules = rules_response["results"]
                _LOGGER.debug("Extracted rules from 'results' key")
            else:
                rules = rules_response
                
            # Check if rules is a list
            if not isinstance(rules, list):
                _LOGGER.warning("Rules data is not a list: %s", rules)
                return []
                
            # Process rules to ensure they have an id
            processed_rules = []
            for rule in rules:
                if isinstance(rule, dict):
                    # If rule doesn't have an id but has a uuid, use that as id
                    if "id" not in rule and "uuid" in rule:
                        rule["id"] = rule["uuid"]
                    # If rule doesn't have an id but has a name, use that as id
                    elif "id" not in rule and "name" in rule:
                        rule["id"] = f"rule_{rule['name']}"
                    # If rule still doesn't have an id, generate one
                    elif "id" not in rule:
                        rule["id"] = f"rule_{len(processed_rules)}"
                    
                    processed_rules.append(rule)
            
            _LOGGER.debug("Retrieved a total of %s rules", len(processed_rules))
            return processed_rules
            
        except Exception as exc:
            _LOGGER.warning("Error getting rules (endpoint may not be available): %s", exc)
            return []

    async def get_alarms(self) -> List[Dict[str, Any]]:
        """Get all alarms."""
        alarms = []
        try:
            # Get the alarms from the API
            alarms_response = await self._api_request("GET", "alarms")
        
        if not alarms_response:
            _LOGGER.warning("No alarms found or endpoint not available")
            return []
            
        # Check if the response is a dictionary with a 'results' key
        if isinstance(alarms_response, dict) and "results" in alarms_response:
            alarms = alarms_response["results"]
            _LOGGER.debug("Extracted alarms from 'results' key")
        else:
            alarms = alarms_response
            
        # Check if alarms is a list
        if not isinstance(alarms, list):
            _LOGGER.warning("Alarms data is not a list: %s", alarms)
            return []
            
        # Process alarms to ensure they have an id
        processed_alarms = []
        for alarm in alarms:
            if isinstance(alarm, dict):
                # If alarm doesn't have an id but has aid, use that as id
                if "id" not in alarm and "aid" in alarm:
                    alarm["id"] = f"alarm_{alarm['aid']}"
                # If alarm doesn't have an id but has a type, use that as id
                elif "id" not in alarm and "type" in alarm:
                    alarm["id"] = f"alarm_{alarm['type']}_{len(processed_alarms)}"
                # If alarm still doesn't have an id, generate one
                elif "id" not in alarm:
                    alarm["id"] = f"alarm_{len(processed_alarms)}"
                
                processed_alarms.append(alarm)
        
        _LOGGER.debug("Retrieved a total of %s alarms", len(processed_alarms))
        return processed_alarms
        
    except Exception as exc:
        _LOGGER.warning("Error getting alarms (endpoint may not be available): %s", exc)
        return []

    async def get_flows(self) -> List[Dict[str, Any]]:
        """Get all flows."""
        flows = []
        try:
            # Get the flows from the API
            flows_response = await self._api_request("GET", "flows")
            
            if not flows_response:
                _LOGGER.warning("No flows found or endpoint not available")
                return []
            
            # Check if the response is a dictionary with a 'results' key
            if isinstance(flows_response, dict) and "results" in flows_response:
                flows = flows_response["results"]
                _LOGGER.debug("Extracted flows from 'results' key")
            else:
                flows = flows_response
                
            # Check if flows is a list
            if not isinstance(flows, list):
                _LOGGER.warning("Flows data is not a list: %s", flows)
                return []
                
            # Process flows to ensure they have an id
            processed_flows = []
            for flow in flows:
                if isinstance(flow, dict):
                    # Generate a unique ID for the flow if it doesn't have one
                    if "id" not in flow:
                        # Use source and destination if available
                        src_id = flow.get("source", {}).get("id", "unknown")
                        dst_id = flow.get("destination", {}).get("id", "unknown")
                        ts = flow.get("ts", "")
                        flow["id"] = f"flow_{src_id}_{dst_id}_{ts}"
                
                processed_flows.append(flow)
        
            _LOGGER.debug("Retrieved a total of %s flows", len(processed_flows))
            return processed_flows
            
        except Exception as exc:
            _LOGGER.warning("Error getting flows (endpoint may not be available): %s", exc)
            return []

