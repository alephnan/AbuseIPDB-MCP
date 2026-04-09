"""AbuseIPDB API client with retry logic and error handling."""

import json
import logging
from typing import Optional, Dict, Any

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

from .settings import Settings
from .models import (
    IPCheckResponse,
    BlockCheckResponse,
    BlacklistResponse,
    APIError,
)

logger = logging.getLogger(__name__)


def _mask_api_key(key: str | None) -> str:
    """Return partially masked API key for safe logging."""
    if not key:
        return "<empty>"
    cleaned = key.strip()
    if len(cleaned) <= 8:
        return f"{cleaned[:2]}***{cleaned[-2:]}"
    return f"{cleaned[:4]}...{cleaned[-4:]} (len={len(cleaned)})"


class AbuseIPDBClient:
    """HTTP client for AbuseIPDB API with retry logic and error handling."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_url = settings.abuseipdb_base_url
        self.api_key = settings.abuseipdb_api_key
        self.timeout = settings.request_timeout

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
                "User-Agent": "mcp-abuseipdb/0.1.0",
            },
            timeout=self.timeout,
        )

        logger.debug("AbuseIPDBClient initialized (base_url=%s, api_key=%s)", self.base_url, _mask_api_key(self.api_key))

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    def _handle_response(self, response: httpx.Response) -> Dict[str, Any]:
        """Handle HTTP response and convert errors to APIError objects."""
        if response.status_code == 200:
            try:
                return response.json()
            except json.JSONDecodeError as e:
                raise APIError(
                    error="Invalid JSON response",
                    details=str(e),
                    status_code=response.status_code,
                    retryable=False,
                )

        # Handle specific error cases
        if response.status_code == 401:
            logger.warning("AbuseIPDB returned 401 Unauthorized (api_key=%s)", _mask_api_key(self.api_key))
            raise APIError(
                error="Unauthorized - check API key",
                status_code=response.status_code,
                retryable=False,
            )
        elif response.status_code == 403:
            raise APIError(
                error="Forbidden - API key may lack permissions",
                status_code=response.status_code,
                retryable=False,
            )
        elif response.status_code == 429:
            raise APIError(
                error="Rate limit exceeded",
                details="Too many requests to AbuseIPDB API",
                status_code=response.status_code,
                retryable=True,
            )
        elif response.status_code >= 500:
            raise APIError(
                error="Server error",
                details=f"AbuseIPDB server returned {response.status_code}",
                status_code=response.status_code,
                retryable=True,
            )
        else:
            try:
                error_data = response.json()
                error_msg = error_data.get("errors", [{}])[0].get("detail", "Unknown error")
            except (json.JSONDecodeError, IndexError, KeyError):
                error_msg = f"HTTP {response.status_code}"

            raise APIError(
                error=error_msg,
                status_code=response.status_code,
                retryable=False,
            )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make HTTP request with retry logic."""
        try:
            logger.debug("AbuseIPDB request %s %s params=%s", method, endpoint, params)
            response = await self.client.request(method, endpoint, params=params)
            return self._handle_response(response)
        except APIError:
            raise
        except (httpx.TimeoutException, httpx.ConnectError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error in API request: {e}")
            raise APIError(
                error="Request failed",
                details=str(e),
                status_code=0,
                retryable=False,
            )

    async def check_ip(
        self,
        ip_address: str,
        max_age_days: int = 30,
        verbose: bool = False,
    ) -> IPCheckResponse:
        """Check a single IP address."""
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": "true" if verbose else "false",
        }

        response_data = await self._make_request("GET", "/check", params)

        # Extract the data field which contains the actual IP check response
        ip_data = response_data.get("data", {})
        return IPCheckResponse.model_validate(ip_data)

    async def check_block(
        self,
        network: str,
        max_age_days: int = 30,
    ) -> BlockCheckResponse:
        """Check a CIDR block."""
        params = {
            "network": network,
            "maxAgeInDays": max_age_days,
        }

        response_data = await self._make_request("GET", "/check-block", params)

        # Extract the data field
        block_data = response_data.get("data", {})
        return BlockCheckResponse.model_validate(block_data)

    async def get_blacklist(
        self,
        confidence_minimum: int = 90,
        limit: Optional[int] = None,
    ) -> BlacklistResponse:
        """Get the AbuseIPDB blacklist."""
        params = {
            "confidenceMinimum": confidence_minimum,
        }
        if limit is not None:
            params["limit"] = limit

        response_data = await self._make_request("GET", "/blacklist", params)
        return BlacklistResponse.model_validate(response_data)

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()