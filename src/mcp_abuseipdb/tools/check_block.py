"""Tool for checking CIDR blocks against AbuseIPDB."""

import ipaddress
import logging
from typing import Any, Dict

from mcp.types import Tool, TextContent, CallToolResult

from ..settings import Settings
from ..cache import CacheManager, RateLimiter
from ..client_abuseipdb import AbuseIPDBClient
from ..models import BlockCheckResponse, APIError
from ..utils.ip_utils import is_private_network

logger = logging.getLogger(__name__)


class CheckBlockTool:
    """Tool for checking CIDR blocks."""

    def __init__(self, settings: Settings, cache: CacheManager, rate_limiter: RateLimiter):
        self.settings = settings
        self.cache = cache
        self.rate_limiter = rate_limiter

    async def get_tool_definition(self) -> Tool:
        """Get the tool definition for MCP."""
        return Tool(
            name="check_block",
            description="Check the reputation of a CIDR block using AbuseIPDB",
            inputSchema={
                "type": "object",
                "properties": {
                    "network": {
                        "type": "string",
                        "description": "CIDR network to check (e.g., '192.168.1.0/24')",
                    },
                    "max_age_days": {
                        "type": "integer",
                        "description": "Maximum age of reports to consider in days",
                        "default": 30,
                        "minimum": 1,
                        "maximum": 365,
                    },
                },
                "required": ["network"],
            },
        )

    def _validate_network(self, network_str: str) -> str:
        """Validate and normalize CIDR network."""
        try:
            network = ipaddress.ip_network(network_str.strip(), strict=False)

            # Check if private network and settings allow it
            if is_private_network(network) and not self.settings.allow_private_ips:
                raise ValueError("Private networks are not allowed")

            return str(network)
        except ValueError as e:
            raise ValueError(f"Invalid network '{network_str}': {e}")

    async def execute(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Execute the check_block tool."""
        try:
            # Extract and validate arguments
            network = arguments.get("network")
            if not network:
                raise ValueError("network is required")

            network = self._validate_network(network)
            max_age_days = arguments.get("max_age_days", self.settings.max_age_days)

            # Validate max_age_days
            if not 1 <= max_age_days <= 365:
                raise ValueError("max_age_days must be between 1 and 365")

            # Create cache key
            cache_key = self.cache.create_cache_key("check_block", {
                "network": network,
                "max_age": max_age_days,
            })

            # Try cache first
            cached_result = await self.cache.get(cache_key)
            if cached_result:
                logger.info(f"Cache hit for network {network}")
                block_response = BlockCheckResponse.model_validate(cached_result)
            else:
                # Check rate limit
                if not await self.rate_limiter.acquire():
                    return CallToolResult(
                        content=[
                            TextContent(
                                type="text",
                                text="Rate limit exceeded. Please try again later."
                            )
                        ],
                        isError=True,
                    )

                # Make API call
                async with AbuseIPDBClient(self.settings) as client:
                    try:
                        block_response = await client.check_block(
                            network=network,
                            max_age_days=max_age_days,
                        )

                        # Cache the result
                        await self.cache.set(cache_key, block_response.model_dump())
                        logger.info(f"Cached result for network {network}")

                    except APIError as e:
                        logger.error(f"API error checking network {network}: {e.error}")
                        return CallToolResult(
                            content=[
                                TextContent(
                                    type="text",
                                    text=f"API Error: {e.error}"
                                )
                            ],
                            isError=True,
                        )

            # Analyze reported addresses
            reported_addresses = block_response.reported_address
            total_reported = len(reported_addresses)

            high_confidence_addresses = [
                addr for addr in reported_addresses
                if addr.abuse_confidence_percentage >= self.settings.confidence_threshold
            ]

            # Format response
            result = {
                "network_address": block_response.network_address,
                "netmask": block_response.netmask,
                "address_range": {
                    "min": block_response.min_address,
                    "max": block_response.max_address,
                },
                "num_possible_hosts": block_response.num_possible_hosts,
                "address_space_description": block_response.address_space_desc,
                "total_reported_addresses": total_reported,
                "high_confidence_addresses": len(high_confidence_addresses),
                "reported_addresses": [
                    addr.model_dump() for addr in reported_addresses[:20]
                ],  # Limit to first 20
            }

            # Create summary text
            summary_lines = [
                f"Network: {block_response.network_address}/{block_response.netmask}",
                f"Address Range: {block_response.min_address} - {block_response.max_address}",
                f"Possible Hosts: {block_response.num_possible_hosts:,}",
                f"Address Space: {block_response.address_space_desc}",
                f"Reported Addresses: {total_reported}",
                f"High Confidence (≥{self.settings.confidence_threshold}%): {len(high_confidence_addresses)}",
            ]

            if high_confidence_addresses:
                summary_lines.append(f"⚠️  FLAGGED: {len(high_confidence_addresses)} high-confidence threats detected")

            summary = "\n".join(summary_lines)

            # Add top reported addresses if any
            if reported_addresses:
                summary += "\n\nTop Reported Addresses:"
                for addr in reported_addresses[:5]:
                    summary += (
                        f"\n  • {addr.ip_address} - {addr.abuse_confidence_percentage}% "
                        f"confidence ({addr.total_reports} reports)"
                    )

            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=f"{summary}\n\nDetailed data:\n{result}"
                    )
                ]
            )

        except ValueError as e:
            logger.error(f"Validation error in check_block: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Validation Error: {e}")],
                isError=True,
            )
        except Exception as e:
            logger.error(f"Unexpected error in check_block: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unexpected Error: {e}")],
                isError=True,
            )
