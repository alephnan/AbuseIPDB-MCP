"""Tool for checking single IP addresses against AbuseIPDB."""

import ipaddress
import logging
from typing import Any, Dict, Optional

from mcp.types import Tool, TextContent, CallToolResult

from ..settings import Settings
from ..cache import CacheManager, RateLimiter
from ..client_abuseipdb import AbuseIPDBClient
from ..models import IPCheckResponse, APIError
from ..utils.ip_utils import is_private_ip

logger = logging.getLogger(__name__)


class CheckIPTool:
    """Tool for checking single IP addresses."""

    def __init__(self, settings: Settings, cache: CacheManager, rate_limiter: RateLimiter):
        self.settings = settings
        self.cache = cache
        self.rate_limiter = rate_limiter

    async def get_tool_definition(self) -> Tool:
        """Get the tool definition for MCP."""
        return Tool(
            name="check_ip",
            description="Check the reputation of a single IP address using AbuseIPDB",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "IP address to check",
                    },
                    "max_age_days": {
                        "type": "integer",
                        "description": "Maximum age of reports to consider in days",
                        "default": 30,
                        "minimum": 1,
                        "maximum": 365,
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Include detailed report information",
                        "default": False,
                    },
                    "threshold": {
                        "type": "integer",
                        "description": "Abuse confidence threshold for flagging (0-100)",
                        "default": 75,
                        "minimum": 0,
                        "maximum": 100,
                    },
                },
                "required": ["ip_address"],
            },
        )

    def _validate_ip_address(self, ip_str: str) -> str:
        """Validate and normalize IP address."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())

            # Check if private IP and settings allow it
            if is_private_ip(ip) and not self.settings.allow_private_ips:
                raise ValueError("Private IP addresses are not allowed")

            return str(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address '{ip_str}': {e}")

    async def execute(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Execute the check_ip tool."""
        try:
            # Extract and validate arguments
            ip_address = arguments.get("ip_address")
            if not ip_address:
                raise ValueError("ip_address is required")

            ip_address = self._validate_ip_address(ip_address)
            max_age_days = arguments.get("max_age_days", self.settings.max_age_days)
            verbose = arguments.get("verbose", False)
            threshold = arguments.get("threshold", self.settings.confidence_threshold)

            # Validate max_age_days
            if not 1 <= max_age_days <= 365:
                raise ValueError("max_age_days must be between 1 and 365")

            # Validate threshold
            if not 0 <= threshold <= 100:
                raise ValueError("threshold must be between 0 and 100")

            # Create cache key
            cache_key = self.cache.create_cache_key("check", {
                "ip": ip_address,
                "max_age": max_age_days,
                "verbose": verbose,
            })

            # Try cache first
            cached_result = await self.cache.get(cache_key)
            if cached_result:
                logger.info(f"Cache hit for IP {ip_address}")
                check_response = IPCheckResponse.model_validate(cached_result)
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
                        check_response = await client.check_ip(
                            ip_address=ip_address,
                            max_age_days=max_age_days,
                            verbose=verbose,
                        )

                        # Cache the result
                        await self.cache.set(cache_key, check_response.model_dump())
                        logger.info(f"Cached result for IP {ip_address}")

                    except APIError as e:
                        logger.error(f"API error checking IP {ip_address}: {e.error}")
                        return CallToolResult(
                            content=[
                                TextContent(
                                    type="text",
                                    text=f"API Error: {e.error}"
                                )
                            ],
                            isError=True,
                        )

            # Analyze result
            is_flagged = check_response.abuse_confidence_percentage >= threshold
            risk_level = self._assess_risk_level(check_response)

            # Format response
            result = {
                "ip_address": check_response.ip_address,
                "abuse_confidence": check_response.abuse_confidence_percentage,
                "total_reports": check_response.total_reports,
                "distinct_reporters": check_response.num_distinct_users,
                "last_reported": check_response.last_reported_at.isoformat() if check_response.last_reported_at else None,
                "country": {
                    "code": check_response.country_code,
                    "name": check_response.country_name,
                },
                "isp": check_response.isp,
                "domain": check_response.domain,
                "usage_type": check_response.usage_type,
                "is_whitelisted": check_response.is_whitelisted,
                "is_public": check_response.is_public,
                "flagged": is_flagged,
                "risk_level": risk_level,
                "threshold_used": threshold,
            }

            if verbose and check_response.reports:
                result["reports"] = check_response.reports[:10]  # Limit to first 10 reports

            # Create summary text
            summary_lines = [
                f"IP: {check_response.ip_address}",
                f"Abuse Confidence: {check_response.abuse_confidence_percentage}%",
                f"Risk Level: {risk_level}",
                f"Total Reports: {check_response.total_reports}",
                f"Distinct Reporters: {check_response.num_distinct_users}",
            ]

            if check_response.country_name:
                summary_lines.append(f"Country: {check_response.country_name}")

            if check_response.isp:
                summary_lines.append(f"ISP: {check_response.isp}")

            if is_flagged:
                summary_lines.append(f"⚠️  FLAGGED: Exceeds threshold of {threshold}%")

            if check_response.is_whitelisted:
                summary_lines.append("✅ Whitelisted")

            summary = "\n".join(summary_lines)

            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=f"{summary}\n\nDetailed data:\n{result}"
                    )
                ]
            )

        except ValueError as e:
            logger.error(f"Validation error in check_ip: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Validation Error: {e}")],
                isError=True,
            )
        except Exception as e:
            logger.error(f"Unexpected error in check_ip: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unexpected Error: {e}")],
                isError=True,
            )

    def _assess_risk_level(self, response: IPCheckResponse) -> str:
        """Assess risk level based on response data."""
        confidence = response.abuse_confidence_percentage

        if confidence >= 75:
            return "HIGH"
        elif confidence >= 25:
            return "MEDIUM"
        else:
            return "LOW"