"""Tool for bulk checking multiple IP addresses."""

import asyncio
import ipaddress
import logging
from typing import Any, Dict, List, Set

from mcp.types import Tool, TextContent, CallToolResult

from ..settings import Settings
from ..cache import CacheManager, RateLimiter
from ..client_abuseipdb import AbuseIPDBClient
from ..models import IPCheckResponse, BulkCheckResponse, BulkCheckResult, APIError
from ..utils.ip_utils import is_private_ip

logger = logging.getLogger(__name__)


class BulkCheckTool:
    """Tool for bulk checking multiple IP addresses."""

    def __init__(self, settings: Settings, cache: CacheManager, rate_limiter: RateLimiter):
        self.settings = settings
        self.cache = cache
        self.rate_limiter = rate_limiter

    async def get_tool_definition(self) -> Tool:
        """Get the tool definition for MCP."""
        return Tool(
            name="bulk_check",
            description="Check multiple IP addresses in batch against AbuseIPDB",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip_addresses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of IP addresses to check",
                        "minItems": 1,
                        "maxItems": 100,
                    },
                    "max_age_days": {
                        "type": "integer",
                        "description": "Maximum age of reports to consider in days",
                        "default": 30,
                        "minimum": 1,
                        "maximum": 365,
                    },
                    "threshold": {
                        "type": "integer",
                        "description": "Abuse confidence threshold for flagging (0-100)",
                        "default": 75,
                        "minimum": 0,
                        "maximum": 100,
                    },
                },
                "required": ["ip_addresses"],
            },
        )

    def _validate_and_dedupe_ips(self, ip_list: List[str]) -> List[str]:
        """Validate and deduplicate IP addresses."""
        valid_ips = []
        seen_ips: Set[str] = set()

        for ip_str in ip_list:
            try:
                ip = ipaddress.ip_address(ip_str.strip())

                # Check if private IP and settings allow it
                if is_private_ip(ip) and not self.settings.allow_private_ips:
                    logger.warning(f"Skipping private IP: {ip}")
                    continue

                ip_normalized = str(ip)
                if ip_normalized not in seen_ips:
                    valid_ips.append(ip_normalized)
                    seen_ips.add(ip_normalized)

            except ValueError as e:
                logger.warning(f"Invalid IP address '{ip_str}': {e}")
                continue

        return valid_ips

    async def _check_single_ip(
        self,
        ip_address: str,
        max_age_days: int,
        client: AbuseIPDBClient,
        semaphore: asyncio.Semaphore
    ) -> BulkCheckResult:
        """Check a single IP address with rate limiting."""
        async with semaphore:
            # Create cache key
            cache_key = self.cache.create_cache_key("check", {
                "ip": ip_address,
                "max_age": max_age_days,
                "verbose": False,
            })

            # Try cache first
            cached_result = await self.cache.get(cache_key)
            if cached_result:
                logger.info(f"Cache hit for IP {ip_address}")
                try:
                    check_response = IPCheckResponse.model_validate(cached_result)
                    return BulkCheckResult(
                        ip_address=ip_address,
                        success=True,
                        data=check_response,
                    )
                except Exception as e:
                    logger.error(f"Error parsing cached data for {ip_address}: {e}")

            # Check rate limit
            if not await self.rate_limiter.acquire():
                return BulkCheckResult(
                    ip_address=ip_address,
                    success=False,
                    error="Rate limit exceeded",
                )

            # Make API call
            try:
                check_response = await client.check_ip(
                    ip_address=ip_address,
                    max_age_days=max_age_days,
                    verbose=False,
                )

                # Cache the result
                await self.cache.set(cache_key, check_response.model_dump())
                logger.info(f"Cached result for IP {ip_address}")

                return BulkCheckResult(
                    ip_address=ip_address,
                    success=True,
                    data=check_response,
                )

            except APIError as e:
                logger.error(f"API error checking IP {ip_address}: {e.error}")
                return BulkCheckResult(
                    ip_address=ip_address,
                    success=False,
                    error=e.error,
                )
            except Exception as e:
                logger.error(f"Unexpected error checking IP {ip_address}: {e}")
                return BulkCheckResult(
                    ip_address=ip_address,
                    success=False,
                    error=str(e),
                )

    async def execute(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Execute the bulk_check tool."""
        try:
            # Extract and validate arguments
            ip_addresses = arguments.get("ip_addresses", [])
            if not ip_addresses:
                raise ValueError("ip_addresses list is required")

            if len(ip_addresses) > 100:
                raise ValueError("Maximum 100 IP addresses allowed per bulk check")

            max_age_days = arguments.get("max_age_days", self.settings.max_age_days)
            threshold = arguments.get("threshold", self.settings.confidence_threshold)

            # Validate max_age_days
            if not 1 <= max_age_days <= 365:
                raise ValueError("max_age_days must be between 1 and 365")

            # Validate threshold
            if not 0 <= threshold <= 100:
                raise ValueError("threshold must be between 0 and 100")

            # Validate and deduplicate IPs
            valid_ips = self._validate_and_dedupe_ips(ip_addresses)

            if not valid_ips:
                raise ValueError("No valid IP addresses found")

            logger.info(f"Processing {len(valid_ips)} unique IP addresses")

            # Process IPs in parallel with rate limiting
            semaphore = asyncio.Semaphore(5)  # Limit concurrent requests
            async with AbuseIPDBClient(self.settings) as client:
                tasks = [
                    self._check_single_ip(ip, max_age_days, client, semaphore)
                    for ip in valid_ips
                ]

                results = await asyncio.gather(*tasks, return_exceptions=False)

            # Analyze results
            successful_results = [r for r in results if r.success]
            failed_results = [r for r in results if not r.success]

            flagged_ips = []
            for result in successful_results:
                if result.data and result.data.abuse_confidence_percentage >= threshold:
                    flagged_ips.append(result.ip_address)

            # Create bulk response
            bulk_response = BulkCheckResponse(
                results=results,
                total_requested=len(valid_ips),
                successful=len(successful_results),
                failed=len(failed_results),
            )

            # Format response
            result_data = {
                "summary": {
                    "total_requested": len(ip_addresses),
                    "unique_ips_processed": len(valid_ips),
                    "successful": len(successful_results),
                    "failed": len(failed_results),
                    "flagged_count": len(flagged_ips),
                    "threshold_used": threshold,
                },
                "flagged_ips": flagged_ips,
                "results": [
                    {
                        "ip_address": r.ip_address,
                        "success": r.success,
                        "abuse_confidence": r.data.abuse_confidence_percentage if r.data else None,
                        "total_reports": r.data.total_reports if r.data else None,
                        "country": r.data.country_name if r.data else None,
                        "error": r.error if not r.success else None,
                    }
                    for r in results
                ],
            }

            # Create summary text
            summary_lines = [
                f"Bulk Check Results:",
                f"Total Requested: {len(ip_addresses)}",
                f"Unique IPs: {len(valid_ips)}",
                f"Successful: {len(successful_results)}",
                f"Failed: {len(failed_results)}",
                f"Flagged (≥{threshold}%): {len(flagged_ips)}",
            ]

            if flagged_ips:
                summary_lines.append(f"\n⚠️  FLAGGED IPs:")
                for ip in flagged_ips[:10]:  # Show first 10
                    result = next(r for r in results if r.ip_address == ip and r.success)
                    if result.data:
                        summary_lines.append(
                            f"  • {ip} - {result.data.abuse_confidence_percentage}% "
                            f"({result.data.total_reports} reports)"
                        )

                if len(flagged_ips) > 10:
                    summary_lines.append(f"  ... and {len(flagged_ips) - 10} more")

            if failed_results:
                summary_lines.append(f"\n❌ Failed IPs:")
                for result in failed_results[:5]:  # Show first 5 failures
                    summary_lines.append(f"  • {result.ip_address}: {result.error}")

                if len(failed_results) > 5:
                    summary_lines.append(f"  ... and {len(failed_results) - 5} more failures")

            summary = "\n".join(summary_lines)

            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=f"{summary}\n\nDetailed data:\n{result_data}"
                    )
                ]
            )

        except ValueError as e:
            logger.error(f"Validation error in bulk_check: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Validation Error: {e}")],
                isError=True,
            )
        except Exception as e:
            logger.error(f"Unexpected error in bulk_check: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unexpected Error: {e}")],
                isError=True,
            )