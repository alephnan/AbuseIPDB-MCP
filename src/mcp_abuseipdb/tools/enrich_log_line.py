"""Tool for enriching log lines with IP address reputation data."""

import re
import ipaddress
import logging
from typing import Any, Dict, List, Set

from mcp.types import Tool, TextContent, CallToolResult

from ..settings import Settings
from ..cache import CacheManager, RateLimiter
from ..client_abuseipdb import AbuseIPDBClient
from ..models import IPCheckResponse, EnrichmentResult, APIError
from ..utils.ip_utils import is_private_ip

logger = logging.getLogger(__name__)


class EnrichLogLineTool:
    """Tool for enriching log lines with IP reputation data."""

    def __init__(self, settings: Settings, cache: CacheManager, rate_limiter: RateLimiter):
        self.settings = settings
        self.cache = cache
        self.rate_limiter = rate_limiter

        # IP address regex patterns
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        self.ipv6_pattern = re.compile(r'(?i)(?<![0-9a-f:])[0-9a-f:]{2,}(?![0-9a-f:])')

    async def get_tool_definition(self) -> Tool:
        """Get the tool definition for MCP."""
        return Tool(
            name="enrich_log_line",
            description="Extract and enrich IP addresses from a log line with AbuseIPDB data",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_line": {
                        "type": "string",
                        "description": "Log line containing IP addresses to enrich",
                    },
                    "threshold": {
                        "type": "integer",
                        "description": "Abuse confidence threshold for flagging (0-100)",
                        "default": 75,
                        "minimum": 0,
                        "maximum": 100,
                    },
                    "max_age_days": {
                        "type": "integer",
                        "description": "Maximum age of reports to consider in days",
                        "default": 30,
                        "minimum": 1,
                        "maximum": 365,
                    },
                },
                "required": ["log_line"],
            },
        )

    def _extract_ip_addresses(self, log_line: str) -> List[str]:
        """Extract all IP addresses from a log line."""
        ips = []
        seen_ips: Set[str] = set()

        # Find IPv4 addresses
        ipv4_matches = self.ipv4_pattern.findall(log_line)
        for ip_str in ipv4_matches:
            try:
                ip = ipaddress.IPv4Address(ip_str)
                # Skip private IPs if not allowed
                if is_private_ip(ip) and not self.settings.allow_private_ips:
                    continue
                if str(ip) not in seen_ips:
                    ips.append(str(ip))
                    seen_ips.add(str(ip))
            except ValueError:
                continue

        # Find IPv6 addresses
        for match in self.ipv6_pattern.finditer(log_line):
            candidate = match.group(0).strip('[]')
            if ':' not in candidate:
                continue
            try:
                ip = ipaddress.IPv6Address(candidate)
                # Skip private IPs if not allowed
                if is_private_ip(ip) and not self.settings.allow_private_ips:
                    continue
                ip_text = str(ip)
                if ip_text not in seen_ips:
                    ips.append(ip_text)
                    seen_ips.add(ip_text)
            except ValueError:
                continue
        return ips

    async def _enrich_ip(
        self,
        ip_address: str,
        max_age_days: int,
        client: AbuseIPDBClient
    ) -> tuple[str, IPCheckResponse | None]:
        """Enrich a single IP address."""
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
                return ip_address, IPCheckResponse.model_validate(cached_result)
            except Exception as e:
                logger.error(f"Error parsing cached data for {ip_address}: {e}")

        # Check rate limit
        if not await self.rate_limiter.acquire():
            logger.warning(f"Rate limit exceeded for IP {ip_address}")
            return ip_address, None

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

            return ip_address, check_response

        except APIError as e:
            logger.error(f"API error checking IP {ip_address}: {e.error}")
            return ip_address, None
        except Exception as e:
            logger.error(f"Unexpected error checking IP {ip_address}: {e}")
            return ip_address, None

    async def execute(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Execute the enrich_log_line tool."""
        try:
            # Extract and validate arguments
            log_line = arguments.get("log_line", "").strip()
            if not log_line:
                raise ValueError("log_line is required")

            threshold = arguments.get("threshold", self.settings.confidence_threshold)
            max_age_days = arguments.get("max_age_days", self.settings.max_age_days)

            # Validate threshold
            if not 0 <= threshold <= 100:
                raise ValueError("threshold must be between 0 and 100")

            # Validate max_age_days
            if not 1 <= max_age_days <= 365:
                raise ValueError("max_age_days must be between 1 and 365")

            # Extract IP addresses
            extracted_ips = self._extract_ip_addresses(log_line)

            if not extracted_ips:
                return CallToolResult(
                    content=[
                        TextContent(
                            type="text",
                            text=f"No IP addresses found in log line:\n{log_line}"
                        )
                    ]
                )

            logger.info(f"Extracted {len(extracted_ips)} IP addresses from log line")

            # Enrich IP addresses
            enriched_data = {}
            flagged_ips = []

            async with AbuseIPDBClient(self.settings) as client:
                for ip in extracted_ips:
                    ip_address, ip_data = await self._enrich_ip(ip, max_age_days, client)

                    if ip_data:
                        enriched_data[ip_address] = ip_data
                        if ip_data.abuse_confidence_percentage >= threshold:
                            flagged_ips.append(ip_address)

            # Create enrichment result
            result = EnrichmentResult(
                original_line=log_line,
                extracted_ips=extracted_ips,
                enriched_data=enriched_data,
                flagged_ips=flagged_ips,
            )

            # Format response
            result_data = {
                "original_log_line": log_line,
                "extracted_ips": extracted_ips,
                "enrichment_summary": {
                    "total_ips_extracted": len(extracted_ips),
                    "successfully_enriched": len(enriched_data),
                    "flagged_count": len(flagged_ips),
                    "threshold_used": threshold,
                },
                "flagged_ips": flagged_ips,
                "ip_details": {
                    ip: {
                        "abuse_confidence": data.abuse_confidence_percentage,
                        "total_reports": data.total_reports,
                        "country": data.country_name,
                        "isp": data.isp,
                        "last_reported": data.last_reported_at.isoformat() if data.last_reported_at else None,
                        "is_whitelisted": data.is_whitelisted,
                    }
                    for ip, data in enriched_data.items()
                },
            }

            # Create summary text
            summary_lines = [
                f"Log Line Enrichment Results:",
                f"Original Log: {log_line}",
                f"",
                f"IP Addresses Found: {len(extracted_ips)}",
                f"Successfully Enriched: {len(enriched_data)}",
                f"Flagged (≥{threshold}%): {len(flagged_ips)}",
            ]

            if extracted_ips:
                summary_lines.append("\nExtracted IPs:")
                for ip in extracted_ips:
                    summary_lines.append(f"  • {ip}")

            if flagged_ips:
                summary_lines.append(f"\n⚠️  FLAGGED IPs (Threat Detected):")
                for ip in flagged_ips:
                    data = enriched_data.get(ip)
                    if data:
                        summary_lines.append(
                            f"  • {ip} - {data.abuse_confidence_percentage}% confidence "
                            f"({data.total_reports} reports) - {data.country_name or 'Unknown'}"
                        )

            if enriched_data:
                clean_ips = [ip for ip in enriched_data.keys() if ip not in flagged_ips]
                if clean_ips:
                    summary_lines.append(f"\n✅ Clean IPs:")
                    for ip in clean_ips:
                        data = enriched_data[ip]
                        summary_lines.append(
                            f"  • {ip} - {data.abuse_confidence_percentage}% confidence "
                            f"({data.total_reports} reports) - {data.country_name or 'Unknown'}"
                        )

            failed_ips = [ip for ip in extracted_ips if ip not in enriched_data]
            if failed_ips:
                summary_lines.append(f"\n❌ Failed to Enrich:")
                for ip in failed_ips:
                    summary_lines.append(f"  • {ip}")

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
            logger.error(f"Validation error in enrich_log_line: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Validation Error: {e}")],
                isError=True,
            )
        except Exception as e:
            logger.error(f"Unexpected error in enrich_log_line: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unexpected Error: {e}")],
                isError=True,
            )
