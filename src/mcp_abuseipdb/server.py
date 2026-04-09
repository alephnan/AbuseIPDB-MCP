"""MCP Server for AbuseIPDB threat intelligence lookups."""

import asyncio
import json
import logging
import sys
from typing import Any

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    TextResourceContents,
    Prompt,
    GetPromptResult,
    PromptMessage,
    CallToolResult,
)
from pydantic import AnyUrl

from .settings import Settings
from .cache import CacheManager, RateLimiter
from .client_abuseipdb import AbuseIPDBClient

# Import tools (to be created)
from .tools.check_ip import CheckIPTool
from .tools.check_block import CheckBlockTool
from .tools.get_blacklist import GetBlacklistTool
from .tools.bulk_check import BulkCheckTool
from .tools.enrich_log_line import EnrichLogLineTool

logger = logging.getLogger(__name__)


class MCPAbuseIPDBServer:
    """MCP Server for AbuseIPDB integration."""

    def __init__(self):
        # Load settings
        print("[MCP AbuseIPDB] Initializing settings...", file=sys.stderr)
        self.settings = Settings()
        print(f"[MCP AbuseIPDB] Settings loaded successfully", file=sys.stderr)

        # Initialize components
        self.cache = CacheManager(
            self.settings.cache_db_path,
            self.settings.cache_default_ttl
        )
        self.rate_limiter = RateLimiter(self.settings.daily_quota)

        # Initialize MCP server
        self.server = Server("mcp-abuseipdb")

        # Initialize tools
        self.tools = {
            "check_ip": CheckIPTool(self.settings, self.cache, self.rate_limiter),
            "check_block": CheckBlockTool(self.settings, self.cache, self.rate_limiter),
            "get_blacklist": GetBlacklistTool(self.settings, self.cache, self.rate_limiter),
            "bulk_check": BulkCheckTool(self.settings, self.cache, self.rate_limiter),
            "enrich_log_line": EnrichLogLineTool(self.settings, self.cache, self.rate_limiter),
        }

        # Register handlers
        self._register_handlers()

        print(f"[MCP AbuseIPDB] Server initialized successfully", file=sys.stderr)

    async def _validate_api_key(self) -> bool:
        """Validate API key by making a test request to AbuseIPDB."""
        try:
            print("[MCP AbuseIPDB] Validating API key...", file=sys.stderr)

            # Create a temporary client for validation
            from .client_abuseipdb import AbuseIPDBClient
            async with AbuseIPDBClient(self.settings) as client:
                # Test with a known good IP (Google DNS)
                await client.check_ip("8.8.8.8", max_age_days=30, verbose=False)

            print("[MCP AbuseIPDB] API key validation successful", file=sys.stderr)
            return True

        except Exception as e:
            error_msg = str(e)
            print(f"[MCP AbuseIPDB] API key validation failed: {error_msg}", file=sys.stderr)

            # Provide specific guidance for common errors
            if "Unauthorized" in error_msg or "401" in error_msg:
                print("[MCP AbuseIPDB] ERROR: Invalid API key. Please check:", file=sys.stderr)
                print("  1. API key is correctly set in Claude app MCP configuration", file=sys.stderr)
                print("  2. API key matches exactly what's in your .env file", file=sys.stderr)
                print("  3. API key is valid and not expired on AbuseIPDB website", file=sys.stderr)

            return False

    def _register_handlers(self):
        """Register MCP handlers."""

        @self.server.list_tools()
        async def handle_list_tools() -> list[Tool]:
            """List available tools."""
            tools: list[Tool] = []
            for tool in self.tools.values():
                tools.append(await tool.get_tool_definition())
            return tools

        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> Any:
            """Handle tool calls."""
            if name not in self.tools:
                raise ValueError(f"Unknown tool: {name}")

            tool = self.tools[name]
            result = await tool.execute(arguments)

            if isinstance(result, CallToolResult):
                if result.isError:
                    message = 'Tool execution failed.'
                    for block in result.content:
                        if isinstance(block, TextContent):
                            message = block.text
                            break
                    raise RuntimeError(message)

                content = list(result.content) if result.content else []
                if result.structuredContent is not None:
                    return content, result.structuredContent
                return content

            return result

        @self.server.list_resources()
        async def handle_list_resources() -> list[Resource]:
            """List available resources."""
            return [
                Resource(
                    uri=AnyUrl("cache://info"),
                    name="Cache Information",
                    description="Current cache statistics and status",
                    mimeType="application/json",
                ),
                Resource(
                    uri=AnyUrl("doc://usage"),
                    name="Usage Documentation",
                    description="API usage documentation and examples",
                    mimeType="text/markdown",
                ),
            ]

        @self.server.read_resource()
        async def handle_read_resource(uri: AnyUrl) -> list[TextResourceContents]:
            """Handle resource reads."""
            uri_str = str(uri)

            if uri_str == "cache://info":
                cache_info = await self.cache.get_cache_info()
                rate_info = await self.rate_limiter.get_status()

                info = {
                    "cache": cache_info,
                    "rate_limiter": rate_info,
                    "settings": {
                        "max_age_days": self.settings.max_age_days,
                        "confidence_threshold": self.settings.confidence_threshold,
                        "daily_quota": self.settings.daily_quota,
                    }
                }

                payload = json.dumps(info, indent=2)
                return [
                    TextResourceContents(
                        uri=uri,
                        text=payload,
                        mimeType="application/json",
                    )
                ]

            elif uri_str == "doc://usage":
                usage_doc = self._get_usage_documentation()
                return [
                    TextResourceContents(
                        uri=uri,
                        text=usage_doc,
                        mimeType="text/markdown",
                    )
                ]

            else:
                raise ValueError(f"Unknown resource: {uri}")

        @self.server.list_prompts()
        async def handle_list_prompts() -> list[Prompt]:
            """List available prompts."""
            return [
                Prompt(
                    name="triage_ip",
                    description="Generate analyst triage notes for an IP address",
                    arguments=[
                        {
                            "name": "ip_data",
                            "description": "IP check data from AbuseIPDB",
                            "required": True,
                        }
                    ],
                )
            ]

        @self.server.get_prompt()
        async def handle_get_prompt(name: str, arguments: dict) -> GetPromptResult:
            """Handle prompt requests."""
            if name == "triage_ip":
                ip_data = arguments.get("ip_data", {})
                prompt_text = self._generate_triage_prompt(ip_data)

                return GetPromptResult(
                    description="Triage analysis for IP address",
                    messages=[
                        PromptMessage(
                            role="user",
                            content=TextContent(type="text", text=prompt_text),
                        )
                    ],
                )
            else:
                raise ValueError(f"Unknown prompt: {name}")

    def _get_usage_documentation(self) -> str:
        """Generate usage documentation."""
        return """# MCP AbuseIPDB Usage Documentation

## Available Tools

### check_ip
Check reputation of a single IP address.
- **ip_address** (required): IP address to check
- **max_age_days** (optional): Maximum age of reports to consider (default: 30)
- **verbose** (optional): Include detailed reports (default: false)
- **threshold** (optional): Abuse confidence threshold for flagging (default: 75)

### check_block
Check reputation of a CIDR block.
- **network** (required): CIDR network to check (e.g., "192.168.1.0/24")
- **max_age_days** (optional): Maximum age of reports to consider (default: 30)

### get_blacklist
Retrieve AbuseIPDB blacklist.
- **confidence_minimum** (optional): Minimum confidence level (default: 90)
- **limit** (optional): Maximum number of entries to retrieve

### bulk_check
Check multiple IP addresses in batch.
- **ip_addresses** (required): List of IP addresses to check
- **max_age_days** (optional): Maximum age of reports to consider (default: 30)
- **threshold** (optional): Abuse confidence threshold for flagging (default: 75)

### enrich_log_line
Extract and enrich IP addresses from log line.
- **log_line** (required): Log line containing IP addresses
- **threshold** (optional): Abuse confidence threshold for flagging (default: 75)

## Available Resources

### cache://info
Get current cache statistics and rate limiter status.

### doc://usage
This usage documentation.

## Available Prompts

### triage_ip
Generate analyst triage notes for an IP address based on AbuseIPDB data.

## Examples

Check a single IP:
```json
{
  "tool": "check_ip",
  "arguments": {
    "ip_address": "8.8.8.8",
    "max_age_days": 90,
    "threshold": 50
  }
}
```

Enrich a log line:
```json
{
  "tool": "enrich_log_line",
  "arguments": {
    "log_line": "192.168.1.100 - - [10/Jan/2024:10:00:00 +0000] GET /api/data",
    "threshold": 75
  }
}
```
"""

    def _generate_triage_prompt(self, ip_data: dict) -> str:
        """Generate triage prompt for IP analysis."""
        if not ip_data:
            return "No IP data provided for triage analysis."

        ip = ip_data.get("ip_address", "Unknown")
        confidence = ip_data.get("abuse_confidence_percentage", 0)
        reports = ip_data.get("total_reports", 0)
        country = ip_data.get("country_name", "Unknown")
        isp = ip_data.get("isp", "Unknown")
        last_reported = ip_data.get("last_reported_at", "Never")

        return f"""Analyze this IP address and provide a concise security triage assessment:

**IP Address:** {ip}
**Abuse Confidence:** {confidence}%
**Total Reports:** {reports}
**Country:** {country}
**ISP:** {isp}
**Last Reported:** {last_reported}

Please provide:
1. Risk assessment (High/Medium/Low)
2. Recommended actions
3. Key indicators of compromise or legitimacy
4. Any additional context relevant for security operations

Keep the analysis concise and actionable for SOC analysts."""

    async def run(self):
        """Run the MCP server."""
        # Setup logging
        logging.basicConfig(
            level=getattr(logging, self.settings.log_level.upper()),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

        logger.info("Starting MCP AbuseIPDB server")

        # Validate API key on startup
        api_key_valid = await self._validate_api_key()
        if not api_key_valid:
            print("[MCP AbuseIPDB] FATAL: API key validation failed. Server will continue but tools may not work.", file=sys.stderr)
            print("[MCP AbuseIPDB] Please fix the API key configuration and restart.", file=sys.stderr)

        # Initialize cache cleanup task
        asyncio.create_task(self._cleanup_cache_periodically())

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="mcp-abuseipdb",
                    server_version="0.1.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    async def _cleanup_cache_periodically(self):
        """Periodically clean up expired cache entries."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                cleaned = await self.cache.cleanup_expired()
                if cleaned > 0:
                    logger.info(f"Cleaned up {cleaned} expired cache entries")
            except Exception as e:
                logger.error(f"Error during cache cleanup: {e}")


def main():
    """Main entry point."""
    server = MCPAbuseIPDBServer()
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        logger.info("Shutting down server")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()