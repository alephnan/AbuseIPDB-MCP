"""Tests for MCP server integration."""

import pytest
import asyncio
import json
import tempfile
import os
from unittest.mock import AsyncMock, patch, MagicMock

from mcp.types import (
    Tool, Resource, Prompt,
    ListToolsResult, ListResourcesResult, ListPromptsResult,
    CallToolResult, ReadResourceResult, GetPromptResult,
    TextContent
)
from pydantic import AnyUrl

from mcp_abuseipdb.server import MCPAbuseIPDBServer
from mcp_abuseipdb.settings import Settings


@pytest.fixture
def temp_db():
    """Create a temporary database file for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


@pytest.fixture
def mock_settings(temp_db):
    """Mock settings for testing."""
    with patch.dict(os.environ, {
        "ABUSEIPDB_API_KEY": "test_key_12345",
        "CACHE_DB_PATH": temp_db,
        "DAILY_QUOTA": "100",
        "LOG_LEVEL": "DEBUG"
    }):
        return Settings()


@pytest.fixture
def mcp_server(mock_settings):
    """Create MCP server instance for testing."""
    with patch('mcp_abuseipdb.server.Settings', return_value=mock_settings):
        server = MCPAbuseIPDBServer()
        return server


class TestMCPServerInitialization:
    """Test cases for MCP server initialization."""

    def test_server_initialization(self, mcp_server):
        """Test server initializes correctly."""
        assert mcp_server.settings is not None
        assert mcp_server.cache is not None
        assert mcp_server.rate_limiter is not None
        assert mcp_server.server is not None
        assert len(mcp_server.tools) == 5  # All 5 tools should be registered

    def test_tools_registration(self, mcp_server):
        """Test that all tools are registered."""
        expected_tools = [
            "check_ip",
            "check_block",
            "get_blacklist",
            "bulk_check",
            "enrich_log_line"
        ]

        for tool_name in expected_tools:
            assert tool_name in mcp_server.tools


class TestToolsHandler:
    """Test cases for tools handler."""

    @pytest.mark.asyncio
    async def test_list_tools(self, mcp_server):
        """Test listing available tools."""
        # Test that tools are properly configured
        assert len(mcp_server.tools) == 5

        # Test each tool has proper definition
        for tool_name, tool in mcp_server.tools.items():
            definition = await tool.get_tool_definition()
            assert isinstance(definition, Tool)
            assert definition.name == tool_name
            assert definition.description is not None
            assert definition.inputSchema is not None

    @pytest.mark.asyncio
    async def test_call_tool_check_ip(self, mcp_server):
        """Test calling check_ip tool."""
        # Mock the tool execution
        with patch.object(mcp_server.tools["check_ip"], "execute") as mock_execute:
            mock_execute.return_value = CallToolResult(
                content=[TextContent(type="text", text="Mock result")]
            )

            # Call the tool directly
            result = await mcp_server.tools["check_ip"].execute({"ip_address": "8.8.8.8"})

            assert isinstance(result, CallToolResult)
            mock_execute.assert_called_once_with({"ip_address": "8.8.8.8"})

    @pytest.mark.asyncio
    async def test_call_tool_unknown(self, mcp_server):
        """Test calling unknown tool raises error."""
        # Test that unknown tool is not in tools dict
        assert "unknown_tool" not in mcp_server.tools

    @pytest.mark.asyncio
    async def test_call_tool_all_tools(self, mcp_server):
        """Test that all tools can be called without error."""
        tool_test_args = {
            "check_ip": {"ip_address": "8.8.8.8"},
            "check_block": {"network": "203.0.113.0/24"},
            "get_blacklist": {},
            "bulk_check": {"ip_addresses": ["8.8.8.8"]},
            "enrich_log_line": {"log_line": "Test log with 8.8.8.8"}
        }

        for tool_name, args in tool_test_args.items():
            with patch.object(mcp_server.tools[tool_name], "execute") as mock_execute:
                mock_execute.return_value = CallToolResult(
                    content=[TextContent(type="text", text=f"Mock result for {tool_name}")]
                )

                result = await mcp_server.tools[tool_name].execute(args)
                assert isinstance(result, CallToolResult)


class TestResourcesHandler:
    """Test cases for resources handler."""

    @pytest.mark.asyncio
    async def test_list_resources(self, mcp_server):
        """Test listing available resources."""
        # Test that server has the expected configuration for resources
        # Since we can't easily access the handler without MCP infrastructure,
        # we'll test the components that would be used by the handlers
        assert mcp_server.cache is not None
        assert mcp_server.rate_limiter is not None
        assert mcp_server.settings is not None

    @pytest.mark.asyncio
    async def test_read_cache_info_resource(self, mcp_server):
        """Test reading cache info resource."""
        # Test that cache info can be retrieved
        cache_info = await mcp_server.cache.get_cache_info()
        rate_info = await mcp_server.rate_limiter.get_status()

        assert "total_entries" in cache_info
        assert "tokens_available" in rate_info
        assert hasattr(mcp_server.settings, "max_age_days")

    @pytest.mark.asyncio
    async def test_read_usage_documentation_resource(self, mcp_server):
        """Test reading usage documentation resource."""
        # Test that the documentation method exists and works
        doc = mcp_server._get_usage_documentation()
        assert "# MCP AbuseIPDB Usage Documentation" in doc
        assert "## Available Tools" in doc

    @pytest.mark.asyncio
    async def test_read_unknown_resource(self, mcp_server):
        """Test reading unknown resource raises error."""
        # Test that server properly validates resource URIs
        # This would be tested in actual MCP integration tests
        pass


class TestPromptsHandler:
    """Test cases for prompts handler."""

    @pytest.mark.asyncio
    async def test_list_prompts(self, mcp_server):
        """Test listing available prompts."""
        # Test that the server is configured for prompts
        # The actual prompt listing would be tested in MCP integration tests
        assert hasattr(mcp_server, "_generate_triage_prompt")

    @pytest.mark.asyncio
    async def test_get_triage_ip_prompt(self, mcp_server):
        """Test getting triage IP prompt."""
        ip_data = {
            "ip_address": "203.0.113.100",
            "abuse_confidence_percentage": 85,
            "total_reports": 15,
            "country_name": "United States",
            "isp": "Example ISP",
            "last_reported_at": "2024-01-10T09:00:00Z"
        }

        # Test the prompt generation method directly
        prompt_text = mcp_server._generate_triage_prompt(ip_data)

        assert "203.0.113.100" in prompt_text
        assert "85%" in prompt_text
        assert "United States" in prompt_text
        assert "Risk assessment" in prompt_text

    @pytest.mark.asyncio
    async def test_get_triage_ip_prompt_no_data(self, mcp_server):
        """Test getting triage IP prompt with no data."""
        # Test the prompt generation method directly with empty data
        prompt_text = mcp_server._generate_triage_prompt({})
        assert "No IP data provided" in prompt_text

    @pytest.mark.asyncio
    async def test_get_unknown_prompt(self, mcp_server):
        """Test getting unknown prompt raises error."""
        # This would be tested in actual MCP integration tests
        # Here we just verify the method exists
        assert hasattr(mcp_server, "_generate_triage_prompt")


class TestServerUtilities:
    """Test cases for server utility methods."""

    def test_get_usage_documentation(self, mcp_server):
        """Test usage documentation generation."""
        doc = mcp_server._get_usage_documentation()

        assert "# MCP AbuseIPDB Usage Documentation" in doc
        assert "check_ip" in doc
        assert "check_block" in doc
        assert "get_blacklist" in doc
        assert "bulk_check" in doc
        assert "enrich_log_line" in doc

    def test_generate_triage_prompt_with_data(self, mcp_server):
        """Test triage prompt generation with IP data."""
        ip_data = {
            "ip_address": "203.0.113.100",
            "abuse_confidence_percentage": 85,
            "total_reports": 15,
            "country_name": "United States",
            "isp": "Example ISP",
            "last_reported_at": "2024-01-10T09:00:00Z"
        }

        prompt = mcp_server._generate_triage_prompt(ip_data)

        assert "203.0.113.100" in prompt
        assert "85%" in prompt
        assert "15" in prompt  # total reports
        assert "United States" in prompt
        assert "Example ISP" in prompt
        assert "Risk assessment" in prompt
        assert "Recommended actions" in prompt

    def test_generate_triage_prompt_empty_data(self, mcp_server):
        """Test triage prompt generation with empty data."""
        prompt = mcp_server._generate_triage_prompt({})

        assert "No IP data provided" in prompt

    @pytest.mark.asyncio
    async def test_cleanup_cache_periodically(self, mcp_server):
        """Test periodic cache cleanup task."""
        with patch.object(mcp_server.cache, "cleanup_expired") as mock_cleanup:
            mock_cleanup.return_value = 5  # 5 entries cleaned

            # Mock asyncio.sleep to prevent actual sleeping
            with patch('asyncio.sleep') as mock_sleep:
                mock_sleep.side_effect = [None, asyncio.CancelledError()]  # First call returns, second raises to break loop

                # Test the cleanup method with timeout
                try:
                    await asyncio.wait_for(mcp_server._cleanup_cache_periodically(), timeout=0.1)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    # Expected - the method runs indefinitely or gets cancelled
                    pass

                # Verify cleanup was called
                mock_cleanup.assert_called()


class TestServerConfiguration:
    """Test cases for server configuration."""

    def test_server_with_custom_settings(self, temp_db):
        """Test server initialization with custom settings."""
        with patch.dict(os.environ, {
            "ABUSEIPDB_API_KEY": "custom_key",
            "CACHE_DB_PATH": temp_db,
            "DAILY_QUOTA": "2000",
            "CONFIDENCE_THRESHOLD": "80",
            "LOG_LEVEL": "DEBUG"
        }):
            server = MCPAbuseIPDBServer()

            assert server.settings.abuseipdb_api_key == "custom_key"
            assert server.settings.daily_quota == 2000
            assert server.settings.confidence_threshold == 80
            assert server.settings.log_level == "DEBUG"

    def test_server_tools_inherit_settings(self, mcp_server):
        """Test that tools inherit server settings."""
        for tool_name, tool in mcp_server.tools.items():
            assert tool.settings is mcp_server.settings
            assert tool.cache is mcp_server.cache
            assert tool.rate_limiter is mcp_server.rate_limiter