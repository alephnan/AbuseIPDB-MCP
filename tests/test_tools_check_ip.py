"""Tests for check_ip tool."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from mcp.types import CallToolResult

from mcp_abuseipdb.tools.check_ip import CheckIPTool
from mcp_abuseipdb.settings import Settings
from mcp_abuseipdb.cache import CacheManager, RateLimiter
from mcp_abuseipdb.models import IPCheckResponse


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    return Settings(
        abuseipdb_api_key="test_key",
        max_age_days=30,
        confidence_threshold=75,
        allow_private_ips=False
    )


@pytest.fixture
def mock_cache():
    """Mock cache manager."""
    cache = AsyncMock(spec=CacheManager)
    cache.get.return_value = None
    cache.set = AsyncMock()

    def build_key(endpoint, params):
        sorted_params = sorted(params.items())
        params_str = "&".join(f"{k}={v}" for k, v in sorted_params)
        return f"{endpoint}?{params_str}"

    cache.create_cache_key.side_effect = build_key
    return cache


@pytest.fixture
def mock_rate_limiter():
    """Mock rate limiter."""
    limiter = AsyncMock(spec=RateLimiter)
    limiter.acquire.return_value = True
    return limiter


@pytest.fixture
def check_ip_tool(mock_settings, mock_cache, mock_rate_limiter):
    """Create CheckIPTool instance for testing."""
    return CheckIPTool(mock_settings, mock_cache, mock_rate_limiter)


class TestCheckIPTool:
    """Test cases for CheckIPTool."""

    @pytest.mark.asyncio
    async def test_get_tool_definition(self, check_ip_tool):
        """Test tool definition generation."""
        definition = await check_ip_tool.get_tool_definition()

        assert definition.name == "check_ip"
        assert "reputation" in definition.description.lower()
        assert "ip_address" in definition.inputSchema["properties"]
        assert definition.inputSchema["required"] == ["ip_address"]

    def test_validate_ip_address_valid_ipv4(self, check_ip_tool):
        """Test validation of valid IPv4 address."""
        result = check_ip_tool._validate_ip_address("8.8.8.8")
        assert result == "8.8.8.8"

    def test_validate_ip_address_valid_ipv6(self, check_ip_tool):
        """Test validation of valid IPv6 address."""
        result = check_ip_tool._validate_ip_address("2001:4860:4860::8888")
        assert result == "2001:4860:4860::8888"

    def test_validate_ip_address_invalid(self, check_ip_tool):
        """Test validation of invalid IP address."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            check_ip_tool._validate_ip_address("not.an.ip")

    def test_validate_ip_address_private_not_allowed(self, check_ip_tool):
        """Test private IP rejection when not allowed."""
        with pytest.raises(ValueError, match="Private IP addresses are not allowed"):
            check_ip_tool._validate_ip_address("192.168.1.1")

    @pytest.mark.asyncio
    async def test_execute_missing_ip_address(self, check_ip_tool):
        """Test execution with missing IP address."""
        result = await check_ip_tool.execute({})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "ip_address is required" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_invalid_ip_address(self, check_ip_tool):
        """Test execution with invalid IP address."""
        result = await check_ip_tool.execute({"ip_address": "invalid"})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "Validation Error" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_rate_limit_exceeded(self, check_ip_tool, mock_rate_limiter):
        """Test execution when rate limit is exceeded."""
        mock_rate_limiter.acquire.return_value = False

        result = await check_ip_tool.execute({"ip_address": "8.8.8.8"})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "Rate limit exceeded" in result.content[0].text

    def test_assess_risk_level_high(self, check_ip_tool):
        """Test risk level assessment for high confidence."""
        mock_response = MagicMock()
        mock_response.abuse_confidence_percentage = 85

        risk = check_ip_tool._assess_risk_level(mock_response)
        assert risk == "HIGH"

    def test_assess_risk_level_medium(self, check_ip_tool):
        """Test risk level assessment for medium confidence."""
        mock_response = MagicMock()
        mock_response.abuse_confidence_percentage = 50

        risk = check_ip_tool._assess_risk_level(mock_response)
        assert risk == "MEDIUM"

    def test_assess_risk_level_low(self, check_ip_tool):
        """Test risk level assessment for low confidence."""
        mock_response = MagicMock()
        mock_response.abuse_confidence_percentage = 10

        risk = check_ip_tool._assess_risk_level(mock_response)
        assert risk == "LOW"