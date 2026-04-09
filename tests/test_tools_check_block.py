"""Tests for check_block tool."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from mcp.types import CallToolResult

from mcp_abuseipdb.tools.check_block import CheckBlockTool
from mcp_abuseipdb.settings import Settings
from mcp_abuseipdb.cache import CacheManager, RateLimiter
from mcp_abuseipdb.models import BlockCheckResponse, APIError


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
def check_block_tool(mock_settings, mock_cache, mock_rate_limiter):
    """Create CheckBlockTool instance for testing."""
    return CheckBlockTool(mock_settings, mock_cache, mock_rate_limiter)


@pytest.fixture
def sample_block_response():
    """Sample block check response."""
    return {
        "network_address": "203.0.113.0",
        "netmask": "24",
        "min_address": "203.0.113.0",
        "max_address": "203.0.113.255",
        "num_possible_hosts": 256,
        "address_space_desc": "Public Address Space",
        "reported_address": [
            {
                "ipAddress": "203.0.113.100",
                "abuseConfidencePercentage": 85,
                "totalReports": 15,
                "countryCode": "US"
            },
            {
                "ipAddress": "203.0.113.200",
                "abuseConfidencePercentage": 25,
                "totalReports": 3,
                "countryCode": "US"
            }
        ]
    }


class TestCheckBlockTool:
    """Test cases for CheckBlockTool."""

    @pytest.mark.asyncio
    async def test_get_tool_definition(self, check_block_tool):
        """Test tool definition generation."""
        definition = await check_block_tool.get_tool_definition()

        assert definition.name == "check_block"
        assert "CIDR" in definition.description
        assert "network" in definition.inputSchema["properties"]
        assert definition.inputSchema["required"] == ["network"]

    def test_validate_network_valid_ipv4(self, check_block_tool):
        """Test validation of valid IPv4 CIDR."""
        result = check_block_tool._validate_network("203.0.113.0/24")
        assert result == "203.0.113.0/24"

    def test_validate_network_valid_ipv6(self, check_block_tool):
        """Test validation of valid IPv6 CIDR."""
        result = check_block_tool._validate_network("2001:db8::/32")
        assert result == "2001:db8::/32"

    def test_validate_network_auto_fix_host_bits(self, check_block_tool):
        """Test network validation with host bits set."""
        result = check_block_tool._validate_network("203.0.113.100/24")
        assert result == "203.0.113.0/24"

    def test_validate_network_invalid(self, check_block_tool):
        """Test validation of invalid network."""
        with pytest.raises(ValueError, match="Invalid network"):
            check_block_tool._validate_network("not.a.network")

    def test_validate_network_private_not_allowed(self, check_block_tool):
        """Test private network rejection when not allowed."""
        with pytest.raises(ValueError, match="Private networks are not allowed"):
            check_block_tool._validate_network("192.168.1.0/24")

    @pytest.mark.asyncio
    async def test_execute_missing_network(self, check_block_tool):
        """Test execution with missing network parameter."""
        result = await check_block_tool.execute({})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "network is required" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_invalid_max_age(self, check_block_tool):
        """Test execution with invalid max_age_days."""
        result = await check_block_tool.execute({
            "network": "203.0.113.0/24",
            "max_age_days": 400
        })

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "max_age_days must be between 1 and 365" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_rate_limit_exceeded(self, check_block_tool, mock_rate_limiter):
        """Test execution when rate limit is exceeded."""
        mock_rate_limiter.acquire.return_value = False

        result = await check_block_tool.execute({"network": "203.0.113.0/24"})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "Rate limit exceeded" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_cache_hit(self, check_block_tool, mock_cache, sample_block_response):
        """Test execution with cache hit."""
        mock_cache.get.return_value = sample_block_response

        result = await check_block_tool.execute({"network": "203.0.113.0/24"})

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False
        assert "203.0.113.0" in result.content[0].text
        assert "Cache hit" in result.content[0].text or "Network:" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_api_error(self, check_block_tool, mock_cache):
        """Test execution with API error."""
        mock_cache.get.return_value = None

        with patch('mcp_abuseipdb.tools.check_block.AbuseIPDBClient') as mock_client_cls:
            client_instance = AsyncMock()
            client_instance.__aenter__.return_value = client_instance
            client_instance.check_block.side_effect = APIError(
                error="Unauthorized - check API key",
                status_code=401,
                retryable=False,
            )
            mock_client_cls.return_value = client_instance

            result = await check_block_tool.execute({"network": "203.0.113.0/24"})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "API Error" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_successful_response(self, check_block_tool, mock_cache, sample_block_response):
        """Test successful execution with API response."""
        mock_cache.get.return_value = sample_block_response

        result = await check_block_tool.execute({
            "network": "203.0.113.0/24",
            "max_age_days": 30
        })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "203.0.113.0/24" in content
        assert "256" in content  # num_possible_hosts
        assert "2" in content  # total reported addresses

    @pytest.mark.asyncio
    async def test_execute_high_confidence_flagging(self, check_block_tool, mock_cache, sample_block_response):
        """Test flagging of high confidence addresses."""
        mock_cache.get.return_value = sample_block_response

        result = await check_block_tool.execute({"network": "203.0.113.0/24"})

        content = result.content[0].text
        assert "⚠️" in content or "FLAGGED" in content  # Should flag high confidence IPs
        assert "203.0.113.100" in content  # High confidence IP should be mentioned

    @pytest.mark.asyncio
    async def test_execute_accepts_normalized_reported_address_fields(self, check_block_tool, mock_cache):
        """Test normalized cached reported-address fields are handled correctly."""
        mock_cache.get.return_value = {
            "network_address": "203.0.113.0",
            "netmask": "24",
            "min_address": "203.0.113.0",
            "max_address": "203.0.113.255",
            "num_possible_hosts": 256,
            "address_space_desc": "Public Address Space",
            "reported_address": [
                {
                    "ip_address": "203.0.113.100",
                    "abuse_confidence_percentage": 85,
                    "total_reports": 15,
                    "country_code": "US",
                }
            ],
        }

        result = await check_block_tool.execute({"network": "203.0.113.0/24"})

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False
        content = result.content[0].text
        assert "High Confidence (≥75%): 1" in content
        assert "203.0.113.100 - 85% confidence (15 reports)" in content
