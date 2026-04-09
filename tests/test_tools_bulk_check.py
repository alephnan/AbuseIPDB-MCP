"""Tests for bulk_check tool."""

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime
from mcp.types import CallToolResult

from mcp_abuseipdb.tools.bulk_check import BulkCheckTool
from mcp_abuseipdb.settings import Settings
from mcp_abuseipdb.cache import CacheManager, RateLimiter
from mcp_abuseipdb.models import IPCheckResponse, BulkCheckResult


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
def bulk_check_tool(mock_settings, mock_cache, mock_rate_limiter):
    """Create BulkCheckTool instance for testing."""
    return BulkCheckTool(mock_settings, mock_cache, mock_rate_limiter)


@pytest.fixture
def sample_ip_response_high():
    """Sample IP response with high confidence."""
    return {
        "ip_address": "203.0.113.100",
        "is_public": True,
        "ip_version": 4,
        "is_whitelisted": False,
        "abuse_confidence_percentage": 85,
        "country_code": "US",
        "country_name": "United States",
        "usage_type": "hosting",
        "isp": "Example ISP",
        "domain": "example.com",
        "total_reports": 15,
        "num_distinct_users": 8,
        "last_reported_at": datetime.now()
    }


@pytest.fixture
def sample_ip_response_low():
    """Sample IP response with low confidence."""
    return {
        "ip_address": "8.8.8.8",
        "is_public": True,
        "ip_version": 4,
        "is_whitelisted": False,
        "abuse_confidence_percentage": 0,
        "country_code": "US",
        "country_name": "United States",
        "usage_type": "hosting",
        "isp": "Google LLC",
        "domain": "google.com",
        "total_reports": 0,
        "num_distinct_users": 0,
        "last_reported_at": None
    }


class TestBulkCheckTool:
    """Test cases for BulkCheckTool."""

    @pytest.mark.asyncio
    async def test_get_tool_definition(self, bulk_check_tool):
        """Test tool definition generation."""
        definition = await bulk_check_tool.get_tool_definition()

        assert definition.name == "bulk_check"
        assert "multiple" in definition.description.lower() or "batch" in definition.description.lower()
        assert "ip_addresses" in definition.inputSchema["properties"]
        assert definition.inputSchema["required"] == ["ip_addresses"]
        assert definition.inputSchema["properties"]["ip_addresses"]["maxItems"] == 100

    def test_validate_and_dedupe_ips_valid(self, bulk_check_tool):
        """Test validation and deduplication of valid IPs."""
        ip_list = ["8.8.8.8", "1.1.1.1", "8.8.8.8", "  203.0.113.100  "]

        result = bulk_check_tool._validate_and_dedupe_ips(ip_list)

        assert len(result) == 3  # Duplicates removed
        assert "8.8.8.8" in result
        assert "1.1.1.1" in result
        assert "203.0.113.100" in result

    def test_validate_and_dedupe_ips_invalid(self, bulk_check_tool):
        """Test validation with invalid IPs."""
        ip_list = ["8.8.8.8", "not.an.ip", "1.1.1.1", ""]

        result = bulk_check_tool._validate_and_dedupe_ips(ip_list)

        assert len(result) == 2  # Only valid IPs
        assert "8.8.8.8" in result
        assert "1.1.1.1" in result

    def test_validate_and_dedupe_ips_private_not_allowed(self, bulk_check_tool):
        """Test filtering of private IPs when not allowed."""
        ip_list = ["8.8.8.8", "192.168.1.1", "10.0.0.1", "172.16.0.1"]

        result = bulk_check_tool._validate_and_dedupe_ips(ip_list)

        assert len(result) == 1  # Only public IP
        assert "8.8.8.8" in result

    @pytest.mark.asyncio
    async def test_execute_empty_ip_list(self, bulk_check_tool):
        """Test execution with empty IP list."""
        result = await bulk_check_tool.execute({"ip_addresses": []})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "ip_addresses list is required" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_too_many_ips(self, bulk_check_tool):
        """Test execution with too many IPs."""
        ip_list = [f"203.0.113.{i}" for i in range(101)]

        result = await bulk_check_tool.execute({"ip_addresses": ip_list})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "Maximum 100 IP addresses allowed" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_invalid_threshold(self, bulk_check_tool):
        """Test execution with invalid threshold."""
        result = await bulk_check_tool.execute({
            "ip_addresses": ["8.8.8.8"],
            "threshold": 150
        })

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "threshold must be between 0 and 100" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_no_valid_ips(self, bulk_check_tool):
        """Test execution with no valid IPs after validation."""
        result = await bulk_check_tool.execute({
            "ip_addresses": ["not.an.ip", "invalid", ""]
        })

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "No valid IP addresses found" in result.content[0].text

    @pytest.mark.asyncio
    async def test_check_single_ip_cache_hit(self, bulk_check_tool, mock_cache, sample_ip_response_high):
        """Test checking single IP with cache hit."""
        mock_cache.get.return_value = sample_ip_response_high

        with patch('mcp_abuseipdb.tools.bulk_check.AbuseIPDBClient') as mock_client:
            mock_semaphore = AsyncMock()
            result = await bulk_check_tool._check_single_ip(
                "203.0.113.100", 30, mock_client, mock_semaphore
            )

        assert isinstance(result, BulkCheckResult)
        assert result.success is True
        assert result.ip_address == "203.0.113.100"
        assert result.data.abuse_confidence_percentage == 85

    @pytest.mark.asyncio
    async def test_check_single_ip_rate_limited(self, bulk_check_tool, mock_cache, mock_rate_limiter):
        """Test checking single IP when rate limited."""
        mock_cache.get.return_value = None
        mock_rate_limiter.acquire.return_value = False

        with patch('mcp_abuseipdb.tools.bulk_check.AbuseIPDBClient') as mock_client:
            mock_semaphore = AsyncMock()
            result = await bulk_check_tool._check_single_ip(
                "203.0.113.100", 30, mock_client, mock_semaphore
            )

        assert isinstance(result, BulkCheckResult)
        assert result.success is False
        assert result.error == "Rate limit exceeded"

    @pytest.mark.asyncio
    async def test_execute_mixed_results(self, bulk_check_tool, mock_cache, sample_ip_response_high, sample_ip_response_low):
        """Test execution with mixed success/failure results."""
        # Mock cache to return different responses for different IPs
        def cache_side_effect(key):
            if "203.0.113.100" in key:
                return sample_ip_response_high
            elif "8.8.8.8" in key:
                return sample_ip_response_low
            return None

        mock_cache.get.side_effect = cache_side_effect

        with patch('mcp_abuseipdb.tools.bulk_check.AbuseIPDBClient'):
            result = await bulk_check_tool.execute({
                "ip_addresses": ["203.0.113.100", "8.8.8.8"],
                "threshold": 75
            })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "2" in content  # 2 IPs processed
        assert "203.0.113.100" in content  # High confidence IP mentioned
        assert "⚠️" in content or "FLAGGED" in content  # Should flag high confidence IP

    @pytest.mark.asyncio
    async def test_execute_all_clean_ips(self, bulk_check_tool, mock_cache, sample_ip_response_low):
        """Test execution with all clean IPs."""
        mock_cache.get.return_value = sample_ip_response_low

        with patch('mcp_abuseipdb.tools.bulk_check.AbuseIPDBClient'):
            result = await bulk_check_tool.execute({
                "ip_addresses": ["8.8.8.8", "1.1.1.1"],
                "threshold": 75
            })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "Flagged" in content and "0" in content  # 0 flagged IPs

    @pytest.mark.asyncio
    async def test_execute_deduplication(self, bulk_check_tool, mock_cache, sample_ip_response_low):
        """Test that duplicate IPs are deduplicated."""
        mock_cache.get.return_value = sample_ip_response_low

        with patch('mcp_abuseipdb.tools.bulk_check.AbuseIPDBClient'):
            result = await bulk_check_tool.execute({
                "ip_addresses": ["8.8.8.8", "8.8.8.8", "8.8.8.8"]
            })

        content = result.content[0].text
        assert "Unique IPs: 1" in content  # Should deduplicate to 1 IP

    @pytest.mark.asyncio
    async def test_execute_custom_parameters(self, bulk_check_tool, mock_cache, sample_ip_response_high):
        """Test execution with custom parameters."""
        mock_cache.get.return_value = sample_ip_response_high

        with patch('mcp_abuseipdb.tools.bulk_check.AbuseIPDBClient'):
            result = await bulk_check_tool.execute({
                "ip_addresses": ["203.0.113.100"],
                "max_age_days": 90,
                "threshold": 50
            })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "≥50%" in content  # Custom threshold mentioned