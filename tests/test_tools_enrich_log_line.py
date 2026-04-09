"""Tests for enrich_log_line tool."""

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime
from mcp.types import CallToolResult

from mcp_abuseipdb.tools.enrich_log_line import EnrichLogLineTool
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
def enrich_log_tool(mock_settings, mock_cache, mock_rate_limiter):
    """Create EnrichLogLineTool instance for testing."""
    return EnrichLogLineTool(mock_settings, mock_cache, mock_rate_limiter)


@pytest.fixture
def sample_malicious_ip_data():
    """Sample data for malicious IP."""
    return {
        "ip_address": "203.0.113.100",
        "is_public": True,
        "ip_version": 4,
        "is_whitelisted": False,
        "abuse_confidence_percentage": 85,
        "country_code": "US",
        "country_name": "United States",
        "usage_type": "hosting",
        "isp": "Malicious ISP",
        "domain": "bad-example.com",
        "total_reports": 25,
        "num_distinct_users": 15,
        "last_reported_at": datetime.now()
    }


@pytest.fixture
def sample_clean_ip_data():
    """Sample data for clean IP."""
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


class TestEnrichLogLineTool:
    """Test cases for EnrichLogLineTool."""

    @pytest.mark.asyncio
    async def test_get_tool_definition(self, enrich_log_tool):
        """Test tool definition generation."""
        definition = await enrich_log_tool.get_tool_definition()

        assert definition.name == "enrich_log_line"
        assert "log line" in definition.description.lower()
        assert "log_line" in definition.inputSchema["properties"]
        assert definition.inputSchema["required"] == ["log_line"]

    def test_extract_ip_addresses_apache_log(self, enrich_log_tool):
        """Test IP extraction from Apache access log."""
        log_line = '203.0.113.100 - - [10/Jan/2024:10:00:00 +0000] "GET /admin/login.php HTTP/1.1" 200 1234'

        ips = enrich_log_tool._extract_ip_addresses(log_line)

        assert len(ips) == 1
        assert "203.0.113.100" in ips

    def test_extract_ip_addresses_multiple_ips(self, enrich_log_tool):
        """Test extraction of multiple IPs from log line."""
        log_line = "Connection from 203.0.113.100 forwarded through 198.51.100.25 to 8.8.8.8"

        ips = enrich_log_tool._extract_ip_addresses(log_line)

        assert len(ips) == 3
        assert "203.0.113.100" in ips
        assert "198.51.100.25" in ips
        assert "8.8.8.8" in ips

    def test_extract_ip_addresses_ipv6(self, enrich_log_tool):
        """Test extraction of IPv6 addresses."""
        log_line = "Connection from 2001:db8::1 to internal server"

        ips = enrich_log_tool._extract_ip_addresses(log_line)

        assert len(ips) == 1
        assert "2001:db8::1" in ips

    def test_extract_ip_addresses_private_filtered(self, enrich_log_tool):
        """Test that private IPs are filtered when not allowed."""
        log_line = "Connection from 192.168.1.100 to 203.0.113.100"

        ips = enrich_log_tool._extract_ip_addresses(log_line)

        assert len(ips) == 1
        assert "203.0.113.100" in ips
        assert "192.168.1.100" not in ips

    def test_extract_ip_addresses_no_ips(self, enrich_log_tool):
        """Test extraction when no IPs are present."""
        log_line = "This is a log line with no IP addresses"

        ips = enrich_log_tool._extract_ip_addresses(log_line)

        assert len(ips) == 0

    def test_extract_ip_addresses_deduplication(self, enrich_log_tool):
        """Test deduplication of IP addresses."""
        log_line = "Multiple connections from 203.0.113.100 and 203.0.113.100 again"

        ips = enrich_log_tool._extract_ip_addresses(log_line)

        assert len(ips) == 1
        assert "203.0.113.100" in ips

    @pytest.mark.asyncio
    async def test_execute_empty_log_line(self, enrich_log_tool):
        """Test execution with empty log line."""
        result = await enrich_log_tool.execute({"log_line": ""})

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "log_line is required" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_no_ips_found(self, enrich_log_tool):
        """Test execution when no IPs are found in log line."""
        result = await enrich_log_tool.execute({
            "log_line": "This log line has no IP addresses"
        })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False
        assert "No IP addresses found" in result.content[0].text

    @pytest.mark.asyncio
    async def test_execute_invalid_threshold(self, enrich_log_tool):
        """Test execution with invalid threshold."""
        result = await enrich_log_tool.execute({
            "log_line": "203.0.113.100 connection",
            "threshold": 150
        })

        assert isinstance(result, CallToolResult)
        assert result.isError is True
        assert "threshold must be between 0 and 100" in result.content[0].text

    @pytest.mark.asyncio
    async def test_enrich_ip_cache_hit(self, enrich_log_tool, mock_cache, sample_malicious_ip_data):
        """Test enriching IP with cache hit."""
        mock_cache.get.return_value = sample_malicious_ip_data

        with patch('mcp_abuseipdb.tools.enrich_log_line.AbuseIPDBClient') as mock_client:
            ip, data = await enrich_log_tool._enrich_ip("203.0.113.100", 30, mock_client)

        assert ip == "203.0.113.100"
        assert data is not None
        assert data.abuse_confidence_percentage == 85

    @pytest.mark.asyncio
    async def test_enrich_ip_rate_limited(self, enrich_log_tool, mock_cache, mock_rate_limiter):
        """Test enriching IP when rate limited."""
        mock_cache.get.return_value = None
        mock_rate_limiter.acquire.return_value = False

        with patch('mcp_abuseipdb.tools.enrich_log_line.AbuseIPDBClient') as mock_client:
            ip, data = await enrich_log_tool._enrich_ip("203.0.113.100", 30, mock_client)

        assert ip == "203.0.113.100"
        assert data is None

    @pytest.mark.asyncio
    async def test_execute_single_clean_ip(self, enrich_log_tool, mock_cache, sample_clean_ip_data):
        """Test execution with single clean IP."""
        mock_cache.get.return_value = sample_clean_ip_data

        with patch('mcp_abuseipdb.tools.enrich_log_line.AbuseIPDBClient'):
            result = await enrich_log_tool.execute({
                "log_line": "8.8.8.8 - - [10/Jan/2024:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1234"
            })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "1" in content  # 1 IP found
        assert "0" in content  # 0 flagged
        assert "✅ Clean IPs:" in content
        assert "8.8.8.8" in content

    @pytest.mark.asyncio
    async def test_execute_single_malicious_ip(self, enrich_log_tool, mock_cache, sample_malicious_ip_data):
        """Test execution with single malicious IP."""
        mock_cache.get.return_value = sample_malicious_ip_data

        with patch('mcp_abuseipdb.tools.enrich_log_line.AbuseIPDBClient'):
            result = await enrich_log_tool.execute({
                "log_line": "203.0.113.100 - - [10/Jan/2024:10:00:00 +0000] \"GET /admin HTTP/1.1\" 404 1234",
                "threshold": 75
            })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "1" in content  # 1 IP found
        assert "1" in content  # 1 flagged
        assert "⚠️" in content or "FLAGGED" in content
        assert "203.0.113.100" in content

    @pytest.mark.asyncio
    async def test_execute_mixed_ips(self, enrich_log_tool, mock_cache, sample_malicious_ip_data, sample_clean_ip_data):
        """Test execution with both clean and malicious IPs."""
        def cache_side_effect(key):
            if "203.0.113.100" in key:
                return sample_malicious_ip_data
            elif "8.8.8.8" in key:
                return sample_clean_ip_data
            return None

        mock_cache.get.side_effect = cache_side_effect

        with patch('mcp_abuseipdb.tools.enrich_log_line.AbuseIPDBClient'):
            result = await enrich_log_tool.execute({
                "log_line": "Connection from 203.0.113.100 to DNS server 8.8.8.8",
                "threshold": 75
            })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "2" in content  # 2 IPs found
        assert "1" in content  # 1 flagged
        assert "⚠️" in content or "FLAGGED" in content
        assert "✅ Clean IPs:" in content
        assert "203.0.113.100" in content
        assert "8.8.8.8" in content

    @pytest.mark.asyncio
    async def test_execute_enrichment_failure(self, enrich_log_tool, mock_cache, mock_rate_limiter):
        """Test execution when enrichment fails for some IPs."""
        mock_cache.get.return_value = None
        mock_rate_limiter.acquire.return_value = False  # Simulate rate limiting

        with patch('mcp_abuseipdb.tools.enrich_log_line.AbuseIPDBClient'):
            result = await enrich_log_tool.execute({
                "log_line": "Failed connection from 203.0.113.100"
            })

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "1" in content  # 1 IP extracted
        assert "0" in content  # 0 successfully enriched
        assert "❌ Failed to Enrich:" in content
        assert "203.0.113.100" in content

    @pytest.mark.asyncio
    async def test_execute_complex_log_line(self, enrich_log_tool, mock_cache, sample_clean_ip_data):
        """Test execution with complex log line containing multiple IPs."""
        mock_cache.get.return_value = sample_clean_ip_data

        complex_log = (
            "[2024-01-10 10:15:30] firewall: ACCEPT TCP "
            "203.0.113.100:45678 -> 8.8.8.8:53 (DNS query) "
            "via gateway 198.51.100.1"
        )

        with patch('mcp_abuseipdb.tools.enrich_log_line.AbuseIPDBClient'):
            result = await enrich_log_tool.execute({"log_line": complex_log})

        assert isinstance(result, CallToolResult)
        assert result.isError is None or result.isError is False

        content = result.content[0].text
        assert "Extracted IPs:" in content
        # Should extract 203.0.113.100, 8.8.8.8, and 198.51.100.1