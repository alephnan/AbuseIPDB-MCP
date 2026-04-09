"""Integration and end-to-end tests."""

import pytest
import asyncio
import tempfile
import os
import json
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime

from mcp_abuseipdb.server import MCPAbuseIPDBServer
from mcp_abuseipdb.settings import Settings
from mcp_abuseipdb.client_abuseipdb import AbuseIPDBClient
from mcp_abuseipdb.models import IPCheckResponse


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
def integration_settings(temp_db):
    """Settings for integration testing."""
    with patch.dict(os.environ, {
        "ABUSEIPDB_API_KEY": "test_integration_key",
        "CACHE_DB_PATH": temp_db,
        "DAILY_QUOTA": "50",
        "REQUEST_TIMEOUT": "5",
        "LOG_LEVEL": "DEBUG"
    }):
        return Settings()


@pytest.fixture
def mock_api_responses():
    """Mock API responses for consistent testing."""
    return {
        "check_ip_clean": {
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidencePercentage": 0,
                "countryCode": "US",
                "countryName": "United States",
                "usageType": "hosting",
                "isp": "Google LLC",
                "domain": "google.com",
                "totalReports": 0,
                "numDistinctUsers": 0,
                "lastReportedAt": None
            }
        },
        "check_ip_malicious": {
            "data": {
                "ipAddress": "203.0.113.100",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidencePercentage": 95,
                "countryCode": "US",
                "countryName": "United States",
                "usageType": "hosting",
                "isp": "Malicious ISP",
                "domain": "bad-example.com",
                "totalReports": 25,
                "numDistinctUsers": 15,
                "lastReportedAt": "2024-01-10T09:00:00Z"
            }
        },
        "check_block": {
            "data": {
                "networkAddress": "203.0.113.0",
                "netmask": "24",
                "minAddress": "203.0.113.0",
                "maxAddress": "203.0.113.255",
                "numPossibleHosts": 256,
                "addressSpaceDesc": "Public Address Space",
                "reportedAddress": [
                    {
                        "ipAddress": "203.0.113.100",
                        "abuseConfidencePercentage": 95,
                        "totalReports": 25,
                        "countryCode": "US"
                    }
                ]
            }
        },
        "blacklist": {
            "generatedAt": "2024-01-10T10:00:00Z",
            "data": [
                {
                    "ipAddress": "203.0.113.100",
                    "countryCode": "US",
                    "abuseConfidencePercentage": 95,
                    "lastReportedAt": "2024-01-10T09:00:00Z"
                },
                {
                    "ipAddress": "198.51.100.50",
                    "countryCode": "DE",
                    "abuseConfidencePercentage": 92,
                    "lastReportedAt": "2024-01-10T08:30:00Z"
                }
            ]
        }
    }


class TestEndToEndWorkflows:
    """End-to-end workflow tests."""

    @pytest.mark.asyncio
    async def test_complete_ip_check_workflow(self, integration_settings, mock_api_responses):
        """Test complete workflow for IP checking."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            # Mock the HTTP client
            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                # Mock successful API response
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = mock_api_responses["check_ip_clean"]
                mock_client.request.return_value = mock_response

                # Test the complete workflow
                tool = server.tools["check_ip"]
                result = await tool.execute({
                    "ip_address": "8.8.8.8",
                    "max_age_days": 30,
                    "threshold": 75
                })

                # Verify the result
                assert result.isError is None or result.isError is False
                content = result.content[0].text

                assert "8.8.8.8" in content
                assert "0%" in content  # Abuse confidence
                assert "Google LLC" in content
                assert "LOW" in content  # Risk level

    @pytest.mark.asyncio
    async def test_malicious_ip_detection_workflow(self, integration_settings, mock_api_responses):
        """Test workflow for detecting malicious IP."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = mock_api_responses["check_ip_malicious"]
                mock_client.request.return_value = mock_response

                tool = server.tools["check_ip"]
                result = await tool.execute({
                    "ip_address": "203.0.113.100",
                    "threshold": 75
                })

                content = result.content[0].text

                assert "203.0.113.100" in content
                assert "95%" in content  # High confidence
                assert "⚠️" in content or "FLAGGED" in content
                assert "HIGH" in content  # Risk level

    @pytest.mark.asyncio
    async def test_log_enrichment_workflow(self, integration_settings, mock_api_responses):
        """Test complete log enrichment workflow."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                # Mock responses for different IPs
                def mock_request_side_effect(method, endpoint, params=None):
                    mock_response = MagicMock()
                    mock_response.status_code = 200

                    ip = params.get("ipAddress") if params else None
                    if ip == "8.8.8.8":
                        mock_response.json.return_value = mock_api_responses["check_ip_clean"]
                    elif ip == "203.0.113.100":
                        mock_response.json.return_value = mock_api_responses["check_ip_malicious"]
                    else:
                        mock_response.json.return_value = mock_api_responses["check_ip_clean"]

                    return mock_response

                mock_client.request.side_effect = mock_request_side_effect

                tool = server.tools["enrich_log_line"]
                result = await tool.execute({
                    "log_line": "Connection from 203.0.113.100 to DNS server 8.8.8.8",
                    "threshold": 75
                })

                content = result.content[0].text

                assert "2" in content  # 2 IPs found
                assert "1" in content  # 1 flagged
                assert "203.0.113.100" in content
                assert "8.8.8.8" in content
                assert "⚠️" in content or "FLAGGED" in content

    @pytest.mark.asyncio
    async def test_bulk_check_workflow(self, integration_settings, mock_api_responses):
        """Test bulk checking workflow."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                def mock_request_side_effect(method, endpoint, params=None):
                    mock_response = MagicMock()
                    mock_response.status_code = 200

                    ip = params.get("ipAddress") if params else None
                    if ip == "203.0.113.100":
                        mock_response.json.return_value = mock_api_responses["check_ip_malicious"]
                    else:
                        mock_response.json.return_value = mock_api_responses["check_ip_clean"]

                    return mock_response

                mock_client.request.side_effect = mock_request_side_effect

                tool = server.tools["bulk_check"]
                result = await tool.execute({
                    "ip_addresses": ["8.8.8.8", "1.1.1.1", "203.0.113.100"],
                    "threshold": 75
                })

                content = result.content[0].text

                assert "3" in content  # 3 IPs processed
                assert "1" in content  # 1 flagged
                assert "203.0.113.100" in content


class TestCachingIntegration:
    """Test caching behavior in integration scenarios."""

    @pytest.mark.asyncio
    async def test_cache_hit_miss_workflow(self, integration_settings, mock_api_responses):
        """Test cache hit and miss behavior."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = mock_api_responses["check_ip_clean"]
                mock_client.request.return_value = mock_response

                tool = server.tools["check_ip"]

                # First call - should miss cache and call API
                result1 = await tool.execute({"ip_address": "8.8.8.8"})
                assert mock_client.request.call_count == 1

                # Second call - should hit cache and not call API
                result2 = await tool.execute({"ip_address": "8.8.8.8"})
                assert mock_client.request.call_count == 1  # No additional calls

                # Both results should be the same
                assert result1.content[0].text == result2.content[0].text

    @pytest.mark.asyncio
    async def test_cache_different_parameters(self, integration_settings, mock_api_responses):
        """Test cache behavior with different parameters."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = mock_api_responses["check_ip_clean"]
                mock_client.request.return_value = mock_response

                tool = server.tools["check_ip"]

                # Same IP, different parameters - should call API twice
                await tool.execute({"ip_address": "8.8.8.8", "max_age_days": 30})
                await tool.execute({"ip_address": "8.8.8.8", "max_age_days": 60})

                assert mock_client.request.call_count == 2


class TestRateLimitingIntegration:
    """Test rate limiting behavior in integration scenarios."""

    @pytest.mark.asyncio
    async def test_rate_limit_enforcement(self, integration_settings, mock_api_responses):
        """Test rate limit enforcement across multiple requests."""
        # Set very low quota for testing
        integration_settings.daily_quota = 2

        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = mock_api_responses["check_ip_clean"]
                mock_client.request.return_value = mock_response

                tool = server.tools["check_ip"]

                # First two requests should succeed
                result1 = await tool.execute({"ip_address": "8.8.8.8"})
                result2 = await tool.execute({"ip_address": "1.1.1.1"})

                assert result1.isError is None or result1.isError is False
                assert result2.isError is None or result2.isError is False

                # Third request should be rate limited
                result3 = await tool.execute({"ip_address": "9.9.9.9"})
                assert result3.isError is True
                assert "Rate limit exceeded" in result3.content[0].text


class TestErrorHandlingIntegration:
    """Test error handling in integration scenarios."""

    @pytest.mark.asyncio
    async def test_api_error_handling(self, integration_settings):
        """Test handling of API errors."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                # Mock 401 Unauthorized response
                mock_response = MagicMock()
                mock_response.status_code = 401
                mock_client.request.return_value = mock_response

                tool = server.tools["check_ip"]
                result = await tool.execute({"ip_address": "8.8.8.8"})

                assert result.isError is True
                assert "API Error" in result.content[0].text

    @pytest.mark.asyncio
    async def test_network_timeout_handling(self, integration_settings):
        """Test handling of network timeouts."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                # Mock timeout exception
                import httpx
                mock_client.request.side_effect = httpx.TimeoutException("Timeout")

                tool = server.tools["check_ip"]
                result = await tool.execute({"ip_address": "8.8.8.8"})

                assert result.isError is True
                assert "Error" in result.content[0].text or "Timeout" in result.content[0].text


class TestResourcesIntegration:
    """Test resources in integration scenarios."""

    @pytest.mark.asyncio
    async def test_cache_info_resource_integration(self, integration_settings):
        """Test cache info resource with actual cache data."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            # Add some data to cache
            await server.cache.set("test_key1", {"ip": "8.8.8.8"})
            await server.cache.set("test_key2", {"ip": "1.1.1.1"})

            # Get cache info
            cache_info = await server.cache.get_cache_info()
            rate_info = await server.rate_limiter.get_status()

            # Simulate resource read
            info = {
                "cache": cache_info,
                "rate_limiter": rate_info,
                "settings": {
                    "max_age_days": server.settings.max_age_days,
                    "confidence_threshold": server.settings.confidence_threshold,
                    "daily_quota": server.settings.daily_quota,
                }
            }

            # Verify structure
            assert "cache" in info
            assert "rate_limiter" in info
            assert "settings" in info
            assert info["cache"]["total_entries"] >= 2


class TestConcurrentRequests:
    """Test concurrent request handling."""

    @pytest.mark.asyncio
    async def test_concurrent_tool_execution(self, integration_settings, mock_api_responses):
        """Test handling of concurrent tool executions."""
        with patch('mcp_abuseipdb.server.Settings', return_value=integration_settings):
            server = MCPAbuseIPDBServer()

            with patch('httpx.AsyncClient') as mock_client_class:
                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client

                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = mock_api_responses["check_ip_clean"]
                mock_client.request.return_value = mock_response

                tool = server.tools["check_ip"]

                # Execute multiple requests concurrently
                tasks = [
                    tool.execute({"ip_address": f"8.8.8.{i}"})
                    for i in range(1, 6)
                ]

                results = await asyncio.gather(*tasks, return_exceptions=True)

                # All should complete successfully
                for result in results:
                    assert not isinstance(result, Exception)
                    assert result.isError is None or result.isError is False