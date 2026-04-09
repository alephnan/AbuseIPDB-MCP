"""Tests for Pydantic models."""

import pytest
from datetime import datetime
from pydantic import ValidationError

from mcp_abuseipdb.models import (
    IPCheckResponse,
    BlockReportedAddress,
    BlockCheckResponse,
    BlacklistResponse,
    BlacklistEntry,
    BulkCheckResult,
    BulkCheckResponse,
    EnrichmentResult,
    CacheEntry,
    APIError
)


class TestIPCheckResponse:
    """Test cases for IPCheckResponse model."""

    def test_ip_check_response_valid(self):
        """Test valid IP check response parsing."""
        data = {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidencePercentage": 25,
            "countryCode": "US",
            "countryName": "United States",
            "usageType": "hosting",
            "isp": "Google LLC",
            "domain": "google.com",
            "totalReports": 5,
            "numDistinctUsers": 3,
            "lastReportedAt": "2024-01-10T10:00:00Z"
        }

        response = IPCheckResponse.model_validate(data)

        assert response.ip_address == "8.8.8.8"
        assert response.is_public is True
        assert response.ip_version == 4
        assert response.abuse_confidence_percentage == 25
        assert response.country_code == "US"
        assert response.total_reports == 5
        assert isinstance(response.last_reported_at, datetime)

    def test_ip_check_response_minimal(self):
        """Test IP check response with minimal required fields."""
        data = {
            "ipAddress": "203.0.113.100",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidencePercentage": 85,
            "usageType": "hosting",
            "totalReports": 15,
            "numDistinctUsers": 8
        }

        response = IPCheckResponse.model_validate(data)

        assert response.ip_address == "203.0.113.100"
        assert response.country_code is None
        assert response.last_reported_at is None
        assert response.reports is None

    def test_ip_check_response_with_reports(self):
        """Test IP check response with reports data."""
        data = {
            "ipAddress": "203.0.113.100",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidencePercentage": 95,
            "usageType": "hosting",
            "totalReports": 20,
            "numDistinctUsers": 12,
            "reports": [
                {
                    "reportedAt": "2024-01-10T09:00:00Z",
                    "comment": "Malicious activity detected",
                    "categories": [18, 20]
                }
            ]
        }

        response = IPCheckResponse.model_validate(data)

        assert response.reports is not None
        assert len(response.reports) == 1

    def test_ip_check_response_alias_handling(self):
        """Test that field aliases work correctly."""
        # Using camelCase field names (as from API)
        data = {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidencePercentage": 0,
            "countryCode": "US",
            "countryName": "United States",
            "usageType": "hosting",
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None
        }

        response = IPCheckResponse.model_validate(data)

        # Check that snake_case properties work
        assert response.ip_address == "8.8.8.8"
        assert response.is_public is True
        assert response.abuse_confidence_percentage == 0


class TestBlockCheckResponse:
    """Test cases for BlockCheckResponse model."""

    def test_block_reported_address_alias_handling(self):
        """Test reported-address parsing with the newer score field."""
        data = {
            "ipAddress": "203.0.113.100",
            "abuseConfidenceScore": 85,
            "totalReports": 15,
            "countryCode": "US",
        }

        response = BlockReportedAddress.model_validate(data)

        assert response.ip_address == "203.0.113.100"
        assert response.abuse_confidence_percentage == 85
        assert response.total_reports == 15

    def test_block_check_response_valid(self):
        """Test valid block check response parsing."""
        data = {
            "networkAddress": "203.0.113.0",
            "netmask": "24",
            "minAddress": "203.0.113.0",
            "maxAddress": "203.0.113.255",
            "numPossibleHosts": 256,
            "addressSpaceDesc": "Public Address Space",
            "reportedAddress": [
                {
                    "ipAddress": "203.0.113.100",
                    "abuseConfidencePercentage": 85,
                    "totalReports": 15,
                    "countryCode": "US"
                }
            ]
        }

        response = BlockCheckResponse.model_validate(data)

        assert response.network_address == "203.0.113.0"
        assert response.netmask == "24"
        assert response.num_possible_hosts == 256
        assert len(response.reported_address) == 1

    def test_block_check_response_empty_reports(self):
        """Test block check response with no reported addresses."""
        data = {
            "networkAddress": "192.0.2.0",
            "netmask": "24",
            "minAddress": "192.0.2.0",
            "maxAddress": "192.0.2.255",
            "numPossibleHosts": 256,
            "addressSpaceDesc": "Test Network",
            "reportedAddress": []
        }

        response = BlockCheckResponse.model_validate(data)

        assert len(response.reported_address) == 0


class TestBlacklistModels:
    """Test cases for blacklist-related models."""

    def test_blacklist_entry_valid(self):
        """Test valid blacklist entry parsing."""
        data = {
            "ipAddress": "203.0.113.100",
            "countryCode": "US",
            "abuseConfidencePercentage": 95,
            "lastReportedAt": "2024-01-10T09:00:00Z"
        }

        entry = BlacklistEntry.model_validate(data)

        assert entry.ip_address == "203.0.113.100"
        assert entry.country_code == "US"
        assert entry.abuse_confidence_percentage == 95
        assert isinstance(entry.last_reported_at, datetime)

    def test_blacklist_entry_minimal(self):
        """Test blacklist entry with minimal data."""
        data = {
            "ipAddress": "203.0.113.100",
            "abuseConfidencePercentage": 95
        }

        entry = BlacklistEntry.model_validate(data)

        assert entry.ip_address == "203.0.113.100"
        assert entry.country_code is None
        assert entry.last_reported_at is None

    def test_blacklist_response_valid(self):
        """Test valid blacklist response parsing."""
        data = {
            "generatedAt": "2024-01-10T10:00:00Z",
            "data": [
                {
                    "ipAddress": "203.0.113.100",
                    "countryCode": "US",
                    "abuseConfidencePercentage": 95,
                    "lastReportedAt": "2024-01-10T09:00:00Z"
                }
            ]
        }

        response = BlacklistResponse.model_validate(data)

        assert isinstance(response.generated_at, datetime)
        assert len(response.data) == 1
        assert isinstance(response.data[0], BlacklistEntry)


class TestBulkCheckModels:
    """Test cases for bulk check models."""

    def test_bulk_check_result_success(self):
        """Test successful bulk check result."""
        ip_data = {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidencePercentage": 0,
            "usageType": "hosting",
            "totalReports": 0,
            "numDistinctUsers": 0
        }

        ip_response = IPCheckResponse.model_validate(ip_data)

        result = BulkCheckResult(
            ip_address="8.8.8.8",
            success=True,
            data=ip_response
        )

        assert result.ip_address == "8.8.8.8"
        assert result.success is True
        assert result.data is not None
        assert result.error is None

    def test_bulk_check_result_failure(self):
        """Test failed bulk check result."""
        result = BulkCheckResult(
            ip_address="203.0.113.100",
            success=False,
            error="Rate limit exceeded"
        )

        assert result.ip_address == "203.0.113.100"
        assert result.success is False
        assert result.data is None
        assert result.error == "Rate limit exceeded"

    def test_bulk_check_response_valid(self):
        """Test valid bulk check response."""
        results = [
            BulkCheckResult(ip_address="8.8.8.8", success=True, data=None),
            BulkCheckResult(ip_address="1.1.1.1", success=True, data=None),
            BulkCheckResult(ip_address="203.0.113.100", success=False, error="Failed")
        ]

        response = BulkCheckResponse(
            results=results,
            total_requested=3,
            successful=2,
            failed=1
        )

        assert len(response.results) == 3
        assert response.total_requested == 3
        assert response.successful == 2
        assert response.failed == 1


class TestEnrichmentResult:
    """Test cases for EnrichmentResult model."""

    def test_enrichment_result_valid(self):
        """Test valid enrichment result."""
        ip_data = {
            "ipAddress": "203.0.113.100",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidencePercentage": 85,
            "usageType": "hosting",
            "totalReports": 15,
            "numDistinctUsers": 8
        }

        ip_response = IPCheckResponse.model_validate(ip_data)

        result = EnrichmentResult(
            original_line="Log line with 203.0.113.100 and 8.8.8.8",
            extracted_ips=["203.0.113.100", "8.8.8.8"],
            enriched_data={"203.0.113.100": ip_response},
            flagged_ips=["203.0.113.100"]
        )

        assert result.original_line == "Log line with 203.0.113.100 and 8.8.8.8"
        assert len(result.extracted_ips) == 2
        assert len(result.enriched_data) == 1
        assert len(result.flagged_ips) == 1


class TestCacheEntry:
    """Test cases for CacheEntry model."""

    def test_cache_entry_valid(self):
        """Test valid cache entry."""
        now = datetime.utcnow()
        later = datetime.utcnow()

        entry = CacheEntry(
            key="test_key",
            value={"ip": "8.8.8.8", "confidence": 0},
            created_at=now,
            expires_at=later
        )

        assert entry.key == "test_key"
        assert entry.value["ip"] == "8.8.8.8"
        assert isinstance(entry.created_at, datetime)

    def test_cache_entry_is_expired(self):
        """Test cache entry expiration check."""
        now = datetime.utcnow()
        past = datetime(2023, 1, 1)
        future = datetime(2025, 1, 1)

        expired_entry = CacheEntry(
            key="expired_key",
            value={"data": "test"},
            created_at=past,
            expires_at=past
        )

        valid_entry = CacheEntry(
            key="valid_key",
            value={"data": "test"},
            created_at=now,
            expires_at=future
        )

        assert expired_entry.is_expired is True
        assert valid_entry.is_expired is False


class TestAPIError:
    """Test cases for APIError model."""

    def test_api_error_minimal(self):
        """Test API error with minimal data."""
        error = APIError(
            error="Test error",
            status_code=400
        )

        assert error.error == "Test error"
        assert error.details is None
        assert error.status_code == 400
        assert error.retryable is False

    def test_api_error_complete(self):
        """Test API error with all fields."""
        error = APIError(
            error="Rate limit exceeded",
            details="Too many requests",
            status_code=429,
            retryable=True
        )

        assert error.error == "Rate limit exceeded"
        assert error.details == "Too many requests"
        assert error.status_code == 429
        assert error.retryable is True


class TestModelValidation:
    """Test cases for model validation."""

    def test_ip_check_response_missing_required_field(self):
        """Test validation error for missing required field."""
        incomplete_data = {
            "isPublic": True,
            "ipVersion": 4
            # Missing required fields like ipAddress
        }

        with pytest.raises(ValidationError) as exc_info:
            IPCheckResponse.model_validate(incomplete_data)

        errors = exc_info.value.errors()
        assert any("ipAddress" in str(error) or "ip_address" in str(error) for error in errors)

    def test_blacklist_entry_invalid_confidence(self):
        """Test validation error for invalid confidence percentage."""
        invalid_data = {
            "ipAddress": "203.0.113.100",
            "abuseConfidencePercentage": 150  # Invalid: > 100
        }

        # Note: The current model doesn't have validation constraints on confidence percentage
        # This test demonstrates where you might want to add such validation
        entry = BlacklistEntry.model_validate(invalid_data)
        assert entry.abuse_confidence_percentage == 150  # Currently allows invalid values

    def test_datetime_parsing(self):
        """Test datetime field parsing from various formats."""
        iso_format = "2024-01-10T10:00:00Z"
        iso_with_microseconds = "2024-01-10T10:00:00.123456Z"

        # Test ISO format
        entry1 = BlacklistEntry.model_validate({
            "ipAddress": "203.0.113.100",
            "abuseConfidencePercentage": 95,
            "lastReportedAt": iso_format
        })

        # Test ISO format with microseconds
        entry2 = BlacklistEntry.model_validate({
            "ipAddress": "203.0.113.100",
            "abuseConfidencePercentage": 95,
            "lastReportedAt": iso_with_microseconds
        })

        assert isinstance(entry1.last_reported_at, datetime)
        assert isinstance(entry2.last_reported_at, datetime)
