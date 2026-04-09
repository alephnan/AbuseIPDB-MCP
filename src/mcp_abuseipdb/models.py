"""Pydantic models for AbuseIPDB API responses and internal data structures."""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, AliasPath, AliasChoices


class AbuseCategory(BaseModel):
    """AbuseIPDB abuse category."""
    id: int
    name: str


class IPCheckResponse(BaseModel):
    """Response model for IP check endpoint."""
    ip_address: str = Field(alias="ipAddress")
    is_public: bool = Field(alias="isPublic")
    ip_version: int = Field(alias="ipVersion")
    is_whitelisted: bool = Field(alias="isWhitelisted")
    abuse_confidence_percentage: int = Field(
        alias="abuseConfidenceScore",
        validation_alias=AliasChoices("abuseConfidenceScore", "abuseConfidencePercentage"),
    )
    country_code: Optional[str] = Field(alias="countryCode", default=None)
    country_name: Optional[str] = Field(alias="countryName", default=None)
    usage_type: str = Field(alias="usageType")
    isp: Optional[str] = Field(default=None)
    domain: Optional[str] = Field(default=None)
    total_reports: int = Field(alias="totalReports")
    num_distinct_users: int = Field(alias="numDistinctUsers")
    last_reported_at: Optional[datetime] = Field(alias="lastReportedAt", default=None)
    reports: Optional[List[Dict[str, Any]]] = Field(default=None)

    model_config = {"populate_by_name": True}


class BlockReportedAddress(BaseModel):
    """Reported address entry returned by the block check endpoint."""
    ip_address: str = Field(alias="ipAddress")
    abuse_confidence_percentage: int = Field(
        alias="abuseConfidenceScore",
        validation_alias=AliasChoices("abuseConfidenceScore", "abuseConfidencePercentage"),
    )
    total_reports: int = Field(alias="totalReports")
    country_code: Optional[str] = Field(alias="countryCode", default=None)
    last_reported_at: Optional[datetime] = Field(alias="lastReportedAt", default=None)

    model_config = {"populate_by_name": True}


class BlockCheckResponse(BaseModel):
    """Response model for CIDR block check endpoint."""
    network_address: str = Field(alias="networkAddress")
    netmask: str
    min_address: str = Field(alias="minAddress")
    max_address: str = Field(alias="maxAddress")
    num_possible_hosts: int = Field(alias="numPossibleHosts")
    address_space_desc: str = Field(alias="addressSpaceDesc")
    reported_address: List[BlockReportedAddress] = Field(alias="reportedAddress", default_factory=list)

    model_config = {"populate_by_name": True}


class BlacklistEntry(BaseModel):
    """Single entry from blacklist endpoint."""
    ip_address: str = Field(alias="ipAddress")
    country_code: Optional[str] = Field(alias="countryCode", default=None)
    abuse_confidence_percentage: int = Field(
        alias="abuseConfidenceScore",
        validation_alias=AliasChoices("abuseConfidenceScore", "abuseConfidencePercentage"),
    )
    last_reported_at: Optional[datetime] = Field(alias="lastReportedAt", default=None)

    model_config = {"populate_by_name": True}


class BlacklistResponse(BaseModel):
    """Response model for blacklist endpoint."""
    generated_at: datetime = Field(
        validation_alias=AliasChoices(
            AliasPath("meta", "generatedAt"),
            "generatedAt",
            "generated_at",
        )
    )
    data: List[BlacklistEntry]

    model_config = {"populate_by_name": True}


class BulkCheckResult(BaseModel):
    """Result for a single IP in bulk check operation."""
    ip_address: str
    success: bool
    data: Optional[IPCheckResponse] = None
    error: Optional[str] = None


class BulkCheckResponse(BaseModel):
    """Response model for bulk check operation."""
    results: List[BulkCheckResult]
    total_requested: int
    successful: int
    failed: int


class EnrichmentResult(BaseModel):
    """Result of log line enrichment."""
    original_line: str
    extracted_ips: List[str]
    enriched_data: Dict[str, IPCheckResponse]
    flagged_ips: List[str]  # IPs above threshold


class CacheEntry(BaseModel):
    """Cache entry model."""
    key: str
    value: Dict[str, Any]
    created_at: datetime
    expires_at: datetime

    @property
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        now = datetime.now(timezone.utc)

        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        created_at = self.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        if expires_at < created_at:
            return False

        return now >= expires_at


class ValidationError(BaseModel):
    """Validation error details."""
    field: str
    message: str
    value: Optional[str] = None


class APIError(Exception):
    """Exception raised for AbuseIPDB API errors."""

    def __init__(
        self,
        error: str,
        *,
        status_code: int,
        details: Optional[str] = None,
        retryable: bool = False,
    ) -> None:
        self.error = error
        self.status_code = status_code
        self.details = details
        self.retryable = retryable
        message = error
        if details:
            message = f"{message}: {details}"
        if status_code:
            message = f"{message} (status_code={status_code})"
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Return a serialisable representation of the error."""
        return {
            "error": self.error,
            "details": self.details,
            "status_code": self.status_code,
            "retryable": self.retryable,
        }
