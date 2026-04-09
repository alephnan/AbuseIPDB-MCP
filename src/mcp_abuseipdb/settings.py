"""Configuration settings for MCP AbuseIPDB server."""

import os
import sys

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # AbuseIPDB API Configuration
    abuseipdb_api_key: str
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"

    # Request Configuration
    max_age_days: int = Field(default=30, ge=1, le=365)
    confidence_threshold: int = Field(default=75, ge=0, le=100)
    blacklist_confidence_min: int = Field(default=90, ge=0, le=100)

    # Rate Limiting
    daily_quota: int = Field(default=1000, ge=1)
    request_timeout: int = Field(default=30, ge=5, le=300)
    max_retries: int = Field(default=3, ge=0, le=10)

    # Cache Configuration
    cache_db_path: str = "./cache.db"
    cache_default_ttl: int = Field(default=3600, ge=60)  # 1 hour

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # Security
    allow_private_ips: bool = False

    model_config = SettingsConfigDict(
        env_file=None,
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    def __init__(self, _env_file: str | None = None, **data: object) -> None:
        if _env_file is None:
            config_env_file = getattr(self.model_config, 'get', lambda *args, **kwargs: None)('env_file')
            if config_env_file is not None:
                _env_file = config_env_file
            else:
                running_tests = 'pytest' in sys.modules or os.environ.get('PYTEST_CURRENT_TEST') is not None
                # Always try to load .env for MCP server, but fall back gracefully
                if not running_tests:
                    # Try to find .env file in current directory or parent directories
                    import pathlib
                    current_dir = pathlib.Path.cwd()
                    for path in [current_dir] + list(current_dir.parents):
                        env_file = path / '.env'
                        if env_file.exists():
                            _env_file = str(env_file)
                            break
                    else:
                        # If no .env found, still set it to '.env' for pydantic-settings to handle
                        _env_file = '.env'

        # For MCP server debugging, log environment loading
        if _env_file and os.path.exists(_env_file):
            print(f"[MCP AbuseIPDB] Loading environment from: {_env_file}", file=sys.stderr)
        elif _env_file:
            print(f"[MCP AbuseIPDB] Environment file not found: {_env_file}", file=sys.stderr)

        super().__init__(_env_file=_env_file, **data)

        # Validate API key is loaded
        if not self.abuseipdb_api_key or self.abuseipdb_api_key.strip() == "":
            api_key_env = os.environ.get('ABUSEIPDB_API_KEY', '')
            print(f"[MCP AbuseIPDB] API key validation failed:", file=sys.stderr)
            print(f"  - Settings API key: {'SET' if self.abuseipdb_api_key else 'EMPTY'}", file=sys.stderr)
            print(f"  - Environment var:  {'SET' if api_key_env else 'EMPTY'}", file=sys.stderr)
            print(f"  - Environment file: {_env_file}", file=sys.stderr)
            raise ValueError("ABUSEIPDB_API_KEY is required but not found in environment variables or .env file")
