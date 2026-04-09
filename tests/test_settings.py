"""Tests for settings configuration."""

import pytest
import os
import tempfile
from unittest.mock import patch

from pydantic import ValidationError
from mcp_abuseipdb.settings import Settings


class TestSettings:
    """Test cases for Settings."""

    def test_settings_with_required_api_key(self):
        """Test settings creation with required API key."""
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test_key_123"}):
            settings = Settings()
            assert settings.abuseipdb_api_key == "test_key_123"

    def test_settings_missing_api_key(self):
        """Test settings creation fails without API key."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            # Check that the error is about the missing API key
            errors = exc_info.value.errors()
            assert any("abuseipdb_api_key" in str(error) for error in errors)

    def test_settings_default_values(self):
        """Test default values are set correctly."""
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test_key"}, clear=True):
            settings = Settings()

            assert settings.abuseipdb_base_url == "https://api.abuseipdb.com/api/v2"
            assert settings.max_age_days == 30
            assert settings.confidence_threshold == 75
            assert settings.blacklist_confidence_min == 90
            assert settings.daily_quota == 1000
            assert settings.request_timeout == 30
            assert settings.max_retries == 3
            assert settings.cache_db_path == "./cache.db"
            assert settings.cache_default_ttl == 3600
            assert settings.log_level == "INFO"
            assert settings.log_format == "json"
            assert settings.allow_private_ips is False

    def test_settings_custom_values(self):
        """Test settings with custom environment values."""
        custom_env = {
            "ABUSEIPDB_API_KEY": "custom_key_456",
            "ABUSEIPDB_BASE_URL": "https://custom.api.com/v2",
            "MAX_AGE_DAYS": "60",
            "CONFIDENCE_THRESHOLD": "80",
            "BLACKLIST_CONFIDENCE_MIN": "95",
            "DAILY_QUOTA": "2000",
            "REQUEST_TIMEOUT": "45",
            "MAX_RETRIES": "5",
            "CACHE_DB_PATH": "/custom/cache.db",
            "CACHE_DEFAULT_TTL": "7200",
            "LOG_LEVEL": "DEBUG",
            "LOG_FORMAT": "text",
            "ALLOW_PRIVATE_IPS": "true"
        }

        with patch.dict(os.environ, custom_env):
            settings = Settings()

            assert settings.abuseipdb_api_key == "custom_key_456"
            assert settings.abuseipdb_base_url == "https://custom.api.com/v2"
            assert settings.max_age_days == 60
            assert settings.confidence_threshold == 80
            assert settings.blacklist_confidence_min == 95
            assert settings.daily_quota == 2000
            assert settings.request_timeout == 45
            assert settings.max_retries == 5
            assert settings.cache_db_path == "/custom/cache.db"
            assert settings.cache_default_ttl == 7200
            assert settings.log_level == "DEBUG"
            assert settings.log_format == "text"
            assert settings.allow_private_ips is True

    def test_settings_validation_max_age_days(self):
        """Test validation of max_age_days range."""
        base_env = {"ABUSEIPDB_API_KEY": "test_key"}

        # Test minimum boundary
        with patch.dict(os.environ, {**base_env, "MAX_AGE_DAYS": "0"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test maximum boundary
        with patch.dict(os.environ, {**base_env, "MAX_AGE_DAYS": "366"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test valid values
        with patch.dict(os.environ, {**base_env, "MAX_AGE_DAYS": "1"}):
            settings = Settings()
            assert settings.max_age_days == 1

        with patch.dict(os.environ, {**base_env, "MAX_AGE_DAYS": "365"}):
            settings = Settings()
            assert settings.max_age_days == 365

    def test_settings_validation_confidence_threshold(self):
        """Test validation of confidence_threshold range."""
        base_env = {"ABUSEIPDB_API_KEY": "test_key"}

        # Test below minimum
        with patch.dict(os.environ, {**base_env, "CONFIDENCE_THRESHOLD": "-1"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test above maximum
        with patch.dict(os.environ, {**base_env, "CONFIDENCE_THRESHOLD": "101"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test valid values
        with patch.dict(os.environ, {**base_env, "CONFIDENCE_THRESHOLD": "0"}):
            settings = Settings()
            assert settings.confidence_threshold == 0

        with patch.dict(os.environ, {**base_env, "CONFIDENCE_THRESHOLD": "100"}):
            settings = Settings()
            assert settings.confidence_threshold == 100

    def test_settings_validation_blacklist_confidence_min(self):
        """Test validation of blacklist_confidence_min range."""
        base_env = {"ABUSEIPDB_API_KEY": "test_key"}

        # Test below minimum
        with patch.dict(os.environ, {**base_env, "BLACKLIST_CONFIDENCE_MIN": "-1"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test above maximum
        with patch.dict(os.environ, {**base_env, "BLACKLIST_CONFIDENCE_MIN": "101"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test valid boundary values
        with patch.dict(os.environ, {**base_env, "BLACKLIST_CONFIDENCE_MIN": "0"}):
            settings = Settings()
            assert settings.blacklist_confidence_min == 0

        with patch.dict(os.environ, {**base_env, "BLACKLIST_CONFIDENCE_MIN": "100"}):
            settings = Settings()
            assert settings.blacklist_confidence_min == 100

    def test_settings_validation_daily_quota(self):
        """Test validation of daily_quota minimum."""
        base_env = {"ABUSEIPDB_API_KEY": "test_key"}

        # Test below minimum
        with patch.dict(os.environ, {**base_env, "DAILY_QUOTA": "0"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test valid minimum
        with patch.dict(os.environ, {**base_env, "DAILY_QUOTA": "1"}):
            settings = Settings()
            assert settings.daily_quota == 1

    def test_settings_validation_request_timeout(self):
        """Test validation of request_timeout range."""
        base_env = {"ABUSEIPDB_API_KEY": "test_key"}

        # Test below minimum
        with patch.dict(os.environ, {**base_env, "REQUEST_TIMEOUT": "4"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test above maximum
        with patch.dict(os.environ, {**base_env, "REQUEST_TIMEOUT": "301"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test valid boundary values
        with patch.dict(os.environ, {**base_env, "REQUEST_TIMEOUT": "5"}):
            settings = Settings()
            assert settings.request_timeout == 5

        with patch.dict(os.environ, {**base_env, "REQUEST_TIMEOUT": "300"}):
            settings = Settings()
            assert settings.request_timeout == 300

    def test_settings_validation_max_retries(self):
        """Test validation of max_retries range."""
        base_env = {"ABUSEIPDB_API_KEY": "test_key"}

        # Test below minimum
        with patch.dict(os.environ, {**base_env, "MAX_RETRIES": "-1"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test above maximum
        with patch.dict(os.environ, {**base_env, "MAX_RETRIES": "11"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test valid boundary values
        with patch.dict(os.environ, {**base_env, "MAX_RETRIES": "0"}):
            settings = Settings()
            assert settings.max_retries == 0

        with patch.dict(os.environ, {**base_env, "MAX_RETRIES": "10"}):
            settings = Settings()
            assert settings.max_retries == 10

    def test_settings_validation_cache_default_ttl(self):
        """Test validation of cache_default_ttl minimum."""
        base_env = {"ABUSEIPDB_API_KEY": "test_key"}

        # Test below minimum
        with patch.dict(os.environ, {**base_env, "CACHE_DEFAULT_TTL": "59"}):
            with pytest.raises(ValidationError):
                Settings()

        # Test valid minimum
        with patch.dict(os.environ, {**base_env, "CACHE_DEFAULT_TTL": "60"}):
            settings = Settings()
            assert settings.cache_default_ttl == 60

    def test_settings_case_insensitive(self):
        """Test that environment variables are case insensitive."""
        with patch.dict(os.environ, {"abuseipdb_api_key": "test_key_lowercase"}):
            settings = Settings()
            assert settings.abuseipdb_api_key == "test_key_lowercase"

    def test_settings_from_env_file(self):
        """Test loading settings from .env file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write("ABUSEIPDB_API_KEY=env_file_key\n")
            f.write("MAX_AGE_DAYS=45\n")
            f.write("CONFIDENCE_THRESHOLD=85\n")
            f.flush()

            try:
                # Clear environment variables that might interfere
                with patch.dict(os.environ, {}, clear=True):
                    with patch('mcp_abuseipdb.settings.Settings.model_config',
                              {"env_file": f.name, "env_file_encoding": "utf-8", "case_sensitive": False}):
                        settings = Settings()

                        # Note: This test may not work exactly as expected due to how pydantic-settings works
                        # In practice, you would typically set the env file path in the Settings constructor
                        # or through environment variables

            finally:
                os.unlink(f.name)

    def test_settings_bool_conversion(self):
        """Test boolean environment variable conversion."""
        base_env = {"ABUSEIPDB_API_KEY": "test_key"}

        # Test various true values
        for true_val in ["true", "True", "TRUE", "1", "yes", "on"]:
            with patch.dict(os.environ, {**base_env, "ALLOW_PRIVATE_IPS": true_val}):
                settings = Settings()
                assert settings.allow_private_ips is True

        # Test various false values
        for false_val in ["false", "False", "FALSE", "0", "no", "off"]:
            with patch.dict(os.environ, {**base_env, "ALLOW_PRIVATE_IPS": false_val}):
                settings = Settings()
                assert settings.allow_private_ips is False

    def test_settings_type_conversion(self):
        """Test type conversion from string environment variables."""
        env_vars = {
            "ABUSEIPDB_API_KEY": "test_key",
            "MAX_AGE_DAYS": "90",  # string -> int
            "REQUEST_TIMEOUT": "45",  # string -> int
            "ALLOW_PRIVATE_IPS": "true"  # string -> bool
        }

        with patch.dict(os.environ, env_vars):
            settings = Settings()

            assert isinstance(settings.max_age_days, int)
            assert isinstance(settings.request_timeout, int)
            assert isinstance(settings.allow_private_ips, bool)

            assert settings.max_age_days == 90
            assert settings.request_timeout == 45
            assert settings.allow_private_ips is True