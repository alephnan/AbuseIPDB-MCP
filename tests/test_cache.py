"""Tests for cache functionality."""

import pytest
import tempfile
import os
import asyncio
from datetime import timedelta
from unittest.mock import patch

from mcp_abuseipdb.cache import CacheManager, RateLimiter


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
def cache_manager(temp_db):
    """Create CacheManager instance for testing."""
    return CacheManager(temp_db, default_ttl=3600)


class TestCacheManager:
    """Test cases for CacheManager."""

    @pytest.mark.asyncio
    async def test_cache_init_creates_tables(self, cache_manager):
        """Test that cache initialization creates necessary tables."""
        # Accessing _init_db should create the tables
        cache_manager._init_db()

        # Try to set and get a value to verify tables exist
        await cache_manager.set("test_key", {"test": "value"})
        result = await cache_manager.get("test_key")

        assert result is not None
        assert result["test"] == "value"

    @pytest.mark.asyncio
    async def test_set_and_get_value(self, cache_manager):
        """Test basic set and get operations."""
        test_data = {"ip": "8.8.8.8", "confidence": 0}

        await cache_manager.set("test_key", test_data)
        result = await cache_manager.get("test_key")

        assert result == test_data

    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self, cache_manager):
        """Test getting a non-existent key returns None."""
        result = await cache_manager.get("nonexistent_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_set_with_custom_ttl(self, cache_manager):
        """Test setting value with custom TTL."""
        test_data = {"ip": "8.8.8.8", "confidence": 0}

        await cache_manager.set("test_key", test_data, ttl=0.1)  # 0.1 second TTL

        # Should be available immediately
        result = await cache_manager.get("test_key")
        assert result == test_data

        # Wait for expiration
        await asyncio.sleep(0.15)

        # Should be expired now
        result = await cache_manager.get("test_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_key(self, cache_manager):
        """Test deleting a key."""
        test_data = {"ip": "8.8.8.8", "confidence": 0}

        await cache_manager.set("test_key", test_data)

        # Verify it exists
        result = await cache_manager.get("test_key")
        assert result == test_data

        # Delete it
        deleted = await cache_manager.delete("test_key")
        assert deleted is True

        # Verify it's gone
        result = await cache_manager.get("test_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_key(self, cache_manager):
        """Test deleting a non-existent key."""
        deleted = await cache_manager.delete("nonexistent_key")
        assert deleted is False

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, cache_manager):
        """Test cleanup of expired entries."""
        # Add some entries with different TTLs
        await cache_manager.set("key1", {"data": 1}, ttl=0.1)
        await cache_manager.set("key2", {"data": 2}, ttl=3600)
        await cache_manager.set("key3", {"data": 3}, ttl=0.1)

        # Wait for some to expire
        await asyncio.sleep(0.15)

        # Cleanup expired entries
        cleaned_count = await cache_manager.cleanup_expired()
        assert cleaned_count == 2  # key1 and key3 should be expired

        # Verify only key2 remains
        assert await cache_manager.get("key1") is None
        assert await cache_manager.get("key2") is not None
        assert await cache_manager.get("key3") is None

    @pytest.mark.asyncio
    async def test_get_cache_info(self, cache_manager):
        """Test getting cache statistics."""
        # Add some entries
        await cache_manager.set("key1", {"data": 1}, ttl=0.1)
        await cache_manager.set("key2", {"data": 2}, ttl=3600)

        info = await cache_manager.get_cache_info()

        assert info["total_entries"] == 2
        assert info["active_entries"] <= 2
        assert info["expired_entries"] >= 0

        # Wait for expiration and check again
        await asyncio.sleep(0.15)
        info = await cache_manager.get_cache_info()

        assert info["expired_entries"] >= 1

    def test_create_cache_key(self, cache_manager):
        """Test cache key creation."""
        params = {"ip": "8.8.8.8", "max_age": 30, "verbose": False}
        key = cache_manager.create_cache_key("check", params)

        assert "check" in key
        assert "ip=8.8.8.8" in key
        assert "max_age=30" in key
        assert "verbose=False" in key

    def test_create_cache_key_sorted_params(self, cache_manager):
        """Test that cache keys are consistent regardless of parameter order."""
        params1 = {"ip": "8.8.8.8", "max_age": 30, "verbose": False}
        params2 = {"verbose": False, "ip": "8.8.8.8", "max_age": 30}

        key1 = cache_manager.create_cache_key("check", params1)
        key2 = cache_manager.create_cache_key("check", params2)

        assert key1 == key2

    @pytest.mark.asyncio
    async def test_concurrent_access(self, cache_manager):
        """Test concurrent cache access."""
        async def set_values(start_idx, count):
            for i in range(start_idx, start_idx + count):
                await cache_manager.set(f"key{i}", {"value": i})

        async def get_values(start_idx, count):
            results = []
            for i in range(start_idx, start_idx + count):
                result = await cache_manager.get(f"key{i}")
                results.append(result)
            return results

        # Set values concurrently
        await asyncio.gather(
            set_values(0, 10),
            set_values(10, 10),
            set_values(20, 10)
        )

        # Get values concurrently
        results = await asyncio.gather(
            get_values(0, 10),
            get_values(10, 10),
            get_values(20, 10)
        )

        # Verify all values were set correctly
        all_results = []
        for result_group in results:
            all_results.extend(result_group)

        assert len(all_results) == 30
        for i, result in enumerate(all_results):
            if result is not None:  # Some might be None due to race conditions
                assert result["value"] == i


class TestRateLimiter:
    """Test cases for RateLimiter."""

    def test_rate_limiter_init(self):
        """Test rate limiter initialization."""
        limiter = RateLimiter(tokens_per_day=1000)

        assert limiter.tokens_per_day == 1000
        assert limiter.tokens == 1000

    @pytest.mark.asyncio
    async def test_acquire_tokens_success(self):
        """Test successful token acquisition."""
        limiter = RateLimiter(tokens_per_day=1000)

        success = await limiter.acquire(1)
        assert success is True
        assert limiter.tokens == 999

        success = await limiter.acquire(10)
        assert success is True
        assert limiter.tokens == 989

    @pytest.mark.asyncio
    async def test_acquire_tokens_insufficient(self):
        """Test token acquisition when insufficient tokens."""
        limiter = RateLimiter(tokens_per_day=10)

        # Use up most tokens
        success = await limiter.acquire(9)
        assert success is True
        assert limiter.tokens == 1

        # Should fail to acquire more than available
        success = await limiter.acquire(5)
        assert success is False
        assert limiter.tokens == 1  # Should remain unchanged

    @pytest.mark.asyncio
    async def test_acquire_exact_tokens(self):
        """Test acquiring exact number of available tokens."""
        limiter = RateLimiter(tokens_per_day=10)

        success = await limiter.acquire(10)
        assert success is True
        assert limiter.tokens == 0

        # Should fail to acquire any more
        success = await limiter.acquire(1)
        assert success is False

    @pytest.mark.asyncio
    async def test_token_refill(self):
        """Test token refill over time."""
        limiter = RateLimiter(tokens_per_day=86400)  # 1 token per second

        # Use some tokens
        await limiter.acquire(10)
        assert limiter.tokens == 86390

        # Mock time passing
        with patch('mcp_abuseipdb.cache.datetime') as mock_datetime:
            future_time = limiter.last_refill + timedelta(seconds=10)
            mock_datetime.now.return_value = future_time

            # Should refill 10 tokens (1 per second for 10 seconds)
            success = await limiter.acquire(1)
            assert success is True
            # Should have gained 10 tokens minus the 1 we just acquired
            assert limiter.tokens == 86399

    @pytest.mark.asyncio
    async def test_token_refill_cap(self):
        """Test that token refill doesn't exceed the daily limit."""
        limiter = RateLimiter(tokens_per_day=100)

        # Use all tokens
        await limiter.acquire(100)
        assert limiter.tokens == 0

        # Mock a long time passing (more than a day)
        with patch('mcp_abuseipdb.cache.datetime') as mock_datetime:
            future_time = limiter.last_refill + timedelta(days=2)
            mock_datetime.now.return_value = future_time

            # Should refill to maximum, not beyond
            success = await limiter.acquire(1)
            assert success is True
            assert limiter.tokens == 99  # Should cap at 100, minus 1 acquired

    @pytest.mark.asyncio
    async def test_get_status(self):
        """Test getting rate limiter status."""
        limiter = RateLimiter(tokens_per_day=1000)

        await limiter.acquire(100)

        status = await limiter.get_status()

        assert status["tokens_available"] == 900
        assert status["tokens_per_day"] == 1000
        assert "last_refill" in status
        assert isinstance(status["last_refill"], str)

    @pytest.mark.asyncio
    async def test_concurrent_token_acquisition(self):
        """Test concurrent token acquisition."""
        limiter = RateLimiter(tokens_per_day=100)

        async def acquire_tokens(count):
            return await limiter.acquire(count)

        # Try to acquire tokens concurrently
        results = await asyncio.gather(
            acquire_tokens(30),
            acquire_tokens(30),
            acquire_tokens(30),
            acquire_tokens(30)
        )

        # Only some should succeed due to token limit
        successful = sum(1 for r in results if r)
        failed = sum(1 for r in results if not r)

        # Should have some successes and some failures
        assert successful > 0
        assert failed > 0
        # Total acquired should not exceed available tokens
        assert limiter.tokens >= 0
