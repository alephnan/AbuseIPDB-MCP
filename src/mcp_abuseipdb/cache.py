"""SQLite-based caching with TTL support."""

import json
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, AsyncContextManager
from contextlib import asynccontextmanager
import asyncio
from threading import Lock

from .models import CacheEntry

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Return a naive UTC timestamp without using deprecated APIs."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class CacheManager:
    """SQLite-based cache manager with TTL support."""

    def __init__(self, db_path: str, default_ttl: int = 3600):
        self.db_path = db_path
        self.default_ttl = default_ttl
        self._lock = Lock()
        self._initialized = False

    def _init_db(self) -> None:
        """Initialize the cache database."""
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_expires_at ON cache_entries(expires_at)
                """)
                conn.commit()
                self._initialized = True
                logger.info(f"Cache database initialized at {self.db_path}")
            finally:
                conn.close()

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get a value from the cache."""
        self._init_db()

        def _get():
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    "SELECT value, expires_at FROM cache_entries WHERE key = ?",
                    (key,)
                )
                row = cursor.fetchone()
                if not row:
                    return None

                value_json, expires_at_str = row
                expires_at = datetime.fromisoformat(expires_at_str)

                # Check if expired
                if _utcnow() > expires_at:
                    # Delete expired entry
                    conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                    conn.commit()
                    return None

                return json.loads(value_json)
            finally:
                conn.close()

        # Run in thread pool to avoid blocking
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _get)

    async def set(
        self,
        key: str,
        value: Dict[str, Any],
        ttl: Optional[int] = None
    ) -> None:
        """Set a value in the cache with TTL."""
        self._init_db()

        if ttl is None:
            ttl = self.default_ttl

        now = _utcnow()
        expires_at = now + timedelta(seconds=ttl)

        def _set():
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO cache_entries
                       (key, value, created_at, expires_at) VALUES (?, ?, ?, ?)""",
                    (
                        key,
                        json.dumps(value, default=str),
                        now.isoformat(),
                        expires_at.isoformat(),
                    )
                )
                conn.commit()
            finally:
                conn.close()

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _set)

    async def delete(self, key: str) -> bool:
        """Delete a key from the cache."""
        self._init_db()

        def _delete():
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _delete)

    async def cleanup_expired(self) -> int:
        """Remove expired entries from the cache."""
        self._init_db()

        def _cleanup():
            conn = sqlite3.connect(self.db_path)
            try:
                now = _utcnow().isoformat()
                cursor = conn.execute(
                    "DELETE FROM cache_entries WHERE expires_at < ?",
                    (now,)
                )
                conn.commit()
                return cursor.rowcount
            finally:
                conn.close()

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _cleanup)

    async def get_cache_info(self) -> Dict[str, Any]:
        """Get cache statistics."""
        self._init_db()

        def _get_info():
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                total_entries = cursor.fetchone()[0]

                now = _utcnow().isoformat()
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM cache_entries WHERE expires_at < ?",
                    (now,)
                )
                expired_entries = cursor.fetchone()[0]

                return {
                    "total_entries": total_entries,
                    "expired_entries": expired_entries,
                    "active_entries": total_entries - expired_entries,
                }
            finally:
                conn.close()

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _get_info)

    def create_cache_key(self, endpoint: str, params: Dict[str, Any]) -> str:
        """Create a cache key from endpoint and parameters."""
        # Sort params for consistent keys
        sorted_params = sorted(params.items())
        params_str = "&".join(f"{k}={v}" for k, v in sorted_params)
        return f"{endpoint}?{params_str}"


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, tokens_per_day: int):
        self.tokens_per_day = tokens_per_day
        self.tokens = tokens_per_day
        self.last_refill = _utcnow()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens. Returns True if successful."""
        async with self._lock:
            now = _utcnow()

            # Refill tokens based on time passed
            time_passed = (now - self.last_refill).total_seconds()
            tokens_to_add = int(time_passed * self.tokens_per_day / 86400)  # 24 * 60 * 60

            if tokens_to_add > 0:
                self.tokens = min(self.tokens_per_day, self.tokens + tokens_to_add)
                self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            return False

    async def get_status(self) -> Dict[str, Any]:
        """Get current rate limiter status."""
        async with self._lock:
            return {
                "tokens_available": self.tokens,
                "tokens_per_day": self.tokens_per_day,
                "last_refill": self.last_refill.isoformat(),
            }
