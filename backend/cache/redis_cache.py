"""
Redis Cache Layer
─────────────────
Two-tier caching strategy:
  Hot  (Redis):    sub-second, TTL-based, survives across requests
  Warm (Postgres): cross-session, stores last_scanned per domain

Why cache OSINT results?
  - Shodan/Censys API credits are precious on free tiers
  - Same domain scanned twice in one day = wasted quota
  - Makes demos instant (cached result = <50ms response)

TTLs by data freshness:
  DNS records    → 6 h  (change rarely)
  Shodan/ports   → 12 h (infra changes slowly)
  Certs (crt.sh) → 24 h (very stable)
  GitHub leaks   → 1 h  (new commits possible)
  Email/HTTP     → 6 h
"""

import json
import hashlib
import logging
from typing import Any, Optional, Callable
from functools import wraps

logger = logging.getLogger(__name__)

# TTLs in seconds
CACHE_TTL = {
    "dns":     6  * 3600,
    "shodan":  12 * 3600,
    "certs":   24 * 3600,
    "github":  1  * 3600,
    "email":   6  * 3600,
    "tech":    6  * 3600,
}

DEFAULT_TTL = 6 * 3600


def _cache_key(namespace: str, *parts: str) -> str:
    """
    Stable cache key: namespace:sha256(joined_parts)[:16]
    Short enough for Redis key limits, collision-resistant enough for our scale.
    """
    raw = ":".join(str(p).lower().strip() for p in parts)
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"asm:{namespace}:{digest}"


class CacheLayer:
    """
    Thin async wrapper around redis.asyncio.
    Falls back gracefully to no-cache mode when Redis is unavailable.
    """

    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._available = redis_client is not None

    async def get(self, key: str) -> Optional[Any]:
        if not self._available:
            return None
        try:
            raw = await self._redis.get(key)
            if raw:
                logger.debug("Cache HIT: %s", key)
                return json.loads(raw)
            logger.debug("Cache MISS: %s", key)
            return None
        except Exception as e:
            logger.warning("Redis GET failed (%s) — bypassing cache", e)
            return None

    async def set(self, key: str, value: Any, ttl: int = DEFAULT_TTL) -> None:
        if not self._available:
            return
        try:
            await self._redis.setex(key, ttl, json.dumps(value, default=str))
            logger.debug("Cache SET: %s (TTL %ds)", key, ttl)
        except Exception as e:
            logger.warning("Redis SET failed (%s) — result not cached", e)

    async def delete(self, key: str) -> None:
        if not self._available:
            return
        try:
            await self._redis.delete(key)
        except Exception as e:
            logger.warning("Redis DELETE failed: %s", e)

    async def invalidate_domain(self, domain: str) -> int:
        """Nuke all cache keys for a domain (force fresh scan)."""
        if not self._available:
            return 0
        try:
            pattern = f"asm:*:{hashlib.sha256(domain.lower().encode()).hexdigest()[:16]}*"
            keys = []
            async for key in self._redis.scan_iter(match=pattern):
                keys.append(key)
            if keys:
                await self._redis.delete(*keys)
            logger.info("Invalidated %d cache keys for %s", len(keys), domain)
            return len(keys)
        except Exception as e:
            logger.warning("Cache invalidation failed: %s", e)
            return 0

    async def ping(self) -> bool:
        """Health check."""
        try:
            return await self._redis.ping()
        except Exception:
            return False


def cached_osint(namespace: str, ttl: Optional[int] = None):
    """
    Decorator for OSINTEngine methods.
    Cache key = namespace + self.domain.

    Usage:
        @cached_osint("dns")
        async def enumerate_dns(self) -> dict:
            ...
    """
    actual_ttl = ttl if ttl is not None else CACHE_TTL.get(namespace, DEFAULT_TTL)

    def decorator(fn: Callable):
        @wraps(fn)
        async def wrapper(self, *args, **kwargs):
            # self must have .cache (CacheLayer) and .domain
            cache: CacheLayer = getattr(self, "cache", None)
            domain: str = getattr(self, "domain", "unknown")

            key = _cache_key(namespace, domain, *[str(a) for a in args])

            if cache:
                cached = await cache.get(key)
                if cached is not None:
                    logger.info("Cache hit for %s:%s", namespace, domain)
                    cached["_cached"] = True
                    return cached

            result = await fn(self, *args, **kwargs)

            if cache and result:
                await cache.set(key, result, ttl=actual_ttl)

            return result
        return wrapper
    return decorator


async def build_cache(redis_url: str = "redis://localhost:6379/0") -> CacheLayer:
    """
    Factory — tries to connect to Redis, returns a no-op CacheLayer on failure.
    Never raises — the app runs fine without Redis, just slower.
    """
    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(
            redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        await client.ping()
        logger.info("Redis connected: %s", redis_url)
        return CacheLayer(client)
    except Exception as e:
        logger.warning("Redis unavailable (%s) — running without cache", e)
        return CacheLayer(redis_client=None)