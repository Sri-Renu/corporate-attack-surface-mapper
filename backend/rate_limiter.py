"""
Rate Limiter — Fixed "next-slot" design (no token debt spiral).
Retry decorator with exponential backoff + jitter.
"""

import asyncio
import random
import time
import logging
from functools import wraps
from typing import Tuple, Type

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Slot-based rate limiter.  Tracks WHEN the next call is allowed,
    not how many tokens remain.  Immune to the negative-token debt spiral.

    Under lock:
        1. If now < next_allowed → sleep the exact gap.
        2. Advance next_allowed by one interval (from the later of now/next_allowed).

    This means bursts are impossible — every call is spaced at least
    `interval` seconds apart.  For APIs with burst allowances, instantiate
    with a higher calls_per_second and throttle externally.
    """

    def __init__(self, calls_per_second: float):
        if calls_per_second <= 0:
            raise ValueError("calls_per_second must be positive")
        self.interval = 1.0 / calls_per_second
        self.next_allowed = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self.next_allowed - now
            if wait > 0:
                logger.debug("Rate limiter sleeping %.2fs", wait)
                await asyncio.sleep(wait)
            # Advance from the REAL current time after the sleep
            self.next_allowed = max(time.monotonic(), self.next_allowed) + self.interval


# Pre-configured limiters matching each API's free-tier limits
LIMITERS = {
    "shodan":   RateLimiter(calls_per_second=0.9),   # 1 req/s free
    "censys":   RateLimiter(calls_per_second=0.4),   # ~25 req/min free
    "github":   RateLimiter(calls_per_second=1.5),   # 10 req/min unauth → use token for 30/min
    "crtsh":    RateLimiter(calls_per_second=2.0),
    "dns":      RateLimiter(calls_per_second=10.0),
    "http":     RateLimiter(calls_per_second=5.0),
}


def retry_with_backoff(
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    rate_limit_multiplier: float = 3.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
):
    """
    Async retry decorator with exponential backoff + full jitter.

    Detects 429 / rate-limit responses and applies extra back-off.
    On final failure re-raises the last exception — never swallows errors.

    Usage:
        @retry_with_backoff(max_retries=5, exceptions=(aiohttp.ClientError,))
        async def fetch_shodan(ip): ...
    """
    def decorator(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries):
                try:
                    return await fn(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt == max_retries - 1:
                        logger.error(
                            "%s failed after %d retries: %s",
                            fn.__name__, max_retries, exc,
                        )
                        raise

                    # Detect rate-limit signal in exception message or status
                    msg = str(exc).lower()
                    is_rate_limit = any(
                        tok in msg for tok in ("429", "rate limit", "too many requests", "throttle")
                    )

                    # Full jitter: sleep in [0, cap] where cap grows exponentially
                    cap = min(max_delay, base_delay * (2 ** attempt))
                    jitter = random.uniform(0, cap)
                    if is_rate_limit:
                        jitter *= rate_limit_multiplier

                    logger.warning(
                        "%s attempt %d/%d failed (%s). Retrying in %.1fs",
                        fn.__name__, attempt + 1, max_retries, exc, jitter,
                    )
                    await asyncio.sleep(jitter)

            raise last_exc  # unreachable but satisfies type checkers
        return wrapper
    return decorator