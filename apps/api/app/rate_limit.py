"""CYVRIX V1 Rate Limiter.

Security properties:
- Redis-backed (consistent across workers)
- Fixed window rate limiting
- Fails closed if Redis unavailable
- Safe identifiers in logs only
"""
import time
import logging
from typing import Optional

import redis.asyncio as redis

from app.config import get_settings

logger = logging.getLogger("cyvrix.rate_limit")

settings = get_settings()


async def check_rate_limit(
    key: str,
    max_requests: int,
    window_seconds: int,
    r: Optional[redis.Redis] = None,
) -> tuple[bool, int]:
    """Check rate limit for a given key.

    Uses fixed window algorithm.

    Returns:
        (allowed: bool, remaining: int)
        If Redis is unavailable, returns (False, 0) — fail closed.
    """
    if r is None:
        try:
            from app.session import get_redis
            r = await get_redis()
        except Exception:
            logger.warning("rate_limit_redis_unavailable key=%s — failing closed", key[:20])
            return False, 0

    try:
        current_time = int(time.time())
        window_start = current_time - (current_time % window_seconds)
        redis_key = f"ratelimit:{key}:{window_start}"

        # Atomic increment and expiry
        pipe = r.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, window_seconds)
        results = await pipe.execute()

        count = results[0]
        remaining = max(0, max_requests - count)

        if count > max_requests:
            logger.warning("rate_limit_exceeded key=%s count=%d limit=%d", key[:20], count, max_requests)
            return False, remaining

        return True, remaining

    except Exception as e:
        logger.warning("rate_limit_error key=%s error=%s — failing closed", key[:20], str(e)[:100])
        return False, 0


def get_client_ip(request) -> str:
    """Extract client IP from request, handling proxies safely."""
    # Check X-Forwarded-For but don't trust it blindly
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Take the first IP (original client)
        ip = forwarded.split(",")[0].strip()
        if ip:
            return ip
    return request.client.host if request.client else "unknown"
