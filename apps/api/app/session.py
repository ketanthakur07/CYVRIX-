"""CYVRIX V1 Session Management.

Security properties:
- Sessions stored in Redis with configurable TTL
- Session IDs are cryptographically random (32 bytes)
- Session cookies are signed with HMAC-SHA256
- Sessions can be revoked (logout)
- Session fixation prevented (new session on login)
- No secrets in logs
"""
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Optional
from uuid import UUID

import redis.asyncio as redis

from app.config import get_settings

logger = logging.getLogger("cyvrix.session")

settings = get_settings()

# Redis connection pool
_redis_pool: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    """Get or create Redis connection pool."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
    return _redis_pool


async def close_redis():
    """Close Redis connection pool."""
    global _redis_pool
    if _redis_pool:
        await _redis_pool.aclose()
        _redis_pool = None


def _sign_session_id(session_id: str) -> str:
    """Sign a session ID with HMAC-SHA256."""
    return hmac.new(
        settings.secret_key.encode(),
        session_id.encode(),
        hashlib.sha256,
    ).hexdigest()


def _verify_session_signature(session_id: str, signature: str) -> bool:
    """Verify session ID signature."""
    expected = _sign_session_id(session_id)
    return hmac.compare_digest(expected, signature)


def generate_session_id() -> tuple[str, str]:
    """Generate a new session ID and its signature.

    Returns (session_id, signature) tuple.
    """
    session_id = secrets.token_hex(32)
    signature = _sign_session_id(session_id)
    return session_id, signature


def encode_session_cookie(session_id: str, signature: str) -> str:
    """Encode session ID and signature into a cookie value."""
    return f"{session_id}.{signature}"


def decode_session_cookie(cookie_value: str) -> Optional[tuple[str, str]]:
    """Decode a session cookie value into (session_id, signature).

    Returns None if the cookie is malformed.
    """
    try:
        parts = cookie_value.split(".", 1)
        if len(parts) != 2:
            return None
        session_id, signature = parts
        if not session_id or not signature:
            return None
        return session_id, signature
    except Exception:
        return None


async def create_session(user_id: UUID, metadata: Optional[dict] = None, r: Optional[redis.Redis] = None) -> tuple[str, str, str]:
    """Create a new session for a user.

    Returns (session_id, signature, cookie_value).
    Prevents session fixation by always creating a fresh session.
    """
    session_id, signature = generate_session_id()
    cookie_value = encode_session_cookie(session_id, signature)

    if r is None:
        r = await get_redis()
    session_data = {
        "user_id": str(user_id),
        "created_at": str(int(time.time())),
        "last_access": str(int(time.time())),
    }
    if metadata:
        session_data.update(metadata)

    # Store session in Redis with TTL
    key = f"session:{session_id}"
    await r.setex(key, settings.session_ttl_seconds, json.dumps(session_data))

    logger.info("session_created user_id=%s", user_id)
    return session_id, signature, cookie_value


async def get_session_user_id(session_id: str, signature: str, r: Optional[redis.Redis] = None) -> Optional[UUID]:
    """Validate and retrieve user ID from a session.

    Returns None if session is invalid, expired, or tampered.
    Updates last_access timestamp on successful validation.
    """
    # Verify signature
    if not _verify_session_signature(session_id, signature):
        logger.warning("session_invalid_signature session_id=%s", session_id[:8])
        return None

    if r is None:
        r = await get_redis()
    key = f"session:{session_id}"
    data = await r.get(key)

    if not data:
        logger.debug("session_expired session_id=%s", session_id[:8])
        return None

    try:
        session_data = json.loads(data)
        user_id = UUID(session_data["user_id"])

        # Update last access and extend TTL
        session_data["last_access"] = str(int(time.time()))
        await r.setex(key, settings.session_ttl_seconds, json.dumps(session_data))

        return user_id
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning("session_corrupted session_id=%s error=%s", session_id[:8], str(e)[:100])
        return None


async def destroy_session(session_id: str, r: Optional[redis.Redis] = None) -> bool:
    """Destroy a session (logout).

    Returns True if session was destroyed.
    """
    if r is None:
        r = await get_redis()
    key = f"session:{session_id}"
    deleted = await r.delete(key)
    if deleted:
        logger.info("session_destroyed session_id=%s", session_id[:8])
    return bool(deleted)


async def destroy_user_sessions(user_id: UUID) -> int:
    """Destroy all sessions for a user.

    Returns number of sessions destroyed.
    """
    r = await get_redis()
    count = 0
    async for key in r.scan_iter("session:*"):
        data = await r.get(key)
        if data:
            try:
                session_data = json.loads(data)
                if session_data.get("user_id") == str(user_id):
                    await r.delete(key)
                    count += 1
            except (json.JSONDecodeError, KeyError):
                pass
    if count > 0:
        logger.info("user_sessions_destroyed user_id=%s count=%d", user_id, count)
    return count
