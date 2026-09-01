"""CYVRIX Redis Integration Tests.

Tests session management and rate limiting with real Redis behavior.
Uses a test Redis instance or mocks for CI environments.
"""
import os
import sys
import time
import pytest
from uuid import uuid4
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.session import (
    generate_session_id,
    encode_session_cookie,
    decode_session_cookie,
    _sign_session_id,
    _verify_session_signature,
)
from app.rate_limit import check_rate_limit


class TestSessionSecurity:
    """Test session cookie signing and verification."""

    def test_generate_session_id_returns_hex(self):
        session_id, signature = generate_session_id()
        assert len(session_id) == 64  # 32 bytes = 64 hex chars
        assert len(signature) == 64  # SHA-256 hex digest

    def test_session_id_is_random(self):
        id1, _ = generate_session_id()
        id2, _ = generate_session_id()
        assert id1 != id2

    def test_encode_decode_cookie(self):
        session_id, signature = generate_session_id()
        cookie = encode_session_cookie(session_id, signature)
        decoded = decode_session_cookie(cookie)
        assert decoded is not None
        assert decoded[0] == session_id
        assert decoded[1] == signature

    def test_decode_malformed_cookie(self):
        assert decode_session_cookie("invalid") is None
        assert decode_session_cookie("") is None
        assert decode_session_cookie(".") is None
        assert decode_session_cookie("abc.") is None
        assert decode_session_cookie(".def") is None

    def test_signature_verification(self):
        session_id, signature = generate_session_id()
        assert _verify_session_signature(session_id, signature) is True

    def test_signature_tampering_detected(self):
        session_id, signature = generate_session_id()
        tampered = signature[:-2] + "00"
        assert _verify_session_signature(session_id, tampered) is False

    def test_wrong_session_id_detected(self):
        session_id, signature = generate_session_id()
        wrong_id, _ = generate_session_id()
        assert _verify_session_signature(wrong_id, signature) is False


class TestRateLimiting:
    """Test rate limiting logic."""

    @pytest.mark.asyncio
    async def test_rate_limit_fails_closed_on_none_redis(self):
        """When no Redis is available, rate limit should fail closed."""
        with patch("app.session.get_redis", side_effect=Exception("Redis unavailable")):
            allowed, remaining = await check_rate_limit(
                key="test:no-redis",
                max_requests=10,
                window_seconds=60,
                r=None,
            )
            assert allowed is False
            assert remaining == 0

    @pytest.mark.asyncio
    async def test_rate_limit_fails_closed_on_redis_error(self):
        """When Redis throws an error, rate limit should fail closed."""
        mock_redis = MagicMock()
        mock_redis.pipeline.side_effect = Exception("Redis down")

        allowed, remaining = await check_rate_limit(
            key="test:error",
            max_requests=10,
            window_seconds=60,
            r=mock_redis,
        )
        assert allowed is False
        assert remaining == 0


class TestSessionCreation:
    """Test session creation with mocked Redis."""

    @pytest.mark.asyncio
    async def test_create_session_returns_valid_cookie(self):
        from app.session import create_session

        mock_redis = AsyncMock()
        mock_redis.setex.return_value = True

        with patch("app.session.get_redis", return_value=mock_redis):
            user_id = uuid4()
            session_id, signature, cookie = await create_session(user_id)

            assert len(session_id) == 64
            assert len(signature) == 64
            assert "." in cookie

            # Verify Redis was called
            mock_redis.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_session_validates_signature(self):
        from app.session import get_session_user_id

        session_id, signature = generate_session_id()

        # Valid signature should work with mock Redis
        mock_redis = AsyncMock()
        import json
        import time
        mock_redis.get.return_value = json.dumps({
            "user_id": str(uuid4()),
            "created_at": str(int(time.time())),
            "last_access": str(int(time.time())),
        })
        mock_redis.setex.return_value = True

        with patch("app.session.get_redis", return_value=mock_redis):
            user_id = await get_session_user_id(session_id, signature)
            assert user_id is not None

    @pytest.mark.asyncio
    async def test_get_session_rejects_tampered_signature(self):
        from app.session import get_session_user_id

        session_id, signature = generate_session_id()
        tampered = signature[:-2] + "00"

        user_id = await get_session_user_id(session_id, tampered)
        assert user_id is None

    @pytest.mark.asyncio
    async def test_get_session_returns_none_for_expired(self):
        from app.session import get_session_user_id

        session_id, signature = generate_session_id()

        mock_redis = AsyncMock()
        mock_redis.get.return_value = None  # Expired/not found

        with patch("app.session.get_redis", return_value=mock_redis):
            user_id = await get_session_user_id(session_id, signature)
            assert user_id is None

    @pytest.mark.asyncio
    async def test_destroy_session_removes_from_redis(self):
        from app.session import destroy_session

        session_id, _ = generate_session_id()

        mock_redis = AsyncMock()
        mock_redis.delete.return_value = 1

        with patch("app.session.get_redis", return_value=mock_redis):
            result = await destroy_session(session_id)
            assert result is True
            mock_redis.delete.assert_called_once_with(f"session:{session_id}")
