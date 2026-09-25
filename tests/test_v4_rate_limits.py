"""CYVRIX V4.0 — organization-scoped rate limiting (REAL Redis, §29/§30).

Rate limits are a tenant control, so the property that matters is
ISOLATION: one organization exhausting a bucket must not throttle another
organization, and must not be able to spend another tenant's budget. The
limiter must also fail CLOSED when Redis is unavailable — a rate limiter
that silently allows everything under load is worse than no limiter.

These tests run against the real Redis from `infra/integration.env`
(`REDIS_URL`), not a fake, because the fixed-window key derivation and the
atomic INCR/EXPIRE pipeline are exactly what is under test.

Event-loop hygiene: `app.session` keeps a module-global connection pool.
`asyncio_mode = auto` gives each test its own event loop, so a pooled
connection created on an earlier loop raises "Event loop is closed" and
would make these tests SKIP. A skipped isolation test certifies nothing,
so this module binds a fresh client to the current loop and points the
application's `get_redis()` resolver at it.
"""
import os
import sys
import uuid

import pytest
import redis.asyncio as aioredis

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="V4 rate-limit tests require RUN_INTEGRATION_TESTS=1 and a real Redis",
)

from fastapi import HTTPException  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.rate_limit import check_rate_limit  # noqa: E402
from app.services.org_auth import rate_limit_org  # noqa: E402


def _org_id() -> str:
    """A fresh organization id per test, so no test can throttle another."""
    return f"org-{uuid.uuid4()}"


@pytest.fixture
async def redis_client(monkeypatch):
    """A real Redis client bound to THIS test's event loop.

    Also installs it as the application resolver so code paths that call
    `check_rate_limit(..., r=None)` use the same loop-local connection.
    """
    client = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        await client.ping()
    except Exception as exc:  # pragma: no cover - environment dependent
        await client.aclose()
        pytest.skip(f"real Redis required for V4 rate-limit tests: {exc}")

    import app.session as session_module

    async def _resolve():
        return client

    monkeypatch.setattr(session_module, "get_redis", _resolve)

    yield client

    await client.aclose()


class TestOrgBucketIsolation:
    async def test_exhausting_one_organization_does_not_throttle_another(
        self, redis_client
    ):
        org_a, org_b = _org_id(), _org_id()
        bucket = "org-read"

        # Exhaust A's budget (limit 3 → the 4th call is refused).
        for _ in range(3):
            allowed, _ = await check_rate_limit(
                f"org:{org_a}:{bucket}", 3, 3600, redis_client
            )
            assert allowed is True, "A should be within its own budget"

        allowed_a, remaining_a = await check_rate_limit(
            f"org:{org_a}:{bucket}", 3, 3600, redis_client
        )
        assert allowed_a is False, "A must be throttled after exceeding its limit"
        assert remaining_a == 0

        # B is untouched: same bucket name, different tenant.
        allowed_b, remaining_b = await check_rate_limit(
            f"org:{org_b}:{bucket}", 3, 3600, redis_client
        )
        assert allowed_b is True, "B must not inherit A's consumption"
        assert remaining_b == 2

    async def test_buckets_within_an_organization_are_independent(self, redis_client):
        org = _org_id()

        for _ in range(2):
            allowed, _ = await check_rate_limit(
                f"org:{org}:members-write", 2, 3600, redis_client
            )
            assert allowed is True
        allowed_write, _ = await check_rate_limit(
            f"org:{org}:members-write", 2, 3600, redis_client
        )
        assert allowed_write is False

        # A different bucket for the SAME organization still has budget.
        allowed_read, _ = await check_rate_limit(
            f"org:{org}:org-read", 600, 3600, redis_client
        )
        assert allowed_read is True

    async def test_keys_are_namespaced_by_organization_and_bucket(self, redis_client):
        """Spending a bucket must create keys that name the tenant."""
        org = _org_id()
        await check_rate_limit(f"org:{org}:keys", 5, 3600, redis_client)

        keys = await redis_client.keys(f"ratelimit:org:{org}:*")
        try:
            assert keys, "expected at least one org-scoped rate-limit key"
            for key in keys:
                assert key.startswith(f"ratelimit:org:{org}:keys:")
        finally:
            if keys:
                await redis_client.delete(*keys)


class TestFailClosed:
    async def test_redis_error_denies_the_request(self):
        class BrokenRedis:
            def pipeline(self):  # noqa: D401 - deliberately exploding client
                raise RuntimeError("redis is down")

        allowed, remaining = await check_rate_limit(
            "org:any:read", 10, 3600, BrokenRedis()
        )
        assert allowed is False, "an unavailable limiter must fail CLOSED"
        assert remaining == 0

    async def test_unavailable_redis_refuses_instead_of_allowing(self, monkeypatch):
        """The real dependency path must refuse when Redis cannot be reached."""
        import app.session as session_module

        async def _unavailable():
            raise RuntimeError("redis connection refused")

        monkeypatch.setattr(session_module, "get_redis", _unavailable)

        with pytest.raises(HTTPException) as excinfo:
            await rate_limit_org(None, org_id=_org_id(), bucket="keys", limit=10)

        assert excinfo.value.status_code == 429
        assert excinfo.value.detail == "ORG_RATE_LIMITED"


class TestRateLimitOrgDependency:
    async def test_exceeding_limit_raises_429_org_rate_limited(self, redis_client):
        org = _org_id()

        for _ in range(2):
            # Within budget: must not raise.
            await rate_limit_org(None, org_id=org, bucket="keys", limit=2)

        with pytest.raises(HTTPException) as excinfo:
            await rate_limit_org(None, org_id=org, bucket="keys", limit=2)

        assert excinfo.value.status_code == 429
        assert excinfo.value.detail == "ORG_RATE_LIMITED"

    async def test_limit_is_per_organization_not_global(self, redis_client):
        org_a, org_b = _org_id(), _org_id()

        for _ in range(3):
            await rate_limit_org(None, org_id=org_a, bucket="invites", limit=3)

        with pytest.raises(HTTPException):
            await rate_limit_org(None, org_id=org_a, bucket="invites", limit=3)

        # A different organization still has its full budget.
        await rate_limit_org(None, org_id=org_b, bucket="invites", limit=3)
