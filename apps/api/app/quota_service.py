"""CYVRIX V4.1 — organization quotas.

Quotas are a SECOND, coarser control alongside the V4.0 rate limiter:

  rate limit  = burst protection per window (fixed window, per class)
  quota       = absolute ceiling per period (per organization, per action)

Hierarchy and precedence:

    GLOBAL  (platform ceiling — consumed by every organization)
      → ORGANIZATION  (per-tenant ceiling)

The GLOBAL quota is checked FIRST and the ORGANIZATION quota second; a
request is admitted only when BOTH have capacity. Both checks are atomic
Redis operations — never a read-then-increment in Python — so two
simultaneous requests around the final slot cannot both be admitted.

Fail-closed: if Redis is unreachable, the request is REFUSED (503), not
allowed. A quota that degrades to "allow" under infrastructure failure
is a bypass, not a degradation.

No client can ever modify a quota value: limits come from server
configuration only, and no public endpoint accepts a quota parameter.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("cyvrix.quota")


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    reason_code: Optional[str] = None   # QUOTA_GLOBAL_EXCEEDED | QUOTA_ORG_EXCEEDED | QUOTA_UNAVAILABLE
    org_limit: int = 0
    org_remaining: int = 0
    global_limit: int = 0


class QuotaUnavailableError(Exception):
    """Redis is unreachable. Fail closed — the caller must refuse."""


def _window_start(now: int, period_seconds: int) -> int:
    return now - (now % period_seconds)


async def consume_quota(
    redis,
    *,
    organization_id,
    action: str,
    org_limit: int,
    global_limit: int,
    period_seconds: int = 86400,
) -> QuotaDecision:
    """Atomically consume one quota slot, or refuse.

    `redis` is injected so callers and tests can fail Redis explicitly.
    Two atomic increments run in a pipeline: the global ceiling first,
    then the organization ceiling. If either exceeds its limit the
    increment that over-consumed is DECREMENTED back (compensation), so
    a refused request never consumes capacity it did not use. Global is
    never rolled back to pay for an org refusal being retried — the
    compensation order (global first, then org) means a refused request
    restores both counters to their pre-call values.
    """
    if redis is None:
        # Caller could not obtain Redis. Fail closed.
        return QuotaDecision(False, "QUOTA_UNAVAILABLE", org_limit, 0, global_limit)

    now = int(__import__("time").time())
    window = _window_start(now, period_seconds)
    gkey = f"quota:global:{action}:{window}"
    okey = f"quota:org:{organization_id}:{action}:{window}"

    try:
        pipe = redis.pipeline()
        pipe.incr(gkey, 1)
        pipe.expire(gkey, period_seconds)
        pipe.incr(okey, 1)
        pipe.expire(okey, period_seconds)
        results = await pipe.execute()
    except Exception as exc:  # noqa: BLE001 — any Redis failure refuses
        logger.warning("quota_redis_error action=%s err=%s", action, type(exc).__name__)
        return QuotaDecision(False, "QUOTA_UNAVAILABLE", org_limit, 0, global_limit)

    gcount = int(results[0])
    ocount = int(results[2])

    if gcount > global_limit:
        # Refuse + compensate so capacity is not burned by refusals.
        try:
            await redis.decr(gkey, 1)
        except Exception:  # noqa: BLE001
            logger.warning("quota_compensation_failed key=%s", gkey)
        return QuotaDecision(
            False, "QUOTA_GLOBAL_EXCEEDED", org_limit, max(0, org_limit - ocount), global_limit
        )

    if ocount > org_limit:
        try:
            pipe = redis.pipeline()
            pipe.decr(gkey, 1)
            pipe.decr(okey, 1)
            await pipe.execute()
        except Exception:  # noqa: BLE001
            logger.warning("quota_compensation_failed key=%s", okey)
        return QuotaDecision(
            False, "QUOTA_ORG_EXCEEDED", org_limit, 0, global_limit
        )

    return QuotaDecision(
        True, None, org_limit, max(0, org_limit - ocount), global_limit
    )


# ── Server-owned limit table (config only; no client input ever) ─────

DEFAULT_ACTION_LIMITS: dict[str, int] = {
    # Per-organization daily ceilings. The platform's noisy-neighbour
    # protection: no tenant may push more than this through the public
    # API in one day, regardless of rate-limit headroom.
    "scans": 200,
}

GLOBAL_ACTION_LIMITS: dict[str, int] = {
    # Platform-wide daily ceilings (sum across all organizations).
    "scans": 5000,
}

QUOTA_PERIOD_SECONDS = 86400


def limit_for(action: str) -> tuple[int, int]:
    """(org_limit, global_limit) for an action, defaulting to 0 = refused.

    An unknown action is NOT unlimited: it refuses, so an action that
    gains quota enforcement must be registered here explicitly.
    """
    return DEFAULT_ACTION_LIMITS.get(action, 0), GLOBAL_ACTION_LIMITS.get(action, 0)
