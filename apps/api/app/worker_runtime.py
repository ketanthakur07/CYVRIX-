"""CYVRIX V4.2 — worker runtime support (Phase 4/20/26/27).

Heartbeat and drain coordination live in REDIS, not process memory, so
the API fleet can observe worker fleet liveness across instances and a
drain command reaches every worker regardless of which instance sends it.

Keys (all bounded, all content-free):
  cyvrix:worker:<id>           HASH   per-worker liveness + current work,
                               EXPIRE 90s (refreshed every HEARTBEAT_SECONDS)
  cyvrix:drain:<worker_id>     STRING "1", EXPIRE 1h (drain request marker)

Nothing here authorizes anything: this is liveness telemetry and a
deployment-control channel for jobs that are already authorized. The
worker heartbeat payload contains identifiers only (queue names, job
ids) — never credentials, never payload contents.

V4.2 completion — active_jobs semantics (docs/v4-metrics.md §4):
`active_jobs` is the number of jobs the worker CURRENTLY owns and is
executing. Queued, failed, and dead-lettered jobs are NOT active. The
platform-wide gauge is the SUM over live workers (heartbeat TTL bounds
each contribution; a crashed worker's count expires with its record).
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import redis.asyncio as aioredis

logger = logging.getLogger("cyvrix.worker_runtime")

HEARTBEAT_SECONDS = 30
HEARTBEAT_TTL_SECONDS = 90
DRAIN_TTL_SECONDS = 3600
_WORKER_KEY_PREFIX = "cyvrix:worker:"
_DRAIN_KEY_PREFIX = "cyvrix:drain:"


def _worker_key(worker_id: str) -> str:
    return f"{_WORKER_KEY_PREFIX}{worker_id}"


def _drain_key(worker_id: str) -> str:
    return f"{_DRAIN_KEY_PREFIX}{worker_id}"


async def heartbeat(
    redis: aioredis.Redis,
    *,
    worker_id: str,
    queues: list[str],
    current_job: Optional[str] = None,
    state: str = "RUNNING",
    active_jobs: int = 0,
) -> None:
    """Record worker liveness. Bounded payload, bounded TTL — a crashed
    worker's entry disappears on its own (fleet liveness is derivable).

    V4.2 completion: `active_jobs` is this worker's REAL count of jobs
    currently owned/executing (0 or 1 for a standard RQ worker). It
    lives in the same bounded-TTL hash, so a crashed worker's count
    expires with its liveness — no permanently stuck gauge."""
    now = int(time.time())
    try:
        pipe = redis.pipeline()
        pipe.hset(
            _worker_key(worker_id),
            mapping={
                "state": state,
                "queues": ",".join(queues)[:200],
                "current_job": (current_job or "")[:64],
                "active_jobs": str(max(0, int(active_jobs))),
                "last_heartbeat": str(now),
            },
        )
        pipe.expire(_worker_key(worker_id), HEARTBEAT_TTL_SECONDS)
        await pipe.execute()
    except Exception as exc:  # noqa: BLE001 — heartbeat must never crash the worker
        logger.warning("worker_heartbeat_failed worker=%s err=%s", worker_id[:40], type(exc).__name__)


async def request_drain(redis: aioredis.Redis, *, worker_id: str) -> bool:
    """Mark a worker for draining. The worker observes the marker within
    one heartbeat period, finishes/abandons its current claim honestly,
    and exits cleanly."""
    try:
        await redis.set(_drain_key(worker_id), "1", ex=DRAIN_TTL_SECONDS)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("drain_request_failed worker=%s err=%s", worker_id[:40], type(exc).__name__)
        return False


async def is_drain_requested(redis: aioredis.Redis, *, worker_id: str) -> bool:
    try:
        return bool(await redis.get(_drain_key(worker_id)))
    except Exception:  # noqa: BLE001 — if Redis is gone the worker cannot observe drain; keep working
        return False


async def clear_drain(redis: aioredis.Redis, *, worker_id: str) -> None:
    try:
        await redis.delete(_drain_key(worker_id))
    except Exception:  # noqa: BLE001
        pass


async def fleet_snapshot(redis: aioredis.Redis) -> dict:
    """Live fleet + queue gauges for the ops metrics surface.

    Returns {} on any Redis failure (metrics surface degrades, never
    fabricates)."""
    try:
        workers: dict[str, dict] = {}
        async for key in redis.scan_iter(match=f"{_WORKER_KEY_PREFIX}*", count=100):
            worker_id = key[len(_WORKER_KEY_PREFIX):]
            data = await redis.hgetall(key)
            if data:
                workers[worker_id] = data
        return {"workers": workers}
    except Exception as exc:  # noqa: BLE001
        logger.warning("fleet_snapshot_failed err=%s", type(exc).__name__)
        return {}


def queue_depths(sync_redis, queue_names: list[str]) -> dict[str, int]:
    """Synchronous queue-depth read (worker side). Best-effort."""
    depths: dict[str, int] = {}
    for name in queue_names:
        try:
            depths[name] = int(sync_redis.llen(f"rq:queue:{name}"))
        except Exception:  # noqa: BLE001
            depths[name] = -1  # unknown — honest sentinel, never a fake zero
    return depths
