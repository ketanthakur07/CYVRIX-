"""CYVRIX Database Configuration.

Production schema is managed by Alembic migrations.
Tests use create_all for isolation.

V4.2 (Phase 7 — connection pooling under production scale):
  - pool_pre_ping: a stale connection (idle timeout, DB restart, NAT
    drop) is detected and replaced before a query rides it to a false
    failure. Without this, a DB restart poisons every pooled connection
    and the API 500s until the pool cycles.
  - pool_recycle: bounded connection lifetime, so long-lived processes
    never hold connections the server or a firewall has half-closed.
  - pool_timeout: a caller waits a BOUNDED time for a pool slot, then
    fails fast instead of piling up (retry-storm prevention).
  - pool size / overflow are configuration: an instance count × pool
    size connection budget is now a documented arithmetic, not a hidden
    default.
  - prepare-for-pool-drain: graceful shutdown (Phase 26) returns pooled
    connections before process exit so a rolling deploy never leaves
    the server holding dead client sockets.

Aggregate connection budget (default configuration):

    per API instance      20 pool + 10 overflow  = 30
    per worker (sync)      5 pool                =  5
    per worker (async tasks) 5 (worker.config)  =  5
    alembic/admin (CLI)    5                     =  5

  2 API + 4 workers ≈ 100 connections — within a default PostgreSQL
  max_connections=100 only with headroom; docs/v42-reliability.md
  requires max_connections ≥ 3 × (instances × pool) + 20 for prod.
"""
import logging
import time

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def _positive_int(env_name: str, default: int) -> int:
    """Read a bounded positive pool knob from the environment.

    A non-integer or non-positive value is a configuration error: fail
    closed at import time rather than silently running an unlimited or
    zero-capacity pool.
    """
    import os

    raw = os.environ.get(env_name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{env_name} must be a positive integer, got {raw!r}")
    if value < 1:
        raise RuntimeError(f"{env_name} must be >= 1, got {value}")
    return value


engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_size=_positive_int("CYVRIX_DB_POOL_SIZE", 20),
    max_overflow=_positive_int("CYVRIX_DB_MAX_OVERFLOW", 10),
    pool_timeout=_positive_int("CYVRIX_DB_POOL_TIMEOUT", 30),
    pool_recycle=1800,
    pool_pre_ping=True,
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db(max_attempts: int = 5) -> None:
    """Initialize database connection with bounded startup retries.

    NOTE: Production schema is managed by Alembic migrations.
    This function only verifies the database is reachable.
    Do NOT call create_all() here — use 'alembic upgrade head' instead.

    V4.2: rolling deploys and container orchestration start the API while
    PostgreSQL is still accepting connections, so a single attempt on a
    cold cluster is a false negative. Retries are bounded (never a busy
    loop) and the final failure propagates — startup stays fail-closed.
    """
    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            async with engine.begin() as conn:
                await conn.execute(sa.text("SELECT 1"))
            return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < max_attempts:
                import asyncio

                await asyncio.sleep(min(1.0 * 2 ** (attempt - 1), 5.0))
    raise last_error  # type: ignore[misc]


async def check_db_health() -> bool:
    """Verify database is reachable. Returns True if healthy."""
    try:
        async with engine.begin() as conn:
            await conn.execute(sa.text("SELECT 1"))
        return True
    except Exception:
        return False


async def prepare_for_pool_drain() -> None:
    """V4.2 Phase 26 (graceful shutdown): dispose the engine's pooled
    connections before process exit.

    Terminated client connections would otherwise linger server-side
    until TCP reaping; a rolling deploy of N instances without this
    leaves a burst of dead connections against PostgreSQL.
    """
    try:
        await engine.dispose()
        logger.info("db_pool_disposed_for_shutdown")
    except Exception as exc:  # noqa: BLE001 — shutdown must never crash
        logger.warning("db_pool_dispose_failed err=%s", type(exc).__name__)
