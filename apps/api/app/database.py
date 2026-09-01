"""CYVRIX Database Configuration.

Production schema is managed by Alembic migrations.
Tests use create_all for isolation.
"""
import logging
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

engine = create_async_engine(settings.database_url, echo=False, pool_size=20, max_overflow=10)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Initialize database connection.

    NOTE: Production schema is managed by Alembic migrations.
    This function only verifies the database is reachable.
    Do NOT call create_all() here — use 'alembic upgrade head' instead.
    """
    async with engine.begin() as conn:
        await conn.execute(sa.text("SELECT 1"))


async def check_db_health() -> bool:
    """Verify database is reachable. Returns True if healthy."""
    try:
        async with engine.begin() as conn:
            await conn.execute(sa.text("SELECT 1"))
        return True
    except Exception:
        return False
