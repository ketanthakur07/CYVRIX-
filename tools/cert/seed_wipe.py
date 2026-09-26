"""One-shot certification helper: wipe all rows in the e2e PostgreSQL.

Uses the repository's own wipe_all_tables (tests/conftest.py) so the
V3.8 append-only audit trigger handling matches test-harness policy.
Schema and alembic_version are left intact, so the running containers
keep serving the migrated schema — only the DATA is reset to empty.

Usage (from repo root):
  DATABASE_URL=postgresql+asyncpg://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test \
  DATABASE_URL_SYNC=postgresql://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test \
  REDIS_URL=redis://localhost:6380/0 \
  python tools/cert/seed_wipe.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tests"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "apps", "api"))

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test",
)
os.environ.setdefault(
    "DATABASE_URL_SYNC",
    "postgresql://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6380/0")

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from conftest import wipe_all_tables  # repository's own wipe policy


async def main() -> None:
    engine = create_async_engine(os.environ["DATABASE_URL"])
    try:
        async with engine.begin() as conn:
            await wipe_all_tables(conn)
            version = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar()
        print(f"e2e database wiped (rows only). alembic head = {version}")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
