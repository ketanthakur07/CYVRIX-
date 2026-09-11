"""CYVRIX API Application.

Production schema is managed by Alembic migrations.
Application startup verifies database connectivity only.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.config import get_settings
from app.routes import repos, scans, findings, github, dashboard, auth
from app.routes import container, recommendations, reports
from app.routes import actions
from app.session import get_redis, close_redis
import logging

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: verify database is reachable (schema managed by Alembic)
    try:
        await init_db()
    except Exception as e:
        if settings.is_production:
            raise
        logger.warning("Database connection check failed (non-production): %s", str(e)[:200])

    # Initialize Redis connection
    try:
        await get_redis()
    except Exception:
        pass  # Redis may not be available in tests

    yield

    # Shutdown: close Redis
    try:
        await close_redis()
    except Exception:
        pass


app = FastAPI(
    title="CYVRIX API",
    description="Autonomous Security Intelligence Platform",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — only configured origins, no wildcard credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# Include routers (V1)
app.include_router(auth.router)
app.include_router(repos.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(github.router)
app.include_router(dashboard.router)

# Include V2 routers
app.include_router(container.router)
app.include_router(recommendations.router)
app.include_router(reports.router)

# Include V3.1 router (proposals only — no execution capability)
app.include_router(actions.router)


@app.get("/api/health/live")
async def liveness():
    """Liveness probe: API is running."""
    return {"status": "alive", "version": "2.0.0"}


@app.get("/api/health/ready")
async def readiness():
    """Readiness probe: verify DB and Redis connectivity."""
    from app.database import check_db_health

    checks = {}
    healthy = True

    # Check PostgreSQL
    checks["postgres"] = await check_db_health()
    if not checks["postgres"]:
        healthy = False

    # Check Redis
    try:
        redis = await get_redis()
        await redis.ping()
        checks["redis"] = True
    except Exception:
        checks["redis"] = False
        healthy = False

    status_code = 200 if healthy else 503
    return JSONResponse(
        content={"status": "ready" if healthy else "not_ready", "checks": checks, "version": "1.0.0"},
        status_code=status_code,
    )


@app.get("/api/health")
async def health():
    """Basic health check (kept for backward compatibility)."""
    return {"status": "ok", "version": "1.0.0"}
