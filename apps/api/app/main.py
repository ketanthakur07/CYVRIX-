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
from app.routes import actions, approvals
from app.routes import execution_authorization
from app.routes import execution_runs
from app.routes import git_remediation
from app.routes import ops as ops
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

    # V3.7: validate operational configuration — fail closed in
    # production on invalid security-sensitive settings.
    from app.services.ops_service import validate_ops_configuration
    ops_fail = validate_ops_configuration(settings)
    if ops_fail and settings.is_production:
        raise RuntimeError(f"Invalid operational configuration: {ops_fail}")
    if ops_fail:
        logger.warning("Operational configuration invalid (non-production): %s", ops_fail)

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


# V3.7 observability: per-request correlation id (Phase 27).
# Bounded, secret-free; the client MAY supply x-request-id, the server
# always decides what it stores. Response header aids operator triage.
@app.middleware("http")
async def request_id_middleware(request, call_next):
    import uuid as _uuid

    supplied = (request.headers.get("x-request-id") or "")[:64]
    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    request_id = supplied if supplied and set(supplied) <= safe_chars else _uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["x-request-id"] = request_id
    return response

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

# Include V3.2 router (human approval — authorization data only, still no execution)
app.include_router(approvals.router)

# Include V3.3 router (execution authorization — the final deterministic
# gate between APPROVED and FUTURE EXECUTION; authorization records only,
# NO execution capability of any kind)
app.include_router(execution_authorization.router)

# Include V3.4 router (sandboxed execution — the FIRST real execution.
# Internal service-identity admission only; every run consumes exactly
# one V3.3 authorization; isolated, bounded, non-publishing; NO Git/
# GitHub writes, NO PRs, NO deployments)
app.include_router(execution_runs.router)

# Include V3.5 router (controlled Git/GitHub remediation — branch/commit/
# push/PR after server-verified runs; exactly-once per run; service-identity
# pipeline execution; short-lived repo-scoped credentials; NO force push,
# NO default-branch push)
app.include_router(git_remediation.router)

# CYVRIX V3.6 — verification + rollback
from app.routes import verification_rollback as verification_rollback  # noqa: E402
app.include_router(verification_rollback.router)

# Include V3.7 router (operational control plane — operator API only.
# Controls the platform; NEVER authorizes a remediation: every gate
# here fails closed and no capability bypasses V3.1–V3.6 security)
app.include_router(ops.router)


@app.get("/api/health/live")
async def liveness():
    """Liveness probe: API is running (no dependency info exposed)."""
    return {"status": "alive", "version": "2.0.0"}


@app.get("/api/health/ready")
async def readiness():
    """Readiness probe: verify DB and Redis connectivity.

    A service may be alive but not ready; dependency failures here are
    reported as booleans only (no internal details exposed)."""
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
