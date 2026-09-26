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
from app.routes import audit
from app.routes import orgs as orgs
from app.routes import api_v1
from app.session import get_redis, close_redis
import logging
import re

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # V4.2 Phase 20: structured logging is opt-in via CYVRIX_LOG_FORMAT=json;
    # the default output is unchanged.
    from app.observability import configure_logging
    configure_logging()

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

    # V4.2 Phase 26 — graceful shutdown order: stop serving (caller),
    # close Redis, release pooled DB connections. A rolling deploy must
    # not leave dead sockets against PostgreSQL.
    try:
        await close_redis()
    except Exception:
        pass
    try:
        from app.database import prepare_for_pool_drain
        await prepare_for_pool_drain()
    except Exception:
        pass


app = FastAPI(
    title="CYVRIX API",
    description=(
        "CYVRIX security platform API. The versioned public surface is "
        "`/api/v1` (API-key authenticated, organization-scoped); all other "
        "routes are session-authenticated console operations."
    ),
    version="4.1.0",
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
    from app.observability import set_request_id as _set_request_id
    _set_request_id(request_id)
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
# push/PR after server-verified runs; at-most-once per run (UNIQUE guard,
# V4.2 Phase 6); service-identity
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
app.include_router(audit.router)

# CYVRIX V4.0 — platform foundation.
# Organizations/memberships/RBAC are a NAMESPACE + authorization layer
# around the V3 security chain, never a replacement for it. Organization
# administration cannot approve, authorize, or execute a remediation.
app.include_router(orgs.router)
app.include_router(orgs.invitation_router)

# CYVRIX V4.1 — versioned public API. API-key authenticated,
# organization-scoped from the key, deliberately narrower than the console
# API: it re-exports no workflow mutation and cannot bypass the V3 chain.
app.include_router(api_v1.router)

# CYVRIX V4.1 — inbound GitHub webhooks. SERVICE-class route: the caller is
# GitHub, authenticated by HMAC signature over the raw body. Not session,
# not API key, not on /api/v1. Signature-verified, replay-proof,
# installation/organization/repository-bound, and able to cause exactly one
# side effect: an analysis REQUEST. It can never reach the V3 chain.
from app.routes import webhooks as webhooks  # noqa: E402
app.include_router(webhooks.router)


# ── V4.1 public API error contract (Phase 13/14) ─────────────────────
#
# Only `/api/v1` is reshaped. The console API keeps its existing error
# shape, so an unrelated behavioural change is not smuggled in with the
# public contract. The public envelope is ADDITIVE over the V4.0 shape:
# `detail` is preserved verbatim, so a client written against V4.0 keeps
# working, and `code`/`message`/`request_id` are added.
from fastapi.exceptions import RequestValidationError as _ValidationError  # noqa: E402
from fastapi.exception_handlers import (  # noqa: E402
    http_exception_handler as _default_http_exception_handler,
    request_validation_exception_handler as _default_validation_handler,
)
from starlette.exceptions import HTTPException as _StarletteHTTPException  # noqa: E402
from app.routes.api_v1 import PublicApiError as _PublicApiError  # noqa: E402
from app.services.idempotency_service import (  # noqa: E402
    IdempotencyError as _IdempotencyError,
)

_PUBLIC_API_PREFIX = "/api/v1"

# Fixed, content-free messages. A public error never echoes request data,
# internals, or a stack trace.
_PUBLIC_ERROR_MESSAGES = {
    "API_KEY_REQUIRED": "An API key is required.",
    "API_KEY_INVALID": "The API key is missing, invalid, revoked, or expired.",
    "API_SCOPE_REQUIRED": "This API key does not carry the required scope.",
    "ORG_RATE_LIMITED": "Request budget for this class is exhausted.",
    "VALIDATION_ERROR": "The request is not valid.",
    "IDENTIFIER_INVALID": "Not found.",
    "NOT_FOUND": "Not found.",
}


def _code_from_detail(detail) -> str:
    """Extract a machine-readable token from an HTTPException detail.

    Only a SCREAMING_SNAKE token is accepted; free-form text is replaced by
    a status-derived code so internal phrasing never reaches a client.
    """
    candidate = None
    if isinstance(detail, str):
        candidate = detail
    elif isinstance(detail, dict):
        raw = detail.get("reason_code") or detail.get("code")
        if isinstance(raw, str):
            candidate = raw
    if candidate and re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", candidate):
        return candidate
    return "REQUEST_FAILED"


def _public_envelope(
    request,
    status_code: int,
    code: str,
    message: str,
    details=None,
) -> JSONResponse:
    body = {
        "detail": code,  # V4.0-compatible field, preserved
        "code": code,
        "message": message,
        "request_id": getattr(request.state, "request_id", None),
    }
    if details:
        body["details"] = details
    # Rate-limit headers survive an error response: a 429 without
    # `x-ratelimit-reset` tells a client nothing about when to retry. The
    # endpoint stashes them on request.state because the exception handler
    # builds a fresh response object.
    headers = getattr(request.state, "public_headers", None) or None
    return JSONResponse(status_code=status_code, content=body, headers=headers)


def _safe_validation_details(exc) -> list[dict]:
    """Location and rule only — never the submitted value.

    Pydantic errors can carry the offending input, which for a security
    API may be a credential. Only the field path and the rule name are
    exposed.
    """
    out: list[dict] = []
    for error in (exc.errors() or [])[:20]:
        loc = error.get("loc") or ()
        out.append(
            {
                "field": ".".join(str(part) for part in loc)[:200],
                "type": str(error.get("type") or "invalid")[:64],
            }
        )
    return out


@app.exception_handler(_PublicApiError)
async def _public_api_error_handler(request, exc: _PublicApiError):
    return _public_envelope(
        request, exc.status_code, exc.code, exc.message, exc.details
    )


@app.exception_handler(_StarletteHTTPException)
async def _public_aware_http_handler(request, exc: _StarletteHTTPException):
    if request.url.path.startswith(_PUBLIC_API_PREFIX):
        code = _code_from_detail(exc.detail)
        message = _PUBLIC_ERROR_MESSAGES.get(
            code,
            "Not found." if exc.status_code == 404 else "The request could not be completed.",
        )
        return _public_envelope(request, exc.status_code, code, message)
    return await _default_http_exception_handler(request, exc)


@app.exception_handler(_IdempotencyError)
async def _idempotency_error_handler(request, exc: _IdempotencyError):
    """An unusable client idempotency key is a client error, not a 500.

    Silently ignoring a malformed key would let a caller believe it had
    retry protection it does not have, so it is refused explicitly.
    """
    if exc.reason_code == "IDEMPOTENCY_RETRY":
        return _public_envelope(
            request, 409, exc.reason_code,
            "The previous attempt did not complete. Please retry.",
        )
    return _public_envelope(
        request, 400, exc.reason_code,
        "The Idempotency-Key header is not usable.",
    )


@app.exception_handler(_ValidationError)
async def _public_aware_validation_handler(request, exc: _ValidationError):
    if request.url.path.startswith(_PUBLIC_API_PREFIX):
        return _public_envelope(
            request,
            422,
            "VALIDATION_ERROR",
            _PUBLIC_ERROR_MESSAGES["VALIDATION_ERROR"],
            {"errors": _safe_validation_details(exc)},
        )
    return await _default_validation_handler(request, exc)


# ── V4.1 OpenAPI fidelity (Phase 18/63) ──────────────────────────────
#
# The generated schema is the contract, so the public API's real
# authentication requirement is declared on every public operation rather
# than described only in prose. Nothing is added that the server does not
# enforce: `/api/v1` genuinely requires a bearer API key on every route.

def _annotate_public_security(schema: dict) -> dict:
    components = schema.setdefault("components", {})
    schemes = components.setdefault("securitySchemes", {})
    schemes["ApiKeyBearer"] = {
        "type": "http",
        "scheme": "bearer",
        "description": (
            "Organization API key. Send `Authorization: Bearer "
            "cyv_<prefix>_<secret>`. The organization is derived from the "
            "key and can never be selected by the request."
        ),
    }
    for path, operations in (schema.get("paths") or {}).items():
        if not path.startswith(_PUBLIC_API_PREFIX):
            continue
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if isinstance(operation, dict):
                operation.setdefault("security", [{"ApiKeyBearer": []}])
    return schema


_base_openapi = app.openapi


def _openapi_with_public_security():
    if app.openapi_schema:
        return app.openapi_schema
    app.openapi_schema = _annotate_public_security(_base_openapi())
    return app.openapi_schema


app.openapi = _openapi_with_public_security


@app.get("/api/health/live")
async def liveness():
    """Liveness probe: API is running (no dependency info exposed)."""
    return {"status": "alive", "version": "4.1.0"}


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
