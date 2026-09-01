"""CYVRIX V1 Authentication Routes.

Handles:
- GitHub OAuth login flow
- Session creation/destruction
- Current user info
- Logout
"""
import logging
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import User, GithubInstallation
from app.session import (
    create_session,
    destroy_session,
    decode_session_cookie,
    get_session_user_id,
)
from app.rate_limit import check_rate_limit, get_client_ip
from app.auth import get_current_user

logger = logging.getLogger("cyvrix.auth")

settings = get_settings()
router = APIRouter(prefix="/api/auth", tags=["auth"])

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
import os
GITHUB_USER_URL = os.environ.get("GITHUB_API_BASE", "https://api.github.com") + "/user"


@router.get("/login")
async def login(request: Request):
    """Initiate GitHub OAuth login flow.

    Generates a state parameter, stores it in Redis, and redirects to GitHub.
    """
    # Rate limit login initiation
    client_ip = get_client_ip(request)
    allowed, _ = await check_rate_limit(
        key=f"login_init:{client_ip}",
        max_requests=10,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )

    if not settings.github_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub authentication is not configured.",
        )

    # Generate and store state parameter
    state = secrets.token_urlsafe(32)
    import redis.asyncio as aioredis
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    await r.setex(f"github_oauth_state:{state}", 600, "pending")  # 10 min expiry
    await r.aclose()

    # Build GitHub OAuth URL
    params = {
        "client_id": settings.github_client_id,
        "scope": "read:user user:email read:org",
        "state": state,
    }
    github_url = f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"

    return RedirectResponse(url=github_url)


@router.get("/github/callback")
async def github_callback(
    code: str = "",
    state: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Handle GitHub OAuth callback.

    Validates state, exchanges code for token, creates/updates user, creates session.
    """
    # Validate state parameter
    if not state:
        return RedirectResponse(
            url=f"{settings.app_url}/connect?error=missing_state"
        )

    import redis.asyncio as aioredis
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    stored_state = await r.get(f"github_oauth_state:{state}")
    await r.delete(f"github_oauth_state:{state}")
    await r.aclose()

    if not stored_state:
        logger.warning("oauth_state_invalid state=%s", state[:8])
        return RedirectResponse(
            url=f"{settings.app_url}/connect?error=invalid_state"
        )

    if not code:
        return RedirectResponse(
            url=f"{settings.app_url}/connect?error=no_code"
        )

    # Exchange code for access token
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_resp = await client.post(
                GITHUB_TOKEN_URL,
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            if token_resp.status_code != 200:
                logger.warning("github_token_exchange_failed status=%d", token_resp.status_code)
                return RedirectResponse(
                    url=f"{settings.app_url}/connect?error=auth_failed"
                )
            token_data = token_resp.json()
            access_token = token_data.get("access_token")
            if not access_token:
                return RedirectResponse(
                    url=f"{settings.app_url}/connect?error=auth_failed"
                )

            # Get user info from GitHub
            user_resp = await client.get(
                GITHUB_USER_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            if user_resp.status_code != 200:
                return RedirectResponse(
                    url=f"{settings.app_url}/connect?error=github_unavailable"
                )
            github_user = user_resp.json()

    except httpx.TimeoutException:
        return RedirectResponse(
            url=f"{settings.app_url}/connect?error=github_unavailable"
        )
    except Exception as e:
        logger.error("github_oauth_error error=%s", str(e)[:200])
        return RedirectResponse(
            url=f"{settings.app_url}/connect?error=github_unavailable"
        )

    # Create or update user
    github_id = github_user.get("id")
    email = github_user.get("email") or f"{github_user.get('login', 'user')}@github.local"
    login = github_user.get("login", "unknown")

    result = await db.execute(
        select(User).where(User.github_id == github_id)
    )
    user = result.scalar_one_or_none()

    if user:
        user.email = email
        user.github_login = login
    else:
        user = User(
            github_id=github_id,
            email=email,
            github_login=login,
        )
        db.add(user)

    await db.commit()
    await db.refresh(user)

    # Create session
    _, _, cookie_value = await create_session(
        user.id,
        metadata={"login": login, "github_id": str(github_id)},
    )

    # Redirect to frontend with session cookie
    response = RedirectResponse(url=f"{settings.app_url}/dashboard")
    response.set_cookie(
        key=settings.session_cookie_name,
        value=cookie_value,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_same_site,
        path="/",
    )

    logger.info("login_success user_id=%s github_login=%s", user.id, login)
    return response


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Destroy the current session (logout)."""
    cookie_value = request.cookies.get(settings.session_cookie_name)
    if cookie_value:
        decoded = decode_session_cookie(cookie_value)
        if decoded:
            session_id, _ = decoded
            await destroy_session(session_id)

    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
    )
    return {"ok": True}


@router.get("/me")
async def get_me(user: User = Depends(get_current_user)):
    """Get current authenticated user info."""
    return {
        "id": str(user.id),
        "email": user.email,
        "github_login": getattr(user, "github_login", None),
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }
