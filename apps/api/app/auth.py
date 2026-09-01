"""Authentication and authorization dependencies for CYVRIX V1.

Security properties:
- Real session-based authentication (no first-user fallback)
- Session validated via signed cookies + Redis lookup
- Authorization chain: user → installation → repository
- Fail closed: no session = unauthenticated
- No secrets in logs
"""
from uuid import UUID
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import User, GithubInstallation, Repository
from app.config import get_settings
from app.session import decode_session_cookie, get_session_user_id
from app.rate_limit import check_rate_limit, get_client_ip

settings = get_settings()


def _extract_session(request: Request) -> Optional[tuple[str, str]]:
    """Extract and decode session cookie from request.

    Returns (session_id, signature) or None if not present/malformed.
    """
    cookie_value = request.cookies.get(settings.session_cookie_name)
    if not cookie_value:
        return None
    return decode_session_cookie(cookie_value)


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get the current authenticated user from session.

    Security:
    - Extracts session cookie
    - Verifies HMAC signature
    - Looks up session in Redis
    - Loads user from database
    - Fails closed: no valid session = 401
    """
    session = _extract_session(request)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session_id, signature = session
    user_id = await get_session_user_id(session_id, signature)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Load user from database
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_user_installation(
    installation_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> GithubInstallation:
    """Verify a GitHub installation belongs to the current user."""
    result = await db.execute(
        select(GithubInstallation).where(
            GithubInstallation.id == installation_id,
            GithubInstallation.user_id == user.id,
        )
    )
    installation = result.scalar_one_or_none()
    if not installation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Installation not found or access denied",
        )
    return installation


async def get_user_repository(
    repo_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Repository:
    """Verify a repository belongs to an installation owned by the current user.

    Checks the full ownership chain: repository → installation → user
    """
    result = await db.execute(
        select(Repository)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            Repository.id == repo_id,
            GithubInstallation.user_id == user.id,
        )
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found or access denied",
        )
    return repo


async def require_active_repository(
    repo: Repository = Depends(get_user_repository),
) -> Repository:
    """Ensure the repository is active before allowing operations like scanning."""
    if not repo.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Repository is inactive. Activate it before scanning.",
        )
    return repo


async def check_auth_rate_limit(request: Request):
    """Rate-limit authentication-related endpoints.

    Uses client IP as identifier.
    """
    client_ip = get_client_ip(request)
    allowed, remaining = await check_rate_limit(
        key=f"auth:{client_ip}",
        max_requests=settings.auth_rate_limit_per_minute,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
        )
