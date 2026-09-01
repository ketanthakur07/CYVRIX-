import logging
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import GithubInstallation, Repository, User
from app.schemas import GithubInstallationResponse, RepositoryResponse
from app.config import get_settings
from app.auth import get_current_user, get_user_installation, get_user_repository

router = APIRouter(prefix="/api/github", tags=["github"])
settings = get_settings()
logger = logging.getLogger(__name__)


@router.get("/connect")
async def connect_github():
    """Redirect to GitHub App installation URL."""
    if not settings.github_app_id:
        raise HTTPException(
            status_code=500,
            detail="GitHub App not configured. Set GITHUB_APP_ID in your environment.",
        )
    install_url = f"https://github.com/apps/{settings.github_app_id}/installations/new"
    return RedirectResponse(url=install_url)


@router.get("/callback")
async def github_callback(
    request: Request,
    installation_id: int = Query(..., description="GitHub installation ID"),
    setup_action: str = Query(None),
    state: str = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Handle GitHub App installation callback.

    Flow:
    1. GitHub redirects here after user installs the App
    2. We fetch the repository list via GitHub API
    3. Upsert installation and repositories into DB
    4. Redirect to frontend with success/error status
    """
    logger.info("GitHub callback received for installation_id=%s, action=%s", installation_id, setup_action)

    if not installation_id:
        return RedirectResponse(url=f"{settings.app_url}/connect?error=missing_installation_id")

    # Fetch installation repos from GitHub
    from app.services.github import (
        get_installation_repositories,
        GitHubAuthError,
        GitHubUnavailableError,
    )
    try:
        repos = await get_installation_repositories(installation_id)
    except GitHubAuthError as e:
        logger.error("GitHub auth failed during callback: %s", e)
        return RedirectResponse(url=f"{settings.app_url}/connect?error=auth_failed")
    except GitHubUnavailableError as e:
        logger.error("GitHub unavailable during callback: %s", e)
        return RedirectResponse(url=f"{settings.app_url}/connect?error=github_unavailable")
    except Exception as e:
        logger.error("Unexpected error during GitHub callback: %s", e)
        return RedirectResponse(url=f"{settings.app_url}/connect?error=github_unavailable")

    if not repos:
        return RedirectResponse(url=f"{settings.app_url}/connect?error=no_repositories")

    # Get current authenticated user from session
    from app.auth import _extract_session
    from app.session import get_session_user_id
    
    # For the GitHub callback, we need to get the user from the session cookie
    # The callback comes from GitHub, so we check if there's an existing session
    # If no session, we need to handle this gracefully
    session = _extract_session(request)
    user = None
    if session:
        session_id, signature = session
        user_id = await get_session_user_id(session_id, signature)
        if user_id:
            user_result = await db.execute(select(User).where(User.id == user_id))
            user = user_result.scalar_one_or_none()
    
    if not user:
        # No authenticated session - cannot link installation
        return RedirectResponse(url=f"{settings.app_url}/connect?error=not_authenticated")

    # Upsert installation (unique constraint on installation_id prevents duplicates)
    install_result = await db.execute(
        select(GithubInstallation).where(GithubInstallation.installation_id == installation_id)
    )
    installation = install_result.scalar_one_or_none()

    # Extract account info from the first repo's owner
    account_login = "unknown"
    account_type = "User"
    if repos and repos[0].get("owner"):
        account_login = repos[0]["owner"].get("login", "unknown")
        account_type = repos[0]["owner"].get("type", "User")

    if not installation:
        installation = GithubInstallation(
            user_id=user.id,
            installation_id=installation_id,
            account_login=account_login,
            account_type=account_type,
        )
        db.add(installation)
    else:
        installation.account_login = account_login
        installation.account_type = account_type

    await db.flush()

    # Upsert repositories (unique constraint on github_repo_id prevents duplicates)
    upserted_count = 0
    for repo_data in repos:
        repo_result = await db.execute(
            select(Repository).where(Repository.github_repo_id == repo_data["id"])
        )
        repo = repo_result.scalar_one_or_none()
        if not repo:
            repo = Repository(
                installation_id=installation.id,
                github_repo_id=repo_data["id"],
                owner=repo_data["owner"]["login"],
                name=repo_data["name"],
                default_branch=repo_data.get("default_branch", "main"),
                is_active=True,
            )
            db.add(repo)
            upserted_count += 1
        else:
            # Update branch if changed
            repo.default_branch = repo_data.get("default_branch", repo.default_branch)
            # Ensure repo is linked to this installation
            if repo.installation_id != installation.id:
                repo.installation_id = installation.id

    await db.commit()
    logger.info(
        "GitHub callback completed: installation_id=%s, repos_found=%d, repos_upserted=%d",
        installation_id, len(repos), upserted_count,
    )

    return RedirectResponse(url=f"{settings.app_url}/repositories?connected=true")


@router.get("/installations")
async def list_installations(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all GitHub installations for the current user."""
    result = await db.execute(
        select(GithubInstallation)
        .where(GithubInstallation.user_id == user.id)
        .order_by(GithubInstallation.created_at.desc())
    )
    installations = result.scalars().all()
    return [GithubInstallationResponse.model_validate(i) for i in installations]


@router.get("/installations/{installation_id}")
async def get_installation(
    installation_id: UUID,
    installation: GithubInstallation = Depends(get_user_installation),
):
    """Get details of a specific installation (ownership verified)."""
    return GithubInstallationResponse.model_validate(installation)
