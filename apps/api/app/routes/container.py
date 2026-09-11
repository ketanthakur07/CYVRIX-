"""CYVRIX V2 Container Scanning Routes.

Provides endpoints for Dockerfile analysis and container security scanning.
All routes require authentication and ownership verification.
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Scan, Repository, GithubInstallation, User, Finding
from app.schemas import ScanResponse, ScanCreateRequest
from app.auth import get_current_user, require_active_repository

router = APIRouter(prefix="/api/repositories", tags=["container-scanning"])


async def _verify_repo_access(
    repository_id: UUID,
    user: User,
    db: AsyncSession,
) -> Repository:
    """Verify repository belongs to user's installation and return it."""
    result = await db.execute(
        select(Repository)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            Repository.id == repository_id,
            GithubInstallation.user_id == user.id,
        )
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found or access denied")
    return repo


@router.post("/{repository_id}/container-scan")
async def create_container_scan(
    repository_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a container/Dockerfile security scan.

    Verifies:
    - Repository exists and belongs to current user
    - Repository is active
    - No scan already in progress
    """
    repo = await _verify_repo_access(repository_id, user, db)

    if not repo.is_active:
        raise HTTPException(status_code=400, detail="Repository is inactive.")

    # Check for non-terminal scan in progress
    existing = await db.execute(
        select(Scan).where(
            Scan.repository_id == repo.id,
            Scan.status.notin_(["COMPLETED", "FAILED"]),
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Scan already in progress for this repository")

    # Create scan record with container scan trigger
    scan = Scan(
        repository_id=repo.id,
        status="QUEUED",
        trigger="container_scan",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Enqueue job
    from app.worker import enqueue_container_scan
    enqueue_container_scan(str(scan.id))

    return ScanResponse.model_validate(scan)


@router.post("/{repository_id}/log-analysis")
async def create_log_analysis(
    repository_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a log/security analysis scan.

    Verifies:
    - Repository exists and belongs to current user
    - Repository is active
    - No scan already in progress
    """
    repo = await _verify_repo_access(repository_id, user, db)

    if not repo.is_active:
        raise HTTPException(status_code=400, detail="Repository is inactive.")

    # Check for non-terminal scan in progress
    existing = await db.execute(
        select(Scan).where(
            Scan.repository_id == repo.id,
            Scan.status.notin_(["COMPLETED", "FAILED"]),
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Scan already in progress for this repository")

    # Create scan record
    scan = Scan(
        repository_id=repo.id,
        status="QUEUED",
        trigger="log_analysis",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Enqueue job
    from app.worker import enqueue_log_analysis
    enqueue_log_analysis(str(scan.id))

    return ScanResponse.model_validate(scan)
