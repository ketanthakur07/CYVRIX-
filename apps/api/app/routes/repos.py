import logging
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import (
    Repository, GithubInstallation, Scan, Finding, RiskAssessment, User,
)
from app.schemas import (
    RepositoryResponse, RepositoryToggleRequest, RepositorySummary,
    ScanResponse, SeverityCount, GithubInstallationResponse,
)
from app.auth import get_current_user, get_user_repository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/repositories", tags=["repositories"])


@router.get("")
async def list_repositories(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all repositories accessible by the current user.

    Returns both active and inactive repos so the user can manage them.
    """
    # Join through installation to ensure only user's repos are returned
    result = await db.execute(
        select(Repository)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(GithubInstallation.user_id == user.id)
        .order_by(Repository.created_at.desc())
    )
    repos = result.scalars().all()

    summaries = []
    for repo in repos:
        # Get latest scan
        scan_result = await db.execute(
            select(Scan).where(Scan.repository_id == repo.id).order_by(Scan.created_at.desc()).limit(1)
        )
        latest_scan = scan_result.scalar_one_or_none()

        # Get finding counts by severity
        finding_counts = await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.repository_id == repo.id)
            .group_by(Finding.severity)
        )
        severity_counts = [SeverityCount(severity=s, count=c) for s, c in finding_counts.all()]
        total_findings = sum(sc.count for sc in severity_counts)

        # Get overall risk score (latest)
        risk_score = None
        if latest_scan and latest_scan.status == "COMPLETED":
            risk_result = await db.execute(
                select(RiskAssessment)
                .join(Finding, Finding.id == RiskAssessment.finding_id)
                .where(Finding.repository_id == repo.id)
                .order_by(RiskAssessment.created_at.desc())
                .limit(1)
            )
            risk = risk_result.scalar_one_or_none()
            if risk:
                risk_score = risk.risk_score

        summaries.append(RepositorySummary(
            repository=RepositoryResponse.model_validate(repo),
            total_findings=total_findings,
            findings_by_severity=severity_counts,
            latest_scan=ScanResponse.model_validate(latest_scan) if latest_scan else None,
            risk_score=risk_score,
        ))

    return summaries


@router.get("/{repo_id}")
async def get_repository(
    repo_id: UUID,
    repo: Repository = Depends(get_user_repository),
    db: AsyncSession = Depends(get_db),
):
    """Get repository details with summary (ownership verified)."""
    scan_result = await db.execute(
        select(Scan).where(Scan.repository_id == repo.id).order_by(Scan.created_at.desc()).limit(1)
    )
    latest_scan = scan_result.scalar_one_or_none()

    finding_counts = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.repository_id == repo.id)
        .group_by(Finding.severity)
    )
    severity_counts = [SeverityCount(severity=s, count=c) for s, c in finding_counts.all()]
    total_findings = sum(sc.count for sc in severity_counts)

    return RepositorySummary(
        repository=RepositoryResponse.model_validate(repo),
        total_findings=total_findings,
        findings_by_severity=severity_counts,
        latest_scan=ScanResponse.model_validate(latest_scan) if latest_scan else None,
        risk_score=None,
    )


@router.post("/{repo_id}/activate")
async def activate_repository(
    repo_id: UUID,
    repo: Repository = Depends(get_user_repository),
    db: AsyncSession = Depends(get_db),
):
    """Activate a repository for scanning."""
    repo.is_active = True
    await db.commit()
    logger.info("Repository %s activated", repo_id)
    return {"ok": True, "is_active": True}


@router.post("/{repo_id}/deactivate")
async def deactivate_repository(
    repo_id: UUID,
    repo: Repository = Depends(get_user_repository),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a repository. Inactive repos cannot be scanned."""
    repo.is_active = False
    await db.commit()
    logger.info("Repository %s deactivated", repo_id)
    return {"ok": True, "is_active": False}


@router.patch("/{repo_id}/toggle")
async def toggle_repository(
    repo_id: UUID,
    body: RepositoryToggleRequest,
    repo: Repository = Depends(get_user_repository),
    db: AsyncSession = Depends(get_db),
):
    """Toggle repository active status."""
    repo.is_active = body.is_active
    await db.commit()
    return {"ok": True, "is_active": repo.is_active}


@router.get("/{repo_id}/findings")
async def list_repository_findings(
    repo_id: UUID,
    severity: str = Query(None),
    status: str = Query(None),
    repo: Repository = Depends(get_user_repository),
    db: AsyncSession = Depends(get_db),
):
    """List findings for a repository with optional filters (ownership verified)."""
    query = select(Finding).where(Finding.repository_id == repo.id)
    if severity:
        query = query.where(Finding.severity == severity.upper())
    if status:
        query = query.where(Finding.status == status.upper())
    query = query.order_by(Finding.created_at.desc())

    result = await db.execute(query)
    findings = result.scalars().all()

    from app.schemas import FindingResponse
    return [FindingResponse.model_validate(f) for f in findings]


@router.get("/{repo_id}/scans")
async def list_repository_scans(
    repo_id: UUID,
    repo: Repository = Depends(get_user_repository),
    db: AsyncSession = Depends(get_db),
):
    """List scans for a repository (ownership verified)."""
    result = await db.execute(
        select(Scan).where(Scan.repository_id == repo.id).order_by(Scan.created_at.desc())
    )
    scans = result.scalars().all()
    return [ScanResponse.model_validate(s) for s in scans]
