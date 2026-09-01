from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Repository, Scan, Finding, GithubInstallation, User
from app.schemas import DashboardSummary, SeverityCount, ScanResponse
from app.auth import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
async def get_dashboard_summary(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get dashboard summary data for the authenticated user. Read-only, never triggers scans or LLM calls."""
    # Only count resources owned by the authenticated user
    user_installation_ids = await db.execute(
        select(GithubInstallation.id).where(GithubInstallation.user_id == user.id)
    )
    installation_ids = [row[0] for row in user_installation_ids.all()]

    # Total counts scoped to user
    repo_count = (await db.execute(
        select(func.count(Repository.id))
        .where(Repository.installation_id.in_(installation_ids))
    )).scalar() or 0
    scan_count = (await db.execute(
        select(func.count(Scan.id))
        .join(Repository, Repository.id == Scan.repository_id)
        .where(Repository.installation_id.in_(installation_ids))
    )).scalar() or 0
    finding_count = (await db.execute(
        select(func.count(Finding.id))
        .where(Finding.repository_id.in_(
            select(Repository.id).where(Repository.installation_id.in_(installation_ids))
        ))
    )).scalar() or 0

    # Findings by severity (scoped to user)
    severity_counts = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.repository_id.in_(
            select(Repository.id).where(Repository.installation_id.in_(installation_ids))
        ))
        .group_by(Finding.severity)
    )
    findings_by_severity = [
        SeverityCount(severity=s, count=c) for s, c in severity_counts.all()
    ]

    # Recent scans (scoped to user)
    recent_result = await db.execute(
        select(Scan)
        .join(Repository, Repository.id == Scan.repository_id)
        .where(Repository.installation_id.in_(installation_ids))
        .order_by(Scan.created_at.desc())
        .limit(10)
    )
    recent_scans = [ScanResponse.model_validate(s) for s in recent_result.scalars().all()]

    return DashboardSummary(
        total_repositories=repo_count,
        total_scans=scan_count,
        total_findings=finding_count,
        findings_by_severity=findings_by_severity,
        recent_scans=recent_scans,
    )
