from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Scan, Repository, GithubInstallation, User, Finding, Investigation, RiskAssessment
from app.schemas import (
    ScanResponse, ScanCreateRequest, FindingDetailResponse,
    InvestigationResponse, RiskAssessmentResponse,
)
from app.auth import get_current_user

router = APIRouter(prefix="/api/scans", tags=["scans"])


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


@router.post("")
async def create_scan(
    body: ScanCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a new scan for an active repository.

    Verifies:
    - Repository exists and belongs to current user
    - Repository is active
    - No scan already in progress for this repo
    """
    repo = await _verify_repo_access(body.repository_id, user, db)

    if not repo.is_active:
        raise HTTPException(status_code=400, detail="Repository is inactive. Activate it before scanning.")

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
        trigger="manual",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Enqueue job to Redis (HTTP request returns immediately)
    from app.worker import enqueue_scan
    enqueue_scan(str(scan.id))

    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}")
async def get_scan(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get scan status and details. Verifies the scan belongs to the authenticated user."""
    result = await db.execute(
        select(Scan)
        .join(Repository, Repository.id == Scan.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            Scan.id == scan_id,
            GithubInstallation.user_id == user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")

    # On-read reconciliation: if scan is non-terminal and started > 10 min ago, mark as failed
    from datetime import datetime, timezone, timedelta
    if scan.status not in ("COMPLETED", "FAILED") and scan.started_at:
        elapsed = datetime.now(timezone.utc) - scan.started_at
        if elapsed > timedelta(minutes=10):
            scan.status = "FAILED"
            scan.error_reason = "SCAN_TIMEOUT"
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()

    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get findings for a scan with investigation and risk data. Verifies ownership."""
    scan_result = await db.execute(
        select(Scan)
        .join(Repository, Repository.id == Scan.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            Scan.id == scan_id,
            GithubInstallation.user_id == user.id,
        )
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")

    findings_result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.investigation), selectinload(Finding.risk_assessment))
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at.desc())
    )
    findings = findings_result.scalars().all()

    results = []
    for f in findings:
        detail = FindingDetailResponse(
            id=f.id,
            scan_id=f.scan_id,
            repository_id=f.repository_id,
            fingerprint=f.fingerprint,
            scanner=f.scanner,
            vulnerability_id=f.vulnerability_id,
            package_name=f.package_name,
            package_version=f.package_version,
            title=f.title,
            description=f.description,
            severity=f.severity,
            status=f.status,
            created_at=f.created_at,
            investigation=InvestigationResponse.model_validate(f.investigation) if f.investigation else None,
            risk_assessment=RiskAssessmentResponse.model_validate(f.risk_assessment) if f.risk_assessment else None,
        )
        results.append(detail)

    return results
