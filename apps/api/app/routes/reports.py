"""CYVRIX V2 Report Routes.

Provides endpoints for generating and retrieving security reports.
All routes require authentication and ownership verification.
"""
from uuid import UUID
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import (
    Report, Scan, Repository, GithubInstallation, User,
    Finding, Investigation, RiskAssessment,
)
from app.schemas import ReportResponse, ReportDetailResponse
from app.auth import get_current_user

router = APIRouter(prefix="/api/reports", tags=["reports"])


async def _verify_report_access(
    report_id: UUID,
    user: User,
    db: AsyncSession,
) -> Report:
    """Verify report belongs to user's repository."""
    result = await db.execute(
        select(Report)
        .join(Repository, Repository.id == Report.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            Report.id == report_id,
            GithubInstallation.user_id == user.id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found or access denied")
    return report


@router.post("/{scan_id}")
async def generate_report(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    body: dict = Body({}),
):
    """Generate a security report for a scan.

    Authorization: user must own the scan's repository.
    Supported formats: markdown and json.
    """
    requested_format = str(body.get("format", "markdown")).lower()
    if requested_format not in ("markdown", "json"):
        requested_format = "markdown"

    # Verify scan ownership
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

    # Gather findings, investigations, risk assessments
    findings_result = await db.execute(
        select(Finding)
        .options(
            selectinload(Finding.investigation),
            selectinload(Finding.risk_assessment),
        )
        .where(Finding.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()

    findings_data = []
    investigations_data = []
    risk_data = []

    for f in findings:
        findings_data.append({
            "id": str(f.id),
            "scan_id": str(f.scan_id),
            "repository_id": str(f.repository_id),
            "fingerprint": f.fingerprint,
            "scanner": f.scanner,
            "source_type": f.source_type,
            "vulnerability_id": f.vulnerability_id,
            "package_name": f.package_name,
            "package_version": f.package_version,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "status": f.status,
        })

        if f.investigation:
            inv = f.investigation
            investigations_data.append({
                "finding_id": str(f.id),
                "status": inv.status,
                "verdict": inv.verdict,
                "confidence": float(inv.confidence) if inv.confidence else None,
                "summary": inv.summary,
            })

        if f.risk_assessment:
            risk = f.risk_assessment
            risk_data.append({
                "finding_id": str(f.id),
                "risk_score": risk.risk_score,
                "risk_level": risk.risk_level,
            })

    # Get repository info
    repo_result = await db.execute(
        select(Repository).where(Repository.id == scan.repository_id)
    )
    repo = repo_result.scalar_one()

    scan_data = {
        "id": str(scan.id),
        "repository_name": f"{repo.owner}/{repo.name}",
        "status": scan.status,
        "commit_sha": scan.commit_sha,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }

    # Generate report
    from app.services.report_engine import generate_scan_report
    content = generate_scan_report(
        scan_data, findings_data, investigations_data, risk_data, format=requested_format
    )

    # Persist report
    report = Report(
        scan_id=scan.id,
        repository_id=scan.repository_id,
        report_type="SCAN",
        format=requested_format,
        content=content,
        created_at=datetime.now(timezone.utc),
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return ReportResponse.model_validate(report)


@router.get("/{report_id}")
async def get_report(
    report_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a report by ID.

    Authorization: user must own the report's repository.
    """
    report = await _verify_report_access(report_id, user, db)

    return ReportDetailResponse(
        id=report.id,
        scan_id=report.scan_id,
        repository_id=report.repository_id,
        report_type=report.report_type,
        format=report.format,
        content=report.content,
        created_at=report.created_at,
    )


@router.get("/scan/{scan_id}")
async def get_reports_for_scan(
    scan_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all reports for a scan.

    Authorization: user must own the scan's repository.
    """
    # Verify scan ownership
    scan_result = await db.execute(
        select(Scan)
        .join(Repository, Repository.id == Scan.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            Scan.id == scan_id,
            GithubInstallation.user_id == user.id,
        )
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found or access denied")

    reports_result = await db.execute(
        select(Report)
        .where(Report.scan_id == scan_id)
        .order_by(Report.created_at.desc())
    )
    reports = reports_result.scalars().all()

    return [ReportResponse.model_validate(r) for r in reports]
