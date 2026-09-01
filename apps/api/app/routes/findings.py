from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import Finding, Investigation, RiskAssessment, Repository, GithubInstallation, User
from app.schemas import (
    FindingDetailResponse, InvestigationResponse, RiskAssessmentResponse,
)
from app.auth import get_current_user

router = APIRouter(prefix="/api/findings", tags=["findings"])


async def _get_finding_with_auth(
    finding_id: UUID,
    user: User,
    db: AsyncSession,
) -> Finding:
    """Get a finding verifying ownership through the repository chain."""
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.investigation), selectinload(Finding.risk_assessment))
        .join(Repository, Repository.id == Finding.repository_id)
        .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
        .where(
            Finding.id == finding_id,
            GithubInstallation.user_id == user.id,
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found or access denied")
    return finding


@router.get("/{finding_id}")
async def get_finding(
    finding_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get finding detail with investigation and risk assessment.

    Authorization: user must own the repository.
    Does NOT expose raw_model_response.
    """
    finding = await _get_finding_with_auth(finding_id, user, db)

    inv_response = None
    if finding.investigation:
        inv = finding.investigation
        inv_response = InvestigationResponse(
            id=inv.id,
            finding_id=inv.finding_id,
            status=inv.status,
            verdict=inv.verdict,
            exploitability=inv.exploitability,
            exposure=inv.exposure,
            confidence=float(inv.confidence) if inv.confidence is not None else None,
            summary=inv.summary,
            evidence=inv.evidence,
            assumptions=inv.assumptions,
            uncertainties=inv.uncertainties,
            recommendation=inv.recommendation,
            created_at=inv.created_at,
            # NOTE: raw_model_response intentionally NOT included
        )

    risk_response = None
    if finding.risk_assessment:
        risk = finding.risk_assessment
        risk_response = RiskAssessmentResponse(
            id=risk.id,
            finding_id=risk.finding_id,
            risk_score=risk.risk_score,
            risk_level=risk.risk_level,
            risk_version=risk.risk_version,
            factors=risk.factors,
            created_at=risk.created_at,
        )

    return FindingDetailResponse(
        id=finding.id,
        scan_id=finding.scan_id,
        repository_id=finding.repository_id,
        fingerprint=finding.fingerprint,
        scanner=finding.scanner,
        vulnerability_id=finding.vulnerability_id,
        package_name=finding.package_name,
        package_version=finding.package_version,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        status=finding.status,
        created_at=finding.created_at,
        investigation=inv_response,
        risk_assessment=risk_response,
    )


@router.patch("/{finding_id}/status")
async def update_finding_status(
    finding_id: UUID,
    status: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update finding status (OPEN, CONFIRMED, FALSE_POSITIVE, RESOLVED).

    Authorization: user must own the repository.
    """
    finding = await _get_finding_with_auth(finding_id, user, db)

    valid_statuses = {"OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"}
    if status.upper() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    finding.status = status.upper()
    await db.commit()
    return {"ok": True, "status": finding.status}
