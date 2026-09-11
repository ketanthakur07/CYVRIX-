"""CYVRIX V2 Recommendation Routes.

Provides endpoints for viewing and generating recommendations for findings.
All routes require authentication and ownership verification.
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Finding, Recommendation, Repository, GithubInstallation, User
from app.schemas import RecommendationResponse
from app.auth import get_current_user

router = APIRouter(prefix="/api/findings", tags=["recommendations"])


async def _get_finding_with_auth(
    finding_id: UUID,
    user: User,
    db: AsyncSession,
) -> Finding:
    """Get a finding verifying ownership."""
    result = await db.execute(
        select(Finding)
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


@router.get("/{finding_id}/recommendation")
async def get_recommendation(
    finding_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the recommendation for a finding (read-only).

    Authorization: user must own the finding's repository.
    Returns 404 if no recommendation exists.
    Use POST to generate a recommendation.
    """
    finding = await _get_finding_with_auth(finding_id, user, db)

    result = await db.execute(
        select(Recommendation).where(Recommendation.finding_id == finding_id)
    )
    recommendation = result.scalar_one_or_none()

    if not recommendation:
        raise HTTPException(status_code=404, detail="No recommendation available for this finding")

    return RecommendationResponse.model_validate(recommendation)


@router.post("/{finding_id}/recommendation")
async def generate_recommendation(
    finding_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate (or return existing) recommendation for a finding.

    Authorization: user must own the finding's repository.
    Idempotent: returns existing recommendation if one already exists.
    """
    from datetime import datetime, timezone
    from app.services.recommendation_engine import generate_deterministic_recommendation

    finding = await _get_finding_with_auth(finding_id, user, db)

    result = await db.execute(
        select(Recommendation).where(Recommendation.finding_id == finding_id)
    )
    recommendation = result.scalar_one_or_none()

    if recommendation:
        return RecommendationResponse.model_validate(recommendation)

    finding_dict = {
        "id": str(finding.id),
        "scanner": finding.scanner,
        "source_type": finding.source_type,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "vulnerability_id": finding.vulnerability_id,
        "package_name": finding.package_name,
        "package_version": finding.package_version,
        "evidence": finding.evidence or {},
    }

    rec = generate_deterministic_recommendation(finding_dict)
    if rec:
        recommendation = Recommendation(
            finding_id=finding.id,
            status="COMPLETED",
            trust_level=rec["trust_level"],
            title=rec["title"],
            description=rec.get("description"),
            what=rec.get("what"),
            why=rec.get("why"),
            change=rec.get("change"),
            uncertainty=rec.get("uncertainty"),
            risk=rec.get("risk"),
            validation=rec.get("validation"),
            evidence=rec.get("evidence"),
            created_at=datetime.now(timezone.utc),
        )
        db.add(recommendation)
        await db.commit()
        await db.refresh(recommendation)
        return RecommendationResponse.model_validate(recommendation)

    raise HTTPException(status_code=404, detail="No recommendation available for this finding")


@router.post("/{finding_id}/recommendation/validate")
async def validate_recommendation(
    finding_id: UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger recommendation re-validation for a finding.

    Re-validates the recommendation against current evidence and context.
    Advisory only — does not modify files, git, or external systems.
    Authorization: user must own the finding's repository.
    """
    from datetime import datetime, timezone
    from app.services.revalidation import validate_recommendation as run_revalidation

    finding = await _get_finding_with_auth(finding_id, user, db)

    result = await db.execute(
        select(Recommendation).where(Recommendation.finding_id == finding_id)
    )
    recommendation = result.scalar_one_or_none()

    if not recommendation:
        raise HTTPException(status_code=404, detail="No recommendation to validate")

    # Build dicts for the re-validation engine
    rec_dict = {
        "title": recommendation.title,
        "description": recommendation.description,
        "what": recommendation.what,
        "why": recommendation.why,
        "change": recommendation.change,
        "uncertainty": recommendation.uncertainty,
        "risk": recommendation.risk,
        "validation": recommendation.validation,
        "trust_level": recommendation.trust_level,
        "evidence": recommendation.evidence or [],
    }

    finding_dict = {
        "id": str(finding.id),
        "scanner": finding.scanner,
        "source_type": finding.source_type,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "vulnerability_id": finding.vulnerability_id,
        "package_name": finding.package_name,
        "package_version": finding.package_version,
        "evidence": finding.evidence or {},
    }

    # Run re-validation (advisory only — no side effects)
    validation_result = run_revalidation(rec_dict, finding_dict)

    # Persist validation state
    recommendation.validation_state = validation_result["validation_state"]
    recommendation.validation_details = {
        "checks": validation_result["checks"],
        "summary": validation_result["summary"],
    }
    recommendation.validated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(recommendation)

    return {
        "ok": True,
        "validation_state": validation_result["validation_state"],
        "trust_level": recommendation.trust_level,
        "summary": validation_result["summary"],
        "checks": validation_result["checks"],
    }
