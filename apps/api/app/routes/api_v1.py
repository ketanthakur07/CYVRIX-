"""CYVRIX V4.0 — public API foundation (/api/v1).

Deliberately narrow: only read-oriented, tenant-scoped resources that are
safe to expose to an organization API key. Internal workflow mutation
routes are NOT re-exported here — approving, authorizing, executing and
rolling back remain session-authenticated console operations (with their
full V3 chain).

Authentication: `Authorization: Bearer <api key>`. The organization is
derived from the KEY; the request cannot select it. Every query is scoped
to that organization. A key without the required scope is 403.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import (
    ActionProposal, Finding, GithubInstallation, Repository,
)
from app.services.org_auth import api_key_auth, rate_limit_org, require_api_scope

logger = logging.getLogger("cyvrix.api_v1")
router = APIRouter(prefix="/api/v1", tags=["public-api"])


class ApiIdentityOut(BaseModel):
    organization_id: str
    key_name: str
    key_prefix: str
    scopes: list[str]


class RepositoryOut(BaseModel):
    id: str
    owner: str
    name: str
    default_branch: str
    is_active: bool


class FindingOut(BaseModel):
    id: str
    repository_id: str
    title: str
    severity: str
    status: str
    source_type: str
    vulnerability_id: Optional[str] = None


class ActionProposalOut(BaseModel):
    id: str
    repository_id: str
    action_type: str
    status: str
    risk_level: str
    policy_decision: str
    action_digest: str


@router.get("/me", response_model=ApiIdentityOut)
async def api_identity(
    request: Request,
    key=Depends(api_key_auth),
):
    """Identity for the presented key. Reveals no secret material."""
    await rate_limit_org(request, org_id=key.organization_id, bucket="v1-read", limit=600)
    return ApiIdentityOut(
        organization_id=str(key.organization_id),
        key_name=key.name,
        key_prefix=key.prefix,
        scopes=list(key.scopes or []),
    )


@router.get("/repositories", response_model=list[RepositoryOut])
async def list_repositories(
    request: Request,
    key=Depends(require_api_scope("repositories:read")),
    db: AsyncSession = Depends(get_db),
):
    await rate_limit_org(request, org_id=key.organization_id, bucket="v1-read", limit=600)
    rows = (
        await db.execute(
            select(Repository)
            .join(GithubInstallation,
                  Repository.installation_id == GithubInstallation.id)
            .where(GithubInstallation.organization_id == key.organization_id)
            .order_by(Repository.created_at.asc())
            .limit(500)
        )
    ).scalars().all()
    return [
        RepositoryOut(
            id=str(r.id), owner=r.owner, name=r.name,
            default_branch=r.default_branch, is_active=bool(r.is_active),
        )
        for r in rows
    ]


@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    request: Request,
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    key=Depends(require_api_scope("findings:read")),
    db: AsyncSession = Depends(get_db),
):
    await rate_limit_org(request, org_id=key.organization_id, bucket="v1-read", limit=600)
    q = (
        select(Finding)
        .join(Repository, Finding.repository_id == Repository.id)
        .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
        .where(GithubInstallation.organization_id == key.organization_id)
        .order_by(Finding.created_at.desc())
        .limit(limit)
    )
    if severity:
        q = q.where(Finding.severity == severity.upper())
    rows = (await db.execute(q)).scalars().all()
    return [
        FindingOut(
            id=str(f.id), repository_id=str(f.repository_id), title=f.title,
            severity=f.severity, status=f.status, source_type=f.source_type,
            vulnerability_id=f.vulnerability_id,
        )
        for f in rows
    ]


@router.get("/actions", response_model=list[ActionProposalOut])
async def list_actions(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    key=Depends(require_api_scope("actions:read")),
    db: AsyncSession = Depends(get_db),
):
    await rate_limit_org(request, org_id=key.organization_id, bucket="v1-read", limit=600)
    rows = (
        await db.execute(
            select(ActionProposal)
            .join(Repository, ActionProposal.repository_id == Repository.id)
            .join(GithubInstallation, Repository.installation_id == GithubInstallation.id)
            .where(GithubInstallation.organization_id == key.organization_id)
            .order_by(ActionProposal.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return [
        ActionProposalOut(
            id=str(a.id), repository_id=str(a.repository_id),
            action_type=a.action_type, status=a.status, risk_level=a.risk_level,
            policy_decision=a.policy_decision, action_digest=a.action_digest,
        )
        for a in rows
    ]
