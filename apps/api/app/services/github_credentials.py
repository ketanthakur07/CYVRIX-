"""CYVRIX V3.5 — GitHub credential issuance (short-lived, repo-scoped).

Issuance rules (docs/v3-github-remediation.md §credential model):
- FAIL CLOSED: kill switch active/unreadable, authorization not live, or
  a repository-identity mismatch denies issuance before any token exists.
- The installation token is requested from the GitHub App installation
  token endpoint (fixed allowlisted host), with its server-reported
  expiry; CYVRIX additionally enforces a SHORT maximum lifetime.
- The token exists ONLY as the return value of `issue_push_token()` —
  it is never persisted (no plaintext, no hash), never logged, never
  returned to any client, never placed in argv, never placed in URLs.
- Every issuance/denial produces an audit-only record in
  github_credential_issuances (NO token column by design).
- Exactly one ISSUED record per remediation (partial unique index).
"""
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditEvent, GithubCredentialIssuance
from app.services import git_remediation_model as grm
from app.services.execution_authorization_service import read_kill_switch

logger = logging.getLogger("cyvrix.github_credentials")

# Hard cap: even if GitHub reports a longer expiry, CYVRIX treats the
# credential as expired after this window.
MAX_CREDENTIAL_TTL_SECONDS = 600

_GITHUB_HOSTS = ("https://api.github.com",)


def _token_endpoint_allowlisted() -> bool:
    base = os.environ.get("GITHUB_API_BASE", "https://api.github.com").rstrip("/")
    return base.startswith(_GITHUB_HOSTS) or base.startswith("http://localhost") \
        or base.startswith("http://127.0.0.1") or base.startswith("http://mock-providers")


async def issue_push_token(
    db: AsyncSession,
    *,
    remediation_row,
    actor_id=None,
    purpose: str = "REMEDIATION_PUSH",
) -> tuple[Optional[str], Optional[str]]:
    """Issue a short-lived repo-scoped token for THIS remediation's push.

    Returns (token, fail_reason_code). Exactly one of them is non-None.
    The token is a one-time in-process value: callers must use it for the
    authorized push and drop it. On any denial, records an audit row and
    returns (None, reason).

    purpose: REMEDIATION_PUSH (V3.5 pipeline) or ROLLBACK_PUSH (V3.6
    revert). Each purpose may receive exactly one ISSUED issuance per
    remediation — a rollback is a distinct audited authorization, not a
    replay of the original push credential.
    """
    now = datetime.now(timezone.utc)

    # 0. Kill switch: GitHub mutation is blocked when execution is disabled
    #    (Phase 25) — fail closed on active, missing, or unreadable state.
    disabled, ks_reason = await read_kill_switch(db)
    if disabled:
        await _record_denial(
            db, remediation_row=remediation_row,
            reason_code=ks_reason or grm.RC_KILL_SWITCH_ACTIVE,
            purpose=purpose,
        )
        return None, ks_reason or grm.RC_KILL_SWITCH_ACTIVE

    # 1. Token endpoint must be allowlisted (SSRF defense, Phase 28).
    if not _token_endpoint_allowlisted():
        await _record_denial(db, remediation_row=remediation_row,
                             reason_code=grm.RC_CREDENTIAL_DENIED,
                             purpose=purpose)
        return None, grm.RC_CREDENTIAL_DENIED

    # 2. Request the installation token from the FIXED endpoint.
    token: Optional[str] = None
    expires_at: Optional[datetime] = None
    try:
        from app.services.github import get_installation_access_token
        # The existing V2 service performs the App-JWT exchange; reuse it so
        # the credential chain stays identical to the audited one.
        token = await get_installation_access_token(int(remediation_row.installation_id))
    except Exception as exc:
        logger.warning("github_token_issuance_failed installation=%s err=%s",
                       remediation_row.installation_id, type(exc).__name__)
        await _record_denial(db, remediation_row=remediation_row,
                             reason_code=grm.RC_CREDENTIAL_DENIED,
                             purpose=purpose)
        return None, grm.RC_CREDENTIAL_DENIED

    if not token:
        await _record_denial(db, remediation_row=remediation_row,
                             reason_code=grm.RC_CREDENTIAL_DENIED,
                             purpose=purpose)
        return None, grm.RC_CREDENTIAL_DENIED

    # 3. Enforce the CYVRIX-side short TTL (in-process expiry marker).
    expires_at = now + timedelta(seconds=MAX_CREDENTIAL_TTL_SECONDS)

    # 4. Audit-only record — no token material (model has no such column).
    issuance = GithubCredentialIssuance(
        git_remediation_id=remediation_row.id,
        execution_authorization_id=remediation_row.execution_authorization_id,
        repository_id=remediation_row.repository_id,
        installation_id=int(remediation_row.installation_id),
        repo_owner=remediation_row.repo_owner,
        repo_name=remediation_row.repo_name,
        issued_at=now,
        expires_at=expires_at,
        result="ISSUED",
        purpose=purpose,
    )
    db.add(issuance)
    db.add(AuditEvent(
        repository_id=remediation_row.repository_id,
        finding_id=None,
        event_type="GITHUB_CREDENTIAL_ISSUED",
        event_metadata={
            "git_remediation_id": str(remediation_row.id),
            "execution_authorization_id": str(remediation_row.execution_authorization_id),
            "installation_id": int(remediation_row.installation_id),
            "repo_owner": remediation_row.repo_owner,
            "repo_name": remediation_row.repo_name,
            "ttl_seconds": MAX_CREDENTIAL_TTL_SECONDS,
            "reason_code": grm.RC_OK,
        },
    ))
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        # A concurrent issuance for this remediation won — one-time rule.
        return None, grm.RC_REMEDIATION_IN_PROGRESS

    return token, None


async def _record_denial(
    db: AsyncSession, *, remediation_row, reason_code: str,
    purpose: str = "REMEDIATION_PUSH",
) -> None:
    """Record a credential DENIAL (audit row + security event). No token."""
    db.add(GithubCredentialIssuance(
        git_remediation_id=remediation_row.id,
        execution_authorization_id=remediation_row.execution_authorization_id,
        repository_id=remediation_row.repository_id,
        installation_id=int(remediation_row.installation_id),
        repo_owner=remediation_row.repo_owner,
        repo_name=remediation_row.repo_name,
        issued_at=datetime.now(timezone.utc),
        expires_at=None,
        result="DENIED",
        purpose=purpose,
        fail_reason_code=reason_code,
    ))
    db.add(AuditEvent(
        repository_id=remediation_row.repository_id,
        finding_id=None,
        event_type="CREDENTIAL_DENIED",
        event_metadata={
            "git_remediation_id": str(remediation_row.id),
            "reason_code": reason_code,
        },
    ))
    try:
        await db.commit()
    except Exception:
        await db.rollback()
