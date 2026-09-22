"""CYVRIX V3.7 — Reconciliation engine.

Deterministic, idempotent reconciliation of externally-visible state.
Reconciliation NEVER mutates repositories, NEVER authorizes anything,
and NEVER auto-retries destructive operations. It classifies state,
marks rows, emits operational events, and reports.

Reconciled subjects:
- GitRemediation rows stuck in PUSHING / PR_CREATING (crash windows):
  the remote branch is queried (authoritative GitHub state) and the row
  is classified PUSHED / NOT_PUSHED / UNKNOWN — never guessed from a
  local process outcome.
- GitRemediation rows in INCONSISTENT (ambiguous push outcome): same
  query, same classification.
- ExecutionRun rows stuck in EXECUTING (watchdog): classified STUCK for
  operator attention; leases are marked EXPIRED when their TTL passed.
- Orphan workspaces under the configured workspace root: removed ONLY
  when they are provably orphaned (run terminal) and match the exact
  namespace prefix; ownership/state is proven before deletion.
"""
import logging
import os
import shutil
import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import (
    ExecutionLease, ExecutionRun, GitRemediation, ReconciliationRun, User,
)
from app.services import git_ops, ops_model as om
from app.services import ops_service

logger = logging.getLogger("cyvrix.reconciliation")

# Remediation states that indicate an interrupted or ambiguous pipeline
# at the push/PR boundary (crash windows — Phase 10/11/12).
_PUSH_WINDOW_STATES = ("PUSHING", "PR_CREATING", "INCONSISTENT")

_TERMINAL_REMEDIATION_STATES = frozenset({
    "COMPLETED", "PR_CREATED", "FAILED", "STALE", "CANCELLED",
    "LOCAL_ONLY", "COMMIT_ONLY", "PUSH_ONLY",
})


async def run_reconciliation(
    db: AsyncSession,
    *,
    trigger: str = "OPERATOR",
    actor: Optional[User] = None,
    now: Optional[datetime] = None,
) -> ReconciliationRun:
    """One full reconciliation pass. Idempotent: running it twice in a
    row converges (second pass finds nothing new to classify)."""
    now = now or datetime.now(timezone.utc)
    rec = ReconciliationRun(trigger=trigger, status="RUNNING", started_by_user_id=actor.id if actor else None)
    db.add(rec)
    await db.commit()
    await db.refresh(rec)

    findings: list[dict] = []
    stats = {"inspected": 0, "reconciled": 0, "orphans_removed": 0, "errors": 0}

    try:
        findings.extend(await _reconcile_push_windows(db, rec, findings, stats, now))
        findings.extend(await _reconcile_stuck_executions(db, rec, stats, now))
        findings.extend(await _expire_stale_leases(db, rec, stats, now))
        stats["orphans_removed"] = await _cleanup_orphan_workspaces(db, rec, findings, now)
        rec.status = "COMPLETED"
    except Exception as exc:  # never crash the caller; report failure
        import traceback
        rec.status = "FAILED"
        rec.detail = f"{type(exc).__name__}: {exc}"[:200]
        logger.warning("reconciliation_failed run=%s err=%s\n%s",
                       rec.id, type(exc).__name__, traceback.format_exc()[-800:])
        stats["errors"] += 1

    rec.findings = findings[:100]           # bounded
    rec.stats = stats
    rec.finished_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(rec)
    return rec


# ── Push-window reconciliation (Phase 11/12) ─────────────────────────


async def _reconcile_push_windows(db, rec, findings, stats, now) -> list[dict]:
    settings = get_settings()
    rows = (
        (await db.execute(
            select(GitRemediation).where(
                GitRemediation.remediation_state.in_(_PUSH_WINDOW_STATES)
            )
        ))
        .scalars()
        .all()
    )
    out: list[dict] = []
    for remediation in rows:
        stats["inspected"] += 1
        owner = remediation.repo_owner
        name = remediation.repo_name
        branch = remediation.remediation_branch
        expected_sha = remediation.committed_sha
        if not owner or not name or not branch:
            out.append(_finding(remediation, "UNKNOWN", "MISSING_IDENTITY"))
            continue

        classification = _query_remote_branch_state(
            owner, name, branch, expected_sha, settings
        )
        prior = remediation.remediation_state
        if classification == "PUSHED":
            # The push actually landed: record the durable outcome.
            remediation.remediation_state = "PUSHED"
            remediation.pushed_sha = expected_sha
            remediation.fail_reason_code = None
            remediation.fail_detail = "reconciled: remote branch matches committed sha"
            om_rc = om.RC_OK
        elif classification == "NOT_PUSHED":
            remediation.remediation_state = "FAILED"
            remediation.fail_reason_code = "PUSH_NOT_PERFORMED"
            remediation.fail_detail = "reconciled: remote branch absent; push did not happen"
            om_rc = "PUSH_NOT_PERFORMED"
        else:
            # UNKNOWN: remote differs from the local commit — do NOT
            # guess, mark INCONSISTENT for operator review (fail closed).
            remediation.remediation_state = "INCONSISTENT"
            remediation.fail_reason_code = "GITHUB_STATE_MISMATCH"
            remediation.fail_detail = "reconciled: remote branch exists with different sha"
            om_rc = "GITHUB_STATE_MISMATCH"

        remediation.finished_at = remediation.finished_at or now
        await ops_service._op_event(
            db,
            event_type=om.EVENT_JOB_RECONCILED,
            repository_id=remediation.repository_id,
            subject_type="GIT_REMEDIATION",
            subject_id=remediation.id,
            reason_code=om_rc,
            detail=f"{prior} → {remediation.remediation_state} ({classification})",
        )
        stats["reconciled"] += 1
        out.append(_finding(remediation, classification, prior))
    return out


def _query_remote_branch_state(
    owner: str, name: str, branch: str, expected_sha: Optional[str], settings
) -> str:
    """Query authoritative remote state for one branch (git ls-remote
    against the canonical remote URL — the same identity the remediation
    pipeline pushed to).

    Returns PUSHED | NOT_PUSHED | UNKNOWN. Network errors are UNKNOWN —
    never an optimistic assumption. Authentication is omitted on purpose:
    a public ref lookup needs no token, and a private repo that cannot be
    read anonymously classifies as UNKNOWN (fail closed), never guessed.
    """
    remote_base = os.environ.get(
        "GITHUB_REMOTE_BASE",
        os.environ.get("GITHUB_API_BASE", "https://github.com"),
    )
    if remote_base.startswith("https://api."):
        remote_base = remote_base.replace("api.", "", 1)
    try:
        remote_url = git_ops.build_remote_url(remote_base, owner, name)
        sha = git_ops.ls_remote(f"refs/heads/{branch}", remote_url)
    except Exception:
        return "UNKNOWN"
    if sha is None:
        return "NOT_PUSHED"
    if expected_sha and (sha or "").lower() == expected_sha.lower():
        return "PUSHED"
    return "UNKNOWN"


def _finding(remediation, classification: str, prior: str) -> dict:
    return {
        "subject": f"git_remediation:{remediation.id}",
        "repository_id": str(remediation.repository_id),
        "classification": classification,
        "reason": f"{prior} → classified {classification}",
    }


# ── Stuck executions (Phase 15) ──────────────────────────────────────


async def _reconcile_stuck_executions(db, rec, stats, now) -> list[dict]:
    stuck = await ops_service.detect_stuck_executions(db)
    stats["inspected"] += len(stuck)
    out = []
    for item in stuck:
        raw_subject = (item.get("subject") or "").split(":")[-1]
        try:
            subject_uuid = uuid_mod.UUID(raw_subject) if raw_subject else None
        except (ValueError, AttributeError):
            subject_uuid = None
        await ops_service._op_event(
            db,
            event_type="EXECUTION_STUCK_DETECTED",
            repository_id=item.get("repository_id"),
            subject_type="EXECUTION_RUN",
            subject_id=subject_uuid,
            reason_code=item.get("reason"),
        )
        out.append(item)
    return out


# ── Lease expiry (Phase 9/15) ────────────────────────────────────────


async def _expire_stale_leases(db, rec, stats, now) -> list[dict]:
    leases = (
        (await db.execute(select(ExecutionLease).where(ExecutionLease.lease_state == "ACTIVE")))
        .scalars()
        .all()
    )
    out = []
    for lease in leases:
        stats["inspected"] += 1
        expires = lease.expires_at if lease.expires_at.tzinfo else lease.expires_at.replace(tzinfo=timezone.utc)
        if now >= expires:
            lease.lease_state = "EXPIRED"
            await ops_service._op_event(
                db,
                event_type=om.EVENT_LEASE_EXPIRED,
                repository_id=lease.repository_id,
                subject_type=lease.subject_type,
                subject_id=lease.subject_id,
                reason_code=om.RC_LEASE_EXPIRED,
                detail=f"owner={lease.lease_owner_id}",
            )
            stats["reconciled"] += 1
            out.append({
                "subject": f"lease:{lease.id}",
                "repository_id": str(lease.repository_id),
                "classification": "LEASE_EXPIRED",
                "reason": f"owner={lease.lease_owner_id}",
            })
    return out


# ── Orphan workspace cleanup (Phase 34) ──────────────────────────────


async def _cleanup_orphan_workspaces(db, rec, findings, now) -> int:
    """Remove workspaces only when provably orphaned: the directory name
    must match the exact CYVRIX namespace (ws-<32-hex>) AND the run that
    created it must be in a terminal state with successful cleanup.
    Never deletes based on age alone; unknown directories are untouched.
    """
    root = os.environ.get("CYVRIX_SANDBOX_WORKSPACE_ROOT") or os.path.join(
        __import__("tempfile").gettempdir(), "cyvrix-sandboxes"
    )
    if not os.path.isdir(root):
        return 0
    removed = 0
    for entry in sorted(os.listdir(root))[:200]:  # bounded per pass
        ws_id = _parse_ws_dir(entry)
        if ws_id is None:
            continue  # not our namespace → never touch
        # PROVE state before deletion: resolve the ws id to its originating
        # run and require a terminal state. A live or unresolvable
        # workspace is NEVER deleted (ownership cannot be proven).
        try:
            ws_uuid = uuid_mod.UUID(ws_id)
        except ValueError:
            continue
        run = (
            (await db.execute(
                select(ExecutionRun).where(ExecutionRun.id == ws_uuid)
            ))
            .scalars()
            .first()
        )
        if run is None:
            continue  # cannot prove state → never delete
        if run.run_state not in _TERMINAL_RUN_STATES:
            continue  # live or ambiguous → never delete
        target = os.path.join(root, entry)
        try:
            shutil.rmtree(target)
            removed += 1
            await ops_service._op_event(
                db,
                event_type=om.EVENT_ORPHAN_CLEANUP,
                repository_id=run.repository_id,
                subject_type="EXECUTION_RUN",
                subject_id=run.id,
                reason_code=om.RC_OK,
                detail=f"removed orphan workspace {entry}",
            )
        except Exception as exc:
            logger.warning("orphan_cleanup_failed dir=%s err=%s", entry[:40], type(exc).__name__)
    return removed


_TERMINAL_RUN_STATES = frozenset({"RESULT_READY", "COMPLETED", "FAILED", "CLEANUP_FAILED"})


def _parse_ws_dir(entry: str) -> Optional[str]:
    """Parse a workspace directory in the exact CYVRIX namespace
    (ws-<32 hex chars>); anything else is not ours to touch."""
    parts = entry.split("-", 1)
    if len(parts) == 2 and parts[0] == "ws" and len(parts[1]) == 32:
        try:
            uuid_mod.UUID(parts[1])
            return parts[1]
        except ValueError:
            return None
    return None
