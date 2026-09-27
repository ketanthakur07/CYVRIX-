"""CYVRIX Scan Worker.

Security properties:
- Credentials never logged
- Workspace always cleaned in finally block
- Clone URL constructed from authorized repo record only
- Worker runs as separate process from API
- Structured logging with safe identifiers
"""
import asyncio
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select, create_engine
from sqlalchemy.orm import Session, sessionmaker

from worker.config import get_settings
from worker.outbound_events import notify_commit_mismatch, notify_scan_outcome

settings = get_settings()

# Structured logger — never logs credentials
logger = logging.getLogger("cyvrix.worker")

# Sync engine for worker (RQ is sync)
engine = create_engine(settings.database_url.replace("+asyncpg", ""), pool_size=5)
SessionLocal = sessionmaker(bind=engine)

# Import models using sync path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "apps"))
from app.models import Scan, Repository, Dependency, Finding, Investigation, RiskAssessment, AuditEvent
from app.schemas import InvestigationResult
from app.services.scanner import (
    clone_repo, scan_repository, compute_fingerprint,
)
from app.services.investigation import run_investigation, InvestigationError
from app.services.risk_engine import calculate_risk_safe, RISK_ALGO_VERSION
from app.services.github import get_installation_access_token
from app.services.container_scanner import scan_containers
from app.services.log_analyzer import analyze_logs
from app.services.recommendation_engine import generate_deterministic_recommendation


def run_container_scan(scan_id: str):
    """Container/Dockerfile security scan pipeline."""
    logger.info("container_scan_started scan_id=%s", scan_id)
    db = SessionLocal()
    scan = None
    workspace = None

    try:
        scan = db.get(Scan, UUID(scan_id))
        if not scan:
            logger.error("scan_not_found scan_id=%s", scan_id)
            return {"error": "Scan not found"}

        repo = db.get(Repository, scan.repository_id)
        if not repo:
            _fail_scan(db, scan, "REPOSITORY_NOT_FOUND")
            return {"error": "Repository not found"}

        if not repo.is_active:
            _fail_scan(db, scan, "REPOSITORY_INACTIVE")
            return {"error": "Repository inactive"}

        installation = repo.installation
        if not installation:
            _fail_scan(db, scan, "INSTALLATION_NOT_FOUND")
            return {"error": "Installation not found"}

        workspace = tempfile.mkdtemp(prefix="cyvrix_container_")
        os.chmod(workspace, 0o700)

        try:
            _update_status(db, scan, "CLONING")

            token = asyncio.run(get_installation_access_token(installation.installation_id))
            clone_base = settings.github_clone_url_base
            if "mock-providers" in clone_base or "localhost" in clone_base:
                clone_url = f"http://{clone_base}/{repo.owner}/{repo.name}.git"
            else:
                clone_url = f"https://x-access-token:{token}@{clone_base}/{repo.owner}/{repo.name}.git"

            logger.info("clone_started scan_id=%s owner=%s repo=%s", scan_id, repo.owner, repo.name)
            commit_sha = clone_repo(clone_url, workspace, repo.default_branch)
            scan.commit_sha = commit_sha
            db.commit()
            del clone_url, token

            _update_status(db, scan, "SCANNING")

            scan_result = asyncio.run(scan_containers(
                workspace, str(repo.id),
            ))

            finding_ids = []
            for f_data in scan_result["findings"]:
                _persist_finding(db, repo, scan, f_data, finding_ids)
            db.commit()

            _update_status(db, scan, "ANALYZING")

            for fid in finding_ids:
                finding = db.get(Finding, fid)
                if finding:
                    _compute_risk(db, finding, None)
                    _generate_recommendation(db, finding)
            db.commit()

            _update_status(db, scan, "COMPLETED")

            db.add(AuditEvent(
                repository_id=repo.id,
                event_type="CONTAINER_SCAN_COMPLETED",
                event_metadata={
                    "scan_id": str(scan.id),
                    "findings_count": len(finding_ids),
                    "dockerfiles_found": scan_result["dockerfiles_found"],
                },
            ))
            db.commit()

            logger.info("container_scan_completed scan_id=%s findings=%d", scan_id, len(finding_ids))
            return {"ok": True, "findings": len(finding_ids)}

        finally:
            if workspace and os.path.exists(workspace):
                try:
                    shutil.rmtree(workspace, ignore_errors=True)
                except Exception:
                    pass

    except Exception as e:
        error_msg = f"CONTAINER_SCAN_FAILED: {str(e)[:200]}"
        if scan is not None:
            _fail_scan(db, scan, error_msg)
        logger.error("container_scan_failed scan_id=%s error=%s", scan_id, str(e)[:200])
        return {"error": str(e)[:500]}
    finally:
        if workspace and os.path.exists(workspace):
            try:
                shutil.rmtree(workspace, ignore_errors=True)
            except Exception:
                pass
        db.close()


def run_log_analysis(scan_id: str):
    """Log/security analysis pipeline."""
    logger.info("log_analysis_started scan_id=%s", scan_id)
    db = SessionLocal()
    scan = None
    workspace = None

    try:
        scan = db.get(Scan, UUID(scan_id))
        if not scan:
            logger.error("scan_not_found scan_id=%s", scan_id)
            return {"error": "Scan not found"}

        repo = db.get(Repository, scan.repository_id)
        if not repo:
            _fail_scan(db, scan, "REPOSITORY_NOT_FOUND")
            return {"error": "Repository not found"}

        if not repo.is_active:
            _fail_scan(db, scan, "REPOSITORY_INACTIVE")
            return {"error": "Repository inactive"}

        installation = repo.installation
        if not installation:
            _fail_scan(db, scan, "INSTALLATION_NOT_FOUND")
            return {"error": "Installation not found"}

        workspace = tempfile.mkdtemp(prefix="cyvrix_log_")
        os.chmod(workspace, 0o700)

        try:
            _update_status(db, scan, "CLONING")

            token = asyncio.run(get_installation_access_token(installation.installation_id))
            clone_base = settings.github_clone_url_base
            if "mock-providers" in clone_base or "localhost" in clone_base:
                clone_url = f"http://{clone_base}/{repo.owner}/{repo.name}.git"
            else:
                clone_url = f"https://x-access-token:{token}@{clone_base}/{repo.owner}/{repo.name}.git"

            logger.info("clone_started scan_id=%s owner=%s repo=%s", scan_id, repo.owner, repo.name)
            commit_sha = clone_repo(clone_url, workspace, repo.default_branch)
            scan.commit_sha = commit_sha
            db.commit()
            del clone_url, token

            _update_status(db, scan, "SCANNING")

            scan_result = asyncio.run(analyze_logs(
                workspace, str(repo.id),
            ))

            finding_ids = []
            for f_data in scan_result["findings"]:
                _persist_finding(db, repo, scan, f_data, finding_ids)
            db.commit()

            _update_status(db, scan, "ANALYZING")

            for fid in finding_ids:
                finding = db.get(Finding, fid)
                if finding:
                    _compute_risk(db, finding, None)
                    _generate_recommendation(db, finding)
            db.commit()

            _update_status(db, scan, "COMPLETED")

            db.add(AuditEvent(
                repository_id=repo.id,
                event_type="LOG_ANALYSIS_COMPLETED",
                event_metadata={
                    "scan_id": str(scan.id),
                    "findings_count": len(finding_ids),
                    "log_files_found": scan_result["log_files_found"],
                },
            ))
            db.commit()

            logger.info("log_analysis_completed scan_id=%s findings=%d", scan_id, len(finding_ids))
            return {"ok": True, "findings": len(finding_ids)}

        finally:
            if workspace and os.path.exists(workspace):
                try:
                    shutil.rmtree(workspace, ignore_errors=True)
                except Exception:
                    pass

    except Exception as e:
        error_msg = f"LOG_ANALYSIS_FAILED: {str(e)[:200]}"
        # A failed mid-pipeline flush leaves the session poisoned; the
        # failure handler must rollback before writing terminal state.
        db.rollback()
        if scan is not None:
            _fail_scan(db, scan, error_msg)
        logger.error("log_analysis_failed scan_id=%s error=%s", scan_id, str(e)[:200])
        return {"error": str(e)[:500]}
    finally:
        if workspace and os.path.exists(workspace):
            try:
                shutil.rmtree(workspace, ignore_errors=True)
            except Exception:
                pass
        db.close()


def run_scan(scan_id: str):
    """Main scan pipeline entry point. Called by RQ worker.

    Security:
    - Clone URL constructed from DB records, not client input
    - Credentials never logged
    - Workspace cleaned in finally block
    - All exceptions caught and recorded
    - V4.1 COMMIT BINDING: a scan carrying requested_commit_sha is bound
      to that exact commit. The actual clone SHA is compared to it and a
      mismatch fails the scan (COMMIT_MISMATCH) instead of silently
      analyzing a different commit — a stale CI/webhook request can
      never have its result attributed to the wrong commit.
    """
    logger.info("scan_started scan_id=%s", scan_id)
    db = SessionLocal()
    scan = None
    workspace = None

    try:
        scan = db.get(Scan, UUID(scan_id))
        if not scan:
            logger.error("scan_not_found scan_id=%s", scan_id)
            return {"error": "Scan not found"}

        # ── V4.2 at-least-once claim guard ──────────────────────────
        # Queue delivery is AT-LEAST-ONCE: a redelivered job after a
        # worker crash, a reconciliation race, or a late enqueue retry
        # must never re-run a scan that already reached a terminal
        # state. Non-terminal statuses (CLONING/SCANNING) are the SAME
        # logical job being retried after a crash — they proceed, and
        # artifact persistence below is idempotent so re-runs converge.
        if scan.status in ("COMPLETED", "FAILED"):
            logger.warning(
                "scan_claim_ignored_terminal scan_id=%s status=%s",
                scan_id, scan.status,
            )
            return {"ok": True, "skipped": "SCAN_TERMINAL"}

        repo = db.get(Repository, scan.repository_id)
        if not repo:
            _fail_scan(db, scan, "REPOSITORY_NOT_FOUND")
            logger.error("repository_not_found scan_id=%s", scan_id)
            return {"error": "Repository not found"}

        # Verify repository is still active before proceeding
        if not repo.is_active:
            _fail_scan(db, scan, "REPOSITORY_INACTIVE")
            logger.warning("repository_inactive scan_id=%s", scan_id)
            return {"error": "Repository inactive"}

        installation = repo.installation
        if not installation:
            _fail_scan(db, scan, "INSTALLATION_NOT_FOUND")
            return {"error": "Installation not found"}

        # Create unique temp workspace with restrictive permissions
        workspace = tempfile.mkdtemp(prefix="cyvrix_scan_")
        os.chmod(workspace, 0o700)  # Owner-only access

        try:
            _update_status(db, scan, "CLONING")

            # Construct clone URL from authorized DB records ONLY
            # Never use client-supplied URLs
            token = asyncio.run(get_installation_access_token(installation.installation_id))
            clone_base = settings.github_clone_url_base
            if "mock-providers" in clone_base or "localhost" in clone_base:
                clone_url = f"http://{clone_base}/{repo.owner}/{repo.name}.git"
            else:
                clone_url = f"https://x-access-token:{token}@{clone_base}/{repo.owner}/{repo.name}.git"

            # Log clone event without credentials
            logger.info(
                "clone_started scan_id=%s owner=%s repo=%s",
                scan_id, repo.owner, repo.name,
            )

            commit_sha = clone_repo(clone_url, workspace, repo.default_branch)
            scan.commit_sha = commit_sha

            # ── V4.1 commit binding: verify BEFORE any analysis ──────
            requested = (scan.requested_commit_sha or "").strip().lower()
            if requested and commit_sha and commit_sha.lower() != requested:
                # The repository advanced past the requested commit (or a
                # caller lied about it — the platform cannot tell and
                # does not need to). Refuse: no findings will ever be
                # produced for a commit other than the requested one.
                db.rollback()
                _fail_scan(db, scan, "COMMIT_MISMATCH")
                logger.warning(
                    "commit_binding_mismatch scan_id=%s requested=%s cloned=%s",
                    scan_id, requested[:8], str(commit_sha)[:8],
                )
                # V4.2 completion: subscribed receivers learn the scan
                # failed COMMIT_MISMATCH; CI-triggered scans leave a
                # SECURITY-CRITICAL CI_EVENT_COMMIT_MISMATCH witness.
                try:
                    repo_ref = db.get(Repository, scan.repository_id)
                    if repo_ref is not None:
                        notify_commit_mismatch(db, repo_ref, scan)
                except Exception:
                    pass
                return {"error": "COMMIT_MISMATCH"}
            db.commit()

            # Clone URL no longer needed — clear from memory
            del clone_url, token

            _update_status(db, scan, "SCANNING")

            # Run dependency scanner
            scan_result = asyncio.run(scan_repository(
                workspace,
                str(repo.id),
                str(scan.id),
            ))

            # Persist dependencies. V4.2: a redelivered job re-running
            # the same logical scan must CONVERGE, not duplicate — prior
            # scan-scoped dependency rows are replaced first (findings
            # are repo-scoped and dedup by fingerprint downstream).
            from sqlalchemy import delete as _sa_delete
            db.execute(
                _sa_delete(Dependency).where(Dependency.scan_id == scan.id),
                synchronize_session=False,
            )
            for dep in scan_result["dependencies"]:
                db_dep = Dependency(
                    scan_id=scan.id,
                    name=dep["name"][:500],  # Bound field length
                    version=dep["version"][:200],
                    ecosystem=dep["ecosystem"],
                    manifest_path=dep["manifest_path"][:1000],
                )
                db.add(db_dep)
            db.commit()

            # Persist findings (dedup via fingerprint)
            finding_ids = []
            for f_data in scan_result["findings"]:
                _persist_finding(db, repo, scan, f_data, finding_ids)
            db.commit()

            _update_status(db, scan, "ANALYZING")

            # Run investigations for HIGH/CRITICAL findings
            investigation_count = _run_investigations(
                db, scan, finding_ids, installation, repo, settings
            )

            # Compute risk for any remaining findings without investigation
            for fid in finding_ids:
                finding = db.get(Finding, fid)
                if finding and not db.execute(
                    select(RiskAssessment).where(RiskAssessment.finding_id == fid)
                ).scalar_one_or_none():
                    _compute_risk(db, finding, None)
            db.commit()

            # Mark scan completed
            _update_status(db, scan, "COMPLETED")

            # Audit event (no credentials)
            # Generate recommendations for findings
            for fid in finding_ids:
                finding = db.get(Finding, fid)
                if finding:
                    _generate_recommendation(db, finding)
            db.commit()

            # V4.2 completion: fan the REAL terminal state out to
            # subscribed webhook receivers (SCAN_COMPLETED + any findings
            # created by this run). Best-effort, never fatal.
            notify_scan_outcome(db, repo, scan, [])

            db.add(AuditEvent(
                repository_id=repo.id,
                event_type="SCAN_COMPLETED",
                event_metadata={
                    "scan_id": str(scan.id),
                    "findings_count": len(finding_ids),
                    "manifests_found": scan_result["manifests_found"],
                    "total_deps": scan_result["total_deps"],
                    "parse_errors": len(scan_result.get("parse_errors", [])),
                },
            ))
            db.commit()

            logger.info(
                "scan_completed scan_id=%s findings=%d",
                scan_id, len(finding_ids),
            )
            return {"ok": True, "findings": len(finding_ids)}

        finally:
            # Always clean workspace — guaranteed even on crash
            if workspace and os.path.exists(workspace):
                try:
                    shutil.rmtree(workspace, ignore_errors=True)
                    logger.info("workspace_cleaned scan_id=%s", scan_id)
                except Exception as e:
                    logger.warning("workspace_cleanup_failed scan_id=%s error=%s", scan_id, str(e)[:100])

    except Exception as e:
        error_msg = f"SCAN_FAILED: {str(e)[:200]}"
        # A failed mid-pipeline flush leaves the session poisoned; the
        # failure handler must rollback before writing terminal state.
        db.rollback()
        if scan is not None:
            _fail_scan(db, scan, error_msg)
        logger.error("scan_failed scan_id=%s error=%s", scan_id, str(e)[:200])
        return {"error": str(e)[:500]}
    finally:
        # Clean workspace one more time in case inner finally didn't run
        if workspace and os.path.exists(workspace):
            try:
                shutil.rmtree(workspace, ignore_errors=True)
            except Exception:
                pass
        db.close()


def _persist_finding(db: Session, repo, scan, f_data: dict, finding_ids: list):
    """Persist a V2 finding with dedup via fingerprint.

    Persists full V2 provenance, including source_type and evidence,
    so container and log findings are not dependent on database defaults
    for semantic correctness.

    Uses the database unique constraint as the final dedup backstop.
    """
    try:
        existing = db.execute(
            select(Finding).where(
                Finding.repository_id == repo.id,
                Finding.fingerprint == f_data["fingerprint"],
            )
        ).scalar_one_or_none()

        if existing:
            existing.scan_id = scan.id
            finding_ids.append(existing.id)
        else:
            finding = Finding(
                scan_id=scan.id,
                repository_id=repo.id,
                fingerprint=f_data["fingerprint"],
                scanner=f_data["scanner"],
                source_type=f_data.get("source_type") or "DEPENDENCY",
                vulnerability_id=str(f_data.get("vulnerability_id", ""))[:200],
                package_name=str(f_data.get("package_name", ""))[:500],
                package_version=str(f_data.get("package_version", ""))[:200],
                title=str(f_data["title"])[:1000],
                description=str(f_data.get("description", ""))[:5000],
                severity=f_data["severity"],
                status="OPEN",
                evidence=f_data.get("evidence"),
            )
            db.add(finding)
            db.flush()
            finding_ids.append(finding.id)
    except Exception as e:
        logger.warning("finding_persist_error scan_id=%s error=%s", scan.id, str(e)[:200])


def _run_investigations(db, scan, finding_ids, installation, repo, settings) -> int:
    """Run AI investigations for HIGH/CRITICAL findings. Returns count."""
    investigation_count = 0

    for fid in finding_ids:
        if investigation_count >= settings.max_llm_calls_per_scan:
            break

        finding = db.get(Finding, fid)
        if not finding:
            continue

        if finding.severity not in settings.investigate_severities:
            _compute_risk(db, finding, None)
            continue

        # Findings are deduplicated by fingerprint across scans, so a
        # finding may already carry an investigation (1:1 unique
        # constraint) from a previous scan of the same repository.
        # Reuse and re-run that row instead of inserting a duplicate:
        # a duplicate INSERT violates the constraint, poisons the
        # session, and leaves the scan stuck non-terminal (V4.1
        # release-certification regression).
        investigation = db.execute(
            select(Investigation).where(Investigation.finding_id == fid)
        ).scalar_one_or_none()
        if investigation is None:
            investigation = Investigation(
                finding_id=fid,
                status="RUNNING",
            )
            db.add(investigation)
        else:
            investigation.status = "RUNNING"
        db.commit()

        try:
            result = asyncio.run(_run_investigation_with_context(
                installation.installation_id,
                repo.owner,
                repo.name,
                finding,
            ))

            investigation.status = "COMPLETED"
            investigation.verdict = result.verdict
            investigation.exploitability = result.exploitability
            investigation.exposure = result.exposure
            investigation.confidence = result.confidence
            investigation.summary = result.summary
            investigation.evidence = [e.model_dump() for e in result.evidence]
            investigation.assumptions = result.assumptions
            investigation.uncertainties = result.uncertainties
            investigation.recommendation = result.recommendation
            investigation.raw_model_response = {"status": "completed"}

            _compute_risk(db, finding, result)
            investigation_count += 1

        except InvestigationError as e:
            investigation.status = "FAILED"
            investigation.raw_model_response = {"error": str(e)[:500]}
            _compute_risk(db, finding, None)
            logger.warning(
                "investigation_failed scan_id=%s finding_id=%s error=%s",
                scan.id, str(fid), str(e)[:200],
            )
        except Exception as e:
            investigation.status = "FAILED"
            investigation.raw_model_response = {"error": str(e)[:500]}
            _compute_risk(db, finding, None)
            logger.warning(
                "investigation_error scan_id=%s finding_id=%s error=%s",
                scan.id, str(fid), str(e)[:200],
            )

        db.commit()

    return investigation_count


async def _run_investigation_with_context(
    installation_id: int,
    owner: str,
    repo_name: str,
    finding,
) -> InvestigationResult:
    """Gather context deterministically, then call LLM."""
    from app.services.github import get_file_content, search_code

    evidence_files = []

    # Search for package usage
    if finding.package_name:
        try:
            search_results = await search_code(
                installation_id, owner, repo_name, finding.package_name
            )
            for item in search_results[:3]:
                path = item.get("path", "")
                if path:
                    try:
                        content = await get_file_content(
                            installation_id, owner, repo_name, path
                        )
                        evidence_files.append({
                            "path": path,
                            "content": content[:8000],
                        })
                    except Exception:
                        continue
        except Exception:
            pass

    # Also try to read the manifest
    if finding.package_name:
        manifest_candidates = [
            "package.json", "package-lock.json",
            "requirements.txt", "poetry.lock",
        ]
        for manifest in manifest_candidates:
            try:
                content = await get_file_content(
                    installation_id, owner, repo_name, manifest
                )
                if finding.package_name in content:
                    evidence_files.append({
                        "path": manifest,
                        "content": content[:4000],
                    })
                    break
            except Exception:
                continue

    return await run_investigation(
        package_name=finding.package_name or "unknown",
        package_version=finding.package_version or "",
        vulnerability_id=finding.vulnerability_id or "unknown",
        vuln_summary=finding.title,
        vuln_description=finding.description or "",
        manifest_path="",
        evidence_files=evidence_files,
    )


def _compute_risk(db: Session, finding, investigation_result):
    """Compute and persist risk assessment for a finding.

    NOTE: risk assessments are HISTORICAL by design — one row per scan
    run, never updated in place (the rescan-durability contract depends
    on it). Redelivery convergence applies to findings (fingerprint
    dedup), investigations (1:1 reuse), recommendations (1:1 update)
    and scan-scoped dependencies (delete+reinsert) — not here."""
    exposure = None
    exploitability = None
    confidence = None

    if investigation_result:
        exposure = investigation_result.exposure
        exploitability = investigation_result.exploitability
        confidence = investigation_result.confidence

    score, level, factors = calculate_risk_safe(
        finding.severity,
        exposure,
        exploitability,
        confidence,
    )

    db.add(RiskAssessment(
        finding_id=finding.id,
        risk_score=score,
        risk_level=level,
        risk_version=RISK_ALGO_VERSION,
        factors=factors.model_dump(),
    ))


def _generate_recommendation(db: Session, finding):
    """Generate a deterministic recommendation for a finding."""
    try:
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
            from app.models import Recommendation

            # V4.2: idempotent update-in-place (one recommendation per
            # finding, even across redelivered scan jobs). The row is
            # never deleted — ActionProposals may reference it.
            from sqlalchemy import select as _select
            recommendation = db.execute(
                _select(Recommendation).where(Recommendation.finding_id == finding.id)
            ).scalar_one_or_none()
            if recommendation is None:
                recommendation = Recommendation(finding_id=finding.id)
                db.add(recommendation)
            recommendation.status = "COMPLETED"
            recommendation.trust_level = rec["trust_level"]
            recommendation.title = rec["title"]
            recommendation.what = rec.get("what")
            recommendation.why = rec.get("why")
            recommendation.change = rec.get("change")
            recommendation.uncertainty = rec.get("uncertainty")
            recommendation.risk = rec.get("risk")
            recommendation.validation = rec.get("validation")
            recommendation.evidence = rec.get("evidence")
            recommendation.created_at = datetime.now(timezone.utc)
    except Exception as e:
        logger.warning("recommendation_generation_failed finding_id=%s error=%s", finding.id, str(e)[:100])


def _update_status(db: Session, scan: Scan, status: str):
    """Update scan status with timestamps."""
    scan.status = status
    if status == "CLONING":
        scan.started_at = datetime.now(timezone.utc)
    elif status in ("COMPLETED", "FAILED"):
        scan.completed_at = datetime.now(timezone.utc)
    db.commit()


def _fail_scan(db: Session, scan: Scan, reason: str):
    """Mark scan as failed with sanitized error reason.

    V4.2: never corrupt an honest terminal state — a scan that already
    COMPLETED is never flipped to FAILED by a late failure path, and an
    already-FAILED scan keeps its first failure reason (first cause is
    the diagnosable one)."""
    if scan.status == "COMPLETED":
        logger.warning(
            "fail_scan_refused_terminal scan_id=%s reason=%s",
            str(scan.id), str(reason)[:80],
        )
        db.rollback()
        return
    scan.status = "FAILED"
    scan.error_reason = reason[:500]
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    # V4.2 completion: a FAILED scan is a real event — subscribed
    # receivers are told the server-computed outcome (FAIL).
    try:
        repo_ref = db.get(Repository, scan.repository_id)
        if repo_ref is not None:
            notify_scan_outcome(db, repo_ref, scan, [])
    except Exception:
        pass
