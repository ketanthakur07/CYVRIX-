"""V3.7 operator-API certification driver — REAL stack, REAL sessions.

Drives the live API (http://localhost:8001) with real HMAC-signed session
cookies (tests/create_session.py machinery) over real Redis/PostgreSQL:

  Phase 6/16  status + transitions over HTTP; step-up enforcement
  Phase 17    one-way door + reconciled resume over HTTP
  Phase 19    tenant isolation (404 cross-tenant, never 200/403 leak)
  Phase 20    capability matrix; authority fields create no bypass
  Phase 14    real rate limiting (429 after the configured hourly budget)

Usage (real stack up):
  RUN_INTEGRATION_TESTS=1 \
  DATABASE_URL=postgresql+asyncpg://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test \
  REDIS_URL=redis://localhost:6380/0 \
  SECRET_KEY=test-secret-key-for-integration-only-not-for-production-32chars! \
  ENVIRONMENT=development \
  python tests/cert_v37_ops_api.py
"""
import asyncio
import os
import sys
import time
import uuid as uuid_mod
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))
sys.path.insert(0, os.path.dirname(__file__))

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import (
    AsyncSession, async_sessionmaker, create_async_engine,
)

from app.models import (
    CircuitBreaker, GithubInstallation, ReconciliationRun, Repository, User,
)

API = os.environ.get("API_URL", "http://localhost:8001")
RESULTS = []


def record(name: str, ok: bool, evidence: str) -> None:
    RESULTS.append((name, ok, evidence))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  |  {evidence}")


async def main() -> int:
    engine = create_async_engine(os.environ["DATABASE_URL"], echo=False)
    SF = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    tag = int(time.time()) % 1_000_000
    from create_session import create_session  # real session machinery

    async with SF() as s:
        op_user = User(id=uuid_mod.uuid4(), email=f"v37ops-{tag}@cyvrix.local",
                       github_id=91_000_000 + tag, role="OPERATOR")
        plain_user = User(id=uuid_mod.uuid4(), email=f"v37usr-{tag}@cyvrix.local",
                          github_id=91_100_000 + tag, role="USER")
        other_user = User(id=uuid_mod.uuid4(), email=f"v37oth-{tag}@cyvrix.local",
                          github_id=91_200_000 + tag, role="OPERATOR")
        s.add_all([op_user, plain_user, other_user])
        await s.flush()
        inst = GithubInstallation(id=uuid_mod.uuid4(), user_id=op_user.id,
                                  installation_id=9_300_000 + tag,
                                  account_login="ops-org", account_type="Organization")
        s.add(inst)
        other_inst = GithubInstallation(id=uuid_mod.uuid4(), user_id=other_user.id,
                                        installation_id=9_400_000 + tag,
                                        account_login="other-org", account_type="Organization")
        s.add(other_inst)
        await s.flush()
        own_repo = Repository(id=uuid_mod.uuid4(), installation_id=inst.id,
                              github_repo_id=9_500_000 + tag, owner="ops-org",
                              name=f"own-repo-{tag}", default_branch="main", is_active=True)
        foreign_repo = Repository(id=uuid_mod.uuid4(), installation_id=other_inst.id,
                                  github_repo_id=9_600_000 + tag, owner="other-org",
                                  name=f"foreign-repo-{tag}", default_branch="main",
                                  is_active=True)
        s.add_all([own_repo, foreign_repo])
        await s.commit()
        op_id, plain_id, other_id, own_repo_id, foreign_repo_id = (
            op_user.id, plain_user.id, other_user.id, own_repo.id, foreign_repo.id)

    # Real session cookies (HMAC-signed, stored in real Redis)
    op_cookie = create_session(str(op_id))
    plain_cookie = create_session(str(plain_id))
    other_cookie = create_session(str(other_id))

    def stepup(user_id, fresh=True):
        """Seed/clear a fresh step-up marker in the REAL Redis."""
        import redis as redis_sync
        r = redis_sync.from_url(os.environ["REDIS_URL"], decode_responses=True)
        try:
            if fresh:
                r.set(f"stepup:{user_id}", str(int(datetime.now(timezone.utc).timestamp())))
            else:
                r.delete(f"stepup:{user_id}")
        finally:
            r.close()

    async with httpx.AsyncClient(base_url=API, timeout=30) as c:
        op = {"cookies": {"cyvrix_session": op_cookie}}
        plain = {"cookies": {"cyvrix_session": plain_cookie}}

        # Deterministic start: NORMAL state, no reconciliation history,
        # no step-up markers (the e2e DB/Redis persist between runs).
        from app.models import SystemControl
        async with SF() as s:
            row = (await s.execute(select(SystemControl).where(
                SystemControl.key == "operational_state"))).scalar_one()
            row.value = "NORMAL"
            await s.execute(__import__("sqlalchemy").delete(ReconciliationRun))
            await s.commit()
        stepup(op_id, fresh=False)

        # ── Authn / authz matrix ─────────────────────────────────────
        r = await c.get("/api/ops/status")
        record("E2E unauthenticated status → 401", r.status_code == 401,
               f"status={r.status_code}")
        r = await c.get("/api/ops/status", **plain)
        record("E2E USER role status → 403",
               r.status_code == 403 and r.json()["detail"] == "OPERATOR_CAPABILITY_REQUIRED",
               f"status={r.status_code} detail={r.json().get('detail')}")
        r = await c.get("/api/ops/status", **op)
        body = r.json()
        record("E2E OPERATOR status → 200",
               r.status_code == 200 and body["operational_state"] == "NORMAL",
               f"status={r.status_code} state={body.get('operational_state')}")

        # ── Ordinary operator action: pause (no step-up required) ────
        r = await c.post("/api/ops/state", json={"target": "PAUSED"}, **op)
        record("E2E pause (no step-up needed) → 200 PAUSED",
               r.status_code == 200 and r.json()["operational_state"] == "PAUSED",
               f"status={r.status_code} state={r.json().get('operational_state')}")

        # ── Authority fields create no bypass ────────────────────────
        r = await c.post("/api/ops/state",
                         json={"target": "EMERGENCY_STOP", "force": True,
                               "skip_authorization": True, "bypass": True}, **op)
        record("E2E force/bypass fields grant no authority (403 w/o step-up)",
               r.status_code == 403 and r.json()["detail"] == "STEP_UP_REQUIRED",
               f"status={r.status_code} detail={r.json().get('detail')}")
        stepup(op_id, fresh=True)
        r = await c.post("/api/ops/state", json={"target": "EMERGENCY_STOP"}, **op)
        record("E2E emergency stop (step-up) → 200 EMERGENCY_STOP",
               r.status_code == 200 and r.json()["operational_state"] == "EMERGENCY_STOP",
               f"status={r.status_code} state={r.json().get('operational_state')}")

        # ── One-way door + reconciled resume over HTTP ───────────────
        stepup(op_id, fresh=True)
        r = await c.post("/api/ops/state", json={"target": "NORMAL"}, **op)
        record("E2E ES→NORMAL refused (409 one-way door)",
               r.status_code == 409
               and r.json()["detail"] == "RESUME_FROM_EMERGENCY_STOP_REQUIRES_PAUSE_FIRST",
               f"status={r.status_code} detail={r.json().get('detail')}")
        stepup(op_id, fresh=True)
        r = await c.post("/api/ops/state", json={"target": "PAUSED"}, **op)
        record("E2E ES→PAUSED (reconciled resume) → 200", r.status_code == 200,
               f"status={r.status_code}")
        # Deterministic: the e2e DB persists between runs — remove any
        # past reconciliation runs so "no reconciliation" is really true.
        async with SF() as s:
            await s.execute(
                __import__("sqlalchemy").delete(ReconciliationRun))
            await s.commit()
        r = await c.post("/api/ops/state", json={"target": "NORMAL"}, **op)
        record("E2E resume without reconciliation → 409",
               r.status_code == 409 and "RECONCILIATION" in r.json()["detail"],
               f"status={r.status_code} detail={r.json().get('detail')}")
        async with SF() as s:
            s.add(ReconciliationRun(trigger="CERT", status="COMPLETED",
                                    findings=[], stats={"inspected": 0}))
            await s.commit()
        stepup(op_id, fresh=True)
        r = await c.post("/api/ops/state", json={"target": "NORMAL"}, **op)
        record("E2E resume after clean reconciliation → 200 NORMAL",
               r.status_code == 200 and r.json()["operational_state"] == "NORMAL",
               f"status={r.status_code} state={r.json().get('operational_state')}")

        # ── Repository control + tenant isolation ────────────────────
        r = await c.post(f"/api/ops/repositories/{own_repo_id}/control",
                         json={"control_state": "PAUSED", "reason": "cert"}, **op)
        record("E2E pause own repo → 200", r.status_code == 200,
               f"status={r.status_code} body={r.json()}")
        async with SF() as s:
            from app.services import ops_service
            ok, reason = await ops_service.assert_execution_allowed(
                s, repository_id=own_repo_id, scope="EXECUTION")
        record("E2E repo-pause blocks execution (server-side)",
               not ok and reason == "REPOSITORY_PAUSED", f"reason={reason}")
        r = await c.get(f"/api/ops/repositories/{foreign_repo_id}/control", **op)
        record("E2E cross-tenant repo read → 404 (no leak)", r.status_code == 404,
               f"status={r.status_code}")
        r = await c.post(f"/api/ops/repositories/{foreign_repo_id}/control",
                         json={"control_state": "BLOCKED", "reason": "x"}, **op)
        record("E2E cross-tenant repo control → 404 (no leak)", r.status_code == 404,
               f"status={r.status_code}")
        r = await c.post(f"/api/ops/repositories/{own_repo_id}/control",
                         json={"control_state": "ENABLED", "reason": "restore"}, **op)
        record("E2E restore own repo → 200", r.status_code == 200,
               f"status={r.status_code}")

        # ── Circuit breaker reset (step-up gated) ────────────────────
        stepup(op_id, fresh=False)  # clear markers: negative case first
        async with SF() as s:
            br = CircuitBreaker(repository_id=own_repo_id, scope="EXECUTION",
                                breaker_state="OPEN", consecutive_failures=3)
            s.add(br)
            await s.commit()
            br_id = br.id
        r = await c.post(f"/api/ops/breakers/{br_id}/reset", **op)
        record("E2E breaker reset without fresh step-up → 403",
               r.status_code == 403 and r.json()["detail"] == "STEP_UP_REQUIRED",
               f"status={r.status_code}")
        stepup(op_id, fresh=True)
        r = await c.post(f"/api/ops/breakers/{br_id}/reset", **op)
        record("E2E breaker reset with step-up → 200 CLOSED",
               r.status_code == 200 and r.json()["breaker_state"] == "CLOSED",
               f"status={r.status_code} state={r.json().get('breaker_state')}")
        async with SF() as s:
            row = (await s.execute(select(CircuitBreaker).where(
                CircuitBreaker.id == br_id))).scalar_one()
        record("E2E breaker reset persisted", row.breaker_state == "CLOSED"
               and row.consecutive_failures == 0,
               f"state={row.breaker_state} failures={row.consecutive_failures}")

        # ── Cross-tenant breaker reset (operator vs operator) ────────
        async with SF() as s:
            br2 = CircuitBreaker(repository_id=foreign_repo_id, scope="EXECUTION",
                                 breaker_state="OPEN", consecutive_failures=1)
            s.add(br2)
            await s.commit()
            br2_id = br2.id
        r = await c.post(f"/api/ops/breakers/{br2_id}/reset",
                         cookies={"cyvrix_session": op_cookie})
        record("E2E cross-tenant breaker reset → 404 (no leak)", r.status_code == 404,
               f"status={r.status_code}")

        # ── Real rate limiting (hourly budget) ───────────────────────
        hammer_cookie = create_session(str(other_id))  # dedicated bucket
        codes = []
        async with httpx.AsyncClient(base_url=API, timeout=30) as c2:
            for _ in range(35):
                rr = await c2.get("/api/ops/status",
                                  cookies={"cyvrix_session": hammer_cookie})
                codes.append(rr.status_code)
                if rr.status_code == 429:
                    break
        record("E2E rate limit → 429 within budget",
               codes[-1] == 429 and codes.count(200) >= 25,
               f"n={len(codes)} last={codes[-1]} ok200={codes.count(200)}")

    await engine.dispose()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n== V3.7 operator-API e2e: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed ==")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
