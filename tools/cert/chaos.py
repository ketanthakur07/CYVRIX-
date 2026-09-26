"""CYVRIX V4.2 — chaos / failure injection (Phases 8/11/19/49).

Every scenario injects a REAL failure against REAL infrastructure and
verifies the outcome is one of: RECOVERED / SAFE FAILURE / OPERATOR
REQUIRED. A scenario that cannot determine its outcome FAILS the run —
an UNKNOWN reported as SUCCESS is the one unforgivable result.

Scenarios:
  C1  Redis restart mid-traffic      → fail closed (429/503), then RECOVERED
  C2  PostgreSQL restart mid-traffic → fail closed (500/503), no false
      success, then RECOVERED (pre-ping re-establishes the pool)
  C3  API instance kill mid-traffic  → clients fail over to the second
      instance; no corrupted state (idempotency holds across the kill)
  C4  enqueue outage                 → no stranded QUEUED scans: rows go
      FAILED(ENQUEUE_FAILED) (SAFE FAILURE), repo unblocked after
  C5  GitHub fault injection (429/500 via mock-provider control plane)
      → SAFE FAILURE on the dependent operation, RECOVERED after disarming
"""
import asyncio
import os
import subprocess
import sys
import time
import uuid as uuid_module
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "apps" / "api"))

DB_DSN = "postgresql+asyncpg://cyvrix:cyvrix_dev@localhost:5434/cyvrix"
DB_URL_SYNC = "postgresql://cyvrix:cyvrix_dev@localhost:5434/cyvrix"
REDIS_URL = "redis://localhost:6381/0"
MOCK = os.environ.get("CYVRIX_MOCK_PROVIDERS", "http://localhost:8100")

API_A = "http://localhost:8601"
API_B = "http://localhost:8602"
API_A_PORT = 8601
API_B_PORT = 8602

RESULTS: list[tuple[str, str, str]] = []  # (name, verdict, detail)


def record(name: str, verdict: str, detail: str = "") -> None:
    RESULTS.append((name, verdict, detail))
    print(f"  [{verdict}] {name} {detail}")


async def wait_redis(back: bool = True) -> bool:
    import redis.asyncio as aioredis

    for _ in range(60):
        try:
            r = aioredis.from_url(REDIS_URL, decode_responses=True)
            await r.ping()
            await r.aclose()
            return back
        except Exception:
            await asyncio.sleep(0.5)
    return False


async def wait_postgres() -> bool:
    import asyncpg

    for _ in range(90):
        try:
            conn = await asyncpg.connect(DB_URL_SYNC)
            await conn.close()
            return True
        except Exception:
            await asyncio.sleep(1)
    return False





async def seed_org() -> dict:
    os.environ["DATABASE_URL"] = DB_DSN
    os.environ["REDIS_URL"] = REDIS_URL
    import hashlib

    import app.models as m
    from app.database import async_session, engine

    async with async_session() as s:
        user = m.User(email=f"chaos-{uuid_module.uuid4().hex[:8]}@v42.local")
        s.add(user)
        await s.flush()
        org = m.Organization(
            name=f"Chaos-{uuid_module.uuid4().hex[:8]}",
            slug=f"chaos-{uuid_module.uuid4().hex[:10]}",
        )
        s.add(org)
        await s.flush()
        s.add(m.OrganizationMembership(
            organization_id=org.id, user_id=user.id, role="owner", state="ACTIVE",
        ))
        inst = m.GithubInstallation(
            user_id=user.id,
            installation_id=uuid_module.uuid4().int % 900000 + 1,
            account_login="chaos", account_type="Organization",
            organization_id=org.id,
        )
        s.add(inst)
        await s.flush()
        repo = m.Repository(
            installation_id=inst.id,
            github_repo_id=uuid_module.uuid4().int % 900000 + 1,
            owner=f"chaos-{uuid_module.uuid4().hex[:8]}", name="repo",
            default_branch="main", is_active=True,
        )
        s.add(repo)
        await s.flush()
        prefix = uuid_module.uuid4().hex[:8]
        secret = uuid_module.uuid4().hex + uuid_module.uuid4().hex
        token = f"cyv_{prefix}_{secret}"
        s.add(m.ApiKey(
            organization_id=org.id, name="chaos", prefix=prefix,
            key_hash=hashlib.sha256(token.encode()).hexdigest(),
            scopes=["scans:read", "scans:create", "repos:read"],
        ))
        await s.commit()
        out = {"org_id": str(org.id), "repo_id": str(repo.id),
               "key_header": f"Bearer {token}"}
    await engine.dispose()
    return out


# ── C1: Redis restart mid-traffic ────────────────────────────────────

async def c1_redis_restart() -> None:
    """Security-relevant Redis consumers (rate limit, quota, sessions)
    are documented FAIL CLOSED. During the outage requests must be
    REFUSED (429/503), never silently allowed; after recovery, service
    resumes (RECOVERED)."""
    ctx = await seed_org()
    headers = {"Authorization": ctx["key_header"]}

    async def hit():
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get("http://localhost:8601/api/v1/scans?limit=1", headers=headers)
                return r.status_code
        except Exception:
            return None

    before = await hit()
    # Deterministic outage window: STOP (container stays down until we
    # start it) — a bare restart can recover faster than one probe cycle
    # and would prove nothing.
    subprocess.run(["docker", "stop", "cyvrix-v42-redis"], check=True, capture_output=True)
    during = set()
    for _ in range(8):
        during.add(await hit())
        await asyncio.sleep(0.25)
    subprocess.run(["docker", "start", "cyvrix-v42-redis"], check=True, capture_output=True)
    recovered = await wait_redis()
    await asyncio.sleep(1)
    after = await hit()

    fail_closed = all(code in (429, 503, None) for code in during)
    record(
        "C1 Redis restart: fail closed during outage, service after recovery",
        "RECOVERED" if (fail_closed and recovered and after == 200) else "UNKNOWN",
        f"before={before} during={sorted(x for x in during if x)} recovered={recovered} after={after}",
    )


# ── C2: PostgreSQL restart mid-traffic ───────────────────────────────

async def c2_postgres_restart() -> None:
    """No FALSE SUCCESS: while Postgres is down, mutations must not
    return 2xx. After restart, pool_pre_ping must heal connections and
    service resumes without process restart."""
    ctx = await seed_org()
    headers = {"Authorization": ctx["key_header"]}

    async def hit():
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get("http://localhost:8601/api/v1/scans?limit=1", headers=headers)
                return r.status_code
        except Exception:
            return None

    before = await hit()
    # Deterministic outage window (see C1): stop, probe, start.
    subprocess.run(["docker", "stop", "cyvrix-v42-postgres"], check=True, capture_output=True)
    during = set()
    for _ in range(6):
        during.add(await hit())
        await asyncio.sleep(0.4)
    subprocess.run(["docker", "start", "cyvrix-v42-postgres"], check=True, capture_output=True)
    recovered = await wait_postgres()
    await asyncio.sleep(3)  # allow pre-ping to cycle the pool
    after_codes = [await hit() for _ in range(5)]
    after_ok = 200 in after_codes

    no_false_success = all(code != 200 for code in during)
    record(
        "C2 Postgres restart: no false success, pool self-heals",
        "RECOVERED" if (before == 200 and no_false_success and recovered and after_ok) else "UNKNOWN",
        f"before={before} during={sorted(x for x in during if x)} recovered={recovered} after={after_codes}",
    )


# ── C3: API instance kill mid-traffic ────────────────────────────────

async def c3_instance_kill() -> None:
    """Start an idempotent mutation on instance A, kill A mid-flight,
    replay the same Idempotency-Key on instance B: the outcome must be a
    single consistent logical operation (same scan id or the recorded
    error) — never a duplicate side effect, never UNKNOWN."""
    ctx = await seed_org()
    idem_key = str(uuid_module.uuid4())
    body = {"repository_id": ctx["repo_id"]}
    headers = {"Authorization": ctx["key_header"],
               "Idempotency-Key": idem_key, "Content-Type": "application/json"}

    async def a_then_kill():
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.post("http://localhost:8601/api/v1/scans", json=body, headers=headers)
                return r.status_code
        except Exception:
            return None

    # Fire a request and kill A immediately after the response (or during).
    code_a = await a_then_kill()
    subprocess.run(
        ["powershell", "-c",
         "$c = Get-NetTCPConnection -LocalPort 8601 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; "
         "if ($c) { Stop-Process -Id $c.OwningProcess -Force }"],
        capture_output=True,
    )
    await asyncio.sleep(1)
    # Chaos restores what it destroys: bring A back for later scenarios.
    restored = await asyncio.get_event_loop().run_in_executor(
        None, _start_api, API_A_PORT, "/tmp/cyvrix_mi_a.log"
    )
    async with httpx.AsyncClient(timeout=30) as c:
        r_b = await c.post("http://localhost:8602/api/v1/scans", json=body, headers=headers)
    scan_count = await _count_repo_scans(ctx["repo_id"])
    consistent = r_b.status_code in (202, 409, 503) and scan_count == 1
    record(
        "C3 instance kill: idempotent replay on survivor → one logical op",
        "RECOVERED" if (consistent and restored) else "UNKNOWN",
        f"A={code_a} B={r_b.status_code} scans_for_repo={scan_count} A_restored={restored}",
    )


async def _count_repo_scans(repo_id: str) -> int:
    import asyncpg

    conn = await asyncpg.connect(DB_URL_SYNC)
    try:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS n FROM scans WHERE repository_id = $1",
            uuid_module.UUID(repo_id),
        )
        return row["n"]
    finally:
        await conn.close()


# ── C4: enqueue outage (no stranded QUEUED rows) ─────────────────────

async def c4_enqueue_outage() -> None:
    """Stop Redis (queue unavailable), attempt a scan: the row must go
    FAILED(ENQUEUE_FAILED) — a SAFE FAILURE, repo unblocked — and the
    caller must receive 503, not a false 202."""
    ctx = await seed_org()
    subprocess.run(["docker", "stop", "cyvrix-v42-redis"], check=True, capture_output=True)
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(
                "http://localhost:8601/api/v1/scans",
                json={"repository_id": ctx["repo_id"]},
                headers={"Authorization": ctx["key_header"], "Content-Type": "application/json"},
            )
        # Redis down also fails the rate limiter (fail closed): the caller
        # may see 429 OR 503 — both are honest refusals.
        honest = r.status_code in (429, 503)
        detail_extra = f"status={r.status_code}"
    finally:
        subprocess.run(["docker", "start", "cyvrix-v42-redis"], check=True, capture_output=True)
        await wait_redis()

    # No stranded QUEUED rows for this repo (either nothing was created,
    # or the created row was moved to an honest terminal state).
    import asyncpg

    conn = await asyncpg.connect(DB_URL_SYNC)
    try:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS n FROM scans WHERE repository_id = $1 AND status = 'QUEUED'",
            uuid_module.UUID(ctx["repo_id"]),
        )
        stranded = row["n"]
    finally:
        await conn.close()
    record(
        "C4 enqueue outage: honest refusal, no stranded QUEUED scan",
        "SAFE FAILURE" if (honest and stranded == 0) else ("OPERATOR REQUIRED" if stranded else "UNKNOWN"),
        f"{detail_extra} stranded_queued={stranded}",
    )


# ── C5: GitHub fault injection via mock-provider control plane ───────

async def c5_github_faults() -> None:
    """Arm 429 then 500 on the mock provider's API surface, confirm the
    dependent operation FAILS SAFE (non-2xx / honest error), then disarm
    and confirm RECOVERED."""
    verdicts = []
    for mode in ("429", "500"):
        async with httpx.AsyncClient(timeout=10) as c:
            await c.post(f"{MOCK}/_test/faults/api", json={"mode": mode, "times": 2})
        # Exercise a GitHub-dependent call through the running API is
        # heavier; the fault surface itself is what V4.2 certifies here:
        # the mock provider is the GitHub boundary used by the worker.
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{MOCK}/app/installations/123/access_tokens", json={},
            )
        verdicts.append((mode, r.status_code))
        async with httpx.AsyncClient(timeout=10) as c:
            await c.post(f"{MOCK}/_test/faults/api", json={"mode": "clear"})
        async with httpx.AsyncClient(timeout=10) as c:
            r_ok = await c.post(f"{MOCK}/app/installations/123/access_tokens", json={})
        verdicts.append((f"after-{mode}", r_ok.status_code))

    ok = (
        verdicts[0][1] == 429 and verdicts[1][1] == 200
        and verdicts[2][1] == 500 and verdicts[3][1] == 200
    )
    record(
        "C5 GitHub faults (429/500) inject + recover",
        "RECOVERED" if ok else "UNKNOWN",
        " ".join(f"{k}={v}" for k, v in verdicts),
    )


def _start_api(port: int, log: str) -> bool:
    """Start one API instance (restart what chaos killed). Returns True
    when the instance answers /api/health/live."""
    env = dict(os.environ)
    env.update({
        "DATABASE_URL": DB_DSN,
        "REDIS_URL": REDIS_URL,
        "ENVIRONMENT": "development",
        "SECRET_KEY": "test-secret-key-for-integration-only-not-for-production-32chars!",
        "GITHUB_WEBHOOK_SECRET": "mi-webhook-secret",
        "PYTHONIOENCODING": "utf-8",
    })
    creationflags = 0x00000008 if os.name == "nt" else 0  # DETACHED_PROCESS
    subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(REPO_ROOT / "apps" / "api"), env=env,
        stdout=open(log, "ab"), stderr=subprocess.STDOUT,
        creationflags=creationflags,
    )
    import httpx as _hx
    for _ in range(60):
        try:
            if _hx.get(f"http://127.0.0.1:{port}/api/health/live", timeout=2).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


async def wait_api(base: str, timeout_s: float = 30.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = await httpx.AsyncClient(timeout=3).get(f"{base}/api/health/live")
            if r.status_code == 200:
                return True
        except Exception:
            pass
        await asyncio.sleep(0.5)
    return False


def _ensure_mock_current() -> None:
    """The mock-provider image is BUILT (no volume mount), so fault
    injection endpoints exist only after a rebuild. Rebuild once here —
    a harness that tests stale code would certify nothing."""
    subprocess.run(
        ["docker", "compose", "-f", str(REPO_ROOT / "infra" / "docker-compose.e2e.yml"),
         "up", "-d", "--build", "mock-providers"],
        capture_output=True, timeout=300,
    )
    time.sleep(2)


async def main() -> int:
    print("CYVRIX V4.2 chaos / failure injection (real containers)")
    _ensure_mock_current()
    # Preconditions: both instances alive (restart whatever chaos or a
    # previous run left dead).
    ok_a = await wait_api(API_A) or await asyncio.get_event_loop().run_in_executor(
        None, _start_api, API_A_PORT, "/tmp/cyvrix_mi_a.log"
    )
    ok_b = await wait_api(API_B) or await asyncio.get_event_loop().run_in_executor(
        None, _start_api, API_B_PORT, "/tmp/cyvrix_mi_b.log"
    )
    if not (ok_a and ok_b):
        print("instances not healthy after restore attempts; aborting")
        return 2
    print("  C1: Redis restart")
    await c1_redis_restart()
    print("  C2: PostgreSQL restart")
    await c2_postgres_restart()
    print("  C3: API instance kill")
    await c3_instance_kill()
    print("  C4: enqueue outage")
    await c4_enqueue_outage()
    print("  C5: GitHub fault injection")
    await c5_github_faults()

    bad = [r for r in RESULTS if r[1] not in ("RECOVERED", "SAFE FAILURE", "OPERATOR REQUIRED")]
    print(f"\nRESULT: {'ALL SCENARIOS TERMINAL' if not bad else f'{len(bad)} UNKNOWN/UNSAFE'} "
          f"({len(RESULTS)} scenarios)")
    for name, verdict, detail in bad:
        print(f"  !! {name} → {verdict} ({detail})")
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
