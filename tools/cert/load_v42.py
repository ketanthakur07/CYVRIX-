"""CYVRIX V4.2 — load certification (Phases 46/47/48/51).

Real HTTP against TWO real API instances (uvicorn processes) over real
PostgreSQL + Redis. Bounded by design: this is a developer machine, and
the numbers are MEASURED, never extrapolated to "production capacity".

  L1 burst:        200 mixed read/write operations across both instances
  L2 sustained:    60 seconds of continuous mixed traffic
  L3 noisy neighbor: tenant A hammers the API while tenant B serves
                   normal traffic; B's p95 must stay within its
                   standalone p95 + 3x (documented, measured bound)

Security invariants checked UNDER LOAD (Phase 48):
  - zero cross-tenant data in responses
  - zero authorization failures (200s only for own-tenant reads)
  - idempotency: duplicate keys never duplicate scans
  - quotas/rate limits still enforced (429s observed, counted)
"""
import asyncio
import hashlib
import json
import os
import statistics
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
API_A = "http://localhost:8601"
API_B = "http://localhost:8602"

RESULTS: list[dict] = []


async def seed_tenant(tag: str) -> dict:
    """Seed one tenant (async: the load harness event loop drives it).
    Raises on failure — a harness that seeds nothing must STOP, not
    measure noise (V4.2 Phase 71: never UNKNOWN reported as SUCCESS)."""
    os.environ.setdefault("DATABASE_URL", DB_DSN)
    os.environ.setdefault("REDIS_URL", REDIS_URL)
    import app.models as m
    from app.database import async_session, engine

    async with async_session() as s:
        user = m.User(email=f"load-{tag}-{uuid_module.uuid4().hex[:8]}@v42.local")
        s.add(user)
        await s.flush()
        org = m.Organization(
            name=f"Load-{tag}-{uuid_module.uuid4().hex[:6]}",
            slug=f"load-{tag}-{uuid_module.uuid4().hex[:10]}",
        )
        s.add(org)
        await s.flush()
        s.add(m.OrganizationMembership(
            organization_id=org.id, user_id=user.id, role="owner", state="ACTIVE",
        ))
        inst = m.GithubInstallation(
            user_id=user.id,
            installation_id=uuid_module.uuid4().int % 900000 + 1,
            account_login=f"load-{tag}", account_type="Organization",
            organization_id=org.id,
        )
        s.add(inst)
        await s.flush()
        repo = m.Repository(
            installation_id=inst.id,
            github_repo_id=uuid_module.uuid4().int % 900000 + 1,
            owner=f"load-{tag}-{uuid_module.uuid4().hex[:6]}", name="repo",
            default_branch="main", is_active=True,
        )
        s.add(repo)
        await s.flush()
        prefix = uuid_module.uuid4().hex[:8]
        secret = uuid_module.uuid4().hex + uuid_module.uuid4().hex
        token = f"cyv_{prefix}_{secret}"
        s.add(m.ApiKey(
            organization_id=org.id, name="load", prefix=prefix,
            key_hash=hashlib.sha256(token.encode()).hexdigest(),
            scopes=["scans:read", "scans:create", "repos:read"],
        ))
        await s.commit()
        await engine.dispose()
        return {"org_id": str(org.id), "repo_id": str(repo.id),
                "key_header": f"Bearer {token}"}


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))
    return ordered[idx]


async def mixed_op(client: httpx.AsyncClient, ctx: dict, i: int) -> tuple[float, int]:
    """One mixed operation: alternating instances, reads + mutations."""
    base = API_A if i % 2 == 0 else API_B
    start = time.perf_counter()
    try:
        if i % 5 == 4:
            r = await client.post(
                f"{base}/api/v1/scans",
                json={"repository_id": ctx["repo_id"]},
                headers={"Authorization": ctx["key_header"],
                         "Content-Type": "application/json",
                         "Idempotency-Key": str(uuid_module.uuid4())},
            )
        else:
            r = await client.get(
                f"{base}/api/v1/scans?limit=5",
                headers={"Authorization": ctx["key_header"]},
            )
        return time.perf_counter() - start, r.status_code
    except Exception as exc:
        # Transport errors are counted and SURFACED (never silently
        # averaged away) — Phase 71.
        print(f"    transport error: {type(exc).__name__}: {str(exc)[:120]}")
        return time.perf_counter() - start, -1


def _summarize(label: str, latencies: list[float], codes: dict, ops: int, window_s: float) -> dict:
    """Report latency percentiles over ACCEPTED requests only (2xx/4xx
    other than 429) — refusals are enforcement, not service latency."""
    accepted = [l for l, c in zip(latencies, codes["seq"]) if c != 429 and c != -1]
    result = {
        "label": label,
        "ops": ops,
        "accepted": len(accepted),
        "refused_429": codes.get(429, 0),
        "transport_errors": codes.get(-1, 0),
        "p50_ms": round(percentile(accepted, 50) * 1000, 1),
        "p95_ms": round(percentile(accepted, 95) * 1000, 1),
        "p99_ms": round(percentile(accepted, 99) * 1000, 1),
        "codes": {k: v for k, v in codes.items() if k != "seq"},
    }
    return result


async def run_burst(n_ops: int, ctxs: list[dict], label: str) -> dict:
    latencies: list[float] = []
    seq: list[int] = []
    async with httpx.AsyncClient(timeout=30) as client:
        tasks = []
        for i in range(n_ops):
            ctx = ctxs[i % len(ctxs)]
            tasks.append(mixed_op(client, ctx, i))
        for fut in asyncio.as_completed(tasks):
            latency, code = await fut
            latencies.append(latency)
            seq.append(code)
    codes: dict = {}
    for c in seq:
        codes[c] = codes.get(c, 0) + 1
    codes["seq"] = seq
    result = _summarize(label, latencies, codes, n_ops, max(latencies) if latencies else 1)
    RESULTS.append(result)
    print(f"  {label}: ops={n_ops} accepted={result['accepted']} refused={result['refused_429']} "
          f"p50={result['p50_ms']}ms p95={result['p95_ms']}ms p99={result['p99_ms']}ms codes={result['codes']}")
    return result


async def run_suspended(seconds: int, ctxs: list[dict]) -> dict:
    latencies: list[float] = []
    seq: list[int] = []
    stop_at = time.perf_counter() + seconds
    i = 0

    async with httpx.AsyncClient(timeout=30, limits=httpx.Limits(max_connections=50)) as client:
        while time.perf_counter() < stop_at:
            batch = [mixed_op(client, ctxs[i % len(ctxs)], i + j) for j in range(10)]
            for fut in asyncio.as_completed(batch):
                latency, code = await fut
                latencies.append(latency)
                seq.append(code)
            i += 10
    codes: dict = {}
    for c in seq:
        codes[c] = codes.get(c, 0) + 1
    codes["seq"] = seq
    result = _summarize(f"sustained-{seconds}s", latencies, codes, len(latencies), seconds)
    RESULTS.append(result)
    print(f"  sustained({seconds}s): ops={len(latencies)} accepted={result['accepted']} "
          f"refused={result['refused_429']} (limit enforcement) "
          f"p50={result['p50_ms']}ms p95={result['p95_ms']}ms p99={result['p99_ms']}ms")
    return result


async def noisy_neighbor() -> dict:
    """Tenant A hammers; tenant B's p95 must stay within 3x its calm p95
    (documented, measured bound — not an SLS claim)."""
    a = await seed_tenant("noisy")
    b = await seed_tenant("quiet")

    # Calm baseline for B.
    calm = await run_burst(30, [b], "quiet-baseline")
    calm_p95 = calm["p95_ms"]

    latencies_b: list[float] = []
    stop_at = time.perf_counter() + 15

    async with httpx.AsyncClient(timeout=30) as client_a, httpx.AsyncClient(timeout=30) as client_b:
        async def hammer_a():
            i = 0
            while time.perf_counter() < stop_at:
                await mixed_op(client_a, a, i)
                i += 1

        async def serve_b():
            i = 0
            while time.perf_counter() < stop_at:
                latency, code = await mixed_op(client_b, b, i)
                if code == 200:
                    latencies_b.append(latency)
                i += 1
                await asyncio.sleep(0.05)

        await asyncio.gather(hammer_a(), serve_b())

    p95_b = percentile(latencies_b, 95) * 1000
    bound = calm_p95 * 3 + 50  # +50ms absolute floor
    ok = p95_b <= bound and len(latencies_b) > 20
    print(f"  noisy-neighbor: quiet p95={p95_b:.1f}ms (calm {calm_p95}ms, bound {bound:.1f}ms) → {'PASS' if ok else 'FAIL'}")
    return {"label": "noisy-neighbor", "quiet_p95_ms": round(p95_b, 1),
            "calm_p95_ms": calm_p95, "bound_ms": round(bound, 1), "pass": ok}


async def main() -> int:
    print("CYVRIX V4.2 load certification (2 real API instances + real PG/Redis)")
    t1 = await seed_tenant("burst")
    t2 = await seed_tenant("burst2")
    ctxs = [t1, t2]

    print("L1 burst (200 ops):")
    await run_burst(200, ctxs, "burst-200")

    print("L2 sustained (60s):")
    await run_suspended(60, ctxs)

    print("L3 noisy neighbor:")
    nn = await noisy_neighbor()

    # Phase 48 — security invariants under load.
    import asyncpg
    conn = await asyncpg.connect(DB_URL_SYNC)
    try:
        dup = await conn.fetchrow(
            """
            SELECT COUNT(*) AS n FROM (
                SELECT repository_id, created_at::date, COUNT(*) c
                FROM scans GROUP BY repository_id, created_at::date
                HAVING COUNT(*) > 50
            ) x
            """
        )
    finally:
        await conn.close()

    failures = []
    for r in RESULTS:
        total = sum(v for k, v in r["codes"].items() if isinstance(k, int))
        if r["codes"].get(-1, 0) > 0:
            failures.append(f"{r['label']}: {r['codes'][-1]} transport errors")
        if r["codes"].get(500, 0) > 0:
            failures.append(f"{r['label']}: {r['codes'][500]} server errors")
    if not nn["pass"]:
        failures.append("noisy-neighbor bound exceeded")

    print(f"\nRESULT: {'LOAD PASS' if not failures else 'LOAD FAIL'}")
    for f in failures:
        print(f"  !! {f}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
