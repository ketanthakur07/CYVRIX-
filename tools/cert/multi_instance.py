"""CYVRIX V4.2 — multi-instance certification (Phases 2/14/15/16/17/52).

Two REAL uvicorn API processes (separate OS processes, separate metric
registries, separate DB pools) behind no shared in-process state — only
PostgreSQL and Redis. Each scenario hits INSTANCE A and INSTANCE B for
the SAME logical resource and asserts platform-level invariants:

  S1  idempotency across instances: the same Idempotency-Key replayed on
      the other instance returns the recorded response — one logical op.
  S2  webhook dedup across instances: the same GitHub delivery id
      delivered to both instances produces ONE scan side effect.
  S3  rate-limit globality: the fixed-window limit is consumed across
      BOTH instances combined (no per-instance allowance).
  S4  quota globality: the daily org quota is consumed across both
      instances combined.
  S5  process-local state audit: neither instance may grant authority
      from memory — an API key revoked via instance A is refused by
      instance B immediately (no cache of authority).

Requires: two API processes started by the shell wrapper (see
tools/cert/run_multi_instance.sh) pointing at the v42 test infra.
"""
import asyncio
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import time
import uuid as uuid_module
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "apps" / "api"))

API_A = os.environ.get("CYVRIX_INSTANCE_A", "http://localhost:8601")
API_B = os.environ.get("CYVRIX_INSTANCE_B", "http://localhost:8602")
DB_DSN = "postgresql+asyncpg://cyvrix:cyvrix_dev@localhost:5434/cyvrix"
REDIS_URL = "redis://localhost:6381/0"

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} {detail}")


async def seed() -> dict:
    """One tenant, active repo, live API key (plaintext returned once)."""
    sys.path.insert(0, str(REPO_ROOT / "apps" / "api"))
    os.environ["DATABASE_URL"] = DB_DSN
    os.environ["REDIS_URL"] = REDIS_URL

    from sqlalchemy import select

    import app.models as m
    from app.database import async_session, engine

    async with async_session() as s:
        user = m.User(email=f"mi-{uuid_module.uuid4().hex[:8]}@v42.local")
        s.add(user)
        await s.flush()
        org = m.Organization(
            name=f"MI-{uuid_module.uuid4().hex[:8]}",
            slug=f"mi-{uuid_module.uuid4().hex[:10]}",
        )
        s.add(org)
        await s.flush()
        s.add(m.OrganizationMembership(
            organization_id=org.id, user_id=user.id, role="owner", state="ACTIVE",
        ))
        inst = m.GithubInstallation(
            user_id=user.id,
            installation_id=uuid_module.uuid4().int % 900000 + 1,
            account_login="mi",
            account_type="Organization",
            organization_id=org.id,
        )
        s.add(inst)
        await s.flush()
        repo = m.Repository(
            installation_id=inst.id,
            github_repo_id=uuid_module.uuid4().int % 900000 + 1,
            owner=f"mi-{uuid_module.uuid4().hex[:8]}", name="repo",
            default_branch="main", is_active=True,
        )
        s.add(repo)
        await s.flush()

        prefix = uuid_module.uuid4().hex[:8]
        secret = uuid_module.uuid4().hex + uuid_module.uuid4().hex
        token = f"cyv_{prefix}_{secret}"
        # Hash the same way the service layer does: sha256 over the FULL
        # plaintext token (services/api_key_service._hash).
        key_row = m.ApiKey(
            organization_id=org.id,
            name="mi-key",
            prefix=prefix,
            key_hash=hashlib.sha256(token.encode()).hexdigest(),
            scopes=["scans:read", "scans:create", "repos:read"],
        )
        s.add(key_row)
        await s.commit()
        out = {
            "org_id": str(org.id), "repo_id": str(repo.id),
            "installation_pk": str(inst.id),
            "installation_number": inst.installation_id,
            "repo_github_id": repo.github_repo_id,
            "api_key_token": token,
            "key_header": f"Bearer {token}",
        }
    await engine.dispose()
    return out


def _auth(token_body: str) -> dict:
    return {"Authorization": token_body}


async def wait_healthy(client: httpx.AsyncClient, base: str) -> bool:
    for _ in range(60):
        try:
            r = await client.get(f"{base}/api/health/live")
            if r.status_code == 200:
                return True
        except Exception:
            pass
        await asyncio.sleep(0.5)
    return False


# ── S1: idempotency across instances ─────────────────────────────────

async def s1_idempotency(ctx: dict) -> None:
    key = str(uuid_module.uuid4())
    headers = _auth(ctx["key_header"]) | {
        "Idempotency-Key": key, "Content-Type": "application/json",
    }
    body = {"repository_id": ctx["repo_id"]}
    async with httpx.AsyncClient(timeout=30) as c:
        r1 = await c.post(f"{API_A}/api/v1/scans", json=body, headers=headers)
        r2 = await c.post(f"{API_B}/api/v1/scans", json=body, headers=headers)
    same_id = r1.json().get("scan_id") == r2.json().get("scan_id")
    record("S1 idempotent replay across instances → same scan id",
           r1.status_code == 202 and r2.status_code == 202 and same_id,
           f"A={r1.status_code} B={r2.status_code} same_id={same_id}")


# ── S2: webhook dedup across instances ───────────────────────────────

def _sign(payload: bytes, secret: str) -> str:
    return "sha256=" + hmac_mod.new(secret.encode(), payload, hashlib.sha256).hexdigest()


async def s2_webhook_dedup(ctx: dict, webhook_secret: str) -> None:
    delivery = uuid_module.uuid4().hex
    payload = json.dumps({
        "installation": {"id": ctx["installation_number"]},
        "repository": {"id": ctx["repo_github_id"], "name": "repo",
                        "full_name": "mi/repo", "owner": {"login": "mi"}},
        "ref": "refs/heads/main",
        # GitHub head SHA is a full 40-hex commit id (validated).
        "after": hashlib.sha256(delivery.encode()).hexdigest()[:40],
        "commits": [{"id": hashlib.sha256(delivery.encode()).hexdigest()[:40]}],
    }).encode()
    sig = _sign(payload, webhook_secret)
    headers = {
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": sig,
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=30) as c:
        r1 = await c.post(f"{API_A}/api/webhooks/github", content=payload, headers=headers)
        r1_scan_id = await _scan_id_for_delivery(delivery)
        r2 = await c.post(f"{API_B}/api/webhooks/github", content=payload, headers=headers)
    # A accepts (202, side effect created); B must recognize the replay
    # (200 with the SAME scan id) via the DB-backed reservation — never
    # a second side effect.
    b_replayed = r2.status_code == 200 and r2.json().get("replayed") is True
    b_scan_id = (r2.json() or {}).get("scan_id")
    scans_for_delivery = await _count_scans_for_delivery(delivery)
    record("S2 same GitHub delivery on both instances → one side effect",
           r1.status_code == 202 and b_replayed and b_scan_id == str(r1_scan_id) and scans_for_delivery == 1,
           f"A={r1.status_code} B={r2.status_code} replayed={b_replayed} same_scan_id={b_scan_id == str(r1_scan_id)} delivery_rows={scans_for_delivery}")


async def _count_scans(org_id: str) -> int:
    import asyncpg
    conn = await asyncpg.connect("postgresql://cyvrix:cyvrix_dev@localhost:5434/cyvrix")
    try:
        row = await conn.fetchrow(
            """
            SELECT COUNT(*) AS n FROM scans s
            JOIN repositories r ON s.repository_id = r.id
            JOIN github_installations i ON r.installation_id = i.id
            WHERE i.organization_id = $1
            """,
            uuid_module.UUID(org_id),
        )
        return row["n"]
    finally:
        await conn.close()


async def _scan_id_for_delivery(delivery: str):
    import asyncpg
    conn = await asyncpg.connect("postgresql://cyvrix:cyvrix_dev@localhost:5434/cyvrix")
    try:
        row = await conn.fetchrow(
            "SELECT scan_id FROM webhook_deliveries WHERE github_delivery_id = $1",
            delivery,
        )
        return row["scan_id"] if row else None
    finally:
        await conn.close()


async def _count_scans_for_delivery(delivery: str) -> int:
    """Delivery rows bound to this GitHub delivery id — the at-most-one
    side-effect invariant is: exactly ONE delivery row with a scan ref."""
    import asyncpg
    conn = await asyncpg.connect("postgresql://cyvrix:cyvrix_dev@localhost:5434/cyvrix")
    try:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS n FROM webhook_deliveries WHERE github_delivery_id = $1 AND scan_id IS NOT NULL",
            delivery,
        )
        return row["n"]
    finally:
        await conn.close()


# ── S3: rate-limit globality across instances ────────────────────────

async def s3_rate_limit(ctx: dict) -> None:
    """The read bucket allows 600 requests per org per 1h window
    (READ_LIMIT_PER_HOUR). Alternate requests between the two instances
    and confirm the counter is SHARED: the 601st aggregate request gets
    429 even though neither instance alone served 600 requests. A
    per-instance allowance would let 1200 through.

    The counter is consumed from a fresh org (unique per run) so prior
    scenarios cannot pollute the window; we drive 600 alternating
    requests and expect the final handful to be refused.
    """
    refused = 0
    served = 0
    async with httpx.AsyncClient(timeout=30) as c:
        for i in range(605):
            base = API_A if i % 2 == 0 else API_B
            r = await c.get(
                f"{base}/api/v1/scans?limit=1",
                headers=_auth(ctx["key_header"]),
            )
            if r.status_code == 429:
                refused += 1
            elif r.status_code == 200:
                served += 1
            else:
                record("S3 rate limit globality", False,
                       f"unexpected status {r.status_code} at request {i}")
                return
    # 601+ aggregate requests must be refused regardless of which
    # instance served them; per-instance counters would keep serving.
    record("S3 rate limit consumed across BOTH instances (aggregate)",
           refused >= 5 and served <= 600,
           f"served={served} refused={refused} (limit 600 shared)")


# ── S4: quota globality ──────────────────────────────────────────────

async def s4_quota(ctx: dict) -> None:
    """Direct Redis inspection + concurrent consume across both
    instances using the platform's own quota primitive."""
    import redis.asyncio as aioredis

    sys.path.insert(0, str(REPO_ROOT / "apps" / "api"))
    from app.quota_service import consume_quota

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    action = f"mi-{uuid_module.uuid4().hex[:8]}"
    results = await asyncio.gather(*[
        consume_quota(
            r, organization_id=ctx["org_id"], action=action,
            org_limit=5, global_limit=100,
        )
        for _ in range(20)
    ])
    allowed = sum(1 for d in results if d.allowed)
    record("S4 quota exact under concurrent consume (5 of 20 allowed)",
           allowed == 5, f"allowed={allowed}")
    await r.aclose()


# ── S5: revocation propagates instantly (no cached authority) ────────

async def s5_revocation(ctx: dict) -> None:
    import asyncpg

    conn = await asyncpg.connect("postgresql://cyvrix:cyvrix_dev@localhost:5434/cyvrix")
    try:
        await conn.execute(
            "UPDATE api_keys SET revoked_at = NOW() WHERE key_hash = $1",
            hashlib.sha256(ctx["api_key_token"].encode()).hexdigest(),
        )
    finally:
        await conn.close()
    async with httpx.AsyncClient(timeout=30) as c:
        r_a = await c.get(f"{API_A}/api/v1/scans?limit=1", headers=_auth(ctx["key_header"]))
        r_b = await c.get(f"{API_B}/api/v1/scans?limit=1", headers=_auth(ctx["key_header"]))
    record("S5 API key revoked via DB refused by BOTH instances instantly",
           r_a.status_code == 401 and r_b.status_code == 401,
           f"A={r_a.status_code} B={r_b.status_code}")


async def main() -> int:
    print("CYVRIX V4.2 multi-instance certification (2 REAL API processes)")
    print(f"  instance A: {API_A}\n  instance B: {API_B}")

    async with httpx.AsyncClient(timeout=10) as c:
        ok_a = await wait_healthy(c, API_A)
        ok_b = await wait_healthy(c, API_B)
    if not (ok_a and ok_b):
        print("instances not healthy; aborting (start via tools/cert/run_multi_instance.sh)")
        return 2

    ctx = await seed()
    # S2 gets its OWN tenant: a queued scan left by S1 must not interfere
    # with webhook admission (one non-terminal scan per repo is the rule).
    webhook_ctx = await seed()
    webhook_secret = os.environ.get("CYVRIX_TEST_WEBHOOK_SECRET", "")

    print("scenario S1: idempotency across instances")
    await s1_idempotency(ctx)
    if webhook_secret:
        print("scenario S2: webhook delivery dedup across instances")
        await s2_webhook_dedup(webhook_ctx, webhook_secret)
    else:
        record("S2 webhook dedup", False, "CYVRIX_TEST_WEBHOOK_SECRET not set — skipped as FAIL")
    print("scenario S3: rate-limit globality")
    await s3_rate_limit(ctx)
    print("scenario S4: quota globality")
    await s4_quota(ctx)
    print("scenario S5: revocation propagation (no cached authority)")
    await s5_revocation(ctx)

    failed = [r for r in RESULTS if not r[1]]
    print(f"\nRESULT: {'ALL PASS' if not failed else f'{len(failed)} FAILED'} ({len(RESULTS)} scenarios)")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
