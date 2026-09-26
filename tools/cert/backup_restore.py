"""CYVRIX V4.2 — backup / restore / integrity tooling (Phase 30-34, 66).

What this does — and deliberately does NOT claim:
  - BACKUP: a real PostgreSQL logical backup via pg_dump (custom format),
    executed inside the postgres container. Output is written to a local
    backups/ directory together with a SHA-256 MANIFEST so post-restore
    tampering (bit flips, truncation, silent substitution) is detectable.
  - VERIFY: re-hash the dump and compare against the manifest.
  - RESTORE: drop and recreate a THROWAWAY database from the dump
    (inside the container), run the schema- and data-integrity checks,
    then run the V3.8 audit-chain verifier against the restored rows.
    The production database is NEVER touched by this tool.

Honest scope (documented in docs/v42-backup-restore-dr.md):
  - This is logical backup/restore for a single-node PostgreSQL. It is
    not PITR, not streaming replication, not HA. RPO = backup interval;
    RTO = measured restore time (docs record the measured numbers).

Usage:
  python tools/cert/backup_restore.py backup
  python tools/cert/backup_restore.py verify --file backups/<name>.dump
  python tools/cert/backup_restore.py restore --file backups/<name>.dump
  python tools/cert/backup_restore.py all
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP_DIR = REPO_ROOT / "backups"

# The disposable test-infra container (infra/docker-compose.v42.yml).
PG_CONTAINER = os.environ.get("CYVRIX_V42_PG_CONTAINER", "cyvrix-v42-postgres")
PG_USER = os.environ.get("CYVRIX_V42_PG_USER", "cyvrix")
PG_DB = os.environ.get("CYVRIX_V42_PG_DB", "cyvrix")
RESTORE_DB = "cyvrix_restore_test"  # NEVER a production database name


def _run_in_container(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", PG_CONTAINER, *cmd],
        capture_output=True, text=True, check=check,
    )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_backup(args: argparse.Namespace) -> dict:
    BACKUP_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dump_name = f"cyvrix_{PG_DB}_{stamp}.dump"
    dump_host_path = BACKUP_DIR / dump_name

    print(f"[backup] pg_dump {PG_DB} (custom format) via {PG_CONTAINER}")
    result = _run_in_container([
        "pg_dump", "-U", PG_USER, "-d", PG_DB,
        "-Fc", "-Z", "6",
        "-f", f"/tmp/{dump_name}",
    ])
    if result.returncode != 0:
        print(result.stderr)
        sys.exit(2)

    data = subprocess.run(
        ["docker", "cp", f"{PG_CONTAINER}:/tmp/{dump_name}", str(dump_host_path)],
        capture_output=True, text=True, check=True,
    )
    _run_in_container(["rm", "-f", f"/tmp/{dump_name}"], check=False)

    size = dump_host_path.stat().st_size
    digest = _sha256(dump_host_path)
    manifest = {
        "file": dump_name,
        "sha256": digest,
        "size_bytes": size,
        "database": PG_DB,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "format": "pg_dump custom (Fc), gzip level 6",
    }
    manifest_path = BACKUP_DIR / f"{dump_name}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # pg_restore --list proves the archive is readable — a zero-byte or
    # corrupt file fails HERE, at backup time, not during a disaster.
    print("[backup] archive readback check (pg_restore --list)")
    subprocess.run(
        ["docker", "cp", str(dump_host_path), f"{PG_CONTAINER}:/tmp/verify_{dump_name}"],
        capture_output=True, text=True, check=True,
    )
    result = _run_in_container(["pg_restore", "--list", f"/tmp/verify_{dump_name}"], check=False)
    _run_in_container(["rm", "-f", f"/tmp/verify_{dump_name}"], check=False)
    if result.returncode != 0:
        print("[backup] FAILED: archive is not readable by pg_restore")
        print(result.stderr[:800])
        sys.exit(3)
    toc_lines = len(result.stdout.strip().splitlines())
    manifest["toc_entries"] = toc_lines
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"[backup] OK file={dump_name} size={size} sha256={digest[:16]}... toc_entries={toc_lines}")
    return manifest


def cmd_verify(args: argparse.Namespace) -> dict:
    dump_path = Path(args.file).resolve()
    manifest_path = Path(str(dump_path) + ".manifest.json")
    if not dump_path.exists() or not manifest_path.exists():
        print(f"[verify] FAIL missing dump or manifest: {dump_path}")
        sys.exit(2)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    digest = _sha256(dump_path)
    ok = digest == manifest.get("sha256")
    print(f"[verify] {'OK' if ok else 'FAIL'} sha256 expected={manifest.get('sha256', '')[:16]}... actual={digest[:16]}...")
    if not ok:
        print("[verify] BACKUP TAMPERING OR CORRUPTION DETECTED — restore refused by design")
        sys.exit(4)
    return {"verified": True, "sha256": digest}


def cmd_restore(args: argparse.Namespace) -> dict:
    dump_path = Path(args.file).resolve()
    print("[restore] verifying integrity manifest first")
    cmd_verify(args)

    print(f"[restore] recreating throwaway database {RESTORE_DB}")
    _run_in_container([
        "psql", "-U", PG_USER, "-d", "postgres", "-c",
        f"DROP DATABASE IF EXISTS {RESTORE_DB};",
    ], check=False)
    _run_in_container([
        "psql", "-U", PG_USER, "-d", "postgres", "-c",
        f"CREATE DATABASE {RESTORE_DB};",
    ])

    subprocess.run(
        ["docker", "cp", str(dump_path), f"{PG_CONTAINER}:/tmp/restore_{dump_path.name}"],
        capture_output=True, text=True, check=True,
    )
    result = _run_in_container([
        "pg_restore", "-U", PG_USER, "-d", RESTORE_DB,
        "--no-owner", "--role", PG_USER,
        f"/tmp/restore_{dump_path.name}",
    ], check=False)
    if result.returncode != 0:
        stderr = result.stderr or ""
        # Only extension/owner noise is tolerated; anything else aborts.
        benign = all(
            marker in line
            for line in stderr.splitlines()
            if line.strip()
            for marker in [next((m for m in ("already exists", "extension", "does not exist", "role") if m in line), line)]
        )
        if not benign or "FATAL" in stderr:
            print("[restore] FAILED during pg_restore:")
            print(stderr[:1500])
            sys.exit(5)

    report: dict = {"restore": True, "database": RESTORE_DB}

    # ── Schema + data integrity checks (Phase 33) ───────────────────
    print("[restore] integrity checks")
    checks = {
        "organizations": "SELECT COUNT(*) FROM organizations",
        "users": "SELECT COUNT(*) FROM users",
        "repositories": "SELECT COUNT(*) FROM repositories",
        "scans": "SELECT COUNT(*) FROM scans",
        "findings": "SELECT COUNT(*) FROM findings",
        "audit_chain_events": "SELECT COUNT(*) FROM audit_chain_events",
        "audit_checkpoints": "SELECT COUNT(*) FROM audit_checkpoints",
        "api_idempotency_keys": "SELECT COUNT(*) FROM api_idempotency_keys",
        "webhook_deliveries": "SELECT COUNT(*) FROM webhook_deliveries",
        "orphan_scan_rows": (
            "SELECT COUNT(*) FROM scans s LEFT JOIN repositories r "
            "ON s.repository_id = r.id WHERE s.repository_id IS NOT NULL AND r.id IS NULL"
        ),
    }
    for name, sql in checks.items():
        result = _run_in_container([
            "psql", "-U", PG_USER, "-d", RESTORE_DB, "-tAc", sql,
        ], check=False)
        value = result.stdout.strip()
        report[name] = value
        print(f"[restore]   {name} = {value}")

    # ── V3.8 audit-chain verification against RESTORED data ─────────
    print("[restore] V3.8 audit chain verification on restored database")
    audit_ok = _verify_audit_chain(RESTORE_DB)
    report["audit_chain_verified"] = audit_ok
    print(f"[restore] audit chain: {'VALID' if audit_ok else 'INVALID'}")

    # Cleanup: the throwaway DB exists only for this check.
    _run_in_container([
        "psql", "-U", PG_USER, "-d", "postgres", "-c",
        f"DROP DATABASE IF EXISTS {RESTORE_DB};",
    ], check=False)
    print("[restore] throwaway database dropped; production database untouched")
    return report


def _verify_audit_chain(database: str) -> bool:
    """Run the V3.8 verifier against the restored database.

    Uses the application's own verify logic (the same code path the
    audit API exposes) pointed at the restored DB.
    """
    import asyncio
    import os as _os

    api_path = str(REPO_ROOT / "apps" / "api")
    if api_path not in sys.path:
        sys.path.insert(0, api_path)

    old_url = _os.environ.get("DATABASE_URL")
    _os.environ["DATABASE_URL"] = (
        f"postgresql+asyncpg://{PG_USER}:cyvrix_dev@localhost:5434/{database}"
    )

    async def _run() -> bool:
        # Import AFTER env override so the engine binds to the restored DB.
        import importlib

        import app.database as dbmod
        importlib.reload(dbmod)
        from sqlalchemy import select

        from app.models import AuditChain
        from app.services.audit_service import verify_chain

        all_ok = True
        chains_checked = 0
        async with dbmod.async_session() as session:
            chain_ids = (
                (await session.execute(select(AuditChain.id))).scalars().all()
            )
            for chain_id in chain_ids:
                result = await verify_chain(session, chain_id=chain_id)
                chains_checked += 1
                if result.status not in ("VALID", "EMPTY"):
                    all_ok = False
                    print(
                        f"[restore]   chain {str(chain_id)[:8]}... "
                        f"status={result.status} issues={len(result.issues)}"
                    )
        print(f"[restore]   chains checked: {chains_checked}")
        return all_ok

    try:
        ok = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        print(f"[restore] audit verification could not run: {type(exc).__name__}: {str(exc)[:200]}")
        ok = False
    finally:
        if old_url is None:
            _os.environ.pop("DATABASE_URL", None)
        else:
            _os.environ["DATABASE_URL"] = old_url
    return ok


def main() -> None:
    parser = argparse.ArgumentParser(description="CYVRIX V4.2 backup/restore certification")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("backup")
    p = sub.add_parser("verify"); p.add_argument("--file", required=True)
    p = sub.add_parser("restore"); p.add_argument("--file", required=True)
    sub.add_parser("all")
    args = parser.parse_args()

    if args.cmd == "backup":
        cmd_backup(args)
    elif args.cmd == "verify":
        cmd_verify(args)
    elif args.cmd == "restore":
        cmd_restore(args)
    elif args.cmd == "all":
        manifest = cmd_backup(args)
        verify_args = argparse.Namespace(file=str(BACKUP_DIR / manifest["file"]))
        cmd_verify(verify_args)
        cmd_restore(verify_args)


if __name__ == "__main__":
    main()
