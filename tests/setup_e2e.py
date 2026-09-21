"""Setup script for Playwright E2E tests.

Creates test users, sessions, and data in real PostgreSQL and Redis.
Outputs JSON with cookies and IDs for Playwright to consume.

Usage: python setup_e2e.py > /tmp/e2e_setup.json
"""
import json
import sys
import os
import time
import hashlib
import hmac
import secrets
import tempfile
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

import redis
import psycopg2
from app.config import get_settings

settings = get_settings()

PG_URL = os.environ.get("E2E_PG_URL", "postgresql://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test")
REDIS_URL = os.environ.get("E2E_REDIS_URL", "redis://localhost:6380")
SECRET_KEY = os.environ.get("SECRET_KEY", "test-secret-key-for-integration-only-not-for-production-32chars!")


def create_session_cookie(user_id: str) -> tuple[str, str, str]:
    """Create a session in Redis and return (session_id, signature, cookie)."""
    r = redis.from_url(REDIS_URL, decode_responses=True)

    session_id = secrets.token_hex(32)
    signature = hmac.new(SECRET_KEY.encode(), session_id.encode(), hashlib.sha256).hexdigest()
    cookie = f"{session_id}.{signature}"

    session_data = json.dumps({
        "user_id": user_id,
        "created_at": str(int(time.time())),
        "last_access": str(int(time.time())),
    })
    r.setex(f"session:{session_id}", 3600, session_data)
    r.close()

    return session_id, signature, cookie


def setup():
    """Create all test users and data for E2E tests."""
    conn = psycopg2.connect(PG_URL)
    conn.autocommit = True
    cur = conn.cursor()

    result = {"users": {}, "cleanup_ids": []}

    # Idempotency: remove leftovers of previous runs keyed on the FIXED
    # installation/repo ids below, so the script can be re-run against a
    # warm database without UniqueViolation failures.
    # FK-safe cascade over the FIXED fixture scope. Covers V1..V3.6
    # tables in dependency order — the previous partial ordering deleted
    # installations before their repositories (FK violation on warm DBs).
    repo_scope = """
        SELECT id FROM repositories WHERE github_repo_id IN (222222, 222223, 444444, 666666)
        OR owner = 'golden-org'
        OR installation_id IN (SELECT id FROM github_installations WHERE
            installation_id IN (111111, 333333, 555555))
    """
    remediation_scope = f"""
        SELECT id FROM git_remediations WHERE execution_run_id IN (
            SELECT id FROM execution_runs WHERE execution_authorization_id IN (
                SELECT id FROM execution_authorizations WHERE repository_id IN ({repo_scope})))
    """
    finding_scope = f"""
        SELECT id FROM findings WHERE repository_id IN ({repo_scope})
    """
    scan_scope = f"""
        SELECT id FROM scans WHERE repository_id IN ({repo_scope})
    """
    for stmt in [
        f"DELETE FROM audit_events WHERE repository_id IN ({repo_scope})",
        f"""DELETE FROM rollback_runs WHERE git_remediation_id IN ({remediation_scope})""",
        f"""DELETE FROM verification_checks WHERE verification_run_id IN (
            SELECT id FROM verification_runs WHERE git_remediation_id IN ({remediation_scope}))""",
        f"""DELETE FROM verification_runs WHERE git_remediation_id IN ({remediation_scope})""",
        f"""DELETE FROM github_credential_issuances WHERE git_remediation_id IN ({remediation_scope})""",
        f"""DELETE FROM git_remediations WHERE execution_run_id IN (
            SELECT id FROM execution_runs WHERE execution_authorization_id IN (
                SELECT id FROM execution_authorizations WHERE repository_id IN ({repo_scope})))""",
        f"""DELETE FROM workspace_snapshots WHERE execution_run_id IN (
            SELECT id FROM execution_runs WHERE execution_authorization_id IN (
                SELECT id FROM execution_authorizations WHERE repository_id IN ({repo_scope})))""",
        f"""DELETE FROM execution_runs WHERE execution_authorization_id IN (
            SELECT id FROM execution_authorizations WHERE repository_id IN ({repo_scope}))""",
        f"""DELETE FROM execution_authorizations WHERE repository_id IN ({repo_scope})""",
        f"""DELETE FROM approvals WHERE action_proposal_id IN (
            SELECT id FROM action_proposals WHERE finding_id IN ({finding_scope}))""",
        f"""DELETE FROM action_proposals WHERE finding_id IN ({finding_scope})""",
        f"""DELETE FROM risk_assessments WHERE finding_id IN ({finding_scope})""",
        f"""DELETE FROM investigations WHERE finding_id IN ({finding_scope})""",
        f"""DELETE FROM recommendations WHERE finding_id IN ({finding_scope})""",
        f"""DELETE FROM findings WHERE id IN ({finding_scope})""",
        f"""DELETE FROM dependencies WHERE scan_id IN ({scan_scope})""",
        f"""DELETE FROM scans WHERE id IN ({scan_scope})""",
        f"""DELETE FROM repositories WHERE id IN ({repo_scope})""",
        "DELETE FROM github_installations WHERE installation_id IN (111111, 333333, 555555) "
        "OR account_login IN ('golden-org', 'idor-a-org', 'idor-b-org', 'xss-org')",
    ]:
        cur.execute(stmt)

    # --- Golden Path User ---
    golden_user_id = str(uuid4())
    golden_email = f"golden-{int(time.time()*1000)}-{uuid4().hex[:6]}@cyvrix.test"
    golden_github_id = uuid4().int % 900000 + 100000

    cur.execute(
        "INSERT INTO users (id, email, github_id, github_login) VALUES (%s, %s, %s, %s)",
        (golden_user_id, golden_email, golden_github_id, "golden-user")
    )
    _, _, golden_cookie = create_session_cookie(golden_user_id)
    result["cleanup_ids"].append(golden_user_id)

    # Create installation + repo + scan + finding for golden path
    golden_inst_id = str(uuid4())
    golden_repo_id = str(uuid4())
    golden_scan_id = str(uuid4())
    golden_finding_id = str(uuid4())

    cur.execute(
        "INSERT INTO github_installations (id, user_id, installation_id, account_login, account_type) VALUES (%s, %s, %s, %s, %s)",
        # Dynamic installation id: 111111 is owned by setup_golden_path.py
        # (its spec reads golden_path_setup.json). Sharing the fixed key
        # made the two seeders overwrite each other's repository row.
        (golden_inst_id, golden_user_id, 700000 + uuid4().int % 90000, "golden-org", "Organization")
    )
    cur.execute(
        "INSERT INTO repositories (id, installation_id, github_repo_id, owner, name, default_branch, is_active) VALUES (%s, %s, %s, %s, %s, %s, true)",
        (golden_repo_id, golden_inst_id, 222222, "golden-org", "vulnerable-app", "main")
    )
    cur.execute(
        "INSERT INTO scans (id, repository_id, status, trigger, commit_sha, started_at, completed_at) VALUES (%s, %s, 'COMPLETED', 'manual', 'abc123', NOW(), NOW())",
        (golden_scan_id, golden_repo_id)
    )
    cur.execute(
        "INSERT INTO findings (id, scan_id, repository_id, fingerprint, scanner, vulnerability_id, package_name, package_version, title, description, severity, status) VALUES (%s, %s, %s, %s, 'dependency', 'CVE-2024-9999', 'lodash', '4.17.20', 'Prototype Pollution in lodash', 'Versions before 4.17.21 are vulnerable.', 'HIGH', 'OPEN')",
        (golden_finding_id, golden_scan_id, golden_repo_id, f"fp-golden-{golden_finding_id}")
    )
    cur.execute(
        "INSERT INTO risk_assessments (id, finding_id, risk_score, risk_level, risk_version, factors) VALUES (%s, %s, 65, 'HIGH', 1, %s)",
        (str(uuid4()), golden_finding_id, json.dumps({"base_score": 60, "exposure_mod": 5, "exploit_mod": 0, "confidence_mod": 0, "ai_available": False, "degraded": True}))
    )

    result["users"]["golden"] = {
        "userId": golden_user_id,
        "email": golden_email,
        "cookie": golden_cookie,
        "repoId": golden_repo_id,
        "scanId": golden_scan_id,
        "findingId": golden_finding_id,
    }

    # --- IDOR User A ---
    user_a_id = str(uuid4())
    user_a_email = f"idor-a-{uuid4().hex[:10]}-{int(time.time())}@cyvrix.test"
    cur.execute(
        "INSERT INTO users (id, email, github_id, github_login) VALUES (%s, %s, %s, %s)",
        (user_a_id, user_a_email, uuid4().int % 900000 + 200000, "idor-user-a")
    )
    _, _, user_a_cookie = create_session_cookie(user_a_id)
    result["cleanup_ids"].append(user_a_id)

    user_a_inst = str(uuid4())
    user_a_repo = str(uuid4())
    user_a_scan = str(uuid4())
    user_a_finding = str(uuid4())

    cur.execute(
        "INSERT INTO github_installations (id, user_id, installation_id, account_login, account_type) VALUES (%s, %s, %s, %s, %s)",
        (user_a_inst, user_a_id, 333333, "idor-a-org", "Organization")
    )
    cur.execute(
        "INSERT INTO repositories (id, installation_id, github_repo_id, owner, name, default_branch, is_active) VALUES (%s, %s, %s, %s, %s, %s, true)",
        (user_a_repo, user_a_inst, 444444, "idor-a-org", "idor-repo-a", "main")
    )
    cur.execute(
        "INSERT INTO scans (id, repository_id, status, trigger) VALUES (%s, %s, 'COMPLETED', 'manual')",
        (user_a_scan, user_a_repo)
    )
    cur.execute(
        "INSERT INTO findings (id, scan_id, repository_id, fingerprint, scanner, vulnerability_id, package_name, title, severity, status) VALUES (%s, %s, %s, %s, 'dependency', 'CVE-IDOR-001', 'test-pkg', 'IDOR Test Finding', 'HIGH', 'OPEN')",
        (user_a_finding, user_a_scan, user_a_repo, f"fp-idor-a-{user_a_finding}")
    )

    result["users"]["idorA"] = {
        "userId": user_a_id,
        "email": user_a_email,
        "cookie": user_a_cookie,
        "repoId": user_a_repo,
        "findingId": user_a_finding,
    }

    # --- IDOR User B ---
    user_b_id = str(uuid4())
    user_b_email = f"idor-b-{uuid4().hex[:10]}-{int(time.time())}@cyvrix.test"
    cur.execute(
        "INSERT INTO users (id, email, github_id, github_login) VALUES (%s, %s, %s, %s)",
        (user_b_id, user_b_email, uuid4().int % 900000 + 300000, "idor-user-b")
    )
    _, _, user_b_cookie = create_session_cookie(user_b_id)
    result["cleanup_ids"].append(user_b_id)

    result["users"]["idorB"] = {
        "userId": user_b_id,
        "email": user_b_email,
        "cookie": user_b_cookie,
    }

    # --- XSS User ---
    xss_user_id = str(uuid4())
    xss_email = f"xss-{uuid4().hex[:10]}-{int(time.time())}@cyvrix.test"
    cur.execute(
        "INSERT INTO users (id, email, github_id, github_login) VALUES (%s, %s, %s, %s)",
        (xss_user_id, xss_email, uuid4().int % 900000 + 400000, "xss-user")
    )
    _, _, xss_cookie = create_session_cookie(xss_user_id)
    result["cleanup_ids"].append(xss_user_id)

    xss_inst = str(uuid4())
    xss_repo = str(uuid4())
    xss_scan = str(uuid4())
    xss_finding = str(uuid4())

    cur.execute(
        "INSERT INTO github_installations (id, user_id, installation_id, account_login, account_type) VALUES (%s, %s, %s, %s, %s)",
        (xss_inst, xss_user_id, 555555, "xss-org", "Organization")
    )
    cur.execute(
        "INSERT INTO repositories (id, installation_id, github_repo_id, owner, name, default_branch, is_active) VALUES (%s, %s, %s, %s, %s, %s, true)",
        (xss_repo, xss_inst, 666666, "xss-org", "xss-repo", "main")
    )
    cur.execute(
        "INSERT INTO scans (id, repository_id, status, trigger) VALUES (%s, %s, 'COMPLETED', 'manual')",
        (xss_scan, xss_repo)
    )
    cur.execute(
        "INSERT INTO findings (id, scan_id, repository_id, fingerprint, scanner, title, description, severity, status) VALUES (%s, %s, %s, %s, 'dependency', %s, %s, 'HIGH', 'OPEN')",
        (xss_finding, xss_scan, xss_repo, f"fp-xss-{xss_finding}",
         '<script>alert("XSS")</script>',
         '<img src=x onerror=alert(1)>')
    )

    result["users"]["xss"] = {
        "userId": xss_user_id,
        "email": xss_email,
        "cookie": xss_cookie,
        "repoId": xss_repo,
        "findingId": xss_finding,
    }

    # --- Empty User (no data) ---
    empty_user_id = str(uuid4())
    empty_email = f"empty-{uuid4().hex[:10]}-{int(time.time())}@cyvrix.test"
    cur.execute(
        "INSERT INTO users (id, email, github_id, github_login) VALUES (%s, %s, %s, %s)",
        (empty_user_id, empty_email, uuid4().int % 900000 + 500000, "empty-user")
    )
    _, _, empty_cookie = create_session_cookie(empty_user_id)
    result["cleanup_ids"].append(empty_user_id)

    result["users"]["empty"] = {
        "userId": empty_user_id,
        "email": empty_email,
        "cookie": empty_cookie,
    }

    conn.close()

    # Write to file for Playwright to consume
    setup_path = os.path.join(tempfile.gettempdir(), "e2e_setup.json")
    with open(setup_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Setup complete: {len(result['users'])} users created -> {setup_path}", file=sys.stderr)
    return result


def cleanup():
    """Clean up all E2E test data."""
    try:
        setup_path = os.path.join(tempfile.gettempdir(), "e2e_setup.json")
        with open(setup_path) as f:
            result = json.load(f)
    except FileNotFoundError:
        return

    conn = psycopg2.connect(PG_URL)
    conn.autocommit = True
    cur = conn.cursor()

    for user_id in result.get("cleanup_ids", []):
        # Delete in reverse dependency order
        for table_query in [
            "DELETE FROM audit_events WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN (SELECT id FROM github_installations WHERE user_id = %s))",
            "DELETE FROM risk_assessments WHERE finding_id IN (SELECT id FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN (SELECT id FROM github_installations WHERE user_id = %s))))",
            "DELETE FROM investigations WHERE finding_id IN (SELECT id FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN (SELECT id FROM github_installations WHERE user_id = %s))))",
            "DELETE FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN (SELECT id FROM github_installations WHERE user_id = %s)))",
            "DELETE FROM dependencies WHERE scan_id IN (SELECT id FROM scans WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN (SELECT id FROM github_installations WHERE user_id = %s)))",
            "DELETE FROM scans WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN (SELECT id FROM github_installations WHERE user_id = %s))",
            "DELETE FROM repositories WHERE installation_id IN (SELECT id FROM github_installations WHERE user_id = %s)",
            "DELETE FROM github_installations WHERE user_id = %s",
            "DELETE FROM users WHERE id = %s",
        ]:
            try:
                cur.execute(table_query, (user_id,))
            except Exception:
                pass

    conn.close()

    # Clean Redis sessions
    try:
        r = redis.from_url(REDIS_URL, decode_responses=True)
        keys = r.keys("session:*")
        if keys:
            r.delete(*keys)
        r.close()
    except Exception:
        pass

    print("Cleanup complete", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "cleanup":
        cleanup()
    else:
        setup()
