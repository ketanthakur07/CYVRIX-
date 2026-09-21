"""
Setup for golden path E2E test.

Creates:
- User with GitHub login
- GitHub installation
- Repository pointing to vulnerable-node-app fixture
- Session cookie for authentication

Does NOT pre-seed:
- scans
- findings
- investigations
- risk assessments

These are created by the real worker pipeline during the E2E test.
"""
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import tempfile
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

import redis
import psycopg2

PG_URL = os.environ.get("E2E_PG_URL", "postgresql://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test")
REDIS_URL = os.environ.get("E2E_REDIS_URL", "redis://localhost:6380")
SECRET_KEY = os.environ.get("SECRET_KEY", "test-secret-key-for-integration-only-not-for-production-32chars!")


def create_session_cookie(user_id: str) -> str:
    """Create a session in Redis and return the cookie value."""
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
    return cookie


def setup():
    """Create golden path test data."""
    conn = psycopg2.connect(PG_URL)
    conn.autocommit = True
    cur = conn.cursor()

    # Clean ONLY this seeder's own fixture scope. This script owns the
    # fixed key 911111 and must coexist with tests/setup_e2e.py, whose
    # users/repos (keys 111111/222222/333333/...) it must never delete —
    # a blanket wipe here destroyed the e2e seed data and broke the
    # real-stack/approval specs. FK-safe order for this scope only.
    for stmt in [
        """DELETE FROM audit_events WHERE repository_id IN (SELECT id FROM repositories
              WHERE installation_id IN (SELECT id FROM github_installations
              WHERE installation_id = 911111))""",
        """DELETE FROM rollback_runs WHERE git_remediation_id IN (SELECT id FROM git_remediations
              WHERE execution_run_id IN (SELECT id FROM execution_runs WHERE authorization_id IN
              (SELECT id FROM execution_authorizations WHERE repository_id IN
              (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111)))))""",
        """DELETE FROM verification_checks WHERE verification_run_id IN (SELECT id FROM verification_runs
              WHERE git_remediation_id IN (SELECT id FROM git_remediations
              WHERE execution_run_id IN (SELECT id FROM execution_runs WHERE authorization_id IN
              (SELECT id FROM execution_authorizations WHERE repository_id IN
              (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111))))))""",
        """DELETE FROM verification_runs WHERE git_remediation_id IN (SELECT id FROM git_remediations
              WHERE execution_run_id IN (SELECT id FROM execution_runs WHERE authorization_id IN
              (SELECT id FROM execution_authorizations WHERE repository_id IN
              (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111)))))""",
        """DELETE FROM github_credential_issuances WHERE git_remediation_id IN (SELECT id FROM git_remediations
              WHERE execution_run_id IN (SELECT id FROM execution_runs WHERE authorization_id IN
              (SELECT id FROM execution_authorizations WHERE repository_id IN
              (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111)))))""",
        """DELETE FROM git_remediations WHERE execution_run_id IN (SELECT id FROM execution_runs
              WHERE authorization_id IN (SELECT id FROM execution_authorizations
              WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111))))""",
        """DELETE FROM execution_runs WHERE authorization_id IN (SELECT id FROM execution_authorizations
              WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111)))""",
        """DELETE FROM execution_authorizations WHERE repository_id IN (SELECT id FROM repositories
              WHERE installation_id IN (SELECT id FROM github_installations
              WHERE installation_id = 911111))""",
        """DELETE FROM approvals WHERE proposal_id IN (SELECT id FROM action_proposals
              WHERE finding_id IN (SELECT id FROM findings WHERE repository_id IN
              (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111))))""",
        """DELETE FROM action_proposals WHERE finding_id IN (SELECT id FROM findings
              WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111)))""",
        """DELETE FROM risk_assessments WHERE finding_id IN (SELECT id FROM findings
              WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111)))""",
        """DELETE FROM investigations WHERE finding_id IN (SELECT id FROM findings
              WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111)))""",
        """DELETE FROM recommendations WHERE finding_id IN (SELECT id FROM findings
              WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111)))""",
        """DELETE FROM findings WHERE repository_id IN (SELECT id FROM repositories
              WHERE installation_id IN (SELECT id FROM github_installations
              WHERE installation_id = 911111))""",
        """DELETE FROM dependencies WHERE scan_id IN (SELECT id FROM scans
              WHERE repository_id IN (SELECT id FROM repositories WHERE installation_id IN
              (SELECT id FROM github_installations WHERE installation_id = 911111)))""",
        """DELETE FROM scans WHERE repository_id IN (SELECT id FROM repositories
              WHERE installation_id IN (SELECT id FROM github_installations
              WHERE installation_id = 911111))""",
        """DELETE FROM repositories WHERE installation_id IN (SELECT id FROM
              github_installations WHERE installation_id = 911111)""",
        "DELETE FROM github_installations WHERE installation_id = 911111",
    ]:
        try:
            cur.execute(stmt)
        except Exception:
            pass

    # Create user
    user_id = str(uuid4())
    email = f"golden-{int(time.time())}@cyvrix.test"
    github_id = int(time.time()) % 900000 + 100000
    cur.execute(
        "INSERT INTO users (id, email, github_id, github_login) VALUES (%s, %s, %s, %s)",
        (user_id, email, github_id, "golden-user"),
    )

    # Create installation — disjoint fixture keys (911111/922222,
    # 'golden-cert-org') so this seeder never collides with
    # tests/setup_e2e.py, which owns 111111/222222/'golden-org'.
    installation_id = str(uuid4())
    cur.execute(
        "INSERT INTO github_installations (id, user_id, installation_id, account_login, account_type) VALUES (%s, %s, %s, %s, %s)",
        (installation_id, user_id, 911111, "golden-cert-org", "Organization"),
    )

    # Create repository (pointing to vulnerable-node-app fixture)
    repo_id = str(uuid4())
    cur.execute(
        "INSERT INTO repositories (id, installation_id, github_repo_id, owner, name, default_branch, is_active) VALUES (%s, %s, %s, %s, %s, %s, true)",
        (repo_id, installation_id, 922222, "golden-cert-org", "vulnerable-node-app", "main"),
    )

    # Create session
    cookie = create_session_cookie(user_id)

    conn.close()

    # Write setup data for Playwright
    data = {
        "user": {
            "userId": user_id,
            "email": email,
            "cookie": cookie,
            "repoId": repo_id,
            "installationId": installation_id,
        },
    }

    setup_path = os.path.join(tempfile.gettempdir(), "golden_path_setup.json")
    with open(setup_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Golden path setup complete: {setup_path}", file=sys.stderr)
    print(f"  User: {user_id}", file=sys.stderr)
    print(f"  Repository: {repo_id} (golden-org/vulnerable-node-app)", file=sys.stderr)
    print(f"  Cookie: {cookie[:20]}...", file=sys.stderr)
    return data


if __name__ == "__main__":
    setup()
