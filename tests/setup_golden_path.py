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

    # Clean all data
    for table in ["audit_events", "risk_assessments", "investigations", "findings",
                   "dependencies", "scans", "repositories", "github_installations", "users"]:
        try:
            cur.execute(f"DELETE FROM {table}")
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

    # Create installation
    installation_id = str(uuid4())
    cur.execute(
        "INSERT INTO github_installations (id, user_id, installation_id, account_login, account_type) VALUES (%s, %s, %s, %s, %s)",
        (installation_id, user_id, 111111, "golden-org", "Organization"),
    )

    # Create repository (pointing to vulnerable-node-app fixture)
    repo_id = str(uuid4())
    cur.execute(
        "INSERT INTO repositories (id, installation_id, github_repo_id, owner, name, default_branch, is_active) VALUES (%s, %s, %s, %s, %s, %s, true)",
        (repo_id, installation_id, 222222, "golden-org", "vulnerable-node-app", "main"),
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
