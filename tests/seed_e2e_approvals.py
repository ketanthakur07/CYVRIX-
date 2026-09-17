"""V3.2 E2E seeder — approval-flow data for Playwright on the REAL stack.

Creates (in the e2e PostgreSQL, localhost:5433):
- approval user  (owns repo + 2 proposals: one to APPROVE, one EXPIRED)
- reject user    (owns repo + 1 proposal to REJECT — same user approves
                  their own MEDIUM proposal; cross-user denial is asserted
                  via the approval user's session against THIS user's proposal)
- fresh step-up markers in the e2e Redis (port 6380) for both owners

Writes IDs to the standard e2e_setup.json (key "approvals") so the
Playwright spec can drive the browser flow.

Usage: python tests/seed_e2e_approvals.py
"""
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

import psycopg2

PG_URL = os.environ.get(
    "E2E_PG_URL",
    "postgresql://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test",
)
REDIS_URL = os.environ.get("E2E_REDIS_URL", "redis://localhost:6380/0")
STEPUP_TTL = int(os.environ.get("E2E_STEPUP_TTL", "900"))  # 15 min
BASE_COMMIT = "e" * 40


def compute_digest(row) -> str:
    # Use the SERVER's canonical digest implementation — never a local
    # re-implementation (divergence would fail approval with digest
    # mismatch, which would be a seeder bug, not a product bug).
    from app.services.action_digest import compute_action_digest

    return compute_action_digest({
        "action_type": row["action_type"],
        "repository_id": str(row["repository_id"]),
        "base_commit_sha": row["base_commit_sha"],
        "target_branch": row["target_branch"],
        "files": row["files"],
        "operations": row["operations"],
        "expected_diff": row["expected_diff"],
    })


def main() -> None:
    conn = psycopg2.connect(PG_URL)
    conn.autocommit = True
    cur = conn.cursor()
    now = int(time.time())
    # Unique per run: avoids collisions on installation_id / github_repo_id
    # when the seeder is re-run against the same database.
    run_tag = now % 1000000
    result = {"users": {}, "cleanup_ids": []}

    # ── approval user (owner of repo A) ──────────────────────────────
    uid = str(uuid4())
    email = f"apr-{now}@cyvrix.test"
    cur.execute(
        "INSERT INTO users (id, email, github_id, github_login) VALUES (%s,%s,%s,%s)",
        (uid, email, now % 900000 + 700000, "apr-user"),
    )
    inst = str(uuid4())
    repo = str(uuid4())
    cur.execute(
        "INSERT INTO github_installations (id, user_id, installation_id, account_login, account_type)"
        " VALUES (%s,%s,%s,%s,%s)",
        (inst, uid, 888000 + run_tag, f"apr-org-{run_tag}", "Organization"),
    )
    cur.execute(
        "INSERT INTO repositories (id, installation_id, github_repo_id, owner, name, default_branch, is_active)"
        " VALUES (%s,%s,%s,%s,%s,%s,true)",
        (repo, inst, 888100 + run_tag, f"apr-org-{run_tag}", f"apr-repo-{run_tag}", "main"),
    )
    result["users"]["approval"] = {"userId": uid, "email": email, "repoId": repo}
    result["cleanup_ids"].append(uid)

    # ── reject user (owner of repo B) ────────────────────────────────
    uid_b = str(uuid4())
    email_b = f"rej-{now}@cyvrix.test"
    cur.execute(
        "INSERT INTO users (id, email, github_id, github_login) VALUES (%s,%s,%s,%s)",
        (uid_b, email_b, now % 900000 + 800000, "rej-user"),
    )
    inst_b = str(uuid4())
    repo_b = str(uuid4())
    cur.execute(
        "INSERT INTO github_installations (id, user_id, installation_id, account_login, account_type)"
        " VALUES (%s,%s,%s,%s,%s)",
        (inst_b, uid_b, 888500 + run_tag, f"rej-org-{run_tag}", "Organization"),
    )
    cur.execute(
        "INSERT INTO repositories (id, installation_id, github_repo_id, owner, name, default_branch, is_active)"
        " VALUES (%s,%s,%s,%s,%s,%s,true)",
        (repo_b, inst_b, 888600 + run_tag, f"rej-org-{run_tag}", f"rej-repo-{run_tag}", "main"),
    )
    result["users"]["reject"] = {"userId": uid_b, "email": email_b, "repoId": repo_b}
    result["cleanup_ids"].append(uid_b)

    def make_proposal(repo_id, creator_id, *, risk="MEDIUM", status="POLICY_CHECKED",
                      expires_hours=24) -> dict:
        scan = str(uuid4())
        cur.execute(
            "INSERT INTO scans (id, repository_id, status, trigger, commit_sha, started_at, completed_at)"
            " VALUES (%s,%s,'COMPLETED','manual',%s,NOW(),NOW())",
            (scan, repo_id, BASE_COMMIT),
        )
        finding = str(uuid4())
        cur.execute(
            "INSERT INTO findings (id, scan_id, repository_id, fingerprint, scanner,"
            " source_type, vulnerability_id, package_name, package_version, title,"
            " description, severity, status, evidence)"
            " VALUES (%s,%s,%s,%s,'dependency','DEPENDENCY','GHSA-2024-8888','lodash',"
            "'4.17.19','Prototype Pollution in lodash','Upgrade lodash.','HIGH','OPEN',%s)",
            (finding, scan, repo_id, f"fp-apr-{finding}",
             json.dumps({"manifest_path": "package.json"})),
        )
        rec = str(uuid4())
        cur.execute(
            "INSERT INTO recommendations (id, finding_id, status, trust_level, title,"
            " change, validation_state) VALUES (%s,%s,'COMPLETED','SUPPORTED',"
            "'Upgrade lodash','Upgrade lodash to 4.17.21','VALIDATED')",
            (rec, finding),
        )
        cur.execute(
            "INSERT INTO risk_assessments (id, finding_id, risk_score, risk_level,"
            " risk_version, factors) VALUES (%s,%s,45,%s,1,%s)",
            (str(uuid4()), finding, risk,
             json.dumps({"base_score": 60, "ai_available": False, "degraded": True})),
        )
        pid = str(uuid4())
        row = {
            "id": pid,
            "action_type": "DEPENDENCY_UPGRADE",
            "repository_id": repo_id,
            "base_commit_sha": BASE_COMMIT,
            "target_branch": "cyvrix/fix",
            "files": ["package.json"],
            "operations": [{
                "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                "name": "lodash", "ecosystem": "npm",
                "from_version": "4.17.19", "to_version": "4.17.21",
            }],
            "expected_diff": '- "lodash": "4.17.19"\n+ "lodash": "4.17.21"',
        }
        row["action_digest"] = compute_digest(row)
        cur.execute(
            "INSERT INTO action_proposals (id, finding_id, recommendation_id, repository_id,"
            " created_by, action_type, status, base_commit_sha, target_branch, files,"
            " operations, expected_diff, rationale, risk_score, risk_level,"
            " recommendation_trust, validation_state, policy_version, policy_decision,"
            " policy_reason_code, policy_matched_rule, action_digest, expires_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,45,%s,'SUPPORTED','VALIDATED',"
            "'3.1','REQUIRE_APPROVAL','MEDIUM_RISK_REQUIRES_APPROVAL','POL-027',%s,%s)",
            (pid, finding, rec, repo_id, creator_id, row["action_type"], status,
             row["base_commit_sha"], row["target_branch"],
             json.dumps(row["files"]), json.dumps(row["operations"]),
             row["expected_diff"], "Patch prototype pollution", risk,
             row["action_digest"],
             datetime.now(timezone.utc) + timedelta(hours=expires_hours)),
        )
        return row

    # Proposal 1: to APPROVE (MEDIUM, live)
    p_approve = make_proposal(repo, uid)
    # Proposal 2: EXPIRED (expired 1h ago)
    p_expired = make_proposal(repo, uid, expires_hours=-1)
    # Proposal 3 (reject user's repo): to REJECT
    p_reject = make_proposal(repo_b, uid_b)

    result["users"]["approval"]["proposalId"] = p_approve["id"]
    result["users"]["approval"]["proposalDigest"] = p_approve["action_digest"]
    result["users"]["approval"]["expiredProposalId"] = p_expired["id"]
    result["users"]["reject"]["proposalId"] = p_reject["id"]
    result["users"]["reject"]["proposalDigest"] = p_reject["action_digest"]

    conn.close()

    # ── step-up markers in the e2e Redis ─────────────────────────────
    import redis

    r = redis.from_url(REDIS_URL, decode_responses=True)
    r.setex(f"stepup:{uid}", STEPUP_TTL, str(now))
    r.setex(f"stepup:{uid_b}", STEPUP_TTL, str(now))
    r.close()

    # ── merge into the standard e2e_setup.json for Playwright ────────
    setup_path = os.path.join(tempfile.gettempdir(), "e2e_setup.json")
    data = {}
    if os.path.exists(setup_path):
        with open(setup_path) as f:
            data = json.load(f)
    data["approvals"] = result
    with open(setup_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Approval seed complete -> {setup_path}", file=sys.stderr)
    print(json.dumps({
        "approve_proposal": p_approve["id"],
        "expired_proposal": p_expired["id"],
        "reject_proposal": p_reject["id"],
    }))


if __name__ == "__main__":
    main()
