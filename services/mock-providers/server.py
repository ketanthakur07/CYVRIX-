"""
CYVRIX Mock Provider Servers for Golden Path E2E.

Mocks only external provider boundaries:
- GitHub API (token endpoint, repo contents, code search)
- OSV API (vulnerability database)
- OpenAI API (LLM)

All other CYVRIX services remain REAL.
"""
import base64
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(title="CYVRIX Mock Providers")

# ── Configuration ──────────────────────────────────────────────────

REPOS_DIR = os.environ.get("REPOS_DIR", "/repos")
FIXTURE_DIR = os.environ.get("FIXTURE_DIR", "/fixtures")

# Track which repos have been "cloned" (initialized as bare repos)
_initialized_repos = set()


def _ensure_repo_initialized(repo_name: str) -> str:
    """Ensure a test fixture repo exists as a bare git repo."""
    if repo_name in _initialized_repos:
        bare_path = os.path.join(REPOS_DIR, repo_name + ".git")
        if os.path.exists(bare_path):
            return bare_path

    fixture_path = os.path.join(FIXTURE_DIR, repo_name)
    bare_path = os.path.join(REPOS_DIR, repo_name + ".git")

    if not os.path.exists(fixture_path):
        raise FileNotFoundError(f"Fixture not found: {fixture_path}")

    # Initialize as bare repo
    os.makedirs(REPOS_DIR, exist_ok=True)
    subprocess.run(["git", "init", "--bare", bare_path], check=True, capture_output=True)

    # Clone fixture, commit, push to bare repo
    tmp_dir = f"/tmp/work_{repo_name}"
    if os.path.exists(tmp_dir):
        subprocess.run(["rm", "-rf", tmp_dir], check=True)

    subprocess.run(["git", "init", tmp_dir], check=True, capture_output=True)

    # Copy fixture files
    for item in os.listdir(fixture_path):
        src = os.path.join(fixture_path, item)
        dst = os.path.join(tmp_dir, item)
        if os.path.isdir(src):
            subprocess.run(["cp", "-r", src, dst], check=True)
        else:
            subprocess.run(["cp", src, dst], check=True)

    subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@test.com",
         "commit", "-m", "Initial commit"],
        cwd=tmp_dir, check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@test.com",
         "branch", "-M", "main"],
        cwd=tmp_dir, check=True, capture_output=True,
    )
    subprocess.run(["git", "remote", "add", "origin", bare_path], cwd=tmp_dir, check=True, capture_output=True)
    subprocess.run(["git", "push", "origin", "main"], cwd=tmp_dir, check=True, capture_output=True)

    # Set HEAD to point to main so clones check out main
    head_file = os.path.join(bare_path, "HEAD")
    with open(head_file, "w") as f:
        f.write("ref: refs/heads/main\n")

    subprocess.run(["rm", "-rf", tmp_dir], check=True)
    _initialized_repos.add(repo_name)
    return bare_path


# ═══════════════════════════════════════════════════════════════════
# GitHub API Mocks
# ═══════════════════════════════════════════════════════════════════

@app.post("/app/installations/{installation_id}/access_tokens")
async def github_create_token(installation_id: int):
    """Mock GitHub App installation token creation."""
    token = f"mock_token_{installation_id}_{uuid4().hex[:16]}"
    return {
        "token": token,
        "expires_at": "2099-01-01T00:00:00Z",
        "permissions": {"contents": "read", "metadata": "read"},
    }


@app.get("/installation/repositories")
async def github_list_repos(request: Request):
    """Mock GitHub installation repositories endpoint."""
    auth = request.headers.get("Authorization", "")
    return {
        "total_count": 0,
        "repositories": [],
    }


@app.get("/repos/{owner}/{repo}/contents/{path:path}")
async def github_file_content(owner: str, repo: str, path: str):
    """Mock GitHub file content endpoint for investigation evidence gathering."""
    # Try to read from fixture
    fixture_path = os.path.join(FIXTURE_DIR, repo, path)
    if os.path.exists(fixture_path) and os.path.isfile(fixture_path):
        with open(fixture_path, "r", errors="replace") as f:
            content = f.read()
        encoded = base64.b64encode(content.encode()).decode()
        return {
            "name": os.path.basename(path),
            "path": path,
            "content": encoded,
            "encoding": "base64",
            "size": len(content),
            "type": "file",
        }
    return JSONResponse(status_code=404, content={"message": "Not Found"})


@app.get("/search/code")
async def github_code_search():
    """Mock GitHub code search - return empty results."""
    return {"total_count": 0, "items": []}


# ═══════════════════════════════════════════════════════════════════
# OSV API Mocks
# ═══════════════════════════════════════════════════════════════════

# Pre-defined vulnerability responses for known test packages
OSV_VULNS = {
    "lodash": [
        {
            "id": "GHSA-jf85-cpcp-j695",
            "summary": "Prototype Pollution in lodash",
            "details": "Versions of lodash prior to 4.17.21 are vulnerable to Prototype Pollution.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "aliases": ["CVE-2021-23337"],
        },
    ],
    "express": [
        {
            "id": "GHSA-qw6h-vgh9-j4wx",
            "summary": "Open Redirect in express",
            "details": "Express.js before 4.19.2 allows open redirect via URL encoding.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
            "aliases": ["CVE-2024-29041"],
        },
    ],
    "minimist": [
        {
            "id": "GHSA-xvch-5gv4-984h",
            "summary": "Prototype Pollution in minimist",
            "details": "Minimist before 1.2.6 is vulnerable to Prototype Pollution.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "aliases": ["CVE-2021-44906"],
        },
    ],
}


@app.post("/v1/querybatch")
async def osv_query_batch(request: Request):
    """Mock OSV batch vulnerability query."""
    body = await request.json()
    queries = body.get("queries", [])
    results = []

    for q in queries:
        pkg = q.get("package", {})
        name = pkg.get("name", "")
        version = q.get("version", "")

        vulns = OSV_VULNS.get(name, [])
        if vulns:
            results.append({
                "package": pkg,
                "vulns": vulns,
            })
        else:
            results.append({
                "package": pkg,
                "vulns": [],
            })

    return {"results": results}


# ═══════════════════════════════════════════════════════════════════
# OpenAI LLM API Mocks
# ═══════════════════════════════════════════════════════════════════


@app.post("/v1/chat/completions")
async def llm_chat_completions(request: Request):
    """Mock OpenAI chat completions for investigation."""
    body = await request.json()
    messages = body.get("messages", [])

    # Get the user message to determine context
    user_msg = ""
    for m in messages:
        if m.get("role") == "user":
            user_msg = m.get("content", "")
            break

    # Determine vulnerability context from the prompt
    verdict = "LIKELY"
    exploitability = "MEDIUM"
    exposure = "UNKNOWN"
    confidence = 0.7

    if "lodash" in user_msg.lower():
        summary = "The application imports lodash 4.17.19 which has a known prototype pollution vulnerability. The package is used in the dependency tree."
        recommendation = "Upgrade lodash to version 4.17.21 or later to resolve the prototype pollution vulnerability."
    elif "express" in user_msg.lower():
        summary = "Express.js is listed as a dependency. The open redirect vulnerability affects URL handling in specific middleware configurations."
        recommendation = "Upgrade express to version 4.19.2 or later."
    elif "minimist" in user_msg.lower():
        summary = "Minimist 0.0.8 is vulnerable to prototype pollution. It may be a transitive dependency."
        recommendation = "Upgrade minimist to version 1.2.6 or later."
    else:
        summary = "The vulnerability was identified in the dependency. Further investigation recommended."
        recommendation = "Review the dependency and consider upgrading."

    investigation_result = {
        "verdict": verdict,
        "exploitability": exploitability,
        "exposure": exposure,
        "confidence": confidence,
        "summary": summary,
        "evidence": [
            {"file": "package.json", "line": 1, "reason": "Package listed in dependencies"}
        ],
        "assumptions": ["Dependency is used in production"],
        "uncertainties": ["Deployment configuration unknown"],
        "recommendation": recommendation,
    }

    return {
        "id": f"chatcmpl-{uuid4().hex[:16]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "gpt-4o-mini"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(investigation_result),
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 200, "total_tokens": 300},
    }


# ═══════════════════════════════════════════════════════════════════
# Git Smart HTTP Protocol
# ═══════════════════════════════════════════════════════════════════

@app.get("/{owner}/{repo}.git/info/refs")
@app.post("/{owner}/{repo}.git/info/refs")
async def git_info_refs(owner: str, repo: str, request: Request):
    """Git smart HTTP: advertise refs."""
    bare_path = _ensure_repo_initialized(repo)
    service = request.query_params.get("service", "git-upload-pack")

    result = subprocess.run(
        ["git", "upload-pack", "--stateless-rpc", "--advertise-refs", bare_path],
        capture_output=True,
    )

    # Git smart HTTP requires the service line to be packet-framed
    service_line = f"# service={service}\n"
    pkt = f"{len(service_line) + 4:04x}{service_line}".encode()
    pkt += b"0000"  # flush
    pkt += result.stdout

    return Response(
        content=pkt,
        media_type="application/x-git-upload-pack-advertisement",
        headers={"Cache-Control": "no-cache"},
    )


@app.post("/{owner}/{repo}.git/git-upload-pack")
async def git_upload_pack(owner: str, repo: str, request: Request):
    """Git smart HTTP: upload-pack (clone/fetch)."""
    bare_path = _ensure_repo_initialized(repo)
    body = await request.body()

    result = subprocess.run(
        ["git", "upload-pack", "--stateless-rpc", bare_path],
        input=body,
        capture_output=True,
    )

    return Response(
        content=result.stdout,
        media_type="application/x-git-upload-pack-result",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/{owner}/{repo}.git/HEAD")
async def git_head(owner: str, repo: str):
    """Serve HEAD file for loose clone fallback."""
    try:
        bare_path = _ensure_repo_initialized(repo)
        head_path = os.path.join(bare_path, "HEAD")
        if os.path.exists(head_path):
            with open(head_path, "r") as f:
                return PlainTextResponse(f.read())
    except Exception:
        pass
    return JSONResponse(status_code=404, content={"message": "Not Found"})


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
