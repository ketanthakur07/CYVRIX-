"""Mock git remote — real-transport regression tests (V3.6 certification).

The V3.6 certification discovered that git compresses large
upload-pack/receive-pack request bodies with `Content-Encoding: gzip`
(request size grows with the advertised ref count). The mock previously
fed raw gzip bytes to `git upload-pack --stateless-rpc`, which exited
immediately and produced an empty 200 — the client then failed with
'fatal: the remote end hung up unexpectedly' and, worse, the SILENT
failure masked real behavior in race suites (a missing developer push
made a rollback succeed instead of conflicting).

These tests pin the contract:
- gzip-encoded request bodies are decompressed before reaching git
- unknown Content-Encoding values are rejected with 415
- a git RPC that produces no output fails visibly (500), never 200-empty

They run in-process against services/mock-providers/server.py with no
external services required.
"""
import gzip
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "services", "mock-providers"))

import server as mock_server  # noqa: E402

REPO = "gzip-regression-repo"
REPO_FILES = {
    "package.json": '{\n  "lodash": "4.17.19"\n}\n',
    "README.md": "# gzip-regression\n",
}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def remote():
    port = _free_port()
    mock_server.REPOS_DIR = tempfile.mkdtemp(prefix="gzipreg-repos-")
    mock_server.FIXTURE_DIR = tempfile.mkdtemp(prefix="gzipreg-fix-")
    mock_server._initialized_repos.clear()

    import uvicorn
    config = uvicorn.Config(mock_server.app, host="127.0.0.1", port=port,
                            log_level="error")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("mock git remote did not start")

    base = f"http://127.0.0.1:{port}"
    fixture = os.path.join(mock_server.FIXTURE_DIR, REPO)
    os.makedirs(fixture, exist_ok=True)
    for rel, content in REPO_FILES.items():
        with open(os.path.join(fixture, rel), "w", newline="") as fh:
            fh.write(content)
    yield base

    srv.should_exit = True
    thread.join(timeout=10)


def _git(*args, cwd=None, check=True):
    out = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    if check:
        assert out.returncode == 0, (
            args, out.stderr.decode(errors="replace")[:300])
    return out


def _push_many_branches(work: str, count: int) -> None:
    """Grow the repo past git's compressed-request threshold."""
    _git("-C", work, "fetch", "-q", "origin")
    for i in range(1, count + 1):
        branch = f"bulk{i}"
        _git("-C", work, "checkout", "-q", "-B", branch, "origin/main")
        with open(os.path.join(work, f"bulk_{i}.bin"), "w") as fh:
            fh.write("x" * 2048)
        _git("-C", work, "add", ".")
        _git("-C", work, "-c", "user.name=T", "-c", "user.email=t@t",
             "commit", "-qm", f"bulk {i}")
        _git("-C", work, "push", "-q", "origin", branch)


def test_gzip_upload_pack_request_is_handled(remote, tmp_path):
    """Clone after many branches exist: the upload-pack request body is
    gzip-encoded by git and MUST be decompressed server-side. Before the
    fix this failed with 'remote end hung up unexpectedly'."""
    work = tmp_path / "seed"
    _git("clone", "-q", f"{remote}/test-org/{REPO}.git", str(work))
    _push_many_branches(str(work), 25)

    clone = tmp_path / "after-growth"
    out = _git("clone", "-q", f"{remote}/test-org/{REPO}.git", str(clone), check=False)
    assert out.returncode == 0, out.stderr.decode(errors="replace")[:300]
    assert "hung up" not in out.stderr.decode(errors="replace")


def test_gzip_receive_pack_request_is_handled(remote, tmp_path):
    """Push after many refs exist: receive-pack requests are also
    gzip-encoded above the threshold and must be decompressed."""
    work = tmp_path / "push"
    _git("clone", "-q", f"{remote}/test-org/{REPO}.git", str(work))
    # The repo already carries the bulk branches from the previous test;
    # a fresh clone + push still exercises a large advertisement + push.
    _git("-C", str(work), "checkout", "-q", "-B", "gzip-push", "origin/main")
    with open(os.path.join(str(work), "gzip_push.txt"), "w") as fh:
        fh.write("payload")
    _git("-C", str(work), "add", ".")
    _git("-C", str(work), "-c", "user.name=T", "-c", "user.email=t@t",
         "commit", "-qm", "gzip push")
    out = _git("-C", str(work), "push", "-q", "origin", "gzip-push",
               check=False)
    assert out.returncode == 0, out.stderr.decode(errors="replace")[:300]
    out = _git("ls-remote", f"{remote}/test-org/{REPO}.git", "refs/heads/gzip-push")
    assert out.stdout.decode().strip()


def test_unsupported_content_encoding_rejected_415(remote):
    """A non-gzip Content-Encoding must be rejected 415, not silently
    processed as raw bytes."""
    import httpx
    body = gzip.compress(b"not-a-git-request")
    r = httpx.post(
        f"{remote}/test-org/{REPO}.git/git-upload-pack",
        content=body,
        headers={
            "Content-Type": "application/x-git-upload-pack-request",
            "Content-Encoding": "br",
        },
    )
    assert r.status_code == 415, (r.status_code, r.text[:200])


def test_failed_git_rpc_is_not_silent_200(remote):
    """A git RPC that produces no output must return a visible 500, never
    an empty 200 (the failure mode that masked race-suite behavior)."""
    import httpx
    # Malformed pkt-line body: upload-pack exits without stdout.
    r = httpx.post(
        f"{remote}/test-org/{REPO}.git/git-upload-pack",
        content=b"\xff\xff\xff\xffnot-pkt-line",
        headers={"Content-Type": "application/x-git-upload-pack-request"},
    )
    assert r.status_code == 500, (r.status_code, r.text[:200])
    assert "git rpc failed" in r.text
