"""CYVRIX V3.4 — Workspace materialization + host-side verification.

Materializes ONLY the approved file scope at the PINNED base commit from
a trusted source (GitHub contents API with a short-lived installation
token, ref=pinned SHA), into an ephemeral host-side workspace directory
that becomes the sandbox's /workspace. No host checkout is ever mounted
(§13/§42); nothing here trusts repository content as instructions.

Host-side verification (§49-§53) runs in THIS process — never inside the
sandbox — so repository content cannot forge status or hide changes:
- BEFORE/AFTER content-addressed snapshots (hashes persisted; V3.6/V3.7)
- after-set must equal before-set ± exactly the approved files
- final paths re-resolved AFTER execution (symlink aftermath, §50)
- permission/ownership changes outside the approved files are violations
"""
import hashlib
import os
import shutil
import stat
import tempfile
import uuid as uuid_mod
from pathlib import Path
from typing import Optional

from app.services import execution_run_model as erm

MAX_FILE_BYTES = 2 * 1024 * 1024
SNAPSHOT_SET_ATTRS = {"st_uid", "st_gid", "st_mode"}


class WorkspaceError(Exception):
    def __init__(self, reason_code: str, detail: str = ""):
        self.reason_code = reason_code
        self.detail = detail[:300]
        super().__init__(reason_code)


def sha256_file(path: str) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _workspace_root() -> str:
    """Root of the ephemeral workspace area (dedicated, not the project)."""
    base = os.environ.get("CYVRIX_SANDBOX_WORKSPACE_ROOT") or \
        os.path.join(tempfile.gettempdir(), "cyvrix-sandboxes")
    os.makedirs(base, mode=0o700, exist_ok=True)
    return base


def new_workspace_dir() -> str:
    root = _workspace_root()
    path = os.path.join(root, f"ws-{uuid_mod.uuid4().hex}")
    os.makedirs(path, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def remove_workspace_dir(path: str) -> tuple[bool, str]:
    try:
        # Defense in depth: refuse to rm -rf anything outside the
        # dedicated sandbox workspace root (even if a caller passes a
        # wrong path — e.g. a traversal-smuggled one).
        root = os.path.realpath(_workspace_root())
        real = os.path.realpath(path)
        if real != root and not real.startswith(root + os.sep):
            return False, "refusing to remove path outside sandbox workspace root"
        shutil.rmtree(path, ignore_errors=False)
        return True, ""
    except Exception as exc:
        return False, f"{type(exc).__name__}"


class MaterializationError(WorkspaceError):
    pass


def _validate_materialized_path(repo_rel: str) -> str:
    """Re-validate a scope path with the V3.1 validator at materialization
    time (defense in depth — the proposal was validated at creation)."""
    from app.services.action_model import (
        PathValidationError, normalize_and_validate_path,
    )
    try:
        return normalize_and_validate_path(repo_rel)
    except PathValidationError as exc:
        raise MaterializationError("ACTION_SCOPE_VIOLATION", str(exc)[:200])


async def materialize_workspace(
    installation_id: int,
    owner: str,
    repo_name: str,
    base_commit_sha: str,
    files: list[str],
    workspace_dir: str,
) -> dict:
    """Fetch each approved file at the pinned commit into the workspace.

    Trusted source: GitHub contents API, ref = the proposal's pinned
    base_commit_sha. A missing approved file is a hard error (the
    proposal binds to a snapshot that no longer matches reality). No
    repository content is executed, parsed as instructions, or trusted
    beyond being file bytes.
    """
    from app.services.github import (
        GitHubAuthError, GitHubRateLimitError, GitHubUnavailableError,
        get_installation_access_token,
    )

    if not files:
        raise MaterializationError("ACTION_SCOPE_VIOLATION", "no approved files")

    token = await get_installation_access_token(int(installation_id))
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.raw+json",
    }
    base_url = os.environ.get("GITHUB_API_BASE", "https://api.github.com")
    fetched: dict[str, str] = {}
    import httpx

    async with httpx.AsyncClient(timeout=30.0) as client:
        for rel in files:
            canonical = _validate_materialized_path(rel)
            if canonical in fetched:  # duplicate scope entries
                raise MaterializationError("ACTION_SCOPE_VIOLATION",
                                           "duplicate file in scope")
            url = f"{base_url}/repos/{owner}/{repo_name}/contents/{canonical}"
            resp = await client.get(url, headers=headers,
                                    params={"ref": base_commit_sha})
            if resp.status_code == 404:
                raise MaterializationError(
                    "ACTION_STALE", f"approved file {canonical} missing at base commit")
            if resp.status_code in (401, 403):
                raise MaterializationError("SANDBOX_UNAVAILABLE",
                                           "workspace source authentication failed")
            if resp.status_code >= 500 or resp.status_code == 429:
                raise MaterializationError("SANDBOX_UNAVAILABLE",
                                           "workspace source unavailable")
            if resp.status_code != 200:
                raise MaterializationError("SANDBOX_UNAVAILABLE",
                                           "unexpected workspace source response")
            raw = resp.content
            if len(raw) > MAX_FILE_BYTES:
                raise MaterializationError("RESOURCE_LIMIT",
                                           "file exceeds per-file size cap")
            # Never follow symlinks from the source: GitHub serves content
            # (a symlink entry would be a small text file) — we write bytes.
            target = os.path.join(workspace_dir, *canonical.split("/"))
            os.makedirs(os.path.dirname(target) or workspace_dir, exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(raw)
            fetched[canonical] = sha256_bytes(raw)

    return {"files": fetched, "source": "github-contents-api",
            "ref": base_commit_sha}


def snapshot_workspace(workspace_dir: str, phase: str) -> dict[str, dict]:
    """Content-address the workspace (BEFORE or AFTER).

    Returns {relpath: {sha256, size_bytes, mode, uid, gid}}. Host-side
    only; content itself is never persisted or returned.
    """
    snap: dict[str, dict] = {}
    workspace_dir = os.path.realpath(workspace_dir)
    for dirpath, dirnames, filenames in os.walk(workspace_dir):
        # .cyvrix payload dir is executor-owned machinery, not repo state
        if os.path.realpath(dirpath) == os.path.join(workspace_dir, ".cyvrix"):
            dirnames[:] = []
            continue
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, workspace_dir).replace(os.sep, "/")
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                snap[rel] = {"sha256": "SYMLINK", "size_bytes": int(st.st_size),
                             "mode": stat.S_IMODE(st.st_mode),
                             "uid": st.st_uid, "gid": st.st_gid,
                             "symlink": True}
                continue
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                snap[rel] = {"sha256": f"SPECIAL:{stat.S_IFMT(st.st_mode):o}",
                             "size_bytes": int(st.st_size),
                             "mode": stat.S_IMODE(st.st_mode),
                             "uid": st.st_uid, "gid": st.st_gid}
                continue
            digest = sha256_file(full)
            if digest is None:
                raise WorkspaceError("FILESYSTEM_VIOLATION",
                                     f"unreadable file during snapshot: {rel}")
            snap[rel] = {"sha256": digest, "size_bytes": int(st.st_size),
                         "mode": stat.S_IMODE(st.st_mode),
                         "uid": st.st_uid, "gid": st.st_gid}
    return snap


def _effective_change(rel: str, before: dict, after: dict) -> Optional[str]:
    """Classify the change to one path (None = no material change)."""
    b, a = before.get(rel), after.get(rel)
    if b is None and a is None:
        return None
    if b is not None and a is None:
        return "deleted"
    if b is None and a is not None:
        return "created"
    if b["sha256"] != a["sha256"]:
        return "modified"
    # Same content but permission/ownership drift counts (§52)
    if b["mode"] != a["mode"] or b["uid"] != a["uid"] or b["gid"] != a["gid"]:
        return "metadata_changed"
    return None


def verify_scope_and_diff(
    before: dict, after: dict, allowed_files: list[str], operations: list[dict]
) -> tuple[bool, str, list[str]]:
    """Host-side verification of what ACTUALLY changed (§49/§51/§52).

    Returns (ok, reason_code, changed_files). The after-set must equal
    the before-set plus/minus exactly the approved files; unexpected
    creation/deletion/metadata change outside the approved set is an
    ACTION_SCOPE_VIOLATION. Content inside approved files may differ
    freely (that is the execution), metadata drift inside them is also
    accepted (chown in-container maps to host uid anyway).
    """
    allowed = set(allowed_files)
    violations: list[str] = []

    for rel in sorted(set(before) | set(after)):
        if rel == ".cyvrix" or rel.startswith(".cyvrix/"):
            continue
        change = _effective_change(rel, before, after)
        if change is None:
            continue
        if rel not in allowed:
            violations.append(f"{rel}: {change} outside approved scope")
            continue

    if violations:
        return False, erm.RC_ACTION_SCOPE_VIOLATION, violations

    # Every approved file must have been touched by an operation (a file
    # listed in the contract but unchanged means the operations silently
    # no-op'd — treated as an operation failure at the service layer, not
    # a scope violation).
    changed = [rel for rel in sorted(allowed)
               if _effective_change(rel, before, after) is not None]
    return True, erm.RC_OK, changed


def build_change_set(before: dict, after: dict) -> dict:
    """Change set for the diff digest: {path: {before_sha256, after_sha256}}."""
    change_set = {}
    for rel in sorted(set(before) | set(after)):
        if rel == ".cyvrix" or rel.startswith(".cyvrix/"):
            continue
        b = (before.get(rel) or {}).get("sha256")
        a = (after.get(rel) or {}).get("sha256")
        if b == a and b is not None:
            continue
        change_set[rel] = {"before_sha256": b, "after_sha256": a}
    return change_set
