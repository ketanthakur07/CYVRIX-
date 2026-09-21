"""CYVRIX V3.5 — Hardened Git execution layer (host-side, controlled).

Trust model (docs/v3-github-remediation.md):
- Git is a FIXED trusted tool; repository content is HOSTILE DATA.
- All invocations use fixed argv ARRAYS. No shell, no command strings,
  no dynamic interpreters, no user-controlled git subcommands.
- Repository configuration CANNOT redefine trusted behavior: global/system
  config is cut off (GIT_CONFIG_GLOBAL/GIT_CONFIG_SYSTEM=/dev/null),
  hooks are disabled (core.hooksPath=/dev/null), fsmonitor/untracked
  cache off, gpgsign off, terminal prompts off, protocol allowlist set.
- Credentials NEVER appear in argv (world-readable via process listing)
  — they pass through the process ENVIRONMENT of the git child only
  (owner-readable /proc), via GIT_CONFIG_* http.extraheader injection.
- NO force push. Pushes are plain refspec pushes; a moved remote branch
  fails the push (expected-state verified before and after).
- Every operation is bounded by a hard timeout; failures return (ok,
  reason, detail) and never raise through the pipeline uncaught.

The URL is constructed ONLY from validated canonical owner/name (our own
verified repository identity), never from client input.
"""
import os
import re
import subprocess
from typing import Optional

from app.services import git_remediation_model as grm

GIT_TIMEOUT_DEFAULT = 60
GIT_TIMEOUT_FETCH = 120
GIT_TIMEOUT_PUSH = 90
MAX_DIFF_BYTES = 512 * 1024

# Transport protocol allowlist for the git child process. Production is
# https-only (GitHub). This is a module CONSTANT, not a setting: no env
# var, no config file, no request input can widen it. The real-stack test
# suite monkeypatches it to include local file transports for local mock
# remotes; production code paths never touch it.
GIT_ALLOWED_PROTOCOLS = "https"

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Fixed trusted Git identity for remediation commits (server-owned).
GIT_COMMIT_NAME = "CYVRIX Remediation"
GIT_COMMIT_EMAIL = "remediation@cyvrix.invalid"


class GitError(Exception):
    """A Git operation failed. reason_code is a stable taxonomy value."""

    def __init__(self, reason_code: str, detail: str = ""):
        self.reason_code = reason_code
        self.detail = detail[:500]
        super().__init__(reason_code)


def build_remote_url(remote_base: str, owner: str, name: str) -> str:
    """Construct the remote URL from VALIDATED canonical identity only.

    owner/name come from the server's verified repository row, but they
    are re-validated here so even a poisoned DB row cannot bend the URL
    (SSRF/remote-substitution defense, Phase 28).
    """
    if not owner or not name or not _SAFE_NAME_RE.match(owner) or not _SAFE_NAME_RE.match(name):
        raise GitError(grm.RC_REMOTE_MISMATCH, "repository identity failed URL validation")
    base = (remote_base or "https://github.com").rstrip("/")
    if not re.match(r"^https?://[A-Za-z0-9.\-_:@\[\]]+(:\d+)?$", base):
        raise GitError(grm.RC_REMOTE_MISMATCH, "remote base URL is not allowlisted")
    return f"{base}/{owner}/{name}.git"


def _base_env() -> dict:
    """Environment that ISOLATES git from repository-controlled config.

    - global/system/local-include config sources cut off
    - no terminal prompts, no askpass, no credential helpers
    - transport protocol restricted to https (http/file/ssh/git denied
      for transport unless the allowlist is explicitly widened)
    """
    env = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true" if os.name != "nt" else "cmd.exe",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ALLOW_PROTOCOL": GIT_ALLOWED_PROTOCOLS,
        "GIT_HTTP_LOW_SPEED_LIMIT": "1024",
        "GIT_HTTP_LOW_SPEED_TIME": "30",
        "LC_ALL": "C",
        "HOME": os.devnull if os.name != "nt" else os.environ.get("TEMP", "."),
    }
    env.update({k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP")})
    return env


def run_git(
    args: list,
    *,
    cwd: str,
    timeout: int = GIT_TIMEOUT_DEFAULT,
    env_extra: Optional[dict] = None,
) -> tuple[bool, str, str]:
    """Run git with a FIXED argv array. Never a shell. Bounded.

    The first three arguments are always pinned by the caller contract:
    ["git", "<trusted-global-args...>", "<subcommand>"]. This helper never
    interprets repository content as commands.
    """
    if not args or args[0] != "git":
        raise GitError(grm.RC_GIT_UNAVAILABLE, "argv must start with the fixed git executable")
    env = _base_env()
    if env_extra:
        env.update(env_extra)
    try:
        proc = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=timeout,
            shell=False,  # absolute: no shell, ever
        )
    except subprocess.TimeoutExpired:
        return False, "", "timeout"
    except FileNotFoundError:
        raise GitError(grm.RC_GIT_UNAVAILABLE, "git executable not found")
    except Exception as exc:
        return False, "", f"{type(exc).__name__}"
    out = proc.stdout.decode("utf-8", errors="replace")[:MAX_DIFF_BYTES]
    err = proc.stderr.decode("utf-8", errors="replace")[:2000]
    return proc.returncode == 0, out, err


def _config_args() -> list:
    """Fixed trusted configuration overriding ANY repository config."""
    return [
        "-c", "core.hooksPath=/dev/null",       # hooks can NEVER run
        "-c", "core.fsmonitor=false",
        "-c", "core.untrackedCache=false",
        "-c", "commit.gpgsign=false",
        "-c", "advice.detachedHead=false",
        "-c", "protocol.allow=user",
        "-c", f"user.name={GIT_COMMIT_NAME}",
        "-c", f"user.email={GIT_COMMIT_EMAIL}",
        "-c", "core.autocrlf=false",
        "-c", "safe.directory=*",
    ]


def credential_env(token: Optional[str]) -> dict:
    """Inject an Authorization header via GIT_CONFIG_* ENV VARS only.

    The token never appears in argv. GIT_CONFIG_VALUE_* is process-env —
    readable only by the same uid (unlike cmdline, which is world-readable).
    """
    if not token:
        return {}
    return {
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "http.extraheader",
        "GIT_CONFIG_VALUE_0": f"Authorization: token {token}",
        "GIT_CONFIG_KEY_1": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_1": f"Authorization: token {token}",
    }


# ── Repository lifecycle ─────────────────────────────────────────────


def init_repo(workspace_dir: str, remote_url: str) -> None:
    ok, out, err = run_git(["git", "init", "--quiet"], cwd=workspace_dir)
    if not ok:
        raise GitError(grm.RC_GIT_OPERATION_FAILED, f"init failed: {err[:200]}")
    ok, out, err = run_git(
        ["git", "remote", "add", "origin", remote_url], cwd=workspace_dir
    )
    if not ok:
        raise GitError(grm.RC_GIT_OPERATION_FAILED, f"remote add failed: {err[:200]}")
    # Verify the remote we just set matches EXACTLY what we intended
    ok, out, err = run_git(["git", "remote", "get-url", "origin"], cwd=workspace_dir)
    if not ok or out.strip() != remote_url:
        raise GitError(grm.RC_REMOTE_MISMATCH, "remote URL verification failed")


def fetch_and_verify_base(
    workspace_dir: str, remote_url: str, source_branch: str, base_commit_sha: str
) -> None:
    """Fetch the source branch and PROVE the authorized base is intact.

    Two checks (Phase 11: base-commit protection, STALE = DENY):
    1. TIP equality: the remote source branch must still point at the
       authorized base SHA. A moved tip means the repository changed
       underneath the approved action → STALE, never auto-rebase.
    2. RESOLUTION: after fetching the branch, the base SHA must resolve
       to itself (history rewritten / wrong repository → fail closed).
    """
    grm.validate_repo_branch_name(source_branch)
    remote_tip = ls_remote(f"refs/heads/{source_branch}", remote_url)
    if remote_tip is None:
        raise GitError(grm.RC_BASE_COMMIT_MISMATCH,
                       "remote source branch is missing")
    if remote_tip != base_commit_sha.lower():
        raise GitError(grm.RC_BASE_COMMIT_MISMATCH,
                       "remote source branch moved: repository changed "
                       "underneath the approved action (stale)")
    ok, out, err = run_git(
        ["git", *(_config_args()), "fetch", "--quiet", "--no-tags", "--no-recurse-submodules",
         "origin", source_branch],
        cwd=workspace_dir, timeout=GIT_TIMEOUT_FETCH,
    )
    if not ok:
        raise GitError(grm.RC_GIT_OPERATION_FAILED, f"fetch failed: {err[:200]}")
    ok, out, err = run_git(
        ["git", "rev-parse", "--verify", "--quiet", f"{base_commit_sha}^{{commit}}"],
        cwd=workspace_dir,
    )
    if not ok or out.strip().lower() != base_commit_sha.lower():
        raise GitError(
            grm.RC_BASE_COMMIT_MISMATCH,
            "authorized base commit is not present on the remote source branch",
        )


def checkout_base(workspace_dir: str, base_commit_sha: str) -> None:
    ok, out, err = run_git(
        ["git", *(_config_args()), "checkout", "--quiet", "--detach", base_commit_sha],
        cwd=workspace_dir,
    )
    if not ok:
        raise GitError(grm.RC_BASE_COMMIT_MISMATCH, f"checkout failed: {err[:200]}")
    ok, head, _ = run_git(["git", "rev-parse", "HEAD"], cwd=workspace_dir)
    if not ok or head.strip().lower() != base_commit_sha.lower():
        raise GitError(grm.RC_BASE_COMMIT_MISMATCH, "HEAD does not match authorized base SHA")


def create_branch(workspace_dir: str, branch: str, base_commit_sha: str) -> None:
    grm.validate_repo_branch_name(branch)
    ok, out, err = run_git(
        ["git", *(_config_args()), "checkout", "--quiet", "-b", branch, base_commit_sha],
        cwd=workspace_dir,
    )
    if not ok:
        raise GitError(grm.RC_GIT_OPERATION_FAILED, f"branch creation failed: {err[:200]}")


def stage_authorized_files(workspace_dir: str, files: list[str]) -> None:
    """Stage EXACTLY the authorized file set (pathspec-restricted add).

    Untracked unexpected files are never staged because only the
    authorized pathspecs are passed. Each path is validated before use.
    """
    if not files:
        raise GitError(grm.RC_SCOPE_VIOLATION, "no authorized files to stage")
    from app.services.action_model import normalize_and_validate_path
    for f in files:
        normalize_and_validate_path(f)  # raises on any unsafe path
    ok, out, err = run_git(
        ["git", *(_config_args()), "add", "--", *files],
        cwd=workspace_dir,
    )
    if not ok:
        raise GitError(grm.RC_GIT_OPERATION_FAILED, f"stage failed: {err[:200]}")


def staged_change_set(workspace_dir: str) -> tuple[list[dict], str]:
    """Authoritative server-side diff of staged changes (never client data).

    Returns (changes, raw_diff_bounded). changes: [{path, status}] where
    status is added/modified/deleted (renames are surfaced as add+delete —
    we never let git rename detection silently expand scope).
    """
    ok, out, err = run_git(
        ["git", *(_config_args()), "diff", "--cached", "--no-renames", "--name-status", "-z"],
        cwd=workspace_dir,
    )
    if not ok:
        raise GitError(grm.RC_GIT_OPERATION_FAILED, f"diff failed: {err[:200]}")
    parts = [p for p in out.split("\x00") if p]
    changes: list[dict] = []
    i = 0
    while i < len(parts):
        status = parts[i].strip()
        if not status:
            i += 1
            continue
        if status in ("A", "M", "D") and i + 1 < len(parts):
            changes.append({"path": parts[i + 1], "status": status})
            i += 2
        elif status.startswith("R") or status.startswith("C"):
            # Rename/copy detection disabled by --no-renames; if it still
            # appears, treat as unexpected and fail closed upstream.
            changes.append({"path": parts[i + 1] if i + 1 < len(parts) else "", "status": status})
            i += 2
        else:
            i += 1
    ok, raw, _ = run_git(
        ["git", *(_config_args()), "diff", "--cached", "--no-renames"],
        cwd=workspace_dir,
    )
    raw_bounded = raw[:MAX_DIFF_BYTES]
    if len(raw.encode("utf-8", errors="replace")) > MAX_DIFF_BYTES:
        raise GitError(grm.RC_DIFF_TOO_LARGE, "staged diff exceeds size cap")
    return changes, raw_bounded


def commit(workspace_dir: str, message: str) -> str:
    """Commit staged changes with the fixed server identity. Returns SHA."""
    ok, out, err = run_git(
        ["git", *(_config_args()), "commit", "--quiet", "--no-verify",
         "-m", message],
        cwd=workspace_dir,
    )
    if not ok:
        raise GitError(grm.RC_GIT_OPERATION_FAILED, f"commit failed: {err[:200]}")
    ok, head, _ = run_git(["git", "rev-parse", "HEAD"], cwd=workspace_dir)
    if not ok or not re.match(r"^[0-9a-f]{40}$", head.strip().lower()):
        raise GitError(grm.RC_GIT_OPERATION_FAILED, "commit SHA verification failed")
    return head.strip().lower()


def commit_parent(workspace_dir: str) -> Optional[str]:
    ok, out, _ = run_git(["git", "rev-parse", "HEAD^"], cwd=workspace_dir)
    return out.strip().lower() if ok and re.match(r"^[0-9a-f]{40}$", out.strip().lower()) else None


def ls_remote(ref: str, remote_url: str, token: Optional[str] = None,
              cwd: Optional[str] = None) -> Optional[str]:
    """Query the REMOTE's current ref (trusted server-side state)."""
    ok, out, err = run_git(
        ["git", *(_config_args()), "ls-remote", remote_url, ref],
        cwd=cwd or os.getcwd(),  # ls-remote needs no repository
        timeout=GIT_TIMEOUT_DEFAULT,
        env_extra=credential_env(token),
    )
    if not ok:
        raise GitError(grm.RC_GIT_OPERATION_FAILED, f"ls-remote failed: {err[:200]}")
    for line in out.splitlines():
        sha, _, name = line.partition("\t")
        if name.strip() == ref and re.match(r"^[0-9a-f]{40}$", sha.strip().lower()):
            return sha.strip().lower()
    return None


def show_object(
    workspace_dir: str, commit_sha: str, file_path: str,
) -> Optional[str]:
    """Read ONE file's content at ONE commit from local git objects.

    Trusted host-side read (V3.6 verification evidence source): the argv
    is fixed, the path is validated, output is bounded. The repository
    content itself is still UNTRUSTED DATA — callers must scrub before
    storing/persisting any of it.
    """
    from app.services.action_model import normalize_and_validate_path
    if not re.match(r"^[0-9a-f]{40}$", (commit_sha or "").lower()):
        raise GitError(grm.RC_GIT_OPERATION_FAILED, "invalid commit SHA")
    canonical = normalize_and_validate_path(file_path)
    ok, out, err = run_git(
        ["git", *(_config_args()), "show", f"{commit_sha.lower()}:{canonical}"],
        cwd=workspace_dir,
        timeout=GIT_TIMEOUT_DEFAULT,
    )
    if not ok:
        return None
    return out[:MAX_DIFF_BYTES]


def commit_files_at(workspace_dir: str, commit_sha: str) -> list[dict]:
    """Authoritative list of files changed by ONE commit (name-status)."""
    if not re.match(r"^[0-9a-f]{40}$", (commit_sha or "").lower()):
        raise GitError(grm.RC_GIT_OPERATION_FAILED, "invalid commit SHA")
    ok, out, err = run_git(
        ["git", *(_config_args()), "diff-tree", "--no-commit-id",
         "--name-status", "-r", "--no-renames", "-z",
         commit_sha.lower()],
        cwd=workspace_dir,
    )
    if not ok:
        raise GitError(grm.RC_GIT_OPERATION_FAILED, f"diff-tree failed: {err[:200]}")
    parts = [p for p in out.split("\x00") if p]
    changes: list[dict] = []
    i = 0
    while i < len(parts):
        status = parts[i].strip()
        if status in ("A", "M", "D") and i + 1 < len(parts):
            changes.append({"path": parts[i + 1], "status": status})
            i += 2
        else:
            i += 1
    return changes


def commit_parent_sha(workspace_dir: str, commit_sha: str) -> Optional[str]:
    """Trusted read of ONE commit's first parent SHA (None for root)."""
    if not re.match(r"^[0-9a-f]{40}$", (commit_sha or "").lower()):
        raise GitError(grm.RC_GIT_OPERATION_FAILED, "invalid commit SHA")
    ok, out, _ = run_git(
        ["git", *(_config_args()), "rev-parse", f"{commit_sha.lower()}^"],
        cwd=workspace_dir,
    )
    if not ok:
        return None  # root commit has no parent
    out = out.strip().lower()
    return out if re.match(r"^[0-9a-f]{40}$", out) else None


def push_branch(
    workspace_dir: str, remote_url: str, branch: str,
    token: Optional[str], expected_remote_sha: Optional[str],
) -> str:
    """Push the remediation branch WITHOUT force, after verifying the
    remote branch state. Returns the pushed SHA.

    - Non-fast-forward (remote moved) → push fails → fail closed
    - Force variants are structurally impossible (argv is fixed here;
      no force flag of any kind is ever constructed)
    """
    grm.validate_repo_branch_name(branch)
    remote_sha = ls_remote(f"refs/heads/{branch}", remote_url, token)
    if remote_sha is not None:
        # Branch already exists remotely: only acceptable if it is exactly
        # the state we pushed for THIS remediation (idempotent retry), and
        # the caller validates the SHA. A different remote SHA is a
        # collision → fail closed.
        if expected_remote_sha is None or remote_sha != expected_remote_sha:
            raise GitError(grm.RC_REMOTE_STATE_MISMATCH,
                           "remote remediation branch already exists at an unexpected SHA")
        return remote_sha
    ok, out, err = run_git(
        ["git", *(_config_args()), "push", "--quiet", "--no-verify",
         remote_url, f"{branch}:{branch}"],
        cwd=workspace_dir, timeout=GIT_TIMEOUT_PUSH,
        env_extra=credential_env(token),
    )
    if not ok:
        if "fetch first" in err.lower() or "rejected" in err.lower():
            raise GitError(grm.RC_REMOTE_STATE_MISMATCH, f"push rejected: {err[:200]}")
        if "403" in err or "401" in err or "authentication" in err.lower():
            raise GitError(grm.RC_PUSH_FAILED, f"push unauthorized: {err[:200]}")
        raise GitError(grm.RC_PUSH_FAILED, f"push failed: {err[:200]}")
    pushed = ls_remote(f"refs/heads/{branch}", remote_url, token)
    if pushed is None:
        raise GitError(grm.RC_GITHUB_STATE_MISMATCH, "pushed branch not visible on remote")
    return pushed
