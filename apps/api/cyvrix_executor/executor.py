"""Closed-world, no-shell executor for approved structured operations.

Runs INSIDE the ephemeral sandbox (non-root, no network, read-only root
filesystem except /workspace). Reads the operations payload from
/workspace/.cyvrix/operations.json, applies ONLY the six V3.1 structured
operation types, and writes the bounded result to
/workspace/.cyvrix/result.json.

Security properties (docs/v3-sandbox.md):
- CLOSED WORLD: only known operation types exist; anything unknown is
  denied. No generic fallback, no string interpretation, no eval/exec.
- NO SUBPROCESS AT ALL: the sandbox interpreter imports no subprocess,
  no os.system, no shell. The in-sandbox Python runs with -I (isolated).
- Path security is enforced at every open(): traversal/absolute/UNC/
  control-char rejection, symlink resolution, containment re-check
  AFTER resolution (symlink escape cannot pass), and the allowed-file
  list from the authorization contract.
- No network I/O (socket is not imported; namespace is network-off).
- Result JSON is bounded; host owns the final status.
"""
import json
import os
import sys

MAX_TEXT = 5000
MAX_FILE_BYTES = 2 * 1024 * 1024          # refuse to process huge files
MAX_OPERATIONS = 50                        # mirrors V3.1 proposal cap
MAX_OUTPUT_BYTES = 65536                   # bounded result (§30)
# Inside the sandbox this is always /workspace (the only writable mount).
# The env override exists solely so host-side unit tests can run the SAME
# code path against a temp dir; the sanitized container never sets it.
WORKSPACE = os.environ.get("CYVRIX_SANDBOX_WORKSPACE", "/workspace")
PAYLOAD_DIR = os.path.join(WORKSPACE, ".cyvrix")

# Exactly the V3.1 structured operation types. Anything else is denied.
KNOWN_OPERATION_TYPES = frozenset({
    "UPDATE_DEPENDENCY_VERSION",
    "UPDATE_DOCKERFILE_INSTRUCTION",
    "APPEND_DOCKERFILE_INSTRUCTION",
    "REMOVE_DOCKERFILE_INSTRUCTION",
    "UPDATE_CONFIGURATION_VALUE",
    "REPLACE_TEXT",
})


class Denied(Exception):
    """A hard security denial (escape attempt, scope violation, ...)."""

    def __init__(self, reason_code: str, detail: str = ""):
        self.reason_code = reason_code
        self.detail = detail[:500]
        super().__init__(reason_code)


# ── Path security (§14/§15) ──────────────────────────────────────────

_FORBIDDEN_SUBSTRINGS = ("\\", "%", "\x00")
_CONTROL_CHARS = set(chr(c) for c in range(0x20)) | {chr(0x7f)}


def safe_resolve(repo_rel_path: str, allowed_files) -> str:
    """Resolve a repo-relative path inside the workspace SAFELY.

    Returns the real (symlink-resolved) absolute path. Raises Denied on
    any ambiguity — never "fixes" a suspicious path.
    """
    if not isinstance(repo_rel_path, str) or not repo_rel_path:
        raise Denied("ACTION_SCOPE_VIOLATION", "empty path")
    if len(repo_rel_path) > 1000:
        raise Denied("ACTION_SCOPE_VIOLATION", "path too long")
    if any(c in _FORBIDDEN_SUBSTRINGS for c in repo_rel_path):
        raise Denied("ACTION_SCOPE_VIOLATION", "forbidden characters in path")
    if any(c in _CONTROL_CHARS for c in repo_rel_path):
        raise Denied("ACTION_SCOPE_VIOLATION", "control characters in path")
    if repo_rel_path.startswith("/"):
        raise Denied("ACTION_SCOPE_VIOLATION", "absolute path")
    if repo_rel_path.startswith("~"):
        raise Denied("ACTION_SCOPE_VIOLATION", "home-relative path")
    segments = repo_rel_path.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        raise Denied("ACTION_SCOPE_VIOLATION", "traversal segment")
    if repo_rel_path not in allowed_files:
        raise Denied("ACTION_SCOPE_VIOLATION", "path outside authorized scope")

    # Lexical join, then REALPATH resolve: symlinks cannot smuggle us
    # outside the workspace, and the containment check runs AFTER
    # resolution (a symlink pointing at /etc fails here).
    joined = os.path.join(WORKSPACE, *segments)
    real = os.path.realpath(joined)
    workspace_real = os.path.realpath(WORKSPACE)
    if real != workspace_real and not real.startswith(workspace_real + os.sep):
        raise Denied("SANDBOX_ESCAPE_ATTEMPT", "resolved path escapes workspace")
    # Alias check: the REAL relative path (post-resolution) must itself be
    # in the allowlist — a symlinked directory aliasing an unauthorized
    # file under an approved lexical path fails here (§15).
    real_rel = os.path.relpath(real, workspace_real).replace(os.sep, "/")
    if real_rel != "." and real_rel not in allowed_files:
        raise Denied("ACTION_SCOPE_VIOLATION",
                     "resolved path aliases an unauthorized file")
    return real


def _open_limited(path: str, mode: str):
    """Open a workspace file after re-resolving it (TOCTOU re-check,
    §50) and enforcing the per-file size cap."""
    real = os.path.realpath(path)
    workspace_real = os.path.realpath(WORKSPACE)
    if real != workspace_real and not real.startswith(workspace_real + os.sep):
        raise Denied("SANDBOX_ESCAPE_ATTEMPT", "symlink escape on open")
    if os.path.islink(path):
        raise Denied("SANDBOX_ESCAPE_ATTEMPT", "symlinked target path")
    if "r" in mode:
        size = os.lstat(path).st_size
        if size > MAX_FILE_BYTES:
            raise Denied("RESOURCE_LIMIT", "file exceeds per-file size cap")
    return open(path, mode, encoding="utf-8", newline="")


# ── Text surgery helpers ─────────────────────────────────────────────


def _replace_exact(content: str, old_text: str, new_text: str, what: str) -> str:
    count = content.count(old_text)
    if count != 1:
        raise Denied(
            "OPERATION_FAILED",
            f"{what}: expected exactly 1 occurrence, found {count}",
        )
    return content.replace(old_text, new_text, 1)


def _line_split(content: str):
    return content.splitlines(keepends=True)


def _apply(op: dict, allowed_files) -> None:
    """Apply ONE structured operation. Only known types reach here."""
    op_type = op.get("type")
    if op_type not in KNOWN_OPERATION_TYPES:
        raise Denied("OPERATION_UNSUPPORTED", f"unknown operation type {op_type!r}")

    real_path = safe_resolve(op.get("file"), allowed_files)
    with _open_limited(real_path, "r") as fh:
        content = fh.read()
    original = content

    if op_type == "UPDATE_DEPENDENCY_VERSION":
        name = op.get("name")
        eco = op.get("ecosystem")
        frm = op.get("from_version")
        to = op.get("to_version")
        if eco == "npm":
            line = f'"{name}": "{to}"'
            old_line = f'"{name}": "{frm}"'
        elif eco == "pypi":
            line = f"{name}=={to}"
            old_line = f"{name}=={frm}"
        else:
            raise Denied("OPERATION_FAILED", "unsupported ecosystem")
        content = _replace_exact(content, old_line, line, "dependency pin")

    elif op_type == "UPDATE_DOCKERFILE_INSTRUCTION":
        lines = _line_split(content)
        idx = op.get("line_no") - 1
        if idx < 0 or idx >= len(lines):
            raise Denied("OPERATION_FAILED", "line_no out of range")
        if lines[idx].rstrip("\r\n") != op.get("old_text", ""):
            raise Denied("OPERATION_FAILED", "old_text does not match line")
        new_text = op.get("new_text") or ""
        eol = "\r\n" if lines[idx].endswith("\r\n") else "\n"
        lines[idx] = new_text + eol
        content = "".join(lines)

    elif op_type == "APPEND_DOCKERFILE_INSTRUCTION":
        lines = _line_split(content)
        after = op.get("after_line")
        if after < 0 or after > len(lines):
            raise Denied("OPERATION_FAILED", "after_line out of range")
        instruction = op.get("instruction") or ""
        eol = "\r\n" if (after and lines[after - 1].endswith("\r\n")) else "\n"
        lines.insert(after, instruction + eol)
        content = "".join(lines)

    elif op_type == "REMOVE_DOCKERFILE_INSTRUCTION":
        lines = _line_split(content)
        idx = op.get("line_no") - 1
        if idx < 0 or idx >= len(lines):
            raise Denied("OPERATION_FAILED", "line_no out of range")
        del lines[idx]
        content = "".join(lines)

    elif op_type == "UPDATE_CONFIGURATION_VALUE":
        key = op.get("key")
        value = op.get("value")
        if not isinstance(key, str) or not key:
            raise Denied("OPERATION_FAILED", "invalid key")
        lines = _line_split(content)
        matches = [
            i for i, ln in enumerate(lines)
            if ln.split("=", 1)[0].strip() == key and "=" in ln
        ]
        if len(matches) != 1:
            raise Denied(
                "OPERATION_FAILED",
                f"key expected on exactly 1 line, found {len(matches)}",
            )
        idx = matches[0]
        line = lines[idx]
        eol = "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
        sep = line.index("=")
        lines[idx] = line[:sep + 1] + value + eol
        content = "".join(lines)

    elif op_type == "REPLACE_TEXT":
        content = _replace_exact(content, op.get("old_text", ""),
                                 op.get("new_text") or "", "text")

    if content != original:
        if len(content.encode("utf-8")) > MAX_FILE_BYTES:
            raise Denied("RESOURCE_LIMIT", "resulting file exceeds size cap")
        with _open_limited(real_path, "w") as fh:
            fh.write(content)


def main() -> int:
    try:
        ops_path = os.path.join(PAYLOAD_DIR, "operations.json")
        try:
            with open(ops_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except FileNotFoundError:
            result = {"ok": False, "reason_code": "OPERATION_FAILED",
                      "detail": "operations payload missing", "operations": []}
        else:
            result = run(payload)
        out = json.dumps(result).encode("utf-8")
        if len(out) > MAX_OUTPUT_BYTES:
            out = json.dumps({
                "ok": False, "reason_code": "RESOURCE_LIMIT",
                "detail": "result exceeded output cap", "operations": [],
            }).encode("utf-8")
        with open(os.path.join(PAYLOAD_DIR, "result.json"), "wb") as fh:
            fh.write(out)
        return 0
    except Exception as exc:  # last resort: bounded, non-secret
        try:
            with open(os.path.join(PAYLOAD_DIR, "result.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"ok": False, "reason_code": "OPERATION_FAILED",
                           "detail": f"executor error: {type(exc).__name__}",
                           "operations": []}, fh)
        except Exception:
            pass
        return 1


def run(payload: dict) -> dict:
    """Apply the approved operations. Used by main() and directly by
    unit tests (same code path as production)."""
    if not isinstance(payload, dict):
        return {"ok": False, "reason_code": "OPERATION_FAILED",
                "detail": "payload must be an object", "operations": []}

    allowed_files = payload.get("allowed_files")
    if not isinstance(allowed_files, list) or not allowed_files:
        return {"ok": False, "reason_code": "ACTION_SCOPE_VIOLATION",
                "detail": "no authorized files", "operations": []}

    operations = payload.get("operations")
    if not isinstance(operations, list) or not operations:
        return {"ok": False, "reason_code": "OPERATION_FAILED",
                "detail": "no operations", "operations": []}
    if len(operations) > MAX_OPERATIONS:
        return {"ok": False, "reason_code": "RESOURCE_LIMIT",
                "detail": "too many operations", "operations": []}

    outcomes = []
    applied = 0
    try:
        for idx, op in enumerate(operations):
            if not isinstance(op, dict):
                raise Denied("OPERATION_FAILED", "operation must be an object")
            op_type = op.get("type")
            if op_type not in KNOWN_OPERATION_TYPES:
                raise Denied("OPERATION_UNSUPPORTED",
                             f"unknown operation type {op_type!r}")
            try:
                _apply(op, frozenset(allowed_files))
                outcomes.append({"index": idx, "op_type": str(op_type),
                                 "file_path": str(op.get("file", "")),
                                 "applied": True, "detail": ""})
                applied += 1
            except Denied as d:
                outcomes.append({"index": idx, "op_type": str(op_type),
                                 "file_path": str(op.get("file", "")),
                                 "applied": False, "detail": d.detail})
                return {"ok": False, "reason_code": d.reason_code,
                        "detail": d.detail, "operations": outcomes}
    except Denied as d:
        return {"ok": False, "reason_code": d.reason_code,
                "detail": d.detail, "operations": outcomes}

    return {"ok": True, "reason_code": "OK",
            "detail": f"{applied}/{len(operations)} operations applied",
            "operations": outcomes}


if __name__ == "__main__":
    # Isolated mode: no site, no user site, no environment inheritance
    # effects beyond what the sanitized container env provides.
    sys.exit(main())
