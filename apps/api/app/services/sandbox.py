"""CYVRIX V3.4 — Sandbox runtime manager (host-side control plane).

Creates and destroys the ephemeral hardened sandbox container. The
manager itself NEVER runs repository content: it only assembles the
container, streams the executor's bounded result, and guarantees
teardown. Executor code is the trusted stdlib-only cyvrix_executor
package; repository files are inert data bytes to it.

Hardening manifest (docs/v3-sandbox.md §isolation; ADR-010):
- non-root  (uid/gid 10001 baked into the executor image; §11)
- cap_drop ALL, no cap_add (§9)
- security_opt: no-new-privileges + pinned seccomp profile (§8/§10)
- network_mode: none (§21) — enforced by the runtime, not by code
- read_only root filesystem; tmpfs /tmp + /dev/shm (§12)
- mounts: ONLY the ephemeral workspace → /workspace (rw, private);
  NO host project dirs, NO docker.sock, NO /etc /home /root /proc /sys
  host mounts (§12/§25/§65)
- pid_mode/ipc_mode/userns_mode/uts: private; no privileged, no
  host PID/network/IPC (§8)
- pids_limit, mem_limit, cpu quota, disk quota (tmpfs size + a
  container-level write cap via workspace quota), hard timeout (§26)
- guaranteed teardown in finally (§33); cleanup failures surfaced
- platform capability check at startup: unsupported platform →
  RUNTIME_UNSUPPORTED, never "run anyway" (§35/§36)

Residual risk (documented, not claimed away): container isolation
depends on the host kernel/runtime; a kernel or runtime vulnerability
can still compromise the host. Compensating controls: dedicated worker
host, minimal daemon privileges, frequent runtime updates (§63/§64).
"""
import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cyvrix.sandbox")

# The executor image is built locally from the pinned Dockerfile in this
# repo (supply chain: digest-pinned layers come via the base image pin).
EXECUTOR_IMAGE_TAG = "cyvrix/executor:3.4.0"
EXECUTOR_IMAGE_DOCKERFILE = Path(__file__).resolve().parents[2] / "executor.Dockerfile"
EXECUTOR_IMAGE_CONTEXT = Path(__file__).resolve().parents[2]  # apps/api

SECCOMP_PROFILE_PATH = Path(__file__).resolve().parents[2] / "seccomp_executor.json"
SECCOMP_PROFILE_NAME = "cyvrix-executor-v1"

# UID/GID inside the sandbox (§11) — must match executor.Dockerfile.
SANDBOX_UID = 10001
SANDBOX_GID = 10001

# Container paths
CONTAINER_WORKSPACE = "/workspace"
CONTAINER_PAYLOAD_DIR = "/workspace/.cyvrix"

# Bounded payload/result sizes (host-side caps, §30)
MAX_OPERATIONS_JSON_BYTES = 512 * 1024
MAX_RESULT_JSON_BYTES = 128 * 1024


class SandboxUnavailable(Exception):
    """The sandbox runtime cannot support safe execution (fail closed)."""

    def __init__(self, reason_code: str, detail: str = ""):
        self.reason_code = reason_code
        self.detail = detail[:300]
        super().__init__(reason_code)


class SandboxResult:
    """Bounded container output. No workspace content, no secrets."""

    def __init__(self, exit_code: int, stdout: bytes, stderr: bytes,
                 timed_out: bool):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


# ── Platform capability check (§35/§36) ──────────────────────────────

_RequiredCaps = ("namespace", "cgroup", "seccomp")


def check_platform_support(docker_client=None) -> dict:
    """Verify the RUNTIME supports required isolation controls (§35/§36).

    The controls that matter are properties of the KERNEL the container
    runs on — the Docker daemon's kernel, not the host running the SDK
    client (Docker Desktop on Windows/macOS runs a Linux VM; namespaces,
    seccomp, and cgroups are enforced there). Evidence checked, fail
    closed: daemon reachability, Linux kernel, seccomp support, cgroups.
    """
    client = docker_client
    if client is None:
        client = _get_docker_client()
    try:
        info = client.info()
        version = client.version()
    except Exception as exc:
        raise SandboxUnavailable(
            "SANDBOX_UNAVAILABLE", f"docker daemon unreachable: {type(exc).__name__}"
        )

    kernel = info.get("KernelVersion", "")
    if not kernel or info.get("OSType") != "linux":
        raise SandboxUnavailable(
            "RUNTIME_UNSUPPORTED", "docker daemon is not Linux-based"
        )

    # seccomp support: presence of SecurityOptions indicates the daemon
    # parsed security profiles; no options at all → cannot enforce policy.
    sec_opts = info.get("SecurityOptions") or []
    if not sec_opts:
        raise SandboxUnavailable(
            "SANDBOX_POLICY_UNSUPPORTED", "no daemon security options reported"
        )
    if not any("seccomp" in str(o) for o in sec_opts):
        raise SandboxUnavailable(
            "SANDBOX_POLICY_UNSUPPORTED", "daemon does not support seccomp profiles"
        )

    cgroup = info.get("CgroupVersion")
    if cgroup not in ("1", "2"):
        raise SandboxUnavailable(
            "SANDBOX_POLICY_UNSUPPORTED", f"unsupported cgroup version {cgroup!r}"
        )

    return {
        "kernel": kernel,
        "cgroup": cgroup,
        "security_options": [str(o) for o in sec_opts],
        "server_version": version.get("Version"),
        "driver": info.get("Driver"),
    }


def _get_docker_client():
    import docker

    try:
        return docker.from_env()
    except Exception as exc:
        raise SandboxUnavailable(
            "SANDBOX_UNAVAILABLE", f"docker not reachable: {type(exc).__name__}"
        )


def ensure_executor_image(docker_client=None) -> str:
    """Ensure the pinned executor image exists locally; build it if absent.

    The image is built ONLY from the repository's executor.Dockerfile
    (pinned base digest, minimal). Repository content can never choose
    the image (§40/§41).
    """
    client = docker_client or _get_docker_client()
    try:
        client.images.get(EXECUTOR_IMAGE_TAG)
        return EXECUTOR_IMAGE_TAG
    except Exception:
        pass
    if not EXECUTOR_IMAGE_DOCKERFILE.exists():
        raise SandboxUnavailable(
            "SANDBOX_UNAVAILABLE", "executor image definition missing"
        )
    try:
        img, logs = client.images.build(
            path=str(EXECUTOR_IMAGE_CONTEXT),
            dockerfile="executor.Dockerfile",
            tag=EXECUTOR_IMAGE_TAG,
            rm=True,
            forcerm=True,
        )
        return EXECUTOR_IMAGE_TAG
    except Exception as exc:
        raise SandboxUnavailable(
            "SANDBOX_UNAVAILABLE", f"executor image build failed: {type(exc).__name__}"
        )


# ── Seccomp profile (§8) ─────────────────────────────────────────────

_DEFAULT_SECCOMP = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [
        {
            "names": [
                "accept", "accept4", "access", "arch_prctl", "bind", "brk",
                "capget", "capset", "chdir", "chmod", "chown", "clock_getres",
                "clock_gettime", "clock_nanosleep", "clone", "close", "connect",
                "creat", "dup", "dup2", "dup3", "epoll_create1", "epoll_ctl",
                "epoll_wait", "epoll_pwait", "eventfd2", "execve", "exit",
                "exit_group", "faccessat", "faccessat2", "fadvise64", "fallocate",
                "fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl",
                "fdatasync", "flock", "fork", "fstat", "fstatfs", "fsync",
                "ftruncate", "futex", "getcwd", "getdents", "getdents64",
                "getegid", "geteuid", "getgid", "getgroups", "getpeername",
                "getpgid", "getpgrp", "getpid", "getppid", "getrandom",
                "getresgid", "getresuid", "getrlimit", "getrusage", "getsockname",
                "getsockopt", "gettid", "gettimeofday", "getuid", "inotify_init1",
                "inotify_add_watch", "ioctl", "kill", "link", "linkat", "listen",
                "lseek", "lstat", "madvise", "membarrier", "memfd_create",
                "mkdir", "mkdirat", "mmap", "mprotect", "mremap", "msync",
                "munmap", "nanosleep", "newfstatat", "open", "openat", "openat2",
                "pause", "pipe", "pipe2", "poll", "ppoll", "prctl", "pread64",
                "preadv2", "prlimit64", "pselect6", "read", "readlink",
                "readlinkat", "readv", "recvfrom", "recvmmsg", "recvmsg",
                "rename", "renameat", "renameat2", "restart_syscall", "rmdir",
                "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend",
                "sched_getaffinity", "sched_yield", "sendmmsg", "sendmsg",
                "sendto", "set_robust_list", "set_tid_address", "setgid",
                "setitimer", "setpgid", "setsid", "setsockopt", "setuid",
                "shutdown", "sigaltstack", "signalfd4", "socket", "socketpair",
                "stat", "statfs", "statx", "symlink", "symlinkat", "sysinfo",
                "tgkill", "timerfd_create", "timerfd_settime", "uname",
                "unlink", "unlinkat", "utimensat", "vfork", "wait4", "waitid",
                "write", "writev",
            ],
            "action": "SCMP_ACT_ALLOW",
        },
        {
            "names": ["clone"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{"index": 0, "value": 21170368, "op": "SCMP_CMP_MASKED_EQ",
                      "valueTwo": 21170368}],
        },
    ],
}


def _load_seccomp_profile() -> dict:
    """Prefer the repo-pinned profile file; fall back to the built-in
    conservative default (both default-deny)."""
    try:
        with open(SECCOMP_PROFILE_PATH, "r", encoding="utf-8") as fh:
            profile = json.load(fh)
        if profile.get("defaultAction") == "SCMP_ACT_ERRNO":
            return profile
    except Exception:
        pass
    return _DEFAULT_SECCOMP


# ── Container lifecycle ──────────────────────────────────────────────


def create_sandbox(workspace_dir: str, docker_client=None,
                   platform_info: Optional[dict] = None) -> dict:
    """Create the hardened ephemeral sandbox container (NOT started).

    Admission ordering (§102): callers must have atomically reserved the
    execution BEFORE creating a sandbox. If creation fails the caller
    marks the run failed and calls destroy_sandbox defensively.
    """
    client = docker_client or _get_docker_client()
    if platform_info is None:
        platform_info = check_platform_support(client)
    image = ensure_executor_image(client)

    ws_real = os.path.realpath(workspace_dir)
    if not os.path.isdir(ws_real):
        raise SandboxUnavailable("SANDBOX_UNAVAILABLE", "workspace missing")

    import docker.types

    seccomp = json.dumps(_load_seccomp_profile())

    # Minimal, non-secret environment (§23/§24). No PATH takeover, no
    # inherited host environment, no credentials.
    environment = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "HOME": "/tmp",
    }

    container = client.containers.create(
        image=image,
        name=f"cyvrix-sbx-{os.path.basename(ws_real)}",
        # interpreter: python -I (isolated: no user site, no env PYTHON*),
        # probes first (evidence), then the executor.
        command=[
            "/usr/local/bin/python", "-I",
            "/opt/cyvrix/run_executor.py",
        ],
        environment=environment,
        user=f"{SANDBOX_UID}:{SANDBOX_GID}",
        # isolation hardening
        network_mode="none",
        privileged=False,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges", f"seccomp={seccomp}"],
        read_only=True,
        tmpfs={
            "/tmp": "rw,noexec,nosuid,nodev,size=16m",
            "/dev/shm": "rw,noexec,nosuid,nodev,size=16m",
        },
        mounts=[
            docker.types.Mount(
                target=CONTAINER_WORKSPACE,
                source=ws_real,
                type="bind",
                read_only=False,
            ),
        ],
        # resource limits (§26)
        mem_limit=f"{256}m",
        memswap_limit="256m",          # no swap grace
        mem_swappiness=0,
        nano_cpus=500_000_000,          # 0.5 CPU (nano_cpus ≙ quota/period)
        pids_limit=32,
        # hard namespace isolation (§8)
        pid_mode="",
        ipc_mode="",
        uts_mode="",
        userns_mode="",
        working_dir=CONTAINER_WORKSPACE,
        stdin_open=False,
        tty=False,
        # labels for operational cleanup sweep
        labels={"cyvrix.sandbox": "executor", "cyvrix.phase": "v34"},
        log_config=docker.types.LogConfig(
            type=docker.types.LogConfig.types.JSON, config={"max-size": "1m", "max-file": "1"}
        ),
    )
    return {"container": container, "image": image,
            "platform": platform_info}


def run_executor(sandbox: dict, timeout_seconds: int) -> SandboxResult:
    """Start the sandbox, wait with a HARD timeout, collect bounded output.

    The timeout kills the container (its PID namespace dies with it —
    §31/§32); no orphan processes can outlive teardown.
    """
    import threading

    container = sandbox["container"]
    container.start()
    timed_out = False

    # wait() blocks; enforce the hard timeout from the host side.
    waiter = threading.Thread(target=container.wait, daemon=True)
    waiter.start()
    waiter.join(timeout_seconds)
    if waiter.is_alive():
        timed_out = True
        try:
            container.kill()
        except Exception:
            try:
                container.stop(timeout=0)
            except Exception:
                pass
        try:
            container.wait(timeout=10)
        except Exception:
            pass

    exit_code = None
    try:
        state = container.attrs.get("State", {})
        exit_code = state.get("ExitCode")
    except Exception:
        pass

    stdout = stderr = b""
    try:
        logs = container.logs(stdout=True, stderr=False, tail=None)
        stdout = logs if isinstance(logs, bytes) else bytes(logs)
    except Exception:
        pass
    try:
        logs = container.logs(stdout=False, stderr=True, tail=None)
        stderr = logs if isinstance(logs, bytes) else bytes(logs)
    except Exception:
        pass

    return SandboxResult(
        exit_code=exit_code if exit_code is not None else (-1),
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


def destroy_sandbox(sandbox: dict) -> tuple[bool, str]:
    """Guaranteed teardown: stop → remove → verify removal (§33/§103)."""
    container = sandbox.get("container")
    if container is None:
        return True, ""
    detail_parts = []
    try:
        container.stop(timeout=0)
    except Exception:
        pass
    try:
        container.kill()
    except Exception:
        pass
    try:
        container.remove(force=True, v=False)
        return True, ""
    except Exception as exc:
        detail_parts.append(f"remove failed: {type(exc).__name__}")
        # verify whether it is really gone
        try:
            client = container.client
            client.containers.get(container.id)
            return False, "; ".join(detail_parts)
        except Exception:
            return True, "; ".join(detail_parts) if detail_parts else ""


def sweep_orphan_sandboxes(docker_client=None) -> int:
    """Remove any leftover cyvrix sandbox containers (crash hygiene)."""
    client = docker_client or _get_docker_client()
    removed = 0
    try:
        for c in client.containers.list(
            all=True,
            filters={"label": "cyvrix.sandbox=executor"},
        ):
            try:
                c.remove(force=True)
                removed += 1
            except Exception:
                pass
    except Exception:
        pass
    return removed


# ── Payload / result exchange (host-side, bounded) ───────────────────


def write_operations_payload(workspace_dir: str, allowed_files, operations) -> None:
    """Write the executor's operations payload into the workspace.

    Only the allowlist and the structured operations go in — never
    credentials, never tokens, never user session data (§23/§58).
    """
    payload_dir = os.path.join(workspace_dir, ".cyvrix")
    os.makedirs(payload_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(payload_dir, 0o700)
    except OSError:
        pass
    payload = {
        "allowed_files": sorted(set(allowed_files)),
        "operations": list(operations),
    }
    data = json.dumps(payload).encode("utf-8")
    if len(data) > MAX_OPERATIONS_JSON_BYTES:
        raise SandboxUnavailable("RESOURCE_LIMIT", "operations payload too large")
    with open(os.path.join(payload_dir, "operations.json"), "wb") as fh:
        fh.write(data)


def read_executor_result(workspace_dir: str) -> Optional[dict]:
    """Read the sandbox's bounded result JSON. TRUST NOTHING in it as
    status — the host re-derives the final status from workspace
    verification; this is raw executor data (§53)."""
    path = os.path.join(workspace_dir, ".cyvrix", "result.json")
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_RESULT_JSON_BYTES + 1)
        if len(raw) > MAX_RESULT_JSON_BYTES:
            return {"ok": False, "reason_code": "RESOURCE_LIMIT",
                    "detail": "result.json exceeded cap", "operations": []}
        return json.loads(raw.decode("utf-8", errors="replace"))
    except FileNotFoundError:
        return None
    except Exception:
        return {"ok": False, "reason_code": "OPERATION_FAILED",
                "detail": "unreadable result.json", "operations": []}


def read_probe_results(workspace_dir: str) -> Optional[dict]:
    path = os.path.join(workspace_dir, ".cyvrix", "probes.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None
