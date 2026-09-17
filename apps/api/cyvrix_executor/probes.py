"""Harmless in-sandbox security self-probes (§69/§72).

The executor writes probe results to /workspace/.cyvrix/probes.json.
Every probe is a harmless proof-of-concept: it demonstrates a boundary
 violation WITHOUT causing damage and WITHOUT real attack payloads
(§70). The HOST verifies containment by asserting these results — the
probes are evidence, not trust.
"""
import json
import os

WORKSPACE = "/workspace"
PAYLOAD_DIR = os.path.join(WORKSPACE, ".cyvrix")

# UID/GID the executor image runs as (see executor.Dockerfile: uid 10001)
EXPECTED_UID = 10001
EXPECTED_GID = 10001


def _try(fn):
    try:
        return fn()
    except Exception as exc:
        return f"DENIED:{type(exc).__name__}"


def probe_uid():
    return {"uid": os.getuid(), "gid": os.getgid(), "euid": os.geteuid()}


def probe_root_fs_readonly():
    """Attempt to write outside the writable workspace."""
    for path in ("/etc/passwd", "/usr/bin/x", "/root/x", "/home/x"):
        try:
            with open(path, "a", encoding="utf-8"):
                return {"path": path, "writable": True}
        except Exception as exc:
            last = f"{path}: DENIED:{type(exc).__name__}"
    return {"writable": False, "last_error": last}


def probe_docker_socket():
    """Host-root-equivalent socket must not exist inside the sandbox."""
    return {"exists": os.path.exists("/var/run/docker.sock")}


def probe_host_fs():
    """Host filesystem must not be mounted into the sandbox."""
    return {
        "etc_passwd_readable": _try(lambda: os.path.getsize("/etc/passwd") >= 0
                                    and os.access("/etc/passwd", os.R_OK)),
        "cyvrix_src_visible": os.path.isdir("/cyvrix"),
    }


def probe_network_off():
    """Network namespace is offline: raw socket creation must fail."""
    import socket  # noqa: S602 — probe-only, never used for I/O
    results = {}
    for label, addr in (
        ("internet", ("93.184.216.34", 443)),
        ("private", ("192.168.1.1", 80)),
        ("loopback", ("127.0.0.1", 5432)),
    ):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            try:
                s.connect(addr)
                results[label] = "CONNECTED"
            finally:
                s.close()
        except Exception as exc:
            results[label] = f"DENIED:{type(exc).__name__}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect(("postgres", 5432))
            results["internal_dns"] = "RESOLVED_AND_CONNECTED"
        finally:
            s.close()
    except Exception as exc:
        results["internal_dns"] = f"DENIED:{type(exc).__name__}"
    return results


def probe_privilege_escalation():
    """setuid(0) must fail for the unprivileged executor user (§10/§11)."""
    try:
        os.setuid(0)
        return {"setuid_root": "SUCCEEDED"}
    except PermissionError:
        return {"setuid_root": "DENIED:PermissionError"}
    except OSError as exc:
        return {"setuid_root": f"DENIED:{type(exc).__name__}"}


def probe_capabilities():
    """Effective capabilities: capsh-independent read of the bounding
    set via /proc/self/status. With cap_drop=ALL both sets must be zero
    (§9). Reported as hex strings; the host asserts zeros."""
    caps = {}
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                if line.startswith("CapEff:") or line.startswith("CapBnd:"):
                    key, val = line.split(":")
                    caps[key.strip()] = val.strip()
    except Exception as exc:
        caps["error"] = f"DENIED:{type(exc).__name__}"
    return caps


def probe_env_split():
    """The FULL sandbox environment (names only, values never returned —
    §24). The host asserts the expected minimal set and the absence of
    credential-shaped names."""
    return {"env_names": sorted(os.environ.keys())}


def probe_env_harvest():
    """Flag credential-shaped environment variables (§24). The sandbox
    legitimately carries a minimal PATH/HOME from the image; those are
    NOT leaks and are excluded here. Injection vectors (LD_PRELOAD,
    PYTHONPATH, NODE_OPTIONS, ...) ARE flagged — the host asserts none."""
    dangerous_prefixes = ("CYVRIX_", "GITHUB_", "AWS_", "POSTGRES_", "REDIS_",
                          "SECRET", "OPENAI_", "DOCKER_", "AZURE_", "GH_")
    injection_vectors = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                         "LD_PRELOAD", "NODE_OPTIONS", "RUBYOPT",
                         "BASH_ENV", "ENV", "SHELL")
    harvested = {
        k: "<set>" for k in os.environ
        if any(k.upper().startswith(p) for p in dangerous_prefixes)
        or k.upper() in injection_vectors
    }
    return {"dangerous_vars": sorted(harvested.keys())}


def probe_proc():
    """PID-namespace visibility: host processes must not be visible."""
    pids = [p for p in os.listdir("/proc") if p.isdigit()]
    return {"pid_count": len(pids), "pids": sorted(int(p) for p in pids)[:50]}


ALL_PROBES = {
    "uid": probe_uid,
    "root_fs_readonly": probe_root_fs_readonly,
    "docker_socket": probe_docker_socket,
    "host_fs": probe_host_fs,
    "network": probe_network_off,
    "privilege_escalation": probe_privilege_escalation,
    "capabilities": probe_capabilities,
    "env_split": probe_env_split,
    "env": probe_env_harvest,
    "proc": probe_proc,
}


def run_probes() -> dict:
    return {name: fn() for name, fn in ALL_PROBES.items()}


def main() -> int:
    payload_dir = PAYLOAD_DIR
    os.makedirs(payload_dir, exist_ok=True)
    results = run_probes()
    with open(os.path.join(payload_dir, "probes.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
