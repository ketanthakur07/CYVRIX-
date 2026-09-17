# CYVRIX V3.4 — Sandbox Hardening Manifest

Status: IMPLEMENTED (V3.4). This document describes the sandbox contract as actually
implemented in `apps/api/app/services/sandbox.py`, `apps/api/executor.Dockerfile`,
`apps/api/seccomp_executor.json`, and `apps/api/cyvrix_executor/`. It is the
authoritative isolation reference for `docs/v3-execution-model.md` §2 and the
V3.4 sections of `docs/v3-security-model.md`.

V3.4 scope reminder: the sandbox performs LOCAL structured text operations only.
No Git/GitHub writes, no PRs, no deployments, no rollback (later phases).

---

## 1. Executor image (supply chain)

- Base: `python:3.12-alpine3.20` pinned **by digest** (`executor.Dockerfile`);
  never `:latest`, never repository-chosen. Digest refresh is a deliberate,
  documented update, not an automatic pull.
- Contents: alpine + python + the stdlib-only `cyvrix_executor` package and the
  `executor_entry.py` launcher. No extra packages, no secrets, no host files.
- Code installed at `/opt/cyvrix` with `chown root:root` + `chmod -R 0555`:
  repository content can never modify the executor.
- Dedicated unprivileged user `uid=10001 gid=10001` (`cyvrix_sbx`), no login shell.
- Image is built ONLY from the repo's `executor.Dockerfile` by
  `sandbox.ensure_executor_image()`; the tag is `cyvrix/executor:3.4.0`.

## 2. Container isolation (runtime-enforced, `sandbox.create_sandbox`)

| Control | Value |
| --- | --- |
| user | `10001:10001` (non-root, §11) |
| capabilities | `cap_drop=["ALL"]`, no `cap_add` (§9) |
| privilege escalation | `security_opt=["no-new-privileges", seccomp=<pinned profile>]` (§8/§10) |
| seccomp | repo-pinned `seccomp_executor.json`; `defaultAction: SCMP_ACT_ERRNO` with an explicit allowlist (default-deny; a built-in equally-strict fallback exists if the file is unreadable) |
| network | `network_mode="none"` (§21) |
| root filesystem | `read_only=True`; writable tmpfs only `/tmp` + `/dev/shm` (`noexec,nosuid,nodev,size=16m`) (§12) |
| mounts | ONLY the ephemeral workspace → `/workspace` (bind, rw). NO host project dirs, NO `docker.sock`, NO `/etc`, `/home`, `/root`, `/proc`, `/sys` (§12/§25/§65) |
| namespaces | `pid_mode`/`ipc_mode`/`uts_mode`/`userns_mode` all private; `privileged=False`; no host PID/network/IPC (§8) |
| memory | `mem_limit=256m`, `memswap_limit=256m` (no swap grace), `mem_swappiness=0` |
| CPU | `nano_cpus=500_000_000` (0.5 CPU) |
| processes | `pids_limit=32` (fork-bomb bound) |
| logs | JSON driver, `max-size=1m`, `max-file=1` (output-flooding bound) |
| interpreter | `/usr/local/bin/python -I` (isolated mode: no user site, no env takeover) |

Entry command runs `executor_entry.py`: harmless isolation self-probes first
(evidence written to `/workspace/.cyvrix/probes.json`), then the closed-world
executor. Probe output is EVIDENCE asserted by the host — never trusted status.

## 3. Platform capability gate (fail closed, §35/§36)

`sandbox.check_platform_support()` runs BEFORE any execution and fails closed:
daemon unreachable → `SANDBOX_UNAVAILABLE`; non-Linux daemon →
`RUNTIME_UNSUPPORTED`; no security options / no seccomp support or unsupported
cgroups → `SANDBOX_POLICY_UNSUPPORTED`. There is no "run anyway" path.

## 4. Lifecycle, timeout, teardown (§31–§33, §103)

- Sandbox creation happens strictly AFTER atomic admission reservation (§102).
- `run_executor()` enforces the HOST-side hard timeout from the frozen resource
  profile; timeout ⇒ container kill (PID namespace dies with the container — no
  orphan processes), bounded log collection, run marked `EXECUTION_TIMEOUT`.
- `destroy_sandbox()`: stop → kill → remove(force) → verify removal; failure to
  remove is surfaced as cleanup failure, never reported as success.
- `sweep_orphan_sandboxes()` provides crash hygiene for labeled leftovers.
- Workspace teardown is guarded: `remove_workspace_dir()` refuses to delete
  anything outside the dedicated workspace root (defense in depth).

## 5. Credential isolation (§23/§24/§58/§89)

The sandbox receives NO credentials of any kind: no GitHub OAuth tokens, no
installation tokens, no private keys, no database/Redis credentials, no session
secrets, no LLM keys, no administrator secrets. Container environment is exactly:
`PYTHONDONTWRITEBYTECODE`, `PYTHONUNBUFFERED`/`PYTHONHASHSEED` (from the image),
`HOME=/tmp`. The host never mounts the host environment wholesale. The only data
written into the workspace is the operations payload
(`/workspace/.cyvrix/operations.json`: the allowed-file allowlist + the approved
structured operations — no commands, no tokens). Executor output is bounded
(`result.json` ≤ 128 KB cap) and treated as raw DATA; the host owns final status.

## 6. Workspace (§13–§15, §42, §50)

- Ephemeral host directory per run under a dedicated root
  (`CYVRIX_SANDBOX_WORKSPACE_ROOT` or a tempdir-derived `cyvrix-sandboxes`),
  created `0700`, never reused, removed after success/failure/timeout/exception.
- Materialized from a trusted source: GitHub contents API at the proposal's
  pinned `base_commit_sha` with a short-lived installation token held only on
  the host; per-file 2 MB cap; approved-file-only; duplicate scope = error.
- The executor re-resolves every path (realpath) and re-checks containment AFTER
  resolution; symlink aliasing an unauthorized file is denied; the allowlist is
  enforced per open (TOCTOU re-check).
- Host-side BEFORE/AFTER snapshots (content-addressed hashes) verify that actual
  changes never exceed the authorized scope (`verify_scope_and_diff`); out-of-scope
  mutation ⇒ `ACTION_SCOPE_VIOLATION`, run FAILED, fail closed.

## 7. Residual risk (documented, not claimed away)

Container isolation depends on the host kernel/runtime; a kernel or runtime
vulnerability can still compromise the host. Compensating controls: dedicated
worker host, minimal daemon privileges, frequent runtime updates, and the
platform capability gate above. Migration path to gVisor/Firecracker-class
isolation remains behind the same `create_sandbox` interface.
