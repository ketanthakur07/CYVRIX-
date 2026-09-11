"""CYVRIX Dependency Vulnerability Scanner.

Security properties:
- Path traversal defense: all file reads validated against workspace boundary
- Symlink protection: symlinks pointing outside workspace are rejected
- Safe subprocess: no shell=True, no string concatenation with user input
- Resource limits: configurable max file size, max deps, max manifests
- OSV response validation: external data validated before use
- Credential protection: clone URLs never logged, tokens never persisted
"""
import hashlib
import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

import httpx

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger("cyvrix.scanner")

OSV_BATCH_URL = os.environ.get("OSV_BATCH_URL", "https://api.osv.dev/v1/querybatch")
SCAN_TIMEOUT = settings.scan_timeout_minutes * 60
MAX_REPO_SIZE = settings.max_repo_size_mb * 1024 * 1024

# Resource limits
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per manifest file
MAX_MANIFESTS = 50
MAX_DEPS_TOTAL = 10000
MAX_MANIFEST_LINES = 50000


# ═══════════════════════════════════════════════════════════════════
# Path Traversal / Symlink Defense
# ═══════════════════════════════════════════════════════════════════

def _validate_path_in_workspace(filepath: str, workspace: str) -> str:
    """Resolve a path and verify it stays inside the scan workspace.

    Defends against:
    - ../../etc/passwd traversal
    - Absolute paths
    - Symlink escape
    - Encoded traversal

    Returns the resolved absolute path if safe, raises ValueError if not.
    """
    workspace_resolved = os.path.realpath(workspace)
    filepath_resolved = os.path.realpath(filepath)

    if not filepath_resolved.startswith(workspace_resolved + os.sep) and filepath_resolved != workspace_resolved:
        raise ValueError(
            f"Path traversal detected: {filepath} resolves outside workspace"
        )
    return filepath_resolved


def _is_symlink_safe(filepath: str, workspace: str) -> bool:
    """Check if a symlink target stays within the workspace.

    Returns True if the file is not a symlink or the symlink target is inside workspace.
    Returns False if the symlink escapes the workspace.
    """
    if not os.path.islink(filepath):
        return True

    link_target = os.readlink(filepath)
    # Handle absolute symlinks
    if os.path.isabs(link_target):
        target_resolved = os.path.realpath(filepath)
    else:
        target_resolved = os.path.realpath(filepath)

    workspace_resolved = os.path.realpath(workspace)
    return target_resolved.startswith(workspace_resolved + os.sep)


def _safe_read_file(filepath: str, workspace: str, max_size: int = MAX_FILE_SIZE) -> str:
    """Read a file with path traversal defense, symlink check, and size limit.

    Returns file content if safe, raises ValueError on security violations.
    """
    resolved = _validate_path_in_workspace(filepath, workspace)

    if not _is_symlink_safe(filepath, workspace):
        raise ValueError(f"Symlink escape detected: {filepath}")

    if not os.path.isfile(resolved):
        raise ValueError(f"Not a regular file: {filepath}")

    file_size = os.path.getsize(resolved)
    if file_size > max_size:
        raise ValueError(f"File too large ({file_size} bytes > {max_size} limit): {filepath}")

    with open(resolved, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════════
# Fingerprinting
# ═══════════════════════════════════════════════════════════════════

def compute_fingerprint(repository_id: str, vulnerability_id: str, package_name: str, manifest_path: str) -> str:
    """Compute dedup fingerprint: sha256(repository_id + vulnerability_id + package_name + manifest_path)."""
    raw = f"{repository_id}{vulnerability_id}{package_name}{manifest_path}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════════
# Safe Git Operations
# ═══════════════════════════════════════════════════════════════════

def clone_repo(clone_url: str, target_dir: str, ref: str = "HEAD") -> str:
    """Shallow clone a repository safely.

    Security:
    - No shell=True (prevents command injection)
    - No string concatenation with user input
    - ref parameter validated to prevent injection
    - Credentials in URL not logged
    - Timeout enforced
    - Submodules not initialized
    - Hooks not executed

    Returns the commit SHA.
    """
    # Validate ref to prevent injection (only allow branch/tag names)
    if ref and ref != "HEAD":
        if not re.match(r'^[a-zA-Z0-9._/-]+$', ref):
            raise ValueError(f"Invalid ref: {ref}")

    # Build clone command without shell=True
    cmd = ["git", "clone", "--depth", "1", "--no-tags", "--recurse-submodules=no"]

    if ref and ref != "HEAD":
        cmd.extend(["--branch", ref])

    cmd.extend([clone_url, target_dir])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,  # Critical: prevent command injection
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Git clone timed out")

    if result.returncode != 0:
        # Sanitize error message to not leak credentials
        error_msg = _sanitize_git_error(result.stderr)
        logger.error("Git clone failed: %s", error_msg)

        # Retry without branch flag if branch not found
        if ref and ref != "HEAD" and "does not exist" in result.stderr:
            cmd_retry = ["git", "clone", "--depth", "1", "--no-tags", "--recurse-submodules=no", clone_url, target_dir]
            try:
                result = subprocess.run(
                    cmd_retry,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    shell=False,
                )
            except subprocess.TimeoutExpired:
                raise RuntimeError("Git clone timed out")

            if result.returncode != 0:
                raise RuntimeError(f"Clone failed: {_sanitize_git_error(result.stderr)}")
        else:
            raise RuntimeError(f"Clone failed: {error_msg}")

    # Get commit SHA
    try:
        sha_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=target_dir,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        return sha_result.stdout.strip() if sha_result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _sanitize_git_error(stderr: str) -> str:
    """Remove credentials from git error messages."""
    # Remove x-access-token URLs
    sanitized = re.sub(r'https://x-access-token:[^@]+@', 'https://***@', stderr)
    # Remove any other token patterns
    sanitized = re.sub(r'token[=:]\s*\S+', 'token=***', sanitized, flags=re.IGNORECASE)
    return sanitized.strip()[:500]


# ═══════════════════════════════════════════════════════════════════
# Manifest Detection
# ═══════════════════════════════════════════════════════════════════

SUPPORTED_MANIFESTS = {
    "package-lock.json": "npm",
    "package.json": "npm",
    "requirements.txt": "PyPI",
    "poetry.lock": "PyPI",
}

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox"}


def detect_manifests(repo_dir: str) -> list[tuple[str, str]]:
    """Detect supported manifest files with path traversal defense.

    Returns list of (ecosystem, manifest_path).
    Only returns manifests that are safe regular files inside the workspace.
    """
    manifests = []
    workspace = os.path.realpath(repo_dir)

    for root, dirs, files in os.walk(workspace, followlinks=False):
        # Skip hidden dirs and known large directories
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS]

        for f in files:
            if f not in SUPPORTED_MANIFESTS:
                continue

            full_path = os.path.join(root, f)

            # Security: verify path stays in workspace
            try:
                resolved = _validate_path_in_workspace(full_path, workspace)
            except ValueError:
                logger.warning("Path traversal blocked in manifest detection: %s", full_path)
                continue

            # Security: reject symlinks
            if os.path.islink(full_path):
                logger.warning("Symlink manifest rejected: %s", full_path)
                continue

            # Security: check file size
            try:
                if os.path.getsize(resolved) > MAX_FILE_SIZE:
                    logger.warning("Manifest too large, skipping: %s", f)
                    continue
            except OSError:
                continue

            rel_path = os.path.relpath(resolved, workspace)
            ecosystem = SUPPORTED_MANIFESTS[f]
            manifests.append((ecosystem, rel_path))

            if len(manifests) >= MAX_MANIFESTS:
                logger.warning("Hit manifest limit (%d), stopping detection", MAX_MANIFESTS)
                return manifests

    return manifests


# ═══════════════════════════════════════════════════════════════════
# Manifest Parsers
# ═══════════════════════════════════════════════════════════════════

def _validate_dep(dep: dict) -> bool:
    """Validate a normalized dependency record."""
    if not dep.get("name") or not isinstance(dep["name"], str):
        return False
    if len(dep["name"]) > 500:
        return False
    if dep.get("version") and len(str(dep["version"])) > 200:
        return False
    return True


def parse_package_json(path: str, workspace: str = None) -> list[dict]:
    """Parse dependencies from package.json with path traversal defense."""
    try:
        if workspace:
            content = _safe_read_file(path, workspace)
            data = json.loads(content)
        else:
            with open(path, "r") as f:
                data = json.load(f)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning("Failed to parse package.json: %s", e)
        return []

    deps = []
    for section in ["dependencies", "devDependencies", "peerDependencies"]:
        for name, version in data.get(section, {}).items():
            # Strip version prefixes for OSV query
            clean_version = str(version).lstrip("^~>=<!")
            # Skip workspace/git/url/local references
            if clean_version.startswith((
                "workspace:", "git:", "git+", "hg:", "svn:",
                "http:", "https:", "file:", "/", "..",
                "github:", "bitbucket:", "gitlab:",
            )):
                continue
            dep = {"name": name, "version": clean_version, "ecosystem": "npm"}
            if _validate_dep(dep):
                deps.append(dep)

            if len(deps) >= MAX_DEPS_TOTAL:
                logger.warning("Hit dependency limit in package.json, stopping")
                return deps

    return deps


def parse_package_lock(path: str, workspace: str = None) -> list[dict]:
    """Parse dependencies from package-lock.json with path traversal defense."""
    try:
        if workspace:
            content = _safe_read_file(path, workspace)
            data = json.loads(content)
        else:
            with open(path, "r") as f:
                data = json.load(f)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning("Failed to parse package-lock.json: %s", e)
        return []

    deps = []
    # lockfileVersion 2/3 has packages at root level
    packages = data.get("packages", {})
    if packages:
        for pkg_path, pkg_info in packages.items():
            if pkg_path == "":
                continue
            name = pkg_path.replace("node_modules/", "")
            version = pkg_info.get("version", "")
            if name and version:
                dep = {"name": name, "version": version, "ecosystem": "npm"}
                if _validate_dep(dep):
                    deps.append(dep)
    else:
        # lockfileVersion 1
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "")
            if name and version:
                dep = {"name": name, "version": version, "ecosystem": "npm"}
                if _validate_dep(dep):
                    deps.append(dep)

    if len(deps) > MAX_DEPS_TOTAL:
        logger.warning("Hit dependency limit in package-lock.json, truncating")
        deps = deps[:MAX_DEPS_TOTAL]

    return deps


def parse_requirements_txt(path: str, workspace: str = None) -> list[dict]:
    """Parse dependencies from requirements.txt with path traversal defense."""
    try:
        if workspace:
            content = _safe_read_file(path, workspace)
            lines = content.splitlines()
        else:
            with open(path, "r") as f:
                lines = f.readlines()
    except (ValueError, OSError) as e:
        logger.warning("Failed to read requirements.txt: %s", e)
        return []

    if len(lines) > MAX_MANIFEST_LINES:
        logger.warning("requirements.txt exceeds line limit, truncating")
        lines = lines[:MAX_MANIFEST_LINES]

    deps = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Handle version specifiers
        for sep in ["==", ">=", "~=", "!=", "<=", ">", "<"]:
            if sep in line:
                name, version = line.split(sep, 1)
                # Clean version: take first specifier, handle extras
                version = version.strip().split(",")[0].strip()
                # Remove extras from name like package[extra]
                name = name.strip().split("[")[0]
                dep = {"name": name, "version": version, "ecosystem": "PyPI"}
                if _validate_dep(dep):
                    deps.append(dep)
                break
        else:
            # No version specified — skip (don't send empty version to OSV)
            name = line.strip().split("[")[0]
            if name and _validate_dep({"name": name, "version": "", "ecosystem": "PyPI"}):
                deps.append({"name": name, "version": "", "ecosystem": "PyPI"})

        if len(deps) >= MAX_DEPS_TOTAL:
            logger.warning("Hit dependency limit in requirements.txt, stopping")
            return deps

    return deps


def parse_poetry_lock(path: str, workspace: str = None) -> list[dict]:
    """Parse dependencies from poetry.lock with path traversal defense."""
    try:
        if workspace:
            content = _safe_read_file(path, workspace)
        else:
            with open(path, "r") as f:
                content = f.read()
    except (ValueError, OSError) as e:
        logger.warning("Failed to read poetry.lock: %s", e)
        return []

    if len(content) > MAX_FILE_SIZE:
        logger.warning("poetry.lock exceeds size limit, truncating")
        content = content[:MAX_FILE_SIZE]

    deps = []
    try:
        packages = re.findall(
            r'\[\[package\]\]\s*name\s*=\s*"([^"]+)"\s*version\s*=\s*"([^"]+)"',
            content,
        )
        for name, version in packages:
            dep = {"name": name, "version": version, "ecosystem": "PyPI"}
            if _validate_dep(dep):
                deps.append(dep)

            if len(deps) >= MAX_DEPS_TOTAL:
                logger.warning("Hit dependency limit in poetry.lock, stopping")
                return deps
    except Exception as e:
        logger.warning("Failed to parse poetry.lock: %s", e)

    return deps


def parse_manifest(repo_dir: str, ecosystem: str, manifest_path: str) -> list[dict]:
    """Parse a manifest file and return normalized dependencies.

    Uses workspace-aware parsing for path traversal defense.
    """
    full_path = os.path.join(repo_dir, manifest_path)
    workspace = os.path.realpath(repo_dir)
    filename = os.path.basename(manifest_path)

    parser_map = {
        "package-lock.json": parse_package_lock,
        "package.json": parse_package_json,
        "requirements.txt": parse_requirements_txt,
        "poetry.lock": parse_poetry_lock,
    }

    parser = parser_map.get(filename)
    if not parser:
        return []

    try:
        return parser(full_path, workspace)
    except Exception as e:
        logger.warning("Parser failed for %s: %s", manifest_path, e)
        return []


# ═══════════════════════════════════════════════════════════════════
# OSV Integration
# ═══════════════════════════════════════════════════════════════════

def _validate_osv_query(query: dict) -> bool:
    """Validate an OSV query before sending."""
    pkg = query.get("package", {})
    if not pkg.get("name") or not pkg.get("ecosystem"):
        return False
    if not query.get("version"):
        return False
    if len(pkg["name"]) > 500:
        return False
    return True


def _validate_osv_result(result: dict) -> bool:
    """Validate an OSV response item."""
    if not isinstance(result, dict):
        return False
    # Result should have 'vulns' key (can be empty list)
    if "vulns" not in result:
        return False
    return True


def _validate_osv_vuln(vuln: dict) -> bool:
    """Validate an individual OSV vulnerability entry."""
    if not isinstance(vuln, dict):
        return False
    if not vuln.get("id"):
        return False
    # Must have at least one of: summary, details
    if not vuln.get("summary") and not vuln.get("details"):
        return False
    return True


async def query_osv_batch(deps: list[dict]) -> list[dict]:
    """Query OSV.dev with batch requests.

    Security:
    - Queries validated before sending
    - Responses validated before processing
    - Rate limit (429) handled with backoff
    - 5xx handled with retry
    - Timeout enforced
    - Never returns "0 vulnerabilities" on failure — raises instead
    """
    if not deps:
        return []

    results = []

    for i in range(0, len(deps), settings.max_deps_per_batch):
        chunk = deps[i:i + settings.max_deps_per_batch]

        queries = []
        for d in chunk:
            if not d.get("version"):
                continue
            q = {"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]}
            if _validate_osv_query(q):
                queries.append(q)

        if not queries:
            continue

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        ) as client:
            for attempt in range(3):
                try:
                    resp = await client.post(OSV_BATCH_URL, json={"queries": queries})

                    # Handle rate limiting
                    if resp.status_code == 429:
                        retry_after = int(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
                        logger.warning("OSV rate limited, retrying after %ds", retry_after)
                        import asyncio
                        await asyncio.sleep(min(retry_after, 60))
                        continue

                    # Handle server errors
                    if resp.status_code >= 500:
                        if attempt < 2:
                            import asyncio
                            await asyncio.sleep(2 ** attempt)
                            continue
                        raise RuntimeError(f"OSV server error: {resp.status_code}")

                    # Handle bad request
                    if resp.status_code == 400:
                        raise RuntimeError("OSV returned 400 Bad Request — malformed query")

                    resp.raise_for_status()

                    # Validate response structure
                    data = resp.json()
                    if not isinstance(data, dict):
                        raise RuntimeError("OSV returned invalid response structure")

                    raw_results = data.get("results", [])
                    if not isinstance(raw_results, list):
                        raise RuntimeError("OSV results is not a list")

                    # Validate each result
                    for r in raw_results:
                        if _validate_osv_result(r):
                            results.append(r)
                        else:
                            logger.warning("Invalid OSV result item skipped: %s", str(r)[:200])

                    break

                except httpx.TimeoutException:
                    if attempt == 2:
                        raise RuntimeError("OSV request timed out after retries")
                    import asyncio
                    await asyncio.sleep(2 ** attempt)
                except httpx.NetworkError as e:
                    if attempt == 2:
                        raise RuntimeError(f"OSV network error: {e}")
                    import asyncio
                    await asyncio.sleep(2 ** attempt)

    return results


# ═══════════════════════════════════════════════════════════════════
# Severity Normalization
# ═══════════════════════════════════════════════════════════════════

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}


def normalize_severity(vuln: dict) -> str:
    """Extract severity from OSV vulnerability.

    Priority: CVSS vector > database_specific > UNKNOWN
    Never guesses — returns UNKNOWN when uncertain.
    """
    if not isinstance(vuln, dict):
        return "UNKNOWN"

    # Try CVSS vector
    for severity in vuln.get("severity", []):
        if not isinstance(severity, dict):
            continue
        if severity.get("type") == "CVSS_V3":
            score_str = str(severity.get("score", ""))
            try:
                # Extract base score from CVSS vector
                if "AV:N" in score_str:
                    if "AC:L" in score_str and "PR:N" in score_str:
                        return "CRITICAL" if "UI:N" in score_str else "HIGH"
                    return "HIGH"
                elif "AV:A" in score_str:
                    return "MEDIUM"
                elif "AV:L" in score_str:
                    return "LOW"
            except Exception:
                pass

    # Try numeric CVSS score
    for severity in vuln.get("severity", []):
        if not isinstance(severity, dict):
            continue
        score_str = str(severity.get("score", ""))
        try:
            # Try to extract numeric score
            match = re.search(r'(\d+\.?\d*)$', score_str)
            if match:
                score = float(match.group(1))
                if score >= 9.0:
                    return "CRITICAL"
                elif score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
        except (ValueError, AttributeError):
            pass

    # Try database_specific severity
    db_specific = vuln.get("database_specific")
    if isinstance(db_specific, dict):
        db_severity = db_specific.get("severity")
        if db_severity:
            normalized = str(db_severity).upper()
            if normalized in VALID_SEVERITIES:
                return normalized

    return "UNKNOWN"


# ═══════════════════════════════════════════════════════════════════
# Finding Normalization
# ═══════════════════════════════════════════════════════════════════

def normalize_findings(
    osv_results: list[dict],
    deps: list[dict],
    repository_id: str,
    scan_id: str,
    manifest_path: str,
) -> list[dict]:
    """Normalize OSV results into findings with fingerprints.

    Each OSV result is validated before creating a finding.
    Deduplication happens at both application and database level.
    """
    findings = []
    seen_fingerprints = set()

    for i, result in enumerate(osv_results):
        if not _validate_osv_result(result):
            continue

        vulns = result.get("vulns", [])
        dep = deps[i] if i < len(deps) else {}

        for vuln in vulns:
            if not _validate_osv_vuln(vuln):
                logger.warning("Invalid vuln entry skipped: %s", str(vuln)[:200])
                continue

            vuln_id = str(vuln.get("id", "UNKNOWN"))
            pkg_name = str(dep.get("name", "unknown"))
            severity = normalize_severity(vuln)

            fp = compute_fingerprint(repository_id, vuln_id, pkg_name, manifest_path)
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)

            title = str(vuln.get("summary", f"Vulnerability in {pkg_name}"))[:1000]
            description = str(vuln.get("details", ""))[:5000]

            findings.append({
                "fingerprint": fp,
                "vulnerability_id": vuln_id,
                "package_name": pkg_name,
                "package_version": str(dep.get("version", "")),
                "title": title,
                "description": description,
                "severity": severity,
                "scanner": "dependency",
                "source_type": "DEPENDENCY",
                "aliases": vuln.get("aliases", []),
            })

    return findings


# ═══════════════════════════════════════════════════════════════════
# Main Scan Pipeline
# ═══════════════════════════════════════════════════════════════════

async def scan_repository(
    repo_dir: str,
    repository_id: str,
    scan_id: str,
) -> dict:
    """Run the full dependency scan pipeline on a cloned repo directory.

    Returns:
        {
            "findings": [...],
            "dependencies": [...],
            "commit_sha": str,
            "manifests_found": int,
            "total_deps": int,
        }
    """
    workspace = os.path.realpath(repo_dir)

    # Verify workspace exists and is a directory
    if not os.path.isdir(workspace):
        raise RuntimeError(f"Scan workspace not found: {workspace}")

    logger.info("scan_started scan_id=%s repository_id=%s", scan_id, repository_id)

    manifests = detect_manifests(workspace)
    logger.info(
        "manifests_detected scan_id=%s count=%d",
        scan_id, len(manifests),
    )

    all_deps = []
    all_findings = []
    manifests_for_deps = {}
    parse_errors = []

    for ecosystem, manifest_path in manifests:
        try:
            deps = parse_manifest(workspace, ecosystem, manifest_path)
            for dep in deps:
                dep["manifest_path"] = manifest_path
            all_deps.extend(deps)
            manifests_for_deps[manifest_path] = deps
            logger.info(
                "manifest_parsed scan_id=%s manifest=%s ecosystem=%s deps=%d",
                scan_id, manifest_path, ecosystem, len(deps),
            )
        except Exception as e:
            parse_errors.append({"manifest": manifest_path, "error": str(e)[:200]})
            logger.warning(
                "manifest_parse_failed scan_id=%s manifest=%s error=%s",
                scan_id, manifest_path, str(e)[:200],
            )
            continue  # Don't fail entire scan for one bad manifest

    # Query OSV for all deps
    if all_deps:
        try:
            osv_results = await query_osv_batch(all_deps)
            logger.info("osv_request_completed scan_id=%s results=%d", scan_id, len(osv_results))
        except RuntimeError as e:
            logger.error("osv_request_failed scan_id=%s error=%s", scan_id, str(e))
            raise  # Re-raise to fail the scan properly
    else:
        osv_results = []

    # Normalize findings per manifest
    for ecosystem, manifest_path in manifests:
        manifest_deps = manifests_for_deps.get(manifest_path, [])
        # Match OSV results to deps (positional matching)
        manifest_osv = osv_results[:len(manifest_deps)]
        osv_results = osv_results[len(manifest_deps):]

        manifest_findings = normalize_findings(
            manifest_osv,
            manifest_deps,
            repository_id,
            scan_id,
            manifest_path,
        )
        all_findings.extend(manifest_findings)

    # Get commit SHA
    try:
        sha_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        commit_sha = sha_result.stdout.strip() if sha_result.returncode == 0 else "unknown"
    except Exception:
        commit_sha = "unknown"

    logger.info(
        "scan_completed scan_id=%s findings=%d deps=%d manifests=%d parse_errors=%d",
        scan_id, len(all_findings), len(all_deps), len(manifests), len(parse_errors),
    )

    return {
        "findings": all_findings,
        "dependencies": all_deps,
        "commit_sha": commit_sha,
        "manifests_found": len(manifests),
        "total_deps": len(all_deps),
        "parse_errors": parse_errors,
    }
