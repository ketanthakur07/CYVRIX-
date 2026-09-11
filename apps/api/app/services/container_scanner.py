"""CYVRIX V2 Container / Dockerfile Security Scanner.

Security properties:
- Path traversal defense: all file reads validated against workspace boundary
- Symlink protection: symlinks pointing outside workspace are rejected
- Safe subprocess: no shell=True, no string concatenation with user input
- Resource limits: max Dockerfiles, max instructions, max file size
- No Docker commands executed (static analysis only)
- Provider responses validated before use
"""
import hashlib
import logging
import os
import re
from typing import Optional

from app.config import get_settings

logger = logging.getLogger("cyvrix.container_scanner")
settings = get_settings()

# Resource limits
MAX_DOCKERFILE_SIZE = 512 * 1024  # 512KB
MAX_DOCKERFILES = 20
MAX_DOCKERFILE_LINES = 2000
MAX_INSTRUCTIONS = 200

# Dockerfile patterns to scan
DOCKERFILE_PATTERNS = [
    "Dockerfile",
    "dockerfile",
    "*.Dockerfile",
    "*.dockerfile",
    "Dockerfile.*",
    "dockerfile.*",
]

# Base image vulnerability mapping (simplified for V2)
# In production, this would query a real vulnerability provider
KNOWN_VULNERABLE_IMAGES = {
    "python:2.7": "CRITICAL",
    "python:3.5": "HIGH",
    "python:3.6": "HIGH",
    "python:3.7": "MEDIUM",
    "python:3.8": "MEDIUM",
    "python:3.9": "LOW",
    "node:12": "HIGH",
    "node:14": "MEDIUM",
    "node:16": "MEDIUM",
    "ubuntu:18.04": "HIGH",
    "ubuntu:20.04": "MEDIUM",
    "alpine:3.12": "MEDIUM",
    "alpine:3.13": "MEDIUM",
    "alpine:3.14": "LOW",
}

# Supported package ecosystems in containers
CONTAINER_PACKAGE_ECOSYSTEMS = {
    "apt": "debian",
    "apk": "alpine",
    "yum": "rhel",
    "dnf": "fedora",
    "pip": "PyPI",
    "npm": "npm",
}

# Security rule definitions
SECURITY_RULES = {
    "root_user": {
        "title": "Container runs as root",
        "severity": "MEDIUM",
        "description": "Container runs as root user, which increases the impact of container escapes.",
        "recommendation": "Add USER instruction to run as non-root user.",
    },
    "latest_tag": {
        "title": "Unpinned base image uses 'latest' tag",
        "severity": "MEDIUM",
        "description": "Using 'latest' tag is not reproducible and may introduce unexpected vulnerabilities.",
        "recommendation": "Pin base image to a specific version or digest.",
    },
    "unpinned_image": {
        "title": "Unpinned base image",
        "severity": "LOW",
        "description": "Base image is not pinned to a specific version or digest.",
        "recommendation": "Pin base image to a specific version for reproducibility.",
    },
    "curl_pipe_sh": {
        "title": "Suspicious curl pipe to shell",
        "severity": "HIGH",
        "description": "curl | sh pattern can execute arbitrary code from remote sources.",
        "recommendation": "Download and verify scripts before execution.",
    },
    "secret_env": {
        "title": "Potential secret in ENV instruction",
        "severity": "HIGH",
        "description": "ENV instruction may contain a secret or credential.",
        "recommendation": "Use build-time secrets or runtime secret injection instead.",
    },
    "exposed_sensitive_port": {
        "title": "Sensitive port exposed",
        "severity": "LOW",
        "description": "Container exposes a port commonly associated with sensitive services.",
        "recommendation": "Verify this port exposure is intentional.",
    },
    "add_instead_of_copy": {
        "title": "ADD used instead of COPY",
        "severity": "LOW",
        "description": "ADD instruction can fetch remote resources and extract archives. COPY is preferred for local files.",
        "recommendation": "Use COPY unless ADD's features are specifically needed.",
    },
    "no_healthcheck": {
        "title": "No HEALTHCHECK instruction",
        "severity": "INFO",
        "description": "Dockerfile does not define a HEALTHCHECK.",
        "recommendation": "Add HEALTHCHECK for container orchestration.",
    },
    "privileged_instruction": {
        "title": "Potential privileged operation detected",
        "severity": "HIGH",
        "description": "Instruction may indicate privileged container configuration.",
        "recommendation": "Avoid privileged containers unless absolutely necessary.",
    },
}


def _validate_path_in_workspace(filepath: str, workspace: str) -> str:
    """Validate a path stays within the workspace."""
    workspace_resolved = os.path.realpath(workspace)
    filepath_resolved = os.path.realpath(filepath)
    if not filepath_resolved.startswith(workspace_resolved + os.sep) and filepath_resolved != workspace_resolved:
        raise ValueError(f"Path traversal detected: {filepath}")
    return filepath_resolved


def _is_symlink_safe(filepath: str, workspace: str) -> bool:
    """Check if a symlink target stays within the workspace."""
    if not os.path.islink(filepath):
        return True
    target_resolved = os.path.realpath(filepath)
    workspace_resolved = os.path.realpath(workspace)
    return target_resolved.startswith(workspace_resolved + os.sep)


def detect_dockerfiles(workspace: str) -> list[str]:
    """Detect Dockerfiles in the workspace.

    Returns list of relative paths to Dockerfiles.
    """
    dockerfiles = []
    workspace = os.path.realpath(workspace)

    for root, dirs, files in os.walk(workspace, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {".git", "node_modules", "__pycache__"}]

        for f in files:
            # Check exact matches
            if f in ("Dockerfile", "dockerfile"):
                full_path = os.path.join(root, f)
            # Check pattern matches
            elif f.startswith("Dockerfile.") or f.endswith(".Dockerfile"):
                full_path = os.path.join(root, f)
            elif f.startswith("dockerfile.") or f.endswith(".dockerfile"):
                full_path = os.path.join(root, f)
            else:
                continue

            # Security checks
            try:
                resolved = _validate_path_in_workspace(full_path, workspace)
            except ValueError:
                logger.warning("Path traversal blocked in Dockerfile detection: %s", full_path)
                continue

            if os.path.islink(full_path):
                logger.warning("Symlink Dockerfile rejected: %s", full_path)
                continue

            try:
                if os.path.getsize(resolved) > MAX_DOCKERFILE_SIZE:
                    logger.warning("Dockerfile too large, skipping: %s", f)
                    continue
            except OSError:
                continue

            rel_path = os.path.relpath(resolved, workspace)
            dockerfiles.append(rel_path)

            if len(dockerfiles) >= MAX_DOCKERFILES:
                logger.warning("Hit Dockerfile limit (%d), stopping detection", MAX_DOCKERFILES)
                return dockerfiles

    return dockerfiles


def parse_dockerfile(filepath: str, workspace: str) -> dict:
    """Parse a Dockerfile and extract structured information.

    Returns:
        {
            "base_images": [...],
            "instructions": [...],
            "exposed_ports": [...],
            "has_user": bool,
            "has_healthcheck": bool,
            "env_vars": [...],
            "run_commands": [...],
            "parse_errors": [...],
        }
    """
    resolved = _validate_path_in_workspace(filepath, workspace)

    if not _is_symlink_safe(filepath, workspace):
        raise ValueError(f"Symlink escape detected: {filepath}")

    with open(resolved, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    if len(lines) > MAX_DOCKERFILE_LINES:
        lines = lines[:MAX_DOCKERFILE_LINES]
        logger.warning("Dockerfile truncated to %d lines", MAX_DOCKERFILE_LINES)

    result = {
        "base_images": [],
        "instructions": [],
        "exposed_ports": [],
        "has_user": False,
        "has_healthcheck": False,
        "env_vars": [],
        "run_commands": [],
        "parse_errors": [],
    }

    instruction_count = 0
    continuation = ""

    for line_num, line in enumerate(lines, 1):
        line = line.strip()

        # Handle line continuations
        if continuation:
            continuation += " " + line
            if not line.endswith("\\"):
                line = continuation
                continuation = ""
            else:
                continuation = line[:-1]
                continue
        elif line.endswith("\\"):
            continuation = line[:-1]
            continue

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        instruction_count += 1
        if instruction_count > MAX_INSTRUCTIONS:
            logger.warning("Hit instruction limit, stopping parse")
            break

        # Parse instruction
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue

        instr = parts[0].upper()
        args = parts[1]

        result["instructions"].append({"line": line_num, "instruction": instr, "args": args[:500]})

        if instr == "FROM":
            # Parse base image (handle AS alias)
            image = args.split(" AS ")[0].split(" as ")[0].strip()
            result["base_images"].append(image)

        elif instr == "USER":
            result["has_user"] = True

        elif instr == "HEALTHCHECK":
            result["has_healthcheck"] = True

        elif instr == "EXPOSE":
            for port in args.split():
                port = port.split("/")[0]  # Remove protocol
                if port.isdigit():
                    result["exposed_ports"].append(int(port))

        elif instr == "ENV":
            result["env_vars"].append(args[:200])

        elif instr == "RUN":
            result["run_commands"].append(args[:500])

    return result


def compute_dockerfile_fingerprint(repository_id: str, rule_id: str, dockerfile_path: str) -> str:
    """Compute dedup fingerprint for container findings."""
    raw = f"{repository_id}:{rule_id}:{dockerfile_path}"
    return hashlib.sha256(raw.encode()).hexdigest()


def analyze_dockerfile(
    dockerfile_path: str,
    workspace: str,
    repository_id: str,
) -> list[dict]:
    """Analyze a Dockerfile for security issues.

    dockerfile_path can be relative to workspace or absolute.
    Returns list of normalized findings.
    """
    findings = []

    # Resolve to absolute path if relative
    if os.path.isabs(dockerfile_path):
        full_path = dockerfile_path
    elif os.path.exists(os.path.join(workspace, dockerfile_path)):
        full_path = os.path.join(workspace, dockerfile_path)
    elif os.path.exists(dockerfile_path):
        full_path = dockerfile_path
    else:
        full_path = os.path.join(workspace, dockerfile_path)

    try:
        parsed = parse_dockerfile(full_path, workspace)
    except Exception as e:
        logger.warning("Failed to parse Dockerfile %s: %s", dockerfile_path, str(e)[:200])
        return [{
            "fingerprint": compute_dockerfile_fingerprint(repository_id, "parse_error", dockerfile_path),
            "title": f"Failed to parse Dockerfile: {dockerfile_path}",
            "description": f"Dockerfile could not be parsed: {str(e)[:200]}",
            "severity": "LOW",
            "scanner": "container",
            "source_type": "CONTAINER",
            "vulnerability_id": None,
            "package_name": dockerfile_path,
            "package_version": "",
            "evidence": {"dockerfile": dockerfile_path, "error": str(e)[:200]},
        }]

    # Rule: Root user
    if not parsed["has_user"]:
        findings.append(_create_finding(
            repository_id, "root_user", dockerfile_path,
            "Container runs as root",
            SECURITY_RULES["root_user"]["description"],
            "MEDIUM",
            evidence={"dockerfile": dockerfile_path, "has_user": False},
        ))

    # Rule: Latest/unpinned base images
    for image in parsed["base_images"]:
        image_lower = image.lower()
        if image_lower.endswith(":latest") or ":" not in image_lower:
            findings.append(_create_finding(
                repository_id, "latest_tag" if ":latest" in image_lower else "unpinned_image",
                dockerfile_path,
                SECURITY_RULES["latest_tag" if ":latest" in image_lower else "unpinned_image"]["title"],
                f"Base image: {image}",
                "MEDIUM" if ":latest" in image_lower else "LOW",
                evidence={"dockerfile": dockerfile_path, "image": image},
            ))

    # Rule: Known vulnerable images
    for image in parsed["base_images"]:
        image_lower = image.lower().split("@")[0]  # Remove digest
        for vuln_image, severity in KNOWN_VULNERABLE_IMAGES.items():
            if image_lower.startswith(vuln_image):
                findings.append(_create_finding(
                    repository_id, f"vuln_image_{vuln_image}", dockerfile_path,
                    f"Known vulnerable base image: {vuln_image}",
                    f"Base image {image} is based on {vuln_image} which has known vulnerabilities.",
                    severity,
                    evidence={"dockerfile": dockerfile_path, "image": image, "vuln_image": vuln_image},
                ))
                break

    # Rule: curl pipe to shell
    for cmd in parsed["run_commands"]:
        if re.search(r'curl\s.*\|\s*(sh|bash)', cmd, re.IGNORECASE):
            findings.append(_create_finding(
                repository_id, "curl_pipe_sh", dockerfile_path,
                "Suspicious curl pipe to shell",
                f"Command: {cmd[:200]}",
                "HIGH",
                evidence={"dockerfile": dockerfile_path, "command": cmd[:200]},
            ))

    # Rule: Secret in ENV
    secret_patterns = [
        r"(?i)(password|secret|token|key|api_key|apikey|private_key)\s*=",
        r"(?i)(aws_access_key|aws_secret_key)",
        r"(?i)(GITHUB_TOKEN|GITHUB_SECRET)",
    ]
    for env in parsed["env_vars"]:
        for pattern in secret_patterns:
            if re.search(pattern, env):
                findings.append(_create_finding(
                    repository_id, "secret_env", dockerfile_path,
                    "Potential secret in ENV instruction",
                    f"ENV may contain a secret: {env[:100]}",
                    "HIGH",
                    evidence={"dockerfile": dockerfile_path, "env": env[:200]},
                ))
                break

    # Rule: Sensitive ports
    sensitive_ports = {22: "SSH", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis", 27017: "MongoDB"}
    for port in parsed["exposed_ports"]:
        if port in sensitive_ports:
            findings.append(_create_finding(
                repository_id, "exposed_sensitive_port", dockerfile_path,
                f"Sensitive port exposed: {port} ({sensitive_ports[port]})",
                f"Container exposes port {port} ({sensitive_ports[port]}).",
                "LOW",
                evidence={"dockerfile": dockerfile_path, "port": port, "service": sensitive_ports[port]},
            ))

    # Rule: No healthcheck
    if not parsed["has_healthcheck"] and parsed["base_images"]:
        findings.append(_create_finding(
            repository_id, "no_healthcheck", dockerfile_path,
            "No HEALTHCHECK instruction",
            "Dockerfile does not define a HEALTHCHECK for container orchestration.",
            "INFO",
            evidence={"dockerfile": dockerfile_path, "has_healthcheck": False},
        ))

    return findings


def _create_finding(
    repository_id: str,
    rule_id: str,
    dockerfile_path: str,
    title: str,
    description: str,
    severity: str,
    evidence: Optional[dict] = None,
) -> dict:
    """Create a normalized finding dict for a container issue."""
    return {
        "fingerprint": compute_dockerfile_fingerprint(repository_id, rule_id, dockerfile_path),
        "title": title,
        "description": description,
        "severity": severity,
        "scanner": "container",
        "source_type": "CONTAINER",
        "vulnerability_id": None,
        "package_name": dockerfile_path,
        "package_version": "",
        "evidence": evidence or {"dockerfile": dockerfile_path},
    }


async def scan_containers(
    workspace: str,
    repository_id: str,
) -> dict:
    """Run the full container scanning pipeline.

    Returns:
        {
            "findings": [...],
            "dockerfiles_found": int,
            "total_instructions": int,
        }
    """
    workspace = os.path.realpath(workspace)

    if not os.path.isdir(workspace):
        raise RuntimeError(f"Scan workspace not found: {workspace}")

    logger.info("container_scan_started repository_id=%s", repository_id)

    dockerfiles = detect_dockerfiles(workspace)
    logger.info("dockerfiles_detected repository_id=%s count=%d", repository_id, len(dockerfiles))

    all_findings = []
    total_instructions = 0

    for dockerfile_path in dockerfiles:
        try:
            findings = analyze_dockerfile(
                dockerfile_path,
                workspace,
                repository_id,
            )
            all_findings.extend(findings)

            # Count instructions for metrics
            try:
                parsed = parse_dockerfile(os.path.join(workspace, dockerfile_path), workspace)
                total_instructions += len(parsed.get("instructions", []))
            except Exception:
                pass

            logger.info(
                "dockerfile_analyzed repository_id=%s dockerfile=%s findings=%d",
                repository_id, dockerfile_path, len(findings),
            )
        except Exception as e:
            logger.warning(
                "dockerfile_analysis_failed repository_id=%s dockerfile=%s error=%s",
                repository_id, dockerfile_path, str(e)[:200],
            )

    logger.info(
        "container_scan_completed repository_id=%s dockerfiles=%d findings=%d",
        repository_id, len(dockerfiles), len(all_findings),
    )

    return {
        "findings": all_findings,
        "dockerfiles_found": len(dockerfiles),
        "total_instructions": total_instructions,
    }
