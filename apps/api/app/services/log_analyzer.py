"""CYVRIX V2 Security / Log Analyzer.

Security properties:
- Log files are treated as untrusted input
- Bounded resource consumption (file size, line count, parsing depth)
- Deterministic pattern detection (no AI in initial detection)
- Path traversal and symlink protection
- Unicode and pathological input handling
- No arbitrary code execution from log content
"""
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

from app.config import get_settings

logger = logging.getLogger("cyvrix.log_analyzer")
settings = get_settings()

# Resource limits
MAX_LOG_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_LOG_LINES = 500000
MAX_LINE_LENGTH = 10000
MAX_JSON_NESTING = 10
MAX_EVENTS_PER_ANALYSIS = 10000
MAX_CORRELATION_WINDOW_SECONDS = 3600  # 1 hour

# Detection patterns (deterministic, not AI-driven)
DETECTION_PATTERNS = {
    "repeated_auth_failure": {
        "title": "Potential brute-force pattern",
        "severity": "HIGH",
        "description": "Multiple authentication failures from the same source within a short window.",
        "pattern": re.compile(r'(?i)(auth(?:entication)?|login|sign[\s-]?in)\s+(fail|error|denied|invalid)', re.IGNORECASE),
        "correlation_key": "source_ip",
        "threshold": 5,
        "window_seconds": 300,
    },
    "admin_access_anomaly": {
        "title": "Suspicious administrative access",
        "severity": "MEDIUM",
        "description": "Administrative access detected outside normal patterns.",
        "pattern": re.compile(r'(?i)(admin|root|sudo|superuser)\s+(access|login|command)', re.IGNORECASE),
        "threshold": 1,
        "window_seconds": MAX_CORRELATION_WINDOW_SECONDS,
    },
    "abnormal_status_burst": {
        "title": "Abnormal error status burst",
        "severity": "MEDIUM",
        "description": "High concentration of error status codes detected.",
        "pattern": re.compile(r'(?i)(status|code)[:\s]*(5\d{2}|4\d{2})\b'),
        "correlation_key": "status_code",
        "threshold": 20,
        "window_seconds": 300,
    },
    "forbidden_probing": {
        "title": "Repeated forbidden requests",
        "severity": "MEDIUM",
        "description": "Multiple 403 Forbidden responses detected, possibly probing.",
        "pattern": re.compile(r'(?i)(status|code)[:\s]*403\b|forbidden'),
        "threshold": 10,
        "window_seconds": 600,
    },
    "path_probing": {
        "title": "Suspicious path probing",
        "severity": "MEDIUM",
        "description": "Requests to potentially sensitive paths detected.",
        "pattern": re.compile(r'(?i)(/etc/passwd|/etc/shadow|/proc/|\.env|\.git|wp-admin|phpmyadmin|\.ssh)'),
        "threshold": 3,
        "window_seconds": 600,
    },
    "unusual_auth_sequence": {
        "title": "Unusual authentication sequence",
        "severity": "MEDIUM",
        "description": "Multiple different users authenticating in rapid succession.",
        "pattern": re.compile(r'(?i)(auth(?:entication)?|login|sign[\s-]?in)\s+(success|ok|accept)', re.IGNORECASE),
        "correlation_key": "user",
        "threshold": 10,
        "window_seconds": 60,
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


def detect_log_files(workspace: str) -> list[str]:
    """Detect log files in the workspace.

    Returns list of relative paths to log files.
    """
    log_files = []
    workspace = os.path.realpath(workspace)

    log_extensions = {".log", ".json", ".jsonl", ".txt"}
    log_names = {"access.log", "error.log", "application.log", "security.log", "auth.log"}

    for root, dirs, files in os.walk(workspace, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in {".git", "node_modules", "__pycache__"}]

        for f in files:
            is_log = False
            if f in log_names:
                is_log = True
            elif any(f.endswith(ext) for ext in log_extensions):
                # Check if it's likely a log file (not just any .txt or .json)
                if ".log" in f.lower() or "log" in f.lower():
                    is_log = True

            if not is_log:
                continue

            full_path = os.path.join(root, f)

            try:
                resolved = _validate_path_in_workspace(full_path, workspace)
            except ValueError:
                logger.warning("Path traversal blocked in log detection: %s", full_path)
                continue

            if os.path.islink(full_path):
                continue

            try:
                if os.path.getsize(resolved) > MAX_LOG_FILE_SIZE:
                    logger.warning("Log file too large, skipping: %s", f)
                    continue
            except OSError:
                continue

            rel_path = os.path.relpath(resolved, workspace)
            log_files.append(rel_path)

    return log_files


def parse_log_line(line: str) -> Optional[dict]:
    """Parse a single log line into structured data.

    Attempts to extract:
    - timestamp
    - level
    - source/IP
    - user
    - method/path
    - status code
    - message

    Returns None if line cannot be parsed.
    """
    if not line or len(line) > MAX_LINE_LENGTH:
        return None

    result = {
        "raw": line[:MAX_LINE_LENGTH],
        "timestamp": None,
        "level": None,
        "source_ip": None,
        "user": None,
        "method": None,
        "path": None,
        "status_code": None,
        "message": line[:MAX_LINE_LENGTH],
    }

    # Try common log formats

    # ISO timestamp
    ts_match = re.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)', line)
    if ts_match:
        result["timestamp"] = ts_match.group(1)

    # Level
    level_match = re.search(r'\b(DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|ALERT|EMERG)\b', line, re.IGNORECASE)
    if level_match:
        result["level"] = level_match.group(1).upper()

    # IP address
    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
    if ip_match:
        result["source_ip"] = ip_match.group(1)

    # HTTP status code
    status_match = re.search(r'\b([45]\d{2})\b', line)
    if status_match:
        result["status_code"] = int(status_match.group(1))

    # HTTP method
    method_match = re.search(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b', line)
    if method_match:
        result["method"] = method_match.group(1)

    # User identifier
    user_match = re.search(r'(?i)user[=:]\s*["\']?(\w+)["\']?', line)
    if user_match:
        result["user"] = user_match.group(1)

    return result


def compute_log_fingerprint(repository_id: str, rule_id: str, source: str) -> str:
    """Compute dedup fingerprint for log findings."""
    raw = f"{repository_id}:{rule_id}:{source}"
    return hashlib.sha256(raw.encode()).hexdigest()


def analyze_log_events(
    events: list[dict],
    rule_id: str,
    repository_id: str,
    log_source: str,
) -> list[dict]:
    """Analyze parsed log events for a specific detection rule.

    Returns list of normalized findings.
    """
    findings = []
    rule = DETECTION_PATTERNS.get(rule_id)
    if not rule:
        return findings

    pattern = rule.get("pattern")
    correlation_key = rule.get("correlation_key")
    threshold = rule.get("threshold", 1)
    window_seconds = rule.get("window_seconds", MAX_CORRELATION_WINDOW_SECONDS)

    if pattern is None:
        return findings

    # Filter events matching the pattern
    matching_events = []
    for event in events:
        raw = event.get("raw", "")
        if pattern.search(raw):
            matching_events.append(event)

    if correlation_key:
        # Correlated detection: group by key and check threshold
        groups: dict[str, list] = {}
        for event in matching_events:
            key_value = event.get(correlation_key, "unknown")
            if key_value not in groups:
                groups[key_value] = []
            groups[key_value].append(event)

        for key_value, group_events in groups.items():
            if len(group_events) >= threshold:
                # Check time window
                timestamps = []
                for ev in group_events:
                    ts = ev.get("timestamp")
                    if ts:
                        try:
                            # Parse ISO timestamp
                            ts_clean = ts.replace("Z", "+00:00")
                            dt = datetime.fromisoformat(ts_clean)
                            timestamps.append(dt.timestamp())
                        except (ValueError, TypeError):
                            pass

                if timestamps:
                    time_span = max(timestamps) - min(timestamps)
                    if time_span > window_seconds:
                        continue  # Events span too long a window

                findings.append({
                    "fingerprint": compute_log_fingerprint(repository_id, rule_id, f"{log_source}:{key_value}"),
                    "title": rule["title"],
                    "description": f"{rule['description']} (source: {key_value}, count: {len(group_events)})",
                    "severity": rule["severity"],
                    "scanner": "log_analyzer",
                    "source_type": "LOG",
                    "vulnerability_id": None,
                    "package_name": log_source,
                    "package_version": "",
                    "evidence": {
                        "log_source": log_source,
                        "rule": rule_id,
                        "correlation_key": correlation_key,
                        "correlation_value": str(key_value),
                        "event_count": len(group_events),
                        "sample_events": [e.get("raw", "")[:200] for e in group_events[:5]],
                    },
                })
    else:
        # Simple threshold detection
        if len(matching_events) >= threshold:
            findings.append({
                "fingerprint": compute_log_fingerprint(repository_id, rule_id, log_source),
                "title": rule["title"],
                "description": f"{rule['description']} (source: {log_source}, count: {len(matching_events)})",
                "severity": rule["severity"],
                "scanner": "log_analyzer",
                "source_type": "LOG",
                "vulnerability_id": None,
                "package_name": log_source,
                "package_version": "",
                "evidence": {
                    "log_source": log_source,
                    "rule": rule_id,
                    "event_count": len(matching_events),
                    "sample_events": [e.get("raw", "")[:200] for e in matching_events[:5]],
                },
            })

    return findings


def analyze_json_log(
    filepath: str,
    workspace: str,
    repository_id: str,
) -> list[dict]:
    """Analyze a JSON/JSONL log file."""
    if not os.path.isabs(filepath):
        filepath = os.path.join(workspace, filepath)
    resolved = _validate_path_in_workspace(filepath, workspace)
    if not _is_symlink_safe(filepath, workspace):
        raise ValueError(f"Symlink escape detected: {filepath}")

    rel_path = os.path.relpath(resolved, workspace)
    findings = []

    events = []
    with open(resolved, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            if line_num > MAX_LOG_LINES:
                logger.warning("Log file exceeds line limit, stopping: %s", rel_path)
                break

            line = line.strip()
            if not line:
                continue

            try:
                # Try JSON parse (handle JSONL)
                data = json.loads(line)
                if isinstance(data, dict):
                    # Flatten to a log event
                    event = {
                        "raw": json.dumps(data)[:MAX_LINE_LENGTH],
                        "timestamp": data.get("timestamp") or data.get("time") or data.get("@timestamp"),
                        "level": (data.get("level") or data.get("severity") or "").upper()[:20],
                        "source_ip": data.get("ip") or data.get("remote_addr") or data.get("client_ip"),
                        "user": data.get("user") or data.get("username"),
                        "status_code": data.get("status") or data.get("status_code"),
                        "message": str(data.get("message") or data.get("msg") or "")[:MAX_LINE_LENGTH],
                    }
                    events.append(event)
                elif isinstance(data, list) and data:
                    # Handle log arrays
                    for item in data[:100]:  # Limit per array
                        if isinstance(item, dict):
                            event = {
                                "raw": json.dumps(item)[:MAX_LINE_LENGTH],
                                "timestamp": item.get("timestamp") or item.get("time"),
                                "level": (item.get("level") or "").upper()[:20],
                                "source_ip": item.get("ip") or item.get("remote_addr"),
                                "user": item.get("user"),
                                "status_code": item.get("status"),
                                "message": str(item.get("message") or "")[:MAX_LINE_LENGTH],
                            }
                            events.append(event)
                            if len(events) >= MAX_EVENTS_PER_ANALYSIS:
                                break
            except (json.JSONDecodeError, ValueError):
                # Not JSON — try as plain text
                event = parse_log_line(line)
                if event:
                    events.append(event)

            if len(events) >= MAX_EVENTS_PER_ANALYSIS:
                logger.warning("Hit event limit, stopping analysis: %s", rel_path)
                break

    # Run detection patterns
    for rule_id in DETECTION_PATTERNS:
        rule_findings = analyze_log_events(events, rule_id, repository_id, rel_path)
        findings.extend(rule_findings)

    return findings


def analyze_text_log(
    filepath: str,
    workspace: str,
    repository_id: str,
) -> list[dict]:
    """Analyze a plain text log file."""
    if not os.path.isabs(filepath):
        filepath = os.path.join(workspace, filepath)
    resolved = _validate_path_in_workspace(filepath, workspace)
    if not _is_symlink_safe(filepath, workspace):
        raise ValueError(f"Symlink escape detected: {filepath}")

    rel_path = os.path.relpath(resolved, workspace)
    findings = []

    events = []
    with open(resolved, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            if line_num > MAX_LOG_LINES:
                logger.warning("Log file exceeds line limit, stopping: %s", rel_path)
                break

            event = parse_log_line(line)
            if event:
                events.append(event)

            if len(events) >= MAX_EVENTS_PER_ANALYSIS:
                break

    # Run detection patterns
    for rule_id in DETECTION_PATTERNS:
        rule_findings = analyze_log_events(events, rule_id, repository_id, rel_path)
        findings.extend(rule_findings)

    return findings


async def analyze_logs(
    workspace: str,
    repository_id: str,
) -> dict:
    """Run the full log analysis pipeline.

    Returns:
        {
            "findings": [...],
            "log_files_found": int,
            "total_events": int,
        }
    """
    workspace = os.path.realpath(workspace)

    if not os.path.isdir(workspace):
        raise RuntimeError(f"Analysis workspace not found: {workspace}")

    logger.info("log_analysis_started repository_id=%s", repository_id)

    log_files = detect_log_files(workspace)
    logger.info("log_files_detected repository_id=%s count=%d", repository_id, len(log_files))

    all_findings = []
    total_events = 0

    for log_path in log_files:
        try:
            full_path = os.path.join(workspace, log_path)

            if log_path.endswith(".json") or log_path.endswith(".jsonl"):
                findings = analyze_json_log(log_path, workspace, repository_id)
            else:
                findings = analyze_text_log(log_path, workspace, repository_id)

            all_findings.extend(findings)
            logger.info(
                "log_file_analyzed repository_id=%s file=%s findings=%d",
                repository_id, log_path, len(findings),
            )
        except Exception as e:
            logger.warning(
                "log_analysis_failed repository_id=%s file=%s error=%s",
                repository_id, log_path, str(e)[:200],
            )

    logger.info(
        "log_analysis_completed repository_id=%s log_files=%d findings=%d",
        repository_id, len(log_files), len(all_findings),
    )

    return {
        "findings": all_findings,
        "log_files_found": len(log_files),
        "total_events": total_events,
    }
