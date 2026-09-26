"""CYVRIX V4.2 — structured logging (Phase 20/23).

Opt-in via CYVRIX_LOG_FORMAT=json. Default output is byte-identical to
V4.1 (standard logging) so no test or operator tooling changes.

Design constraints:
  - SECRET-FREE: the formatter never invents fields; it serializes only
    what the logging call passes. The platform-wide convention (enforced
    by review, Phase 55) is that credentials are never passed to log
    calls — log lines carry safe identifiers only.
  - REQUEST CORRELATION: the request-id middleware stores the active
    request id in a ContextVar; every log line emitted inside that
    request carries request_id. A ContextVar (not a global) is used so
    concurrent asyncio requests cannot cross-contaminate ids.
  - EXCEPTIONS: rendered as type + bounded message. Full tracebacks stay
    available to the process's own stderr via the classic handler when
    json format is off; in json mode the traceback text is NOT embedded
    (bounded exception identity only) so internal paths are not leaked
    into aggregated log stores.
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
from datetime import datetime, timezone

request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "cyvrix_request_id", default=""
)

# Standard LogRecord attributes are record metadata, not log payload —
# everything else found in record.__dict__ was passed via `extra=` and is
# serialized as a structured field.
_RESERVED_ATTRS = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "stacklevel", "thread", "threadName",
    "taskName", "request_id",
})


class JsonFormatter(logging.Formatter):
    """One JSON object per log line. Bounded, secret-free, parseable."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        rid = getattr(record, "request_id", None) or request_id_ctx.get()
        if rid:
            entry["request_id"] = rid
        for key, value in record.__dict__.items():
            if key in _RESERVED_ATTRS or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                entry[key] = value
            except (TypeError, ValueError):
                entry[key] = repr(value)[:200]
        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = f"{record.exc_info[0].__name__}: {str(record.exc_info[1])[:200]}"
        return json.dumps(entry, ensure_ascii=False)


def set_request_id(request_id: str) -> None:
    """Bind the current async context to a request id (middleware only)."""
    request_id_ctx.set(request_id or "")


def configure_logging() -> None:
    """Install the JSON formatter when CYVRIX_LOG_FORMAT=json.

    Called once at process start. Any other value (including unset)
    leaves logging untouched — development output is unchanged.
    """
    if os.environ.get("CYVRIX_LOG_FORMAT", "").strip().lower() != "json":
        return
    root = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]
    level = os.environ.get("CYVRIX_LOG_LEVEL", "INFO").upper()
    root.setLevel(getattr(logging, level, logging.INFO))
