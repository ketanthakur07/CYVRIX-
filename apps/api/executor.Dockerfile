# CYVRIX V3.4 — executor sandbox image (§40/§41)
#
# Supply-chain properties:
# - base image pinned BY DIGEST (python 3.12-alpine3.20, public digest)
#   — never :latest, never repository-chosen
# - minimal: alpine + python; no extra packages added
# - runs as a dedicated unprivileged uid/gid 10001:10001 (§11)
# - the only code added is the stdlib-only cyvrix_executor package and
#   a tiny launcher — no secrets, no credentials, no host files
# - PYTHONHASHSEED=0 for deterministic behavior; bytecode off
#
# NOTE on the base digest: verify/refresh via
#   docker pull python:3.12-alpine3.20 && docker image inspect python:3.12-alpine3.20 --format '{{index .RepoDigests 0}}'
# and update the pin deliberately (image update process: docs/v3-sandbox.md).

FROM python:3.12-alpine3.20@sha256:25849f9599e06dfe4d11b552e06f5ac4cc2ad342054eb81f7877e611f6f87c66

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

# Dedicated unprivileged user (§11)
RUN addgroup -g 10001 cyvrix_sbx \
 && adduser -D -u 10001 -G cyvrix_sbx -s /sbin/nologin cyvrix_sbx

# Executor code only — stdlib-only package + launcher
COPY cyvrix_executor/ /opt/cyvrix/cyvrix_executor/
COPY executor_entry.py /opt/cyvrix/run_executor.py

RUN chmod -R 0555 /opt/cyvrix \
 && chown -R root:root /opt/cyvrix

USER 10001:10001
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/python", "-I", "/opt/cyvrix/run_executor.py"]
