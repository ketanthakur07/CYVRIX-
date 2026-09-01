FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r cyvrix && useradd -r -g cyvrix -d /app -s /bin/bash cyvrix

WORKDIR /app

# Copy requirements and install
COPY services/worker/requirements.txt /app/worker-requirements.txt
COPY apps/api/requirements.txt /app/api-requirements.txt
RUN pip install --no-cache-dir -r /app/worker-requirements.txt -r /app/api-requirements.txt

# Copy worker code
COPY services/worker/ /app/services/worker/

# Copy API app code (needed for shared models, services, schemas)
COPY apps/api/app/ /app/apps/api/app/

# Copy Alembic for migrations
COPY apps/api/alembic/ /app/apps/api/alembic/
COPY apps/api/alembic.ini /app/apps/api/alembic.ini

# Set PYTHONPATH so all modules are importable
ENV PYTHONPATH=/app/apps/api:/app/services/worker:/app

# Set ownership
RUN chown -R cyvrix:cyvrix /app

USER cyvrix

EXPOSE 8000

# No HTTP port for worker, but document it doesn't serve HTTP
# Health check verifies worker is alive by checking Redis connectivity
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import redis; r = redis.from_url('${REDIS_URL:-redis://localhost:6379/0}'); r.ping()" || exit 1

CMD ["sh", "-c", "cd /app/services/worker && python main.py"]
