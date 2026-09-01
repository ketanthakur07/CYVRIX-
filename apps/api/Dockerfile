FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r cyvrix && useradd -r -g cyvrix -d /app -s /bin/bash cyvrix

WORKDIR /app

# Copy API requirements and install
COPY apps/api/requirements.txt /app/api-requirements.txt
RUN pip install --no-cache-dir -r /app/api-requirements.txt

# Copy the full project structure (needed for alembic, models, services, routes)
COPY apps/api/ /app/apps/api/

# Set PYTHONPATH so app modules are importable
ENV PYTHONPATH=/app/apps/api:/app

# Set ownership
RUN chown -R cyvrix:cyvrix /app

USER cyvrix

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["sh", "-c", "cd /app/apps/api && python -m alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
