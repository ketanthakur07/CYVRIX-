# CYVRIX V1 — Deployment Guide

## Prerequisites

- Docker & Docker Compose
- Node.js 20+
- Python 3.12+
- PostgreSQL 16 (or Docker)
- Redis 7 (or Docker)
- GitHub App with OAuth credentials
- OpenAI API key (optional — for AI investigation)

## Local Development

### 1. Start Infrastructure

```bash
cd infra
docker-compose up -d postgres redis
```

This starts:
- PostgreSQL on port 5432 (user: `cyvrix`, password: `cyvrix_dev`, db: `cyvrix`)
- Redis on port 6379

### 2. Configure the API

```bash
cd apps/api
cp .env.example .env
```

Edit `.env` with your values:

```env
DATABASE_URL=postgresql+asyncpg://cyvrix:cyvrix_dev@localhost:5432/cyvrix
DATABASE_URL_SYNC=postgresql://cyvrix:cyvrix_dev@localhost:5432/cyvrix
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=<generate: python -c "import secrets; print(secrets.token_hex(32))">
GITHUB_CLIENT_ID=<your-github-oauth-client-id>
GITHUB_CLIENT_SECRET=<your-github-oauth-client-secret>
OPENAI_API_KEY=<your-openai-key>
ENVIRONMENT=development
```

### 3. Run Migrations

```bash
cd apps/api
pip install -r requirements.txt
python -m alembic upgrade head
```

### 4. Start the API

```bash
uvicorn app.main:app --reload --port 8000
```

### 5. Start the Worker

```bash
cd services/worker
cp .env.example .env
# Edit .env with matching credentials
pip install -r requirements.txt
python main.py
```

### 6. Start the Frontend

```bash
cd apps/web
npm ci
npm run dev
```

### 7. Access the Dashboard

Navigate to [http://localhost:3000](http://localhost:3000).

## Production Deployment

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ | PostgreSQL async connection string |
| `DATABASE_URL_SYNC` | ✅ | PostgreSQL sync connection string (for Alembic) |
| `REDIS_URL` | ✅ | Redis connection string |
| `SECRET_KEY` | ✅ | HMAC key (≥32 chars, random) |
| `ENVIRONMENT` | ✅ | Set to `production` |
| `COOKIE_SECURE` | ✅ | Set to `true` |
| `DEBUG` | ✅ | Set to `false` |
| `CORS_ORIGINS` | ✅ | Your frontend domain(s) |
| `GITHUB_CLIENT_ID` | ✅ | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | ✅ | GitHub OAuth client secret |
| `GITHUB_APP_ID` | Optional | For installation tokens |
| `GITHUB_APP_PRIVATE_KEY` | Optional | For installation tokens |
| `OPENAI_API_KEY` | Optional | For AI investigation |

### Production Startup Sequence

```bash
# 1. Build images
docker-compose build

# 2. Start database and cache
docker-compose up -d postgres redis

# 3. Run migrations
docker-compose run --rm api alembic upgrade head

# 4. Verify migration version
docker-compose run --rm api alembic current

# 5. Start all services
docker-compose up -d

# 6. Verify health
curl -f http://localhost:8000/api/health/ready
```

### Health Endpoints

| Endpoint | Purpose | Returns |
|----------|---------|---------|
| `GET /api/health` | Basic health check | `{"status": "ok", "version": "1.0.0"}` |
| `GET /api/health/live` | Liveness probe | `{"status": "alive", "version": "1.0.0"}` |
| `GET /api/health/ready` | Readiness probe (checks DB + Redis) | `{"status": "ready", "checks": {...}}` or 503 |

### Docker Compose Configurations

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Full local development stack |
| `docker-compose.e2e.yml` | E2E testing with mock providers |
| `docker-compose.integration.yml` | Integration testing |

### TLS / HTTPS

CYVRIX does not terminate TLS. In production, place a reverse proxy (nginx, Caddy, cloud LB) in front:

- Terminate TLS at the proxy
- Forward to API (port 8000) and Web (port 3000)
- Set `COOKIE_SECURE=true`
- Set `CORS_ORIGINS` to your HTTPS domain
- Enable HSTS at the proxy level

### Database Backup

```bash
# Backup
docker-compose exec postgres pg_dump -U cyvrix cyvrix > backup_$(date +%Y%m%d).sql

# Restore
cat backup_20260901.sql | docker-compose exec -T postgres psql -U cyvrix cyvrix
```

### Failure Behavior

| Event | Behavior |
|-------|----------|
| PostgreSQL down | API returns 503 on readiness check; startup fails in production |
| Redis down | Sessions fail; API returns 401; scan jobs queue but don't process |
| Worker crash | API unaffected; scan stays in last status; restart worker to resume |
| GitHub API down | Token generation fails; scan fails with INSTALLATION_TOKEN_FAILED |
| OSV API down | Scan fails with OSV_UNAVAILABLE after retries |
| LLM API down | Investigation fails; scan completes with severity-only risk scores |

## E2E Testing

```bash
cd infra
cp e2e.env.example e2e.env
# Edit e2e.env with test RSA key for mock GitHub App

docker-compose -f docker-compose.e2e.yml up -d

# Wait for services to be healthy, then:
cd ../tests
python setup_e2e.py

cd ../apps/web
npx playwright test e2e/real-stack.spec.ts
```
