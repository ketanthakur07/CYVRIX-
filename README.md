# CYVRIX — Security Intelligence Platform

**GitHub dependency vulnerability detection with AI-assisted investigation and deterministic risk scoring.**

CYVRIX connects to GitHub repositories, discovers dependency vulnerabilities via OSV.dev, investigates findings using bounded AI assistance, deterministically evaluates risk, and presents the results through a security dashboard.

---

## Architecture

```
Browser → Next.js → FastAPI → PostgreSQL / Redis → RQ Worker
                                                    ↓
                                            Repository Clone
                                                    ↓
                                            Dependency Scanner
                                                    ↓
                                              OSV.dev Query
                                                    ↓
                                          Finding Normalization
                                                    ↓
                                         AI Investigation (LLM)
                                                    ↓
                                         Evidence Cross-Validation
                                                    ↓
                                       Deterministic Risk Engine
                                                    ↓
                                            PostgreSQL → API → Dashboard
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, TypeScript, Tailwind CSS, shadcn/ui, TanStack Query |
| Backend | FastAPI (Python 3.12), SQLAlchemy (async), Pydantic |
| Database | PostgreSQL 16 with Alembic migrations |
| Queue/Cache | Redis 7 with RQ (background jobs) |
| Worker | Python 3.12, RQ, sync SQLAlchemy |
| Containerization | Docker, Docker Compose |
| CI/CD | GitHub Actions (lint, type-check, unit/integration/E2E tests) |

## V2 Features

1. **GitHub App Integration** — OAuth login, installation management, repository discovery
2. **Dependency Vulnerability Scanner** — npm (package.json, package-lock.json) and Python (requirements.txt, poetry.lock) via OSV.dev batch queries
3. **Container/Dockerfile Scanner (V2.1)** — Static analysis of Dockerfiles for root user, unpinned images, curl-pipe-shell patterns, secrets in ENV, sensitive ports, missing HEALTHCHECK
4. **Security Log Analyzer (V2.2)** — Pattern-based detection of brute-force attacks, admin access anomalies, path probing from text and JSON log files
5. **AI Investigation Agent** — Single bounded LLM call per HIGH/CRITICAL finding with Pydantic-validated output, evidence cross-validation, and prompt-injection defenses
6. **Deterministic Risk Engine** — Pure function scoring (0–100) based on severity, exposure, exploitability, and confidence; versioned algorithm with explainable factors
7. **Recommendation Engine (V2.5)** — Evidence-based remediation recommendations with trust levels (SUPPORTED, LIKELY, UNCERTAIN); deterministic rules + AI fallback
8. **Recommendation Re-validation (V2.6)** — Deterministic validation of recommendations against evidence; states: VALIDATED, PARTIALLY_VALIDATED, UNVERIFIED, UNSAFE
9. **Report Engine** — On-demand security reports in Markdown and JSON formats
10. **Security Dashboard** — Real-time scan status, findings detail, risk scores, source-type badges, recommendation section, and AI investigation results

### Source Types

| Source | Scanner | Evidence |
|--------|---------|----------|
| DEPENDENCY | OSV.dev batch queries | package.json, requirements.txt |
| CONTAINER | Dockerfile static analysis | Dockerfile instructions |
| LOG | Pattern-based detection | access.log, security.log |

### Recommendation Validation

| State | Meaning |
|-------|--------|
| VALIDATED | All claims supported by evidence |
| PARTIALLY_VALIDATED | Some claims supported, some uncertain |
| UNVERIFIED | Insufficient evidence to validate |
| UNSAFE | Recommendation contradicted by evidence or policies |

**Important:** Recommendations are advisory only. CYVRIX never modifies files, pushes code, creates PRs, merges, or deploys.

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 20+
- Python 3.12+

### 1. Start infrastructure

```bash
cd infra
docker-compose up -d postgres redis
```

### 2. Run migrations

```bash
cd apps/api
cp .env.example .env
# Edit .env with your credentials (see Configuration section below)
pip install -r requirements.txt
python -m alembic upgrade head
```

### 3. Start the API

```bash
uvicorn app.main:app --reload --port 8000
```

### 4. Start the worker

```bash
cd services/worker
cp .env.example .env
# Edit .env with matching credentials
python main.py
```

### 5. Start the frontend

```bash
cd apps/web
npm ci
npm run dev
```

### 6. Open the dashboard

Navigate to [http://localhost:3000](http://localhost:3000) and click **Connect GitHub**.

## Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://user:pass@localhost:5432/cyvrix` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `SECRET_KEY` | HMAC key for session signing (min 32 chars) | Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `GITHUB_CLIENT_ID` | GitHub OAuth App client ID | From GitHub Settings → Developer settings |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret | From GitHub Settings → Developer settings |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_APP_ID` | `""` | GitHub App ID (for installation tokens) |
| `GITHUB_APP_PRIVATE_KEY` | `""` | GitHub App private key (PEM format) |
| `OPENAI_API_KEY` | `""` | OpenAI API key for AI investigation |
| `OPENAI_MODEL` | `gpt-4o-mini` | LLM model for investigation |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `ENVIRONMENT` | `development` | `development` or `production` |
| `DEBUG` | `false` | Must be `false` in production |
| `COOKIE_SECURE` | `false` | Must be `true` in production (HTTPS) |
| `SESSION_TTL_SECONDS` | `86400` | Session lifetime (24h default) |

### Production Fail-Closed Behavior

When `ENVIRONMENT=production`:
- `SECRET_KEY` must be set, ≥32 characters, not a known default
- `COOKIE_SECURE` must be `true`
- `DEBUG` must be `false`
- Database startup failure raises immediately (no fallback)

## How It Works

### Scanning Pipeline

1. User clicks **Run Scan**, **Container Scan**, or **Log Analysis** on a repository
2. API creates a scan record (status: QUEUED) and enqueues an RQ job
3. Worker picks up the job and clones the repository (shallow, 120s timeout)
4. **Dependency scan:** Scanner detects manifests → parses deps → queries OSV.dev → normalizes findings
5. **Container scan:** Dockerfile detection → static analysis → security rule checks → normalized findings
6. **Log analysis:** Log file detection → pattern matching → event correlation → normalized findings
7. HIGH/CRITICAL findings receive AI investigation (single LLM call)
8. Evidence is cross-validated against supplied code snippets
9. Deterministic risk scores are computed for all findings
10. Deterministic recommendations are generated for all findings
11. Results are persisted to PostgreSQL and appear on the dashboard

### AI Investigation

- Exactly one bounded LLM call per HIGH/CRITICAL finding (no agent loop)
- Repository content is labeled as `<UNTRUSTED_REPOSITORY_CONTENT>` in the prompt
- Response is Pydantic-schema validated and evidence cross-validated
- AI failures never fail the scan — findings display without AI insight
- Maximum 20 LLM calls per scan (configurable)

### Recommendation Engine

- Deterministic rules first (dependency upgrade, container root, latest tag, etc.)
- AI fallback for complex findings where rules don't apply
- Each recommendation includes: what, why, change, uncertainty, risk, validation
- Trust levels: SUPPORTED (deterministic), LIKELY (AI-backed), UNCERTAIN (insufficient evidence)

### Re-validation (V2.6)

- Advisory validation of recommendations against finding context
- Checks: completeness, evidence existence, trust level consistency, scanner-specific logic, dangerous content
- Pure function: no file system, network, or database access
- Cannot modify security state

### Deterministic Risk Scoring

```
base = {CRITICAL: 80, HIGH: 60, MEDIUM: 40, LOW: 20}
exposure_mod = {EXTERNAL: +15, INTERNAL: -5, UNKNOWN: 0}
exploit_mod = {HIGH: +10, MEDIUM: +5, LOW: 0}
confidence_mod = -20 × (1 - confidence)
score = clamp(base + exposure_mod + exploit_mod + confidence_mod, 0, 100)
```

- Pure function: zero LLM calls, zero network calls
- Versioned algorithm (stored per assessment)
- Explainable factors in every score
- Same inputs always produce the same output

## Running Tests

### Frontend Tests (Jest)

```bash
cd apps/web
npx jest --verbose
```

### Backend Tests (pytest)

```bash
cd tests
pip install -r requirements.txt
pytest -v
```

### TypeScript Check

```bash
cd apps/web
npx tsc --noEmit
```

### Production Build

```bash
cd apps/web
npx next build
```

### E2E Tests (Playwright)

```bash
cd infra
docker-compose -f docker-compose.e2e.yml up -d
cd ../tests
python setup_e2e.py
cd ../apps/web
npx playwright test e2e/real-stack.spec.ts
```

## Security Controls

| Control | Implementation |
|---------|---------------|
| Authentication | GitHub OAuth with HMAC-signed session cookies in Redis |
| Authorization | Ownership chain: user → installation → repository → scan → finding |
| IDOR Protection | Every resource access verified against ownership chain |
| Session Security | httpOnly, SameSite=Lax, Secure (production), 24h TTL |
| CORS | Configurable origins, no wildcard credentialed CORS |
| XSS | React default escaping, no dangerouslySetInnerHTML |
| CSRF | SameSite=Lax cookies + OAuth state parameter |
| Path Traversal | Workspace boundary validation, symlink escape detection |
| Command Injection | subprocess.run with list args (no shell=True) |
| AI Security | Bounded calls, untrusted content labeling, no tools, Pydantic validation |
| Secrets | No secrets in source, logs, or error responses |
| Docker | Non-root containers, healthchecks, resource limits |
| Headers | HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |

## Project Structure

```
cyvrix/
├── apps/
│   ├── api/                 # FastAPI backend
│   │   ├── app/
│   │   │   ├── main.py      # Application entry point
│   │   │   ├── config.py    # Settings with production validation
│   │   │   ├── models.py    # SQLAlchemy models (9 tables)
│   │   │   ├── schemas.py   # Pydantic schemas
│   │   │   ├── auth.py      # Authentication dependencies
│   │   │   ├── session.py   # Redis session management
│   │   │   ├── routes/      # API route handlers
│   │   │   └── services/    # Scanner, investigation, risk engine
│   │   ├── alembic/         # Database migrations
│   │   └── Dockerfile
│   └── web/                 # Next.js frontend
│       ├── app/             # Pages (dashboard, repos, findings, scans)
│       ├── components/      # Shared UI components
│       ├── lib/             # API client, types, auth
│       ├── e2e/             # Playwright E2E tests
│       ├── __tests__/       # Jest unit tests
│       └── Dockerfile
├── services/
│   ├── worker/              # RQ scan pipeline worker
│   └── mock-providers/      # Mock GitHub/OSV/LLM for E2E tests
├── tests/                   # Python test suite
│   ├── fixtures/            # Sample repositories for testing
│   └── *.py                 # Unit, integration, security tests
├── infra/                   # Docker Compose configurations
├── docs/                    # Architecture, security, deployment docs
└── .github/workflows/       # CI/CD pipeline
```

## Known Limitations (V2)

- **Single Redis instance** — no high-availability clustering
- **No SAST / secret scanning** — future scope
- **No automated remediation** — recommendations are advisory only
- **No push-triggered or webhook-based scanning** — manual scan only
- **No multi-tenant organizations, teams, or RBAC** — single-user model
- **npm and Python only** — Java, Go, etc. deferred to future
- **Live provider testing requires credentials** — GitHub, OSV, and LLM are mocked in E2E
- **Container scanner is static analysis only** — no Docker image scanning
- **Log analyzer uses deterministic patterns** — no AI-based anomaly detection

## What V2 Does NOT Do

| Feature | Status |
|---------|--------|
| Modify repositories or files | NEVER — advisory only |
| Push code or create PRs | NEVER — advisory only |
| Merge or deploy | NEVER — advisory only |
| Execute arbitrary remediation | NEVER — advisory only |
| SAST (Semgrep) | Future scope |
| Secret scanning (Gitleaks) | Future scope |
| Attack simulation | Future scope |
| Multi-agent orchestration | Future scope |
| Organization / team management | Future scope |
| RBAC / enterprise auth | Future scope |

## License

MIT
