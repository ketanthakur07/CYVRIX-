# CYVRIX V1.0.0 — Changelog

## Release Date
September 1, 2026

## Summary
CYVRIX V1.0.0 is the initial production release of the Autonomous Security Intelligence Platform. It provides GitHub dependency vulnerability detection with AI-assisted investigation and deterministic risk scoring.

## Features
1. **GitHub App Integration** — OAuth login, installation management, repository discovery
2. **Dependency Vulnerability Scanner** — Parses npm (package.json, package-lock.json) and Python (requirements.txt, poetry.lock) manifests, queries OSV.dev for known vulnerabilities
3. **AI Investigation Agent** — Single bounded LLM call per HIGH/CRITICAL finding with schema-validated output, evidence cross-validation, and prompt-injection defenses
4. **Deterministic Risk Engine** — Pure function scoring (0–100) based on severity, exposure, exploitability, and confidence; versioned algorithm with explainable factors
5. **Security Dashboard** — Next.js frontend with dashboard, repository management, scan triggers, finding details, and risk visualization

## Infrastructure
- **Backend**: FastAPI with async PostgreSQL (SQLAlchemy) and Redis
- **Worker**: RQ-based background job processor for scan pipelines
- **Frontend**: Next.js 14 with TanStack Query, Tailwind CSS, shadcn/ui
- **Database**: PostgreSQL 16 with Alembic migrations
- **Queue**: Redis 7 with RQ for reliable job processing
- **Containerization**: Docker Compose with healthchecks, resource limits, and non-root containers
- **CI/CD**: GitHub Actions with lint, type-check, backend tests, frontend tests, migration validation, integration tests, real-stack Playwright E2E, and security checks

## Security
- HMAC-SHA256 signed session cookies stored in Redis
- Fail-closed authentication: no session = 401
- IDOR/BOLA protection via ownership chain verification
- Path traversal and symlink escape defenses in scanner
- XSS protection via React's default escaping
- CSRF protection via SameSite=Lax cookies
- CORS restricted to configured origins only
- Production fail-closed configuration: SECRET_KEY, COOKIE_SECURE, DEBUG validated
- Docker containers run as non-root with healthchecks
- Security headers: X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy

## Breaking Changes
- None (initial release)

## Known Limitations
- Single Redis instance (no HA clustering)
- Live GitHub OAuth, OSV, and LLM testing require external provider credentials
- No Docker image scanning, SAST, secret scanning, or automated remediation
- No push-triggered or webhook-based scanning
- No multi-tenant organizations, teams, or RBAC
