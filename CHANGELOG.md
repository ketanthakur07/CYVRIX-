# CYVRIX v1.0.0 — Changelog

**Release Date:** September 1, 2026

## Added

### Core Features
- GitHub repository connection via OAuth and GitHub App installation
- Dependency vulnerability scanning (npm + Python) via OSV.dev batch queries
- AI-assisted investigation with evidence cross-validation
- Deterministic risk scoring engine (pure function, versioned, explainable)
- Security dashboard with scan status, findings detail, and risk visualization

### Authentication & Security
- GitHub OAuth login with HMAC-signed session cookies
- Redis-backed session storage with configurable TTL
- Production fail-closed configuration (SECRET_KEY, COOKIE_SECURE, DEBUG)
- IDOR/BOLA protection via ownership chain verification
- CSRF protection via SameSite=Lax cookies and OAuth state parameter
- CORS restricted to configured origins
- Security headers: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy

### Infrastructure
- FastAPI backend with async PostgreSQL (SQLAlchemy) and Redis
- RQ-based background worker for scan pipelines
- Next.js 14 frontend with TanStack Query, Tailwind CSS, shadcn/ui
- PostgreSQL 16 with Alembic migrations (9 tables)
- Docker Compose with healthchecks, resource limits, and non-root containers
- GitHub Actions CI/CD (7 jobs: lint, backend, frontend, migrations, integration, E2E, security)

### Security Hardening
- Path traversal and symlink escape defenses in scanner
- Command injection prevention (subprocess with list args, no shell=True)
- XSS protection via React default escaping
- AI prompt injection defenses (untrusted content labeling, no tools, bounded calls)
- Rate limiting on authentication and scan endpoints
- Clone URL sanitization in logs
- Workspace cleanup in finally blocks

### Testing
- 32 frontend Jest tests (API client, types, XSS security)
- 316 backend pytest tests (scanner, risk engine, investigation, API, security, migrations, integration)
- 17 Playwright E2E tests (authentication, IDOR, XSS, golden path)
- TypeScript type checking
- Next.js production build verification

## Security

- Authentication hardening with fail-closed session validation
- Authorization via ownership chain (user → installation → repository)
- Path traversal protection with workspace boundary validation
- Symlink escape detection in scanner
- Command execution hardening (shell=False, argument arrays)
- XSS protection via React escaping and security headers
- Prompt injection defenses with untrusted content labeling
- Production cookie configuration validation
- CORS restrictions with configurable origins
- Docker containers run as non-root with healthchecks

## Limitations

- Single Redis instance (no HA clustering)
- Live GitHub OAuth, OSV, and LLM testing require external provider credentials
- No Docker image scanning, SAST, secret scanning, or automated remediation
- No push-triggered or webhook-based scanning
- No multi-tenant organizations, teams, or RBAC
- npm and Python ecosystems only (Java, Go, etc. deferred to V2)
- Test RSA key exists in git history (used only with mock providers in E2E tests)

## Future

See [docs/roadmap-v2.md](docs/roadmap-v2.md) for V2 planning.
