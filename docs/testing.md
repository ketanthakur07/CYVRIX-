# CYVRIX V1 — Testing Strategy

## Overview

CYVRIX uses a multi-layered testing approach: unit tests for individual components, integration tests for service interactions, and E2E tests for full user workflows.

## Test Layers

### 1. Frontend Unit Tests (Jest)

**Location:** `apps/web/__tests__/`

| Test File | Focus | Count |
|-----------|-------|-------|
| `api.test.ts` | API client error handling, safe messages | 8 |
| `types.test.ts` | Display constants, utility functions | 13 |
| `xss-security.test.tsx` | XSS defense via React escaping | 11 |
| **Total** | | **32** |

**Run:**
```bash
cd apps/web
npx jest --verbose
```

### 2. Backend Unit Tests (pytest)

**Location:** `tests/`

| Test File | Focus |
|-----------|-------|
| `test_scanner.py` | Manifest parsing, fingerprinting, OSV queries |
| `test_risk_engine.py` | Deterministic scoring formula, edge cases |
| `test_investigation.py` | LLM prompt building, response parsing, validation |
| `test_api.py` | API endpoints, authentication, authorization |
| `test_github_integration.py` | GitHub API integration |
| `test_scanner_security.py` | Path traversal, symlink, command injection |
| `test_migrations.py` | Alembic migration safety |
| `test_config_cookie_security.py` | Cookie configuration validation |
| `test_redis_integration.py` | Redis session operations |
| `test_integration.py` | Multi-service integration |
| `test_real_integration.py` | Real PostgreSQL + Redis integration |

**Run:**
```bash
cd tests
pip install -r requirements.txt
pytest -v
```

### 3. Type Checking

**TypeScript:**
```bash
cd apps/web
npx tsc --noEmit
```

**Python:**
```bash
python -m py_compile apps/api/app/*.py apps/api/app/**/*.py
```

### 4. Production Build

```bash
cd apps/web
npx next build
```

### 5. Playwright E2E Tests

**Location:** `apps/web/e2e/`

| Test File | Focus |
|-----------|-------|
| `real-stack.spec.ts` | Authentication, IDOR, XSS, cookie security, empty states |
| `golden-path.spec.ts` | Full scan pipeline: UI → API → Worker → Findings → Risk |

**Run:**
```bash
cd infra
docker-compose -f docker-compose.e2e.yml up -d
cd ../tests
python setup_e2e.py
cd ../apps/web
npx playwright test e2e/real-stack.spec.ts --reporter=list
```

## Test Infrastructure

### Fixtures

| Fixture | Description |
|---------|-------------|
| `vulnerable-node-app` | Node.js app with known vulnerable dependencies |
| `vulnerable-python-app` | Python app with known vulnerable dependencies |
| `clean-app` | App with no known vulnerabilities |
| `malformed-lockfile-app` | App with corrupt/incomplete lockfile |
| `malicious-symlink-app` | App with symlink escape attempts |

### Mock Providers

`services/mock-providers/` provides mock implementations of:
- GitHub API (OAuth, installation tokens, repositories, file content)
- OSV.dev API (vulnerability queries)
- OpenAI API (LLM investigation)

Mock providers serve fixture data and return deterministic responses for reproducible tests.

### Test Database

- Tests use SQLite with aiosqlite (unit tests) or real PostgreSQL (integration tests)
- `conftest.py` provides fixtures for test users, installations, repositories
- `authenticated_client` fixture overrides `get_current_user` for auth testing
- Database cleaned between tests via table deletion

## Security Test Coverage

| Security Area | Test Coverage |
|---------------|---------------|
| Authentication | 401 on missing session, expired session, invalid session |
| Authorization | IDOR tests: User B cannot access User A's resources |
| Path Traversal | Scanner security tests with traversal payloads |
| Symlink Escape | Malicious symlink fixture tests |
| Command Injection | Scanner uses subprocess with list args, no shell=True |
| XSS | React escaping tests, browser-level Playwright XSS tests |
| CSRF | SameSite=Lax verification, OAuth state parameter |
| CORS | Origin validation tests |
| Prompt Injection | Investigation tests with hostile repository content |
| Secret Leakage | API error messages don't expose internal details |

## CI Pipeline

The GitHub Actions CI pipeline (`.github/workflows/ci.yml`) runs:

1. **Lint** — Python py_compile + TypeScript tsc
2. **Backend Tests** — pytest on unit/security/migration/integration tests
3. **Frontend Tests** — Jest (32 tests) + Next.js production build
4. **Migration Validation** — Alembic upgrade against real PostgreSQL
5. **Integration Tests** — Real PostgreSQL + Redis
6. **Real-Stack E2E** — Playwright with FastAPI + Next.js + PostgreSQL + Redis
7. **Security Checks** — Grep for secrets and dangerous patterns

## Test Counts (Verified)

| Category | Collected | Passed | Failed | Skipped |
|----------|-----------|--------|--------|---------|
| Frontend (Jest) | 32 | 32 | 0 | 0 |
| TypeScript | — | ✅ | 0 | — |
| Next.js Build | — | ✅ | — | — |
| Backend (pytest) | 316 | 313 | 0 | 3 (Windows symlink) |
| Playwright E2E | 17 | 17 | 0 | 0 |
| **Total** | **365** | **362** | **0** | **3** |

### Skipped Tests

- 3 Windows-specific symlink tests (legitimate: symlink behavior differs on Windows)

## Writing New Tests

### Backend Test Pattern
```python
@pytest.mark.asyncio
async def test_feature(authenticated_client, test_repository):
    response = authenticated_client.get(f"/api/repositories/{test_repository.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "test-repo"
```

### Frontend Test Pattern
```typescript
it("renders finding title safely", () => {
  render(<FindingCard title='XSS payload' />);
  expect(screen.getByText('XSS payload')).toBeTruthy();
});
```

### E2E Test Pattern
```typescript
test("authenticated user sees dashboard", async ({ context, page }) => {
  const cookie = createFreshSession(userId);
  await setAuthCookie(context, cookie);
  await page.goto(`${BASE_URL}/dashboard`);
  await expect(page.locator("text=Security Dashboard")).toBeVisible();
});
```
