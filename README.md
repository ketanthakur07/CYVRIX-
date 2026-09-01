# CYVRIX — Autonomous Security Intelligence

Production-grade security vulnerability detection, investigation, and risk scoring platform.

## Architecture

```
Browser → Next.js → FastAPI → PostgreSQL / Redis → Worker → Repository acquisition
                                                            → Dependency scanner → OSV
                                                            → Finding normalization
                                                            → AI investigation → Risk engine
                                                            → PostgreSQL → Dashboard
```

## Tech Stack

- **Frontend:** Next.js + TypeScript + Tailwind CSS + shadcn/ui + TanStack Query
- **Backend:** FastAPI (Python)
- **Worker:** Python (separate process, RQ + Redis)
- **Database:** PostgreSQL
- **Queue:** Redis (RQ)

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

### 2. Set up the API
```bash
cd apps/api
cp .env.example .env
# Edit .env with your GitHub App credentials and OpenAI key
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### 3. Start the worker
```bash
cd services/worker
cp .env.example .env
# Edit .env with matching credentials
pip install -r requirements.txt
python main.py
```

### 4. Start the frontend
```bash
cd apps/web
npm install
npm run dev
```

### 5. Run tests
```bash
cd tests
pip install -r requirements.txt
pytest -v
```

## V1 Features

1. **GitHub App Integration** — Connect GitHub, read repositories
2. **Dependency Vulnerability Scanner** — npm + PyPI via OSV.dev
3. **AI Investigation Agent** — Evidence-based, schema-validated LLM analysis
4. **Deterministic Risk Scoring** — Pure function, zero LLM calls, versioned
5. **Security Dashboard** — Real-time scan status, findings, and risk scores

## Project Structure

```
cyvrix/
  apps/
    web/          # Next.js frontend
    api/          # FastAPI backend
  services/
    worker/       # Scan + investigation pipeline
  tests/
    fixtures/     # Sample repos for testing
  infra/          # Docker infrastructure
```

## Development Rules

- LLM output is untrusted input — validate everything
- Risk scoring is deterministic — zero LLM calls
- Every external API call has timeout + retry + failure handling
- Every scan job is idempotent
- Repository content is untrusted data
- Never expose secrets in logs

## License

MIT
