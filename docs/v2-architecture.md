# CYVRIX V2 — Architecture Document

## Overview

V2 extends CYVRIX from dependency vulnerability intelligence into broader security intelligence with container scanning, log analysis, actionable recommendations, and report generation.

## Architecture

```
Security Sources
├── Dependency Scanner (V1)    → Normalized Finding
├── Container Scanner (V2.1)   → Normalized Finding
└── Log Analyzer (V2.2)        → Normalized Finding
         ↓
Unified Finding Model (source_type: DEPENDENCY|CONTAINER|LOG)
         ↓
AI Investigation (bounded) — HIGH/CRITICAL only
         ↓
Evidence Cross-Validation
         ↓
Deterministic Risk Engine (pure function, 0-100)
         ↓
Recommendation Engine (V2.5) — deterministic + AI fallback
         ↓
Re-validation (V2.6) — VALIDATED|PARTIALLY_VALIDATED|UNVERIFIED|UNSAFE
         ↓
Report Engine — Markdown + JSON on-demand
         ↓
Dashboard (Next.js) — source-type badges, trust levels, validation states
```

## V2 Components

### Container Scanner (V2.1)
- Detects Dockerfiles (Dockerfile, *.Dockerfile, etc.)
- Parses instructions, base images, ENV, RUN, EXPOSE, USER, HEALTHCHECK
- Security rules: root user, latest/unpinned image, curl-pipe-shell, secret in ENV, sensitive ports, no HEALTHCHECK, ADD vs COPY
- Path traversal defense, symlink protection, resource limits
- Known vulnerable image database (python:2.7, node:12, etc.)

### Log Analyzer (V2.2)
- Detects log files (*.log, access.log, security.log, etc.)
- Parses text and JSON log formats
- Pattern detection: brute-force, admin access, path probing
- Event correlation within configurable time windows
- Path traversal defense, resource limits, regex safety

### Recommendation Engine (V2.5)
- Deterministic rules first (dependency upgrade, container root, etc.)
- AI fallback for complex findings
- Trust levels: SUPPORTED, LIKELY, UNCERTAIN
- Advisory only — never modifies files, git, or external systems

### Re-validation (V2.6)
- Deterministic validation of recommendations
- Checks: completeness, evidence, trust level consistency, scanner-specific logic, dangerous content
- Pure function: no file system, network, or database access
- States: VALIDATED, PARTIALLY_VALIDATED, UNVERIFIED, UNSAFE

### Report Engine
- On-demand generation from scan/findings data
- Markdown and JSON output formats
- Ownership-restricted (user can only see own reports)
- Source-type breakdown, severity distribution, risk summary

## Database Schema (V2)

### New/Modified Tables
- `findings`: Added `source_type`, `evidence` columns
- `recommendations`: New table (finding_id, trust_level, what/why/change/uncertainty/risk/validation, validation_state)
- `reports`: New table (scan_id, repository_id, report_type, format, content)

### Migration Strategy
- V1 → V2: Additive only, no destructive changes
- `source_type` defaults to `DEPENDENCY` for existing findings
- All V1 data preserved

## Key Design Decisions

### 1. Finding Model Extension
- `source_type` field: DEPENDENCY, CONTAINER, LOG
- Backward compatible with V1 fields
- Risk engine remains source-agnostic

### 2. Advisory-Only Recommendations
- CYVRIX never modifies files, pushes code, creates PRs, or deploys
- All recommendations are evidence-backed and policy-validated
- Re-validation provides deterministic quality checks

### 3. Deterministic-First Approach
- Container scanner: static analysis only, no Docker execution
- Log analyzer: pattern matching only, no AI anomaly detection
- Recommendation engine: deterministic rules first, AI fallback
- Re-validation: pure function, no external dependencies
