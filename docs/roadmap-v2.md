# CYVRIX V2 — Roadmap

**Status:** Planning only. Do not implement until V1.0.0 is released and stable.

## V2 Vision

V2 = Broader Security Visibility + Actionable Recommendations

V1 proves the core "detect → investigate → prioritize" loop. V2 extends this with additional scanning capabilities and actionable remediation guidance.

## Candidate V2 Features

### 1. Container / Docker Scanning

**Problem:** Teams using Docker have vulnerabilities in base images and Dockerfile configurations that V1 doesn't detect.

**User Value:** Complete dependency visibility across application code and container infrastructure.

**Architecture Impact:**
- New scanner adapter: Dockerfile parser + container image analyzer
- Extended manifest detection: `Dockerfile`, `docker-compose.yml`, `*.dockerfile`
- New ecosystem type: `docker`

**Security Implications:**
- Docker socket access needed (if scanning running containers)
- Increased attack surface from image pulling
- Need to sandbox image analysis

**Data Model Impact:**
- `dependencies.ecosystem` extended with `docker`
- New `container_layers` or similar table (optional)

**Worker Impact:**
- New scanner module for Docker analysis
- Increased scan time budget

**Frontend Impact:**
- Docker-specific finding display
- Container vulnerability severity mapping

**Testing Requirements:**
- Docker fixture files
- Dockerfile parsing tests
- Container image analysis tests

**Major Risks:**
- Docker socket access is a significant security surface
- Image pulling requires network access and storage

---

### 2. Security Log Analysis

**Problem:** Runtime logs contain security signals (failed auth, injection attempts, error patterns) that aren't captured by dependency scanning.

**User Value:** Correlate runtime security signals with dependency vulnerabilities for higher-confidence risk assessments.

**Architecture Impact:**
- New log ingestion pipeline
- Pattern matching engine for security-relevant events
- Correlation with existing findings

**Security Implications:**
- Log data may contain sensitive information
- Need to sanitize/structure logs before storage
- Access control on log data

**Data Model Impact:**
- New `log_events` table
- Relationship between log events and findings

**Worker Impact:**
- Log analysis worker (separate from scan worker)
- Streaming/batch processing modes

**Frontend Impact:**
- Log event timeline on finding detail
- Correlation visualization

**Testing Requirements:**
- Log fixture files with security events
- Pattern matching accuracy tests
- False positive rate measurement

**Major Risks:**
- High volume of log data
- Pattern maintenance burden
- False positive management

---

### 3. Automated Security Reports

**Problem:** Security teams need periodic reports summarizing vulnerability posture, trends, and risk levels.

**User Value:** Automated reporting saves manual effort and provides consistent security metrics.

**Architecture Impact:**
- Report generation engine (PDF/HTML)
- Scheduled report generation
- Historical data aggregation

**Security Implications:**
- Reports may contain sensitive vulnerability data
- Access control on report generation and viewing
- Secure report storage and delivery

**Data Model Impact:**
- New `reports` table
- Report template configuration

**Worker Impact:**
- Report generation as background job
- Template rendering engine

**Frontend Impact:**
- Report generation UI
- Report history and download

**Testing Requirements:**
- Report template rendering tests
- Data aggregation accuracy tests
- Historical trend calculation tests

**Major Risks:**
- PDF generation dependency
- Template maintenance
- Report accuracy over time

---

### 4. Remediation Recommendations

**Problem:** Findings show what's vulnerable but not how to fix it.

**User Value:** Actionable guidance reduces time-to-remediation.

**Architecture Impact:**
- Remediation rule engine
- Version upgrade path analysis
- Compatibility checking

**Security Implications:**
- Remediation suggestions must be verified (not blindly trusted)
- Upgrade paths may introduce new vulnerabilities
- Need to validate suggested versions exist and are safe

**Data Model Impact:**
- `recommendations` field on findings/investigations
- `remediation_status` tracking

**Worker Impact:**
- Remediation analysis as post-investigation step
- Version compatibility checking

**Frontend Impact:**
- Remediation guidance on finding detail
- One-click "create issue" integration (future)

**Testing Requirements:**
- Remediation rule accuracy tests
- Version upgrade path tests
- Compatibility verification tests

**Major Risks:**
- Incorrect remediation advice could cause harm
- Version compatibility is complex
- Rule maintenance burden

---

### 5. Re-Validation After Remediation

**Problem:** After a team applies a fix, there's no automated verification that the vulnerability is actually resolved.

**User Value:** Closed-loop verification ensures fixes work before they're deployed.

**Architecture Impact:**
- Re-scan triggered by fix PR or merge
- Before/after comparison
- Status transition automation

**Security Implications:**
- Re-scan must use the same controls as initial scan
- Need to handle partial fixes
- Race conditions with concurrent scans

**Data Model Impact:**
- `remediation_verified` status on findings
- Scan comparison metadata

**Worker Impact:**
- Scan comparison logic
- Incremental scanning optimization

**Frontend Impact:**
- Fix verification status display
- Before/after comparison view

**Testing Requirements:**
- Fix detection accuracy tests
- Before/after comparison tests
- Race condition tests

**Major Risks:**
- False confidence from incorrect verification
- Complexity of partial fix detection

---

## V2 Architecture Direction

```
Dependency Scanner    +    Container Scanner    +    Log Analyzer
         ↓                        ↓                        ↓
              Unified Finding Model + Correlation
                           ↓
                   AI Investigation
                           ↓
                  Evidence Validation
                           ↓
                Deterministic Risk Engine
                           ↓
                   Remediation Engine
                           ↓
                      Recommendations
                           ↓
                     Security Dashboard
```

## V2 Design Principles

1. **Extend, don't replace** — The V1 risk engine, evidence validation, and ownership model remain foundational
2. **New scanners are adapters** — Pluggable scanner interface; each new ecosystem is a new adapter
3. **Remediation is advisory** — Never auto-apply fixes without explicit user approval
4. **Correlation adds confidence** — Multiple signal sources improve risk accuracy
5. **Backward compatible** — V2 must handle V1 data without migration

## Do Not Implement Yet

This document is a planning artifact only. No code should be written for V2 features until:
- V1.0.0 is released
- V1 has been running in production for at least 2 weeks
- V2 priorities are validated against actual user needs
