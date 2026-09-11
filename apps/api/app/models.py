import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, Boolean, Integer, BigInteger, Numeric,
    ForeignKey, UniqueConstraint, Index, DateTime
)
from sqlalchemy.dialects.postgresql import UUID
from app.types import JSONBCompat as JSONB
from sqlalchemy.orm import relationship
from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


def gen_uuid():
    return uuid.uuid4()


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    email = Column(Text, unique=True, nullable=False)
    github_id = Column(Integer, unique=True, nullable=True)
    github_login = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    installations = relationship("GithubInstallation", back_populates="user")


class GithubInstallation(Base):
    __tablename__ = "github_installations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    installation_id = Column(BigInteger, unique=True, nullable=False)
    account_login = Column(Text, nullable=False)
    account_type = Column(Text, nullable=False)  # 'User' | 'Organization'
    created_at = Column(DateTime(timezone=True), default=utcnow)

    user = relationship("User", back_populates="installations")
    repositories = relationship("Repository", back_populates="installation")


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    installation_id = Column(UUID(as_uuid=True), ForeignKey("github_installations.id"), nullable=False)
    github_repo_id = Column(BigInteger, unique=True, nullable=False)
    owner = Column(Text, nullable=False)
    name = Column(Text, nullable=False)
    default_branch = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("owner", "name", name="uq_owner_name"),
    )

    installation = relationship("GithubInstallation", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository")
    findings = relationship("Finding", back_populates="repository")
    reports = relationship("Report", back_populates="repository")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    status = Column(Text, nullable=False, default="QUEUED")  # QUEUED|CLONING|SCANNING|ANALYZING|COMPLETED|FAILED
    trigger = Column(Text, nullable=False, default="manual")
    error_reason = Column(Text)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    commit_sha = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    repository = relationship("Repository", back_populates="scans")
    dependencies = relationship("Dependency", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")
    reports = relationship("Report", back_populates="scan")


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    name = Column(Text, nullable=False)
    version = Column(Text, nullable=False)
    ecosystem = Column(Text, nullable=False)  # npm | PyPI
    manifest_path = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="dependencies")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    fingerprint = Column(Text, nullable=False)
    scanner = Column(Text, nullable=False, default="dependency")
    source_type = Column(Text, nullable=False, default="DEPENDENCY")  # DEPENDENCY|CONTAINER|LOG
    vulnerability_id = Column(Text)
    package_name = Column(Text)
    package_version = Column(Text)
    title = Column(Text, nullable=False)
    description = Column(Text)
    severity = Column(Text, nullable=False)  # LOW|MEDIUM|HIGH|CRITICAL
    status = Column(Text, nullable=False, default="OPEN")  # OPEN|CONFIRMED|FALSE_POSITIVE|RESOLVED
    evidence = Column(JSONB)  # source-specific evidence metadata
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("repository_id", "fingerprint", name="uq_repo_fingerprint"),
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_source_type", "source_type"),
    )

    scan = relationship("Scan", back_populates="findings")
    repository = relationship("Repository", back_populates="findings")
    investigation = relationship("Investigation", back_populates="finding", uselist=False)
    risk_assessment = relationship("RiskAssessment", back_populates="finding", uselist=False)
    recommendation = relationship("Recommendation", back_populates="finding", uselist=False)


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False, unique=True)
    status = Column(Text, nullable=False, default="PENDING")  # PENDING|RUNNING|COMPLETED|FAILED
    verdict = Column(Text)  # CONFIRMED|LIKELY|UNLIKELY|FALSE_POSITIVE|UNKNOWN
    exploitability = Column(Text)  # LOW|MEDIUM|HIGH|UNKNOWN
    exposure = Column(Text)  # INTERNAL|EXTERNAL|UNKNOWN
    confidence = Column(Numeric(3, 2))
    summary = Column(Text)
    evidence = Column(JSONB)
    assumptions = Column(JSONB)
    uncertainties = Column(JSONB)
    recommendation = Column(Text)
    raw_model_response = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="investigation")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    risk_score = Column(Integer, nullable=False)  # 0-100
    risk_level = Column(Text, nullable=False)  # INFO|LOW|MEDIUM|HIGH|CRITICAL
    risk_version = Column(Integer, nullable=False)
    factors = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="risk_assessment")


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    status = Column(Text, nullable=False, default="PENDING")  # PENDING|COMPLETED|FAILED
    trust_level = Column(Text)  # SUPPORTED|LIKELY|UNCERTAIN
    title = Column(Text, nullable=False)
    description = Column(Text)
    what = Column(Text)  # What is the problem
    why = Column(Text)   # Why does it matter
    change = Column(Text)  # What change is recommended
    uncertainty = Column(Text)  # What uncertainty exists
    risk = Column(Text)  # What could break
    validation = Column(Text)  # How should it be validated
    evidence = Column(JSONB)
    raw_model_response = Column(JSONB)
    validation_state = Column(Text)  # VALIDATED|PARTIALLY_VALIDATED|UNVERIFIED|UNSAFE
    validation_details = Column(JSONB)  # evidence checks, reasons
    validated_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="recommendation")


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    report_type = Column(Text, nullable=False)  # SCAN|REPOSITORY
    format = Column(Text, nullable=False, default="markdown")  # markdown|json
    content = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    scan = relationship("Scan")
    repository = relationship("Repository")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=gen_uuid)
    repository_id = Column(UUID(as_uuid=True))
    finding_id = Column(UUID(as_uuid=True))
    event_type = Column(Text, nullable=False)
    event_metadata = Column("metadata", JSONB)
    created_at = Column(DateTime(timezone=True), default=utcnow)
