"""
Database Models Module for YemenScan.

Defines normalized SQLAlchemy ORM models according to academic and industry
standards: Targets, ScanSessions, Assets, VulnerabilityCatalog,
VulnerabilityFindings, and AIReports.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database import Base

# Dialect-adaptive JSONB type (defaults to JSONB on PostgreSQL, falls back to JSON elsewhere)
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


def utc_now() -> datetime:
    """Helper to return current UTC timestamp."""
    return datetime.now(timezone.utc)


class Targets(Base):
    """
    Targets Table.
    Stores domains and targets tracked by YemenScan.
    """
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    domain_name = Column(String(255), unique=True, index=True, nullable=False)
    organization = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    # Relationships
    scan_sessions = relationship(
        "ScanSessions",
        back_populates="target",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    def __repr__(self) -> str:
        return f"<Target(id={self.id}, domain='{self.domain_name}')>"


class ScanSessions(Base):
    """
    ScanSessions Table.
    Tracks individual scan lifecycle executions, associating them with a target.
    """
    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(String(100), unique=True, index=True, nullable=False)
    target_id = Column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    status = Column(String(50), nullable=False, default="pending")  # pending, running, completed, failed, stopped
    current_stage = Column(String(50), nullable=True)
    progress = Column(Integer, default=0, nullable=False)
    stats_summary = Column(JSON_TYPE, nullable=True)
    execution_logs = Column(JSON_TYPE, nullable=True)
    started_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    target = relationship("Targets", back_populates="scan_sessions")
    assets = relationship(
        "Assets",
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    findings = relationship(
        "VulnerabilityFindings",
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    ai_reports = relationship(
        "AIReports",
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    def __repr__(self) -> str:
        return f"<ScanSession(scan_id='{self.scan_id}', status='{self.status}')>"


class Assets(Base):
    """
    Assets Table.
    Stores discovered subdomains, endpoints, open ports, and tech stacks for a scan session.
    """
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(
        String(100),
        ForeignKey("scan_sessions.scan_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    url = Column(String(2048), nullable=False)
    open_ports = Column(Text, nullable=True)
    tech_stack = Column(JSON_TYPE, nullable=True)
    is_api = Column(Boolean, default=False, nullable=False)
    asset_type = Column(String(50), default="web_service", nullable=True)
    status_code = Column(Integer, nullable=True)

    # Relationships
    session = relationship("ScanSessions", back_populates="assets")

    def __repr__(self) -> str:
        return f"<Asset(id={self.id}, url='{self.url}', is_api={self.is_api})>"


class VulnerabilityCatalog(Base):
    """
    VulnerabilityCatalog Table.
    Master encyclopedia of vulnerability definitions, CVE/CWE classifications,
    CVSS metrics, OWASP categories, and standard remediations.
    """
    __tablename__ = "vulnerability_catalog"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = Column(String(50), unique=True, index=True, nullable=True)
    cwe_id = Column(String(50), index=True, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    owasp_category = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    standard_remediation = Column(Text, nullable=True)
    reference_links = Column(JSON_TYPE, nullable=True)

    # Relationships
    findings = relationship("VulnerabilityFindings", back_populates="catalog_entry")

    def __repr__(self) -> str:
        return f"<VulnerabilityCatalog(id={self.id}, cve='{self.cve_id}', title='{self.title}')>"


class VulnerabilityFindings(Base):
    """
    VulnerabilityFindings Table.
    Stores concrete vulnerability instances discovered during a scan session,
    optionally linked to a master definition in VulnerabilityCatalog.
    """
    __tablename__ = "vulnerability_findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(
        String(100),
        ForeignKey("scan_sessions.scan_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    catalog_id = Column(
        Integer,
        ForeignKey("vulnerability_catalog.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    affected_url = Column(String(2048), nullable=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    source = Column(String(100), default="Vulnerability Engine", nullable=True, index=True)
    status = Column(String(50), default="open", nullable=False)  # open, confirmed, false_positive, resolved
    evidence = Column(Text, nullable=True)
    raw_output = Column(JSON_TYPE, nullable=True)
    discovered_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    # Relationships
    session = relationship("ScanSessions", back_populates="findings")
    catalog_entry = relationship("VulnerabilityCatalog", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, severity='{self.severity}', url='{self.affected_url}')>"


class AIReports(Base):
    """
    AIReports Table.
    Stores generated executive and technical reports produced by Gemini AI.
    """
    __tablename__ = "ai_reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(
        String(100),
        ForeignKey("scan_sessions.scan_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    executive_report = Column(Text, nullable=True)
    technical_report = Column(Text, nullable=True)
    model_used = Column(String(100), nullable=True)
    report_metadata = Column(JSON_TYPE, nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    # Relationships
    session = relationship("ScanSessions", back_populates="ai_reports")

    def __repr__(self) -> str:
        return f"<AIReport(id={self.id}, scan_id='{self.scan_id}')>"


class SystemSettings(Base):
    """
    SystemSettings Table.
    Stores platform configuration settings, API parameters, and environment parameters.
    """
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=True)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self) -> str:
        return f"<SystemSetting(key='{self.key}')>"
