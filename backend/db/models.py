"""
SQLAlchemy async models + Alembic-compatible schema.
Uses asyncpg driver for non-blocking Postgres I/O.
"""

import uuid
from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    Column, Text, Numeric, Integer, Boolean,
    TIMESTAMP, ForeignKey, Index, CheckConstraint, text
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(AsyncAttrs, DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    # ── Identity ────────────────────────────────────────────────
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain       = Column(Text, nullable=False, index=True)
    company_name = Column(Text)
    status       = Column(
        Text, nullable=False, default="queued",
        server_default="queued",
    )

    # ── ML Scores (typed — we GROUP BY / filter on these) ───────
    overall_score      = Column(Numeric(5, 2))
    risk_label         = Column(Text)
    breach_probability = Column(Numeric(4, 3))

    score_network   = Column(Numeric(5, 2))
    score_data_leak = Column(Numeric(5, 2))
    score_email     = Column(Numeric(5, 2))
    score_app_sec   = Column(Numeric(5, 2))
    score_human     = Column(Numeric(5, 2))

    # ── Issue counts (typed for dashboard aggregations) ─────────
    critical_count = Column(Integer, default=0, server_default="0")
    high_count     = Column(Integer, default=0, server_default="0")
    medium_count   = Column(Integer, default=0, server_default="0")
    low_count      = Column(Integer, default=0, server_default="0")

    # ── Raw OSINT payloads (JSONB — queried with @> / GIN index) ─
    raw_dns    = Column(JSONB)
    raw_shodan = Column(JSONB)
    raw_certs  = Column(JSONB)
    raw_github = Column(JSONB)
    raw_email  = Column(JSONB)
    raw_tech   = Column(JSONB)

    # ── ML feature vector (stored for model retraining replay) ──
    ml_features = Column(JSONB)

    # ── Metadata ────────────────────────────────────────────────
    error_message = Column(Text)
    report_path   = Column(Text)
    created_at    = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    completed_at  = Column(TIMESTAMP(timezone=True))

    # ── Relationships ───────────────────────────────────────────
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','completed','failed')",
            name="ck_scans_status",
        ),
        Index("idx_scans_domain",    "domain"),
        Index("idx_scans_status",    "status"),
        Index("idx_scans_score",     "overall_score"),
        Index("idx_scans_critical",  "critical_count"),
        Index("idx_scans_created",   "created_at"),
        # GIN indexes for JSONB payload queries — created in migration SQL below
    )


class Finding(Base):
    __tablename__ = "findings"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id     = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)

    severity    = Column(Text, nullable=False)
    category    = Column(Text, nullable=False)
    title       = Column(Text, nullable=False)
    description = Column(Text)
    recommendation = Column(Text)

    # Optional structured fields (NULL when not applicable)
    affected_host = Column(Text)
    affected_port = Column(Integer)
    cve_id        = Column(Text)
    cvss_score    = Column(Numeric(4, 2))

    # Catch-all for category-specific metadata
    extra_data  = Column(JSONB)
    created_at  = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        CheckConstraint(
            "severity IN ('CRITICAL','HIGH','MEDIUM','LOW')",
            name="ck_findings_severity",
        ),
        Index("idx_findings_scan",     "scan_id"),
        Index("idx_findings_severity", "severity", "scan_id"),
        Index("idx_findings_cve",      "cve_id",
              postgresql_where=text("cve_id IS NOT NULL")),
    )


class DomainCache(Base):
    """
    Warm cache — persists last scan result per domain across Redis restarts.
    Checked before hitting any API.
    """
    __tablename__ = "domain_cache"

    domain       = Column(Text, primary_key=True)
    last_scanned = Column(TIMESTAMP(timezone=True), nullable=False)
    last_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    scan_count   = Column(Integer, default=1)

    # Denormalized for O(1) dashboard lookups — no JOIN needed
    latest_score = Column(Numeric(5, 2))
    latest_label = Column(Text)