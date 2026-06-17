"""
Async database layer.
  - session_factory : async SQLAlchemy sessions via asyncpg
  - ScanRepository  : all DB operations for scans + findings
  - DomainCacheRepo : warm cache lookups
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional, List
from uuid import UUID

from sqlalchemy.ext.asyncio import (
    AsyncSession, AsyncEngine,
    async_sessionmaker, create_async_engine,
)
from sqlalchemy import select, update, func, insert, case, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .models import Base, Scan, Finding, DomainCache

logger = logging.getLogger(__name__)


# ── Engine factory ────────────────────────────────────────────────────────────

def build_engine(database_url: str) -> AsyncEngine:
    """
    Create async engine.  database_url must use asyncpg driver:
        postgresql+asyncpg://user:pass@host:5432/dbname
    """
    return create_async_engine(
        database_url,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,       # detect stale connections
        echo=False,               # set True to log all SQL in dev
    )


async def create_tables(engine: AsyncEngine) -> None:
    """Run CREATE TABLE IF NOT EXISTS + GIN indexes + schema migrations."""
    async with engine.begin() as conn:
        # Step 1: create all tables
        await conn.run_sync(Base.metadata.create_all)

        # Step 2: schema migration — rename old 'metadata' column to 'extra_data'
        # This handles databases created before the rename fix
        migration = """
            ALTER TABLE findings
            RENAME COLUMN metadata TO extra_data
        """
        try:
            await conn.execute(text(migration))
            logger.info("Migration: renamed findings.metadata to extra_data")
        except Exception:
            pass  # column already renamed or doesn't exist — safe to ignore

        # Step 3: GIN indexes for JSONB payload queries
        gin_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_gin_shodan ON scans USING GIN (raw_shodan);",
            "CREATE INDEX IF NOT EXISTS idx_gin_github  ON scans USING GIN (raw_github);",
            "CREATE INDEX IF NOT EXISTS idx_gin_dns     ON scans USING GIN (raw_dns);",
            "CREATE EXTENSION IF NOT EXISTS pg_trgm;",
            "CREATE INDEX IF NOT EXISTS idx_domain_trgm ON scans USING GIN (domain gin_trgm_ops);",
        ]
        for sql in gin_indexes:
            try:
                await conn.execute(text(sql))
            except Exception as e:
                logger.warning("Index creation warning (may already exist): %s", e)
    logger.info("Database tables and indexes ready")


@asynccontextmanager
async def get_session(session_factory: async_sessionmaker):
    """Context manager yielding an AsyncSession with auto-commit/rollback."""
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Scan Repository ───────────────────────────────────────────────────────────

class ScanRepository:
    def __init__(self, session_factory: async_sessionmaker):
        self._sf = session_factory

    async def create(self, domain: str, company_name: Optional[str] = None) -> Scan:
        async with get_session(self._sf) as session:
            scan = Scan(
                domain=domain,
                company_name=company_name or domain,
                status="queued",
                created_at=datetime.utcnow(),
            )
            session.add(scan)
            await session.flush()
            await session.refresh(scan)
            return scan

    async def get(self, scan_id: UUID) -> Optional[Scan]:
        async with get_session(self._sf) as session:
            result = await session.execute(
                select(Scan).where(Scan.id == scan_id)
            )
            return result.scalar_one_or_none()

    async def update_status(self, scan_id: UUID, status: str,
                             error: Optional[str] = None) -> None:
        updates = {"status": status}
        if error:
            updates["error_message"] = error
        if status == "completed":
            updates["completed_at"] = datetime.utcnow()
        async with get_session(self._sf) as session:
            await session.execute(
                update(Scan).where(Scan.id == scan_id).values(**updates)
            )

    async def update_scores(self, scan_id: UUID, scores: dict) -> None:
        dims = scores.get("dimensions", {})
        async with get_session(self._sf) as session:
            await session.execute(
                update(Scan).where(Scan.id == scan_id).values(
                    overall_score      = scores.get("overall"),
                    risk_label         = scores.get("risk_label"),
                    breach_probability = scores.get("breach_probability"),
                    score_network   = dims.get("network_exposure",  {}).get("score"),
                    score_data_leak = dims.get("data_leak",         {}).get("score"),
                    score_email     = dims.get("email_security",    {}).get("score"),
                    score_app_sec   = dims.get("application_security", {}).get("score"),
                    score_human     = dims.get("human_factor",      {}).get("score"),
                    critical_count  = scores.get("critical_issues", 0),
                    high_count      = scores.get("high_issues",     0),
                    medium_count    = scores.get("medium_issues",   0),
                    low_count       = scores.get("low_issues",      0),
                    ml_features     = scores.get("ml_features"),
                )
            )

    async def update_raw_findings(self, scan_id: UUID, findings: dict) -> None:
        async with get_session(self._sf) as session:
            await session.execute(
                update(Scan).where(Scan.id == scan_id).values(
                    raw_dns    = findings.get("dns"),
                    raw_shodan = findings.get("shodan"),
                    raw_certs  = findings.get("certificates"),
                    raw_github = findings.get("github"),
                    raw_email  = findings.get("email_security"),
                    raw_tech   = findings.get("technology"),
                )
            )

    async def set_report_path(self, scan_id: UUID, path: str) -> None:
        async with get_session(self._sf) as session:
            await session.execute(
                update(Scan).where(Scan.id == scan_id).values(report_path=path)
            )

    async def list_recent(self, limit: int = 20) -> List[Scan]:
        async with get_session(self._sf) as session:
            result = await session.execute(
                select(Scan)
                .order_by(Scan.created_at.desc())
                .limit(limit)
            )
            return list(result.scalars().all())

    async def stats(self) -> dict:
        """Dashboard aggregate stats."""
        async with get_session(self._sf) as session:
            total   = await session.scalar(select(func.count(Scan.id)))
            done    = await session.scalar(
                select(func.count(Scan.id)).where(Scan.status == "completed")
            )
            avg_score = await session.scalar(
                select(func.avg(Scan.overall_score)).where(Scan.status == "completed")
            )
            critical_total = await session.scalar(
                select(func.sum(Scan.critical_count)).where(Scan.status == "completed")
            )
        return {
            "total_scans":     total or 0,
            "completed_scans": done or 0,
            "avg_risk_score":  round(float(avg_score or 0), 1),
            "total_critical":  int(critical_total or 0),
        }


# ── Finding Repository ────────────────────────────────────────────────────────

class FindingRepository:
    def __init__(self, session_factory: async_sessionmaker):
        self._sf = session_factory

    async def bulk_insert(self, scan_id: UUID, issues: List[dict]) -> int:
        """Insert all findings for a scan in one round-trip."""
        if not issues:
            return 0
        rows = []
        for issue in issues:
            rows.append({
                "scan_id":        scan_id,
                "severity":       issue.get("severity", "LOW"),
                "category":       issue.get("category", "unknown"),
                "title":          issue.get("title", "Unknown"),
                "description":    issue.get("description"),
                "recommendation": issue.get("recommendation"),
                "affected_host":  issue.get("host"),
                "affected_port":  issue.get("port"),
                "cve_id":         issue.get("cve_id"),
                "cvss_score":     issue.get("cvss"),
                "extra_data":      {k: v for k, v in issue.items()
                                   if k not in ("severity","category","title",
                                                "description","recommendation",
                                                "host","port","cve_id","cvss")},
                "created_at": datetime.utcnow(),
            })
        async with get_session(self._sf) as session:
            await session.execute(
                insert(Finding), rows
            )
        return len(rows)

    async def for_scan(self, scan_id: UUID) -> List[Finding]:
        async with get_session(self._sf) as session:
            result = await session.execute(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .order_by(
                    case(
                        (Finding.severity == "CRITICAL", 0),
                        (Finding.severity == "HIGH",     1),
                        (Finding.severity == "MEDIUM",   2),
                        (Finding.severity == "LOW",      3),
                        else_=4,
                    )
                )
            )
            return list(result.scalars().all())


# ── Domain Cache Repository ───────────────────────────────────────────────────

class DomainCacheRepository:
    STALE_AFTER_HOURS = 24  # re-scan if older than this

    def __init__(self, session_factory: async_sessionmaker):
        self._sf = session_factory

    async def is_fresh(self, domain: str) -> Optional[dict]:
        """Return the last scan summary if scanned recently, else None."""
        cutoff = datetime.utcnow() - timedelta(hours=self.STALE_AFTER_HOURS)
        async with get_session(self._sf) as session:
            result = await session.execute(
                select(DomainCache).where(
                    DomainCache.domain == domain.lower(),
                    DomainCache.last_scanned >= cutoff,
                )
            )
            row = result.scalar_one_or_none()
            if row:
                return {
                    "scan_id":      str(row.last_scan_id),
                    "last_scanned": row.last_scanned.isoformat(),
                    "score":        float(row.latest_score or 0),
                    "label":        row.latest_label,
                    "scan_count":   row.scan_count,
                }
        return None

    async def upsert(self, domain: str, scan_id: UUID,
                     score: float, label: str) -> None:
        async with get_session(self._sf) as session:
            stmt = pg_insert(DomainCache).values(
                domain=domain.lower(),
                last_scanned=datetime.utcnow(),
                last_scan_id=scan_id,
                latest_score=score,
                latest_label=label,
                scan_count=1,
            ).on_conflict_do_update(
                index_elements=["domain"],
                set_={
                    "last_scanned": datetime.utcnow(),
                    "last_scan_id": scan_id,
                    "latest_score": score,
                    "latest_label": label,
                    "scan_count":   DomainCache.scan_count + 1,
                }
            )
            await session.execute(stmt)