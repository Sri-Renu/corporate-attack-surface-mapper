"""
Corporate Attack Surface Mapper — FastAPI Application v2
──────────────────────────────────────────────────────────
Architecture decisions implemented here:
  1. RateLimiter uses next-slot design (no token debt)
  2. Redis cache sits in front of ALL API calls
  3. ML prediction runs in run_in_threadpool (never blocks event loop)
  4. Async DB writes at every scan stage
  5. Streamlit connects via HTTP — never imports engine directly

Run:
    uvicorn main:app --reload --port 8000
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from config import get_settings
from cache import build_cache, CacheLayer
from db import (
    build_engine, create_tables,
    ScanRepository, FindingRepository, DomainCacheRepository,
)
from osint_engine import OSINTEngine
from ml_scorer import RiskScorer
from report_generator import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ── Disclaimer text (injected into all scan responses) ───────────────────────
DISCLAIMER = (
    "FOR RESEARCH AND EDUCATIONAL USE ONLY. "
    "This tool aggregates publicly available OSINT signals. "
    "Risk scores are heuristic estimates based on synthetic training data — "
    "they are NOT certified security assessments and carry no guarantee of accuracy. "
    "Do not make security, legal, or financial decisions based solely on this output. "
    "Always verify findings with a qualified security professional. "
    "Only scan domains you own or have explicit written permission to assess."
)



# ── Application state ─────────────────────────────────────────────────────────

class AppState:
    cache: CacheLayer
    scan_repo: ScanRepository
    finding_repo: FindingRepository
    domain_cache_repo: DomainCacheRepository
    semaphore: asyncio.Semaphore


state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger.info("Starting — connecting to Postgres + Redis")

    engine = build_engine(settings.database_url)
    await create_tables(engine)

    from sqlalchemy.ext.asyncio import async_sessionmaker
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    state.scan_repo         = ScanRepository(session_factory)
    state.finding_repo      = FindingRepository(session_factory)
    state.domain_cache_repo = DomainCacheRepository(session_factory)
    state.cache             = await build_cache(settings.redis_url)
    state.semaphore         = asyncio.Semaphore(settings.max_concurrent_scans)

    os.makedirs(settings.report_dir, exist_ok=True)
    logger.info("Startup complete")
    yield
    logger.info("Shutting down")
    await engine.dispose()


app = FastAPI(title="Attack Surface Mapper", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Schemas ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain: str
    company_name: Optional[str] = None
    shodan_api_key: Optional[str] = None
    force_rescan: bool = False


# ── Pipeline ──────────────────────────────────────────────────────────────────

async def _run_pipeline(scan_id: UUID, request: ScanRequest) -> None:
    settings  = get_settings()
    scan_repo = state.scan_repo

    async with state.semaphore:
        try:
            await scan_repo.update_status(scan_id, "running")

            engine = OSINTEngine(
                domain       = request.domain,
                company_name = request.company_name or request.domain,
                shodan_key   = request.shodan_api_key or settings.shodan_api_key or None,
                cache        = state.cache,
            )

            # ── OSINT phases (all async, rate-limited, cached) ────────
            dns_data    = await engine.enumerate_dns()
            shodan_data = await engine.shodan_scan()
            cert_data   = await engine.cert_transparency()
            github_data = await engine.github_scan()
            email_data  = await engine.email_security_check()
            tech_data   = await engine.tech_fingerprint()

            raw = {
                "dns": dns_data, "shodan": shodan_data,
                "certificates": cert_data, "github": github_data,
                "email_security": email_data, "technology": tech_data,
            }
            await scan_repo.update_raw_findings(scan_id, raw)

            # ── ML scoring — CPU-bound, must NOT block event loop ─────
            scorer      = RiskScorer()
            risk_scores = await run_in_threadpool(scorer.score, raw)
            await scan_repo.update_scores(scan_id, risk_scores)

            # ── Persist individual findings ───────────────────────────
            all_issues = []
            for cat, payload in raw.items():
                if isinstance(payload, dict):
                    for issue in payload.get("issues", []):
                        issue["category"] = cat
                        all_issues.append(issue)
            await state.finding_repo.bulk_insert(scan_id, all_issues)

            # ── PDF report — CPU-bound, threadpool ───────────────────
            report_gen  = ReportGenerator(
                domain=request.domain,
                company=request.company_name or request.domain,
                findings=raw, scores=risk_scores,
            )
            report_path = await run_in_threadpool(report_gen.generate, str(scan_id))
            await scan_repo.set_report_path(scan_id, report_path)

            await scan_repo.update_status(scan_id, "completed")
            await state.domain_cache_repo.upsert(
                domain=request.domain, scan_id=scan_id,
                score=float(risk_scores.get("overall", 0)),
                label=risk_scores.get("risk_label", "UNKNOWN"),
            )
            logger.info("[%s] Done — score %.1f %s",
                        scan_id, risk_scores.get("overall", 0), risk_scores.get("risk_label"))

        except Exception as exc:
            logger.exception("[%s] Failed: %s", scan_id, exc)
            await scan_repo.update_status(scan_id, "failed", error=str(exc))


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not request.force_rescan:
        cached = await state.domain_cache_repo.is_fresh(request.domain)
        if cached:
            return {"job_id": cached["scan_id"], "cached": True,
                    "message": f"Cached result from {cached['last_scanned']}",
                    "disclaimer": DISCLAIMER}

    scan = await state.scan_repo.create(request.domain, request.company_name)
    background_tasks.add_task(_run_pipeline, scan.id, request)
    return {"job_id": str(scan.id), "cached": False, "message": "Scan started", "disclaimer": DISCLAIMER}


@app.get("/api/scan/{job_id}")
async def get_scan(job_id: str):
    try:
        uid = UUID(job_id)
    except ValueError:
        raise HTTPException(400, "Invalid job_id")

    scan = await state.scan_repo.get(uid)
    if not scan:
        raise HTTPException(404, "Scan not found")

    out = {
        "job_id": str(scan.id), "domain": scan.domain,
        "status": scan.status, "error": scan.error_message,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "disclaimer": DISCLAIMER,
    }
    if scan.status == "completed":
        out["risk_scores"] = {
            "overall": float(scan.overall_score or 0),
            "risk_label": scan.risk_label,
            "breach_probability": float(scan.breach_probability or 0),
            "critical_issues": scan.critical_count,
            "high_issues": scan.high_count,
            "medium_issues": scan.medium_count,
            "low_issues": scan.low_count,
            # Dimension scores for frontend radar/bars
            "network_exposure":      float(scan.score_network or 0),
            "data_leak":             float(scan.score_data_leak or 0),
            "email_security":        float(scan.score_email or 0),
            "application_security":  float(scan.score_app_sec or 0),
            "human_factor":          float(scan.score_human or 0),
        }
        out["raw_findings"] = {
            "dns": scan.raw_dns, "shodan": scan.raw_shodan,
            "certificates": scan.raw_certs, "github": scan.raw_github,
            "email_security": scan.raw_email, "technology": scan.raw_tech,
        }
    return out


@app.get("/api/scan/{job_id}/findings")
async def get_findings(job_id: str):
    try:
        uid = UUID(job_id)
    except ValueError:
        raise HTTPException(400, "Invalid job_id")
    findings = await state.finding_repo.for_scan(uid)
    return [
        {"id": str(f.id), "severity": f.severity, "category": f.category,
         "title": f.title, "description": f.description,
         "recommendation": f.recommendation, "cve_id": f.cve_id,
         "cvss_score": float(f.cvss_score) if f.cvss_score else None}
        for f in findings
    ]


@app.get("/api/report/{job_id}")
async def download_report(job_id: str):
    try:
        uid = UUID(job_id)
    except ValueError:
        raise HTTPException(400, "Invalid job_id")
    scan = await state.scan_repo.get(uid)
    if not scan or scan.status != "completed":
        raise HTTPException(404, "Report not ready")
    if not scan.report_path or not os.path.exists(scan.report_path):
        raise HTTPException(404, "Report file missing")
    return FileResponse(
        scan.report_path, media_type="application/pdf",
        filename=f"asm_{scan.domain}_{str(scan.id)[:8]}.pdf",
    )


@app.get("/api/scans/recent")
async def recent_scans(limit: int = 20):
    scans = await state.scan_repo.list_recent(limit)
    return [
        {"id": str(s.id), "domain": s.domain, "status": s.status,
         "risk_label": s.risk_label, "overall_score": float(s.overall_score or 0),
         "critical_count": s.critical_count,
         "created_at": s.created_at.isoformat() if s.created_at else None}
        for s in scans
    ]


@app.get("/api/stats")
async def stats():
    return await state.scan_repo.stats()


@app.get("/api/health")
async def health():
    cache_ok = await state.cache.ping()
    return {"status": "ok", "version": "2.0.0",
            "cache": "connected" if cache_ok else "unavailable"}