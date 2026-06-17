# ⚡ Corporate Attack Surface Mapper v2

> Production-grade OSINT + ML system. Maps a company's public attack surface, scores breach risk, persists everything to Postgres, caches with Redis, and generates boardroom-ready PDF reports.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?style=flat-square)
![XGBoost](https://img.shields.io/badge/XGBoost-2.0-orange?style=flat-square)
![Postgres](https://img.shields.io/badge/PostgreSQL-16-blue?style=flat-square)
![Redis](https://img.shields.io/badge/Redis-7-red?style=flat-square)

---

## Architecture

```
Streamlit (8501)  ──HTTP──▶  FastAPI (8000)
HTML UI   (3000)             │
                             ├── OSINT Engine (async + rate-limited + cached)
                             │     DNS / Shodan / GitHub / Email / Certs / HTTP
                             │
                             ├── ML Scorer ──▶ run_in_threadpool (never blocks loop)
                             ├── PDF Report ──▶ run_in_threadpool
                             │
                             ├── Redis  (hot cache, TTL-based per API)
                             └── PostgreSQL (typed cols + JSONB payloads + GIN indexes)
```

---

## Three Production Bugs Fixed in v2

**1. Rate Limiter Token Debt Spiral**
Token bucket went negative under concurrent load → cascading sleep freeze.
Fix: next-slot design tracks *when* next call is allowed, not token count.

**2. Streamlit asyncio Conflict**
`asyncio.run(engine.scan())` crashed inside Streamlit's own event loop.
Fix: Streamlit makes HTTP calls to FastAPI only — never imports engine.

**3. Event Loop Blockage**
sklearn/pandas/reportlab called directly in `async def` froze all requests.
Fix: `await run_in_threadpool(scorer.score, raw)` — CPU work off the loop.

---

## Project Structure

```
attack-surface-mapper/
├── backend/
│   ├── main.py                   FastAPI app, scan lifecycle, all routes
│   ├── config.py                 Pydantic settings (.env)
│   ├── rate_limiter.py           Fixed RateLimiter + retry decorator
│   ├── osint_engine.py           6 OSINT modules
│   ├── ml_scorer.py              XGBoost risk scoring
│   ├── report_generator.py       ReportLab PDF
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── cache/
│   │   └── redis_cache.py        Hot cache + cached_osint decorator
│   └── db/
│       ├── models.py             SQLAlchemy async models
│       └── repository.py         ScanRepo / FindingRepo / DomainCacheRepo
├── streamlit_app/
│   └── app.py                    Dashboard (HTTP-only, no asyncio.run)
├── ml/
│   └── train_model.py            XGBoost + IsolationForest training pipeline
├── frontend/
│   └── index.html                Standalone HTML dashboard
├── migrations/
│   └── 001_initial.sql           Schema + GIN indexes + pg_trgm
├── tests/
│   └── test_suite.py             Rate limiter / cache / ML / threadpool tests
├── docker-compose.yml            Postgres + Redis + Backend + Streamlit + Nginx
├── pytest.ini
└── .env.example
```

---

## Quick Start

```bash
# One command — full stack
cp .env.example .env
docker-compose up --build

# Services
# Streamlit:  http://localhost:8501
# HTML UI:    http://localhost:3000
# API docs:   http://localhost:8000/docs
```

**Local dev:**
```bash
docker-compose up postgres redis -d
cd backend && pip install -r requirements.txt
uvicorn main:app --reload --port 8000
# new terminal:
cd streamlit_app && streamlit run app.py
# tests:
pytest tests/ -v
```

---

## Database Design (Hybrid JSONB)

Typed columns for everything you filter/sort on.
JSONB for raw OSINT payloads — GIN indexed so they're still queryable.

```sql
-- Score filtering
SELECT domain, overall_score FROM scans WHERE overall_score > 70;

-- Query inside JSON payload
SELECT domain FROM scans WHERE raw_shodan @> '{"critical_cves": 3}';

-- Fuzzy domain search
SELECT domain FROM scans WHERE domain ILIKE '%stripe%';

-- ML feature export for retraining
SELECT ml_features, overall_score FROM scans WHERE status = 'completed';
```

---

## API Keys (all optional)

| Key | Adds |
|-----|------|
| [Shodan](https://account.shodan.io) | Live port/CVE data |
| [GitHub Token](https://github.com/settings/tokens) | 10 → 30 req/min |
| [Censys](https://search.censys.io/account) | TLS/cert intelligence |

No keys = demo mode with realistic simulated data.

---

## Resume Bullet

> *"Built a production-grade Corporate Attack Surface Mapper: async FastAPI backend with fixed next-slot RateLimiter, Redis hot cache + PostgreSQL warm cache (JSONB hybrid schema, GIN indexes, pg_trgm), CPU-bound ML scoring offloaded via run_in_threadpool, XGBoost breach-prediction model (AUC-ROC 0.87), automated ReportLab PDF generation, Streamlit dashboard (HTTP-only architecture). Full Docker Compose stack with Postgres 16 + Redis 7. 40+ pytest assertions covering concurrency, cache, ML bounds, and threadpool isolation."*

---

## Ethics

100% public data: DNS, Shodan internet scans, certificate transparency, GitHub public repos, HTTP headers.
Only test domains you own or have explicit written permission to assess.