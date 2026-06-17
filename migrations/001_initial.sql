-- migrations/001_initial.sql
-- Run once against a fresh database.
-- SQLAlchemy create_all handles this automatically on startup,
-- but this file documents the exact schema for DBA review / manual deploy.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ── SCANS ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain          TEXT NOT NULL,
    company_name    TEXT,
    status          TEXT NOT NULL DEFAULT 'queued'
                        CONSTRAINT ck_scans_status
                        CHECK (status IN ('queued','running','completed','failed')),

    -- ML scores — typed for GROUP BY / filter / ORDER BY
    overall_score       NUMERIC(5,2),
    risk_label          TEXT,
    breach_probability  NUMERIC(4,3),

    -- Dimension scores
    score_network   NUMERIC(5,2),
    score_data_leak NUMERIC(5,2),
    score_email     NUMERIC(5,2),
    score_app_sec   NUMERIC(5,2),
    score_human     NUMERIC(5,2),

    -- Issue counts
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    low_count       INTEGER NOT NULL DEFAULT 0,

    -- Raw OSINT payloads — JSONB so GIN indexes make them queryable
    raw_dns     JSONB,
    raw_shodan  JSONB,
    raw_certs   JSONB,
    raw_github  JSONB,
    raw_email   JSONB,
    raw_tech    JSONB,

    -- Feature vector for ML retraining replay
    ml_features JSONB,

    error_message   TEXT,
    report_path     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

-- ── FINDINGS ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id     UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    severity    TEXT NOT NULL
                    CONSTRAINT ck_findings_severity
                    CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    recommendation TEXT,

    -- Optional typed fields (NULL when not applicable)
    affected_host   TEXT,
    affected_port   INTEGER,
    cve_id          TEXT,
    cvss_score      NUMERIC(4,2),

    -- Category-specific overflow
    metadata    JSONB,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── DOMAIN CACHE ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domain_cache (
    domain          TEXT PRIMARY KEY,
    last_scanned    TIMESTAMPTZ NOT NULL,
    last_scan_id    UUID REFERENCES scans(id),
    scan_count      INTEGER NOT NULL DEFAULT 1,
    latest_score    NUMERIC(5,2),
    latest_label    TEXT
);

-- ── INDEXES ────────────────────────────────────────────────────────────────

-- B-tree indexes on typed query columns
CREATE INDEX IF NOT EXISTS idx_scans_domain    ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_status    ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_score     ON scans(overall_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_scans_critical  ON scans(critical_count DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created   ON scans(created_at DESC);

-- GIN indexes on JSONB payloads
-- These let you query: WHERE raw_shodan @> '{"critical_cves": 2}'
CREATE INDEX IF NOT EXISTS idx_gin_shodan ON scans USING GIN (raw_shodan);
CREATE INDEX IF NOT EXISTS idx_gin_github ON scans USING GIN (raw_github);
CREATE INDEX IF NOT EXISTS idx_gin_dns    ON scans USING GIN (raw_dns);

-- Trigram fuzzy domain search: WHERE domain ILIKE '%stripe%'
CREATE INDEX IF NOT EXISTS idx_domain_trgm ON scans USING GIN (domain gin_trgm_ops);

-- Findings indexes
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev  ON findings(severity, scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_cve
    ON findings(cve_id)
    WHERE cve_id IS NOT NULL;

-- ── USEFUL QUERIES ─────────────────────────────────────────────────────────

-- All CRITICAL findings across the platform this week:
-- SELECT f.*, s.domain FROM findings f
-- JOIN scans s ON s.id = f.scan_id
-- WHERE f.severity = 'CRITICAL'
--   AND s.created_at >= NOW() - INTERVAL '7 days'
-- ORDER BY s.created_at DESC;

-- Companies with Redis/MongoDB/Elasticsearch exposed:
-- SELECT domain, raw_shodan->'services' FROM scans
-- WHERE raw_shodan @> '{"services": ["Redis:6379"]}'
--   AND status = 'completed';

-- Re-trainable ML feature export:
-- SELECT ml_features, overall_score FROM scans
-- WHERE status = 'completed'
--   AND ml_features IS NOT NULL
-- ORDER BY created_at DESC;

-- Domains scanned more than once with worsening score:
-- SELECT s1.domain, s1.overall_score AS latest, s2.overall_score AS previous
-- FROM scans s1
-- JOIN scans s2 ON s1.domain = s2.domain AND s1.created_at > s2.created_at
-- WHERE s1.overall_score > s2.overall_score + 10;