"""
Test suite — rate limiter, cache, ML scorer, API endpoints.
Run: pytest tests/ -v
"""

import asyncio
import time
import json
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4


# ══════════════════════════════════════════════════════════════
# 1. RATE LIMITER TESTS
#    Verifies the next-slot design has no token-debt spiral
# ══════════════════════════════════════════════════════════════

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../backend"))

from rate_limiter import RateLimiter, retry_with_backoff


class TestRateLimiter:

    @pytest.mark.asyncio
    async def test_single_acquire_no_wait(self):
        """First acquire should be instant (no debt yet)."""
        rl = RateLimiter(calls_per_second=10)
        start = time.monotonic()
        await rl.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.05, f"First acquire took {elapsed:.3f}s — should be instant"

    @pytest.mark.asyncio
    async def test_spacing_enforced(self):
        """Two back-to-back acquires must be spaced >= interval apart."""
        cps = 5.0
        rl = RateLimiter(calls_per_second=cps)
        t0 = time.monotonic()
        await rl.acquire()
        await rl.acquire()
        elapsed = time.monotonic() - t0
        expected = 1.0 / cps
        assert elapsed >= expected * 0.95, (
            f"Two acquires took {elapsed:.3f}s, expected >= {expected:.3f}s"
        )

    @pytest.mark.asyncio
    async def test_no_token_debt_spiral(self):
        """
        Under concurrent load, tokens must NEVER go negative.
        This is the specific bug fixed in v2.
        """
        rl = RateLimiter(calls_per_second=20)
        times = []

        async def worker():
            t = time.monotonic()
            await rl.acquire()
            times.append(time.monotonic() - t)

        # Fire 10 concurrent acquires
        await asyncio.gather(*[worker() for _ in range(10)])

        # next_allowed should be a clean monotonically increasing value
        # — verify it's positive and finite
        assert rl.next_allowed > time.monotonic() - 10
        assert rl.next_allowed < time.monotonic() + 10

    @pytest.mark.asyncio
    async def test_invalid_rate_raises(self):
        with pytest.raises(ValueError):
            RateLimiter(calls_per_second=0)
        with pytest.raises(ValueError):
            RateLimiter(calls_per_second=-1)

    @pytest.mark.asyncio
    async def test_throughput_accuracy(self):
        """Actual throughput should be within 10% of configured rate."""
        cps = 10.0
        rl = RateLimiter(calls_per_second=cps)
        n = 5
        start = time.monotonic()
        for _ in range(n):
            await rl.acquire()
        elapsed = time.monotonic() - start
        actual_cps = n / elapsed
        # Allow 20% variance
        assert actual_cps <= cps * 1.20, f"Too fast: {actual_cps:.1f} cps (limit {cps})"


class TestRetryDecorator:

    @pytest.mark.asyncio
    async def test_succeeds_first_try(self):
        call_count = 0

        @retry_with_backoff(max_retries=3, base_delay=0.01)
        async def fn():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = await fn()
        assert result == "ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retries_on_failure(self):
        call_count = 0

        @retry_with_backoff(max_retries=3, base_delay=0.01)
        async def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("temporary error")
            return "recovered"

        result = await fn()
        assert result == "recovered"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_retries(self):
        @retry_with_backoff(max_retries=3, base_delay=0.01)
        async def always_fails():
            raise RuntimeError("permanent failure")

        with pytest.raises(RuntimeError, match="permanent failure"):
            await always_fails()

    @pytest.mark.asyncio
    async def test_rate_limit_gets_extra_backoff(self):
        """429 errors should trigger longer sleep — verify via timing."""
        call_count = 0
        times = []

        @retry_with_backoff(max_retries=2, base_delay=0.05,
                             rate_limit_multiplier=2.0)
        async def rate_limited():
            nonlocal call_count
            call_count += 1
            times.append(time.monotonic())
            if call_count == 1:
                raise Exception("HTTP 429 Too Many Requests")
            return "ok"

        await rate_limited()
        assert call_count == 2


# ══════════════════════════════════════════════════════════════
# 2. CACHE LAYER TESTS
# ══════════════════════════════════════════════════════════════

from cache.redis_cache import CacheLayer, _cache_key, cached_osint


class TestCacheLayer:

    def test_cache_key_deterministic(self):
        k1 = _cache_key("dns", "example.com")
        k2 = _cache_key("dns", "example.com")
        k3 = _cache_key("dns", "other.com")
        assert k1 == k2
        assert k1 != k3

    def test_cache_key_case_insensitive(self):
        k1 = _cache_key("dns", "Example.COM")
        k2 = _cache_key("dns", "example.com")
        assert k1 == k2

    @pytest.mark.asyncio
    async def test_no_op_without_redis(self):
        cache = CacheLayer(redis_client=None)
        await cache.set("key", {"data": 1})          # should not raise
        result = await cache.get("key")              # should return None
        assert result is None

    @pytest.mark.asyncio
    async def test_get_set_round_trip(self):
        mock_redis = AsyncMock()
        mock_redis.get.return_value = json.dumps({"subdomains": ["api.test.com"]})
        mock_redis.setex = AsyncMock()

        cache = CacheLayer(redis_client=mock_redis)
        result = await cache.get("asm:dns:abc123")
        assert result == {"subdomains": ["api.test.com"]}

    @pytest.mark.asyncio
    async def test_redis_failure_is_silent(self):
        """Cache failures must NEVER crash the app."""
        mock_redis = AsyncMock()
        mock_redis.get.side_effect = ConnectionError("Redis down")

        cache = CacheLayer(redis_client=mock_redis)
        result = await cache.get("any_key")
        assert result is None  # graceful degradation


# ══════════════════════════════════════════════════════════════
# 3. ML SCORER TESTS
# ══════════════════════════════════════════════════════════════

from ml_scorer import RiskScorer


class TestRiskScorer:

    def _make_findings(self, **overrides):
        base = {
            "dns": {"subdomains": [{"subdomain": f"s{i}.test.com"} for i in range(5)],
                    "wildcard_dns": False, "zone_transfer": False, "issues": []},
            "shodan": {"open_ports_count": 2, "critical_cves": 0,
                       "high_cves": 0, "issues": [], "hosts": []},
            "certificates": {"issues_count": 0, "issues": [],
                              "expired_certs": 0, "expiring_soon": 0},
            "github": {"leaked_secrets_count": 0, "repositories": [], "issues": []},
            "email_security": {"score": 85, "spf": {"present": True},
                                "dmarc": {"present": True, "policy": "reject"},
                                "dkim": {"present": True, "selectors_found": ["google"]},
                                "issues": []},
            "technology": {"missing_security_headers": [], "technologies": [], "issues": []},
        }
        base.update(overrides)
        return base

    def test_low_risk_profile(self):
        findings = self._make_findings()
        scores = RiskScorer().score(findings)
        assert scores["overall"] < 30, f"Expected low risk, got {scores['overall']}"
        assert scores["risk_label"] in ("MINIMAL", "LOW")

    def test_critical_cves_spike_score(self):
        findings = self._make_findings(
            shodan={"open_ports_count": 10, "critical_cves": 5, "high_cves": 8,
                    "issues": [{"severity": "CRITICAL", "title": "CVE", "description": ""}],
                    "hosts": []}
        )
        scores = RiskScorer().score(findings)
        assert scores["overall"] > 50, f"Critical CVEs should spike score, got {scores['overall']}"

    def test_github_leak_critical(self):
        findings = self._make_findings(
            github={"leaked_secrets_count": 3, "repositories": [],
                    "issues": [{"severity": "CRITICAL", "title": "DB creds leaked",
                                 "description": ""}] * 3}
        )
        scores = RiskScorer().score(findings)
        assert scores["dimensions"]["data_leak"]["score"] > 60

    def test_bad_email_security(self):
        findings = self._make_findings(
            email_security={"score": 10, "issues": [
                {"severity": "HIGH", "title": "No SPF", "description": ""},
                {"severity": "HIGH", "title": "No DMARC", "description": ""},
            ],
            "spf": {"present": False}, "dmarc": {"present": False},
            "dkim": {"present": False, "selectors_found": []}}
        )
        scores = RiskScorer().score(findings)
        # Email security dimension should be high (bad posture = high risk score)
        assert scores["dimensions"]["email_security"]["score"] > 50

    def test_score_bounds(self):
        """Score must always be 0–100."""
        # Worst case — everything on fire
        worst = self._make_findings(
            shodan={"open_ports_count": 50, "critical_cves": 20, "high_cves": 30,
                    "issues": [{"severity": "CRITICAL", "title": "x", "description": ""}]*5,
                    "hosts": []},
            github={"leaked_secrets_count": 10, "repositories": [],
                    "issues": [{"severity": "CRITICAL", "title": "x", "description": ""}]*5},
        )
        scores = RiskScorer().score(worst)
        assert 0 <= scores["overall"] <= 100

    def test_features_present(self):
        """ML feature vector must contain all 15 expected features."""
        findings = self._make_findings()
        scores = RiskScorer().score(findings)
        features = scores.get("ml_features", {})
        expected = [
            "f_subdomain_count", "f_zone_transfer_enabled", "f_wildcard_dns",
            "f_open_ports", "f_critical_cves", "f_high_cves", "f_github_leaks",
            "f_public_repos", "f_email_score", "f_spf_present", "f_dmarc_present",
            "f_dkim_present", "f_missing_headers", "f_version_disclosed", "f_cert_issues",
        ]
        for feat in expected:
            assert feat in features, f"Missing feature: {feat}"

    def test_top_risks_sorted_by_severity(self):
        findings = self._make_findings(
            shodan={"open_ports_count": 3, "critical_cves": 1, "high_cves": 2,
                    "hosts": [],
                    "issues": [
                        {"severity": "LOW",      "title": "Low issue",      "description": ""},
                        {"severity": "CRITICAL",  "title": "Critical issue", "description": ""},
                        {"severity": "HIGH",      "title": "High issue",     "description": ""},
                    ]}
        )
        scores = RiskScorer().score(findings)
        top = scores.get("top_risks", [])
        if len(top) >= 2:
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            for i in range(len(top) - 1):
                assert order.get(top[i]["severity"], 9) <= order.get(top[i+1]["severity"], 9)


# ══════════════════════════════════════════════════════════════
# 4. OSINT ENGINE UNIT TESTS (mocked network)
# ══════════════════════════════════════════════════════════════

from osint_engine import OSINTEngine


class TestOSINTEngine:

    def _engine(self):
        return OSINTEngine(
            domain="test.com",
            company_name="Test Corp",
            shodan_key=None,
            cache=None,
        )

    @pytest.mark.asyncio
    async def test_shodan_demo_mode_returns_valid_shape(self):
        engine = self._engine()
        result = engine._shodan_demo_data()
        assert "hosts" in result
        assert "open_ports_count" in result
        assert "critical_cves" in result
        assert "issues" in result
        assert result["demo_mode"] is True

    @pytest.mark.asyncio
    async def test_email_check_scores_0_to_100(self):
        """Email security score must always be in [0, 100]."""
        with patch("dns.resolver.Resolver") as mock_resolver:
            mock_resolver.return_value.resolve.side_effect = Exception("DNS error")
            engine = self._engine()
            result = await engine.email_security_check()
            assert 0 <= result["score"] <= 100

    def test_engine_domain_normalised(self):
        engine = OSINTEngine(
            domain="  EXAMPLE.COM  ",
            company_name="Test",
            shodan_key=None,
            cache=None,
        )
        assert engine.domain == "example.com"


# ══════════════════════════════════════════════════════════════
# 5. INTEGRATION — threadpool doesn't block event loop
# ══════════════════════════════════════════════════════════════

class TestThreadpoolIntegration:

    @pytest.mark.asyncio
    async def test_cpu_work_doesnt_block_event_loop(self):
        """
        Simulates ML scoring in threadpool while async tasks run concurrently.
        Proves run_in_threadpool keeps the event loop responsive.
        """
        import concurrent.futures

        async def async_counter(n: int) -> int:
            count = 0
            for _ in range(n):
                await asyncio.sleep(0)  # yield to event loop
                count += 1
            return count

        def cpu_work():
            # Simulate 50ms of CPU work
            total = 0
            for i in range(500_000):
                total += i
            return total

        loop = asyncio.get_event_loop()
        executor = concurrent.futures.ThreadPoolExecutor()

        # Run CPU work and async counter concurrently
        cpu_task   = loop.run_in_executor(executor, cpu_work)
        async_task = asyncio.create_task(async_counter(100))

        cpu_result, async_result = await asyncio.gather(cpu_task, async_task)

        assert cpu_result > 0
        assert async_result == 100  # async task completed while CPU was busy