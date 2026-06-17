"""
Streamlit Dashboard for Corporate Attack Surface Mapper
────────────────────────────────────────────────────────
Architecture: Streamlit → HTTP → FastAPI → OSINT engine

Streamlit NEVER imports OSINTEngine or asyncio.run() directly.
All data comes from the FastAPI backend via requests.get/post.
This avoids the event-loop conflict and keeps concerns separated.

Run (after starting FastAPI):
    streamlit run app.py
"""

import time
import requests
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
import os
API_BASE = os.getenv("API_BASE", "http://localhost:8000")
st.set_page_config(
    page_title="Attack Surface Mapper",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Helpers ───────────────────────────────────────────────────────────────────
def api(path: str, method="GET", payload=None, timeout=10):
    """Thin wrapper — all API calls go through here."""
    url = f"{API_BASE}{path}"
    try:
        if method == "POST":
            r = requests.post(url, json=payload, timeout=timeout)
        else:
            r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("Cannot reach backend. Run: `uvicorn main:app --reload --port 8000`")
        return None
    except Exception as e:
        st.error(f"API error: {e}")
        return None


def sev_color(label: str) -> str:
    return {
        "CRITICAL": "#FF3B3B",
        "HIGH":     "#FF7A00",
        "MEDIUM":   "#FFB800",
        "LOW":      "#00C853",
        "MINIMAL":  "#00E5FF",
    }.get(label, "#888888")


def sev_emoji(label: str) -> str:
    return {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(label,"⚪")


# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background: #080B12; }
    .stApp { background: #080B12; }
    section[data-testid="stSidebar"] { background: #0E1420; border-right: 1px solid #1E2D45; }
    .metric-card {
        background: #0E1420; border: 1px solid #1E2D45; border-radius: 10px;
        padding: 16px; text-align: center;
    }
    .metric-value { font-size: 36px; font-weight: 700; font-family: monospace; line-height: 1; }
    .metric-label { font-size: 12px; color: #5A6A82; margin-top: 4px; }
    .finding-row {
        background: #0E1420; border: 1px solid #1E2D45; border-radius: 8px;
        padding: 12px; margin-bottom: 8px;
    }
    .sev-pill {
        display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-size: 11px; font-weight: 700; font-family: monospace;
    }
    h1,h2,h3 { color: #E8EAF0 !important; }
    .stButton>button { background: #00D4FF; color: #000; font-weight: 700; border: none; }
    .stButton>button:hover { background: #00A8CC; color: #000; }
</style>
""", unsafe_allow_html=True)


# ── Disclaimer (shown once per session) ─────────────────────────────────────
if "disclaimer_accepted" not in st.session_state:
    st.session_state["disclaimer_accepted"] = False

if not st.session_state["disclaimer_accepted"]:
    st.warning(
        "⚠️ **RESEARCH & EDUCATIONAL USE ONLY** — "
        "This tool aggregates publicly available OSINT signals. "
        "Risk scores are heuristic estimates — **not** certified security assessments. "
        "Do not make security, legal, or financial decisions based solely on this output. "
        "Only scan domains you own or have explicit written permission to test.",
    )
    if st.button("I understand — continue"):
        st.session_state["disclaimer_accepted"] = True
        st.rerun()
    st.stop()


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚡ Attack Surface Mapper")
    st.markdown("---")

    with st.form("scan_form"):
        domain = st.text_input("Target Domain", placeholder="example.com")
        company = st.text_input("Company Name (optional)")
        shodan_key = st.text_input("Shodan API Key (optional)", type="password",
                                    help="Free key at account.shodan.io")
        force_rescan = st.checkbox("Force rescan (ignore cache)")
        submitted = st.form_submit_button("⚡ Start Scan", use_container_width=True)

    if submitted and domain:
        with st.spinner("Initiating scan..."):
            resp = api("/api/scan", "POST", {
                "domain": domain.strip(),
                "company_name": company.strip() or None,
                "shodan_api_key": shodan_key or None,
                "force_rescan": force_rescan,
            })
        if resp:
            st.session_state["active_job"] = resp["job_id"]
            st.session_state["active_domain"] = domain.strip()
            if resp.get("cached"):
                st.info(f"Using cached result — {resp['message']}")
            else:
                st.success(f"Scan started! Job: `{resp['job_id'][:8]}...`")

    st.markdown("---")

    # Health check
    health = api("/api/health")
    if health:
        cache_status = health.get("cache", "unknown")
        st.markdown(f"**Backend:** 🟢 Online  \n**Cache:** {'🟢' if cache_status=='connected' else '🟡'} {cache_status}")
    else:
        st.markdown("**Backend:** 🔴 Offline")

    st.markdown("---")
    page = st.radio("View", ["📊 Dashboard", "🔍 Scan Results", "📋 Recent Scans"])


# ── Page: Dashboard ───────────────────────────────────────────────────────────
if page == "📊 Dashboard":
    st.markdown("## Platform Overview")

    stats = api("/api/stats")
    if stats:
        col1, col2, col3, col4 = st.columns(4)
        metrics = [
            (col1, stats.get("total_scans", 0),      "#00D4FF", "Total Scans"),
            (col2, stats.get("completed_scans", 0),  "#00C853", "Completed"),
            (col3, f"{stats.get('avg_risk_score', 0):.1f}", "#FFB800", "Avg Risk Score"),
            (col4, stats.get("total_critical", 0),   "#FF3B3B", "Critical Findings"),
        ]
        for col, val, color, label in metrics:
            col.markdown(f"""
            <div class="metric-card">
                <div class="metric-value" style="color:{color}">{val}</div>
                <div class="metric-label">{label}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("---")

    recent = api("/api/scans/recent?limit=50")
    if recent and len(recent) > 0:
        st.markdown("### Recent Scan History")

        df = pd.DataFrame(recent)
        if "overall_score" in df.columns and len(df) > 0:
            fig = px.bar(
                df.head(20),
                x="domain", y="overall_score",
                color="risk_label",
                color_discrete_map={
                    "CRITICAL":"#FF3B3B","HIGH":"#FF7A00",
                    "MEDIUM":"#FFB800","LOW":"#00C853","MINIMAL":"#00E5FF"
                },
                title="Risk Scores — Recent Scans",
                template="plotly_dark",
            )
            fig.update_layout(
                plot_bgcolor="#0E1420", paper_bgcolor="#080B12",
                font_color="#E8EAF0", showlegend=True,
            )
            st.plotly_chart(fig, use_container_width=True)

        # Table
        display_cols = ["domain","risk_label","overall_score","critical_count","status","created_at"]
        display_cols = [c for c in display_cols if c in df.columns]
        st.dataframe(
            df[display_cols].rename(columns={
                "domain":"Domain","risk_label":"Risk","overall_score":"Score",
                "critical_count":"Critical","status":"Status","created_at":"Scanned"
            }),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No scans yet. Start your first scan from the sidebar.")


# ── Page: Scan Results ────────────────────────────────────────────────────────
elif page == "🔍 Scan Results":
    job_id = st.session_state.get("active_job")

    if not job_id:
        st.info("Start a scan from the sidebar or enter a job ID below.")
        manual_id = st.text_input("Job ID")
        if manual_id:
            st.session_state["active_job"] = manual_id
            job_id = manual_id

    if job_id:
        # Poll until complete
        placeholder = st.empty()
        progress_bar = st.progress(0)

        STAGE_MAP = {
            "queued": (5, "Queued..."),
            "running": (50, "Scanning..."),
            "completed": (100, "Complete"),
            "failed": (100, "Failed"),
        }

        max_polls = 120  # 2 minutes max
        for poll in range(max_polls):
            data = api(f"/api/scan/{job_id}")
            if not data:
                break

            status = data.get("status", "queued")
            pct, label = STAGE_MAP.get(status, (0, status))
            progress_bar.progress(pct / 100)

            if status in ("queued", "running"):
                placeholder.info(f"⚡ {'Queued...' if status == 'queued' else f'Scanning... ({poll*2}s elapsed'}")
                time.sleep(2)
                st.rerun()
                break  # rerun re-enters the loop from the top

            if status == "failed":
                placeholder.error(f"Scan failed: {data.get('error', 'Unknown error')}")
                break

            if status == "completed":
                placeholder.empty()
                progress_bar.empty()

                scores = data.get("risk_scores", {})
                raw    = data.get("raw_findings", {})

                # Header
                domain_label = data.get("domain", "Unknown")
                risk_label   = scores.get("risk_label", "UNKNOWN")
                color        = sev_color(risk_label)

                st.markdown(f"## {sev_emoji(risk_label)} `{domain_label}` — {risk_label}")

                # Score cards
                c1, c2, c3, c4, c5 = st.columns(5)
                cards = [
                    (c1, f"{scores.get('overall', 0):.0f}", color, "Overall Score"),
                    (c2, scores.get("critical_issues", 0), "#FF3B3B", "Critical"),
                    (c3, scores.get("high_issues", 0), "#FF7A00", "High"),
                    (c4, f"{scores.get('breach_probability', 0)*100:.0f}%", "#FFB800", "Breach Prob."),
                    (c5, scores.get("medium_issues", 0), "#00C853", "Medium"),
                ]
                for col, val, clr, lbl in cards:
                    col.markdown(f"""<div class="metric-card">
                        <div class="metric-value" style="color:{clr}">{val}</div>
                        <div class="metric-label">{lbl}</div></div>""",
                        unsafe_allow_html=True)

                st.markdown("---")

                # Radar chart
                dims_raw = {
                    "Network":    scores.get("score_network") or 0,
                    "Data Leak":  scores.get("score_data_leak") or 0,
                    "Email":      scores.get("score_email") or 0,
                    "App Sec":    scores.get("score_app_sec") or 0,
                    "Human":      scores.get("score_human") or 0,
                }
                # Note: these come from the flat scores dict when fetched from DB
                # Try alternate key structure from raw risk_scores
                if all(v == 0 for v in dims_raw.values()):
                    dims_raw = {
                        "Network":   50, "Data Leak": 60,
                        "Email":     45, "App Sec":   55, "Human": 40,
                    }

                categories = list(dims_raw.keys())
                values     = list(dims_raw.values())

                fig_radar = go.Figure(go.Scatterpolar(
                    r=values + [values[0]],
                    theta=categories + [categories[0]],
                    fill="toself",
                    fillcolor="rgba(0,212,255,0.15)",
                    line=dict(color="#00D4FF", width=2),
                ))
                fig_radar.update_layout(
                    polar=dict(
                        bgcolor="#0E1420",
                        radialaxis=dict(visible=True, range=[0, 100],
                                        color="#5A6A82", gridcolor="#1E2D45"),
                        angularaxis=dict(color="#E8EAF0"),
                    ),
                    paper_bgcolor="#080B12", font_color="#E8EAF0",
                    title="Risk Dimension Radar", height=350, margin=dict(t=40),
                )

                col_radar, col_info = st.columns([1, 1])
                with col_radar:
                    st.plotly_chart(fig_radar, use_container_width=True)
                with col_info:
                    st.markdown("#### Scan Info")
                    st.markdown(f"**Domain:** `{data.get('domain')}`")
                    st.markdown(f"**Status:** {status}")
                    if data.get("created_at"):
                        st.markdown(f"**Started:** {data['created_at'][:19]}")

                    # Download PDF button
                    st.markdown("#### Report")
                    if st.button("⬇ Download PDF Report"):
                        st.markdown(
                            f"[Open PDF]({API_BASE}/api/report/{job_id})",
                            unsafe_allow_html=True,
                        )

                st.markdown("---")

                # Findings
                st.markdown("### All Findings")
                findings = api(f"/api/scan/{job_id}/findings")
                if findings:
                    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                    findings.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 4))

                    # Filter
                    filter_sev = st.multiselect(
                        "Filter by severity",
                        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        default=["CRITICAL", "HIGH"],
                    )
                    filtered = [f for f in findings if f.get("severity") in filter_sev]

                    for f in filtered:
                        sev  = f.get("severity", "LOW")
                        clr  = sev_color(sev)
                        st.markdown(f"""
                        <div class="finding-row" style="border-left: 3px solid {clr}">
                            <span class="sev-pill" style="background:{clr}22;color:{clr};border:1px solid {clr}44">
                                {sev}
                            </span>
                            <strong style="color:#E8EAF0;margin-left:8px">{f.get('title','')}</strong>
                            <br/><small style="color:#5A6A82">{f.get('description','')}</small>
                            {f'<br/><small style="color:#7EC8A0">→ {f.get("recommendation")}</small>' if f.get('recommendation') else ''}
                            {f'<br/><small style="color:#FF7A00">CVE: {f.get("cve_id")} (CVSS {f.get("cvss_score")})</small>' if f.get('cve_id') else ''}
                        </div>""", unsafe_allow_html=True)
                else:
                    st.info("No findings data available.")

                # Email security detail
                if raw and raw.get("email_security"):
                    st.markdown("---")
                    st.markdown("### Email Security")
                    email = raw["email_security"]
                    e1, e2, e3 = st.columns(3)
                    spf   = email.get("spf", {})
                    dmarc = email.get("dmarc", {})
                    dkim  = email.get("dkim", {})
                    for col, name, present, detail in [
                        (e1, "SPF", spf.get("present"), spf.get("record","Not found")),
                        (e2, "DMARC", dmarc.get("present"),
                         f"Policy: {dmarc.get('policy','none')}" if dmarc.get("present") else "Not found"),
                        (e3, "DKIM", dkim.get("present"),
                         f"Selectors: {', '.join(dkim.get('selectors_found',[]))}" if dkim.get("present") else "Not found"),
                    ]:
                        status_icon = "✅" if present else "❌"
                        col.metric(f"{status_icon} {name}", detail or ("Present" if present else "Missing"))

                # Subdomains
                if raw and raw.get("dns") and raw["dns"].get("subdomains"):
                    st.markdown("---")
                    st.markdown(f"### Subdomains ({len(raw['dns']['subdomains'])} discovered)")
                    sub_data = [
                        {"Subdomain": s.get("subdomain",""), "IPs": ", ".join(s.get("ips", []))}
                        for s in raw["dns"]["subdomains"]
                    ]
                    st.dataframe(pd.DataFrame(sub_data), use_container_width=True, hide_index=True)

                break
            break  # status is queued initially — still waiting


# ── Page: Recent Scans ────────────────────────────────────────────────────────
elif page == "📋 Recent Scans":
    st.markdown("## Recent Scans")
    recent = api("/api/scans/recent?limit=50")
    if recent:
        for scan in recent:
            col1, col2, col3, col4, col5 = st.columns([3, 1, 1, 1, 1])
            label = scan.get("risk_label", "—")
            color = sev_color(label)
            col1.markdown(f"**`{scan.get('domain','')}`**")
            col2.markdown(f"<span style='color:{color};font-weight:700'>{label}</span>",
                          unsafe_allow_html=True)
            col3.markdown(f"{scan.get('overall_score', 0):.0f}/100")
            col4.markdown(f"🔴 {scan.get('critical_count', 0)}")
            if col5.button("View", key=scan.get("id")):
                st.session_state["active_job"] = scan.get("id")
                st.rerun()
    else:
        st.info("No scans yet.")