"""
AI-NIDS Live Dashboard
----------------------
Launch: streamlit run dashboard/app.py

Full real-time view:
  - KPI row: packets, flows, alerts, attack rate, uptime
  - Alert severity timeline 
  - Live alert table with dedup notes
  - ML score histogram
  - Top attacker IPs bar chart
  - Protocol distribution
  - Severity breakdown donut
  - Score percentile gauge
"""

import json
import time
import math
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ── Paths ─────────────────────────────────────────────────────────────────────
ALERT_LOG  = Path("data/alerts.jsonl")
FLOW_LOG   = Path("data/flows.jsonl")

# ── Data helpers ──────────────────────────────────────────────────────────────

@st.cache_data(ttl=1)  # cache lightly for UI interactions
def load_jsonl(path: str, n: int = 1000) -> pd.DataFrame:
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return pd.DataFrame()
    try:
        lines = p.read_text().strip().split("\n")
        lines = [l for l in lines if l][-n:]
        return pd.DataFrame([json.loads(l) for l in lines])
    except Exception:
        return pd.DataFrame()


def fmt_uptime(secs: float) -> str:
    h, rem = divmod(int(secs), 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


SEV_COLOR = {"high": "#ef4444", "medium": "#f97316", "low": "#facc15"}
SEV_ICON  = {"high": "🔴", "medium": "🟠", "low": "🟡"}

DARK_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font_color="#ccc",
    margin=dict(t=30, b=10, l=10, r=10),
)


# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="AI-NIDS Dashboard",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
[data-testid="stMetricValue"]  { font-size: 1.6rem !important; font-weight: 500; }
[data-testid="stMetricLabel"]  { font-size: 0.8rem !important; color: #888; }
[data-testid="stMetricDelta"]  { font-size: 0.8rem !important; }
div[data-testid="column"]      { padding: 0 6px; }
.alert-high   { color: #ef4444; font-weight: 500; }
.alert-medium { color: #f97316; font-weight: 500; }
.alert-low    { color: #facc15; font-weight: 500; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar & Controls ────────────────────────────────────────────────────────
st.sidebar.title("🛡️ AI-NIDS Controls")
auto_refresh = st.sidebar.checkbox("Live Auto-Refresh", value=True, help="Toggle to pause log tailing")
refresh_rate = st.sidebar.slider("Refresh Rate (seconds)", 1, 60, 3, disabled=not auto_refresh)
history_lim  = st.sidebar.select_slider("Log History Size", options=[500, 1000, 2000, 5000, 10000], value=2000)
sev_filter   = st.sidebar.multiselect("Severity Filter", ["high", "medium", "low"], default=["high", "medium", "low"])

# ── Header ────────────────────────────────────────────────────────────────────

col_title, col_time = st.columns([3, 1])
col_title.markdown("## Live Dashboard")
col_time.markdown(
    f"<div style='text-align:right;padding-top:14px;color:#888;font-size:13px'>"
    f"Last Updated: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}</div>",
    unsafe_allow_html=True,
)

# ── Load data ─────────────────────────────────────────────────────────────────

alerts_df = load_jsonl(str(ALERT_LOG), n=history_lim)
flows_df  = load_jsonl(str(FLOW_LOG),  n=history_lim)

if not alerts_df.empty and "severity" in alerts_df.columns and sev_filter:
    alerts_df = alerts_df[alerts_df["severity"].isin(sev_filter)]

has_alerts = not alerts_df.empty
has_flows  = not flows_df.empty

# Compute session-level stats
total_alerts  = len(alerts_df)
total_flows   = len(flows_df)
high_count    = int((alerts_df["severity"] == "high").sum()) if has_alerts and "severity" in alerts_df.columns else 0
attack_rate   = f"{total_alerts / max(total_flows, 1) * 100:.1f}%"

# Estimate uptime
uptime_str = "—"
if has_alerts and "_alerted_at" in alerts_df.columns:
    ts = alerts_df["_alerted_at"].dropna()
    if len(ts) > 1:
        uptime_str = fmt_uptime(ts.max() - ts.min())

# ── KPI row ───────────────────────────────────────────────────────────────────

k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("Total Flows Logged", f"{total_flows:,}")
k2.metric("Total Alerts",    f"{total_alerts:,}")
k3.metric("🔴 High Severity", f"{high_count:,}")
k4.metric("Attack Rate",     attack_rate)
k5.metric("Active Filters",  f"{len(sev_filter)} applied")
k6.metric("Log Span",        uptime_str)

st.divider()

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_overview, tab_alerts, tab_analytics = st.tabs(["📊 Overview", "🚨 Alerts Explorer", "📈 Analytics & ML"])

# == TAB 1: OVERVIEW ==
with tab_overview:
    col_left, col_right = st.columns([3, 2])
    with col_left:
        st.subheader("Alert timeline")
        if has_alerts and "_alerted_at" in alerts_df.columns and "severity" in alerts_df.columns:
            tdf = alerts_df[["_alerted_at", "severity"]].dropna().copy()
            tdf["time"] = pd.to_datetime(tdf["_alerted_at"], unit="s", utc=True)
            tdf = tdf.set_index("time").resample("30s")["severity"].count().reset_index()
            tdf.columns = ["time", "count"]

            fig = px.area(
                tdf, x="time", y="count",
                color_discrete_sequence=["#6366f1"],
                labels={"count": "Alerts", "time": ""},
            )
            fig.update_traces(line_width=1.5, fillcolor="rgba(99,102,241,0.15)")
            fig.update_layout(**DARK_LAYOUT)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No matching alerts found.")

    with col_right:
        st.subheader("Severity breakdown")
        if has_alerts and "severity" in alerts_df.columns:
            sev = alerts_df["severity"].value_counts()
            fig2 = go.Figure(go.Pie(
                labels=sev.index.tolist(),
                values=sev.values.tolist(),
                hole=0.5,
                marker_colors=[SEV_COLOR.get(s, "#888") for s in sev.index],
                textinfo="label+percent",
                textfont_size=12,
            ))
            fig2.update_layout(**DARK_LAYOUT, showlegend=False)
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No severity data available.")

    st.subheader("Top alert sources")
    if has_alerts and "_src_ip" in alerts_df.columns:
        top = (
            alerts_df["_src_ip"].value_counts()
            .head(5).reset_index()
            .rename(columns={"_src_ip": "Source IP", "count": "Alerts"})
        )
        fig4 = px.bar(
            top, x="Alerts", y="Source IP", orientation="h",
            color_discrete_sequence=["#ef4444"],
        )
        fig4.update_layout(**DARK_LAYOUT, yaxis={"autorange": "reversed"}, height=300)
        st.plotly_chart(fig4, use_container_width=True)
    else:
        st.info("Waiting for alerts.")

# == TAB 2: ALERTS EXPLORER ==
with tab_alerts:
    st.subheader("Recent alerts log")
    if has_alerts:
        show_cols = [c for c in [
            "_alerted_at", "severity", "_src_ip", "_src_port",
            "_dst_ip", "_dst_port", "score", "label",
            "signature_match", "suppression_note",
        ] if c in alerts_df.columns]

        display = alerts_df[show_cols].copy()

        if "_alerted_at" in display.columns:
            display["_alerted_at"] = pd.to_datetime(
                display["_alerted_at"], unit="s", utc=True
            ).dt.strftime("%H:%M:%S")
            display.rename(columns={"_alerted_at": "time"}, inplace=True)

        if "score" in display.columns:
            display["score"] = display["score"].round(3)

        if "severity" in display.columns:
            display.insert(0, "  ", display["severity"].map(SEV_ICON).fillna("⚪"))

        if "time" in display.columns:
            display = display.sort_values("time", ascending=False)
            
        csv_data = display.to_csv(index=False).encode('utf-8')
        st.download_button("💾 Download Alerts to CSV", data=csv_data, file_name="ai_nids_alerts.csv", mime="text/csv")
        
        st.dataframe(
            display,
            use_container_width=True,
            hide_index=True,
            height=500,
        )
    else:
        st.info("No matching alerts. Check your severity filters or start the monitor.")

# == TAB 3: ANALYTICS & ML ==
with tab_analytics:
    col_score, col_perc = st.columns([3, 2])
    with col_score:
        st.subheader("ML score distribution")
        if has_flows and "score" in flows_df.columns:
            fig3 = px.histogram(
                flows_df, x="score", nbins=60,
                color_discrete_sequence=["#6366f1"],
                labels={"score": "Attack probability score"},
            )
            for thresh, color, name in [
                (0.65, "#facc15", "Low"),
                (0.80, "#f97316", "Medium"),
                (0.92, "#ef4444", "High"),
            ]:
                fig3.add_vline(
                    x=thresh, line_dash="dash", line_color=color, line_width=1.5,
                    annotation_text=name, annotation_font_color=color,
                    annotation_position="top right",
                )
            fig3.update_layout(**DARK_LAYOUT, showlegend=False)
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("Waiting for scored flows.")

    with col_perc:
        st.subheader("Score percentiles")
        if has_flows and "score" in flows_df.columns:
            scores = flows_df["score"].dropna()
            p_vals = [50, 75, 90, 95, 99]
            p_data = {f"p{p}": round(float(scores.quantile(p/100)), 4) for p in p_vals}
            p_df = pd.DataFrame({"Percentile": list(p_data.keys()), "Score": list(p_data.values())})
            fig6 = px.bar(
                p_df, x="Percentile", y="Score",
                color="Score",
                color_continuous_scale=["#22c55e", "#facc15", "#f97316", "#ef4444"],
                range_color=[0, 1],
            )
            fig6.update_layout(**DARK_LAYOUT, coloraxis_showscale=False)
            st.plotly_chart(fig6, use_container_width=True)

            ca, cb, cc = st.columns(3)
            ca.metric("Mean",  f"{scores.mean():.4f}")
            cb.metric("p90",   f"{scores.quantile(0.90):.4f}")
            cc.metric("p99",   f"{scores.quantile(0.99):.4f}")
        else:
            st.info("Waiting for scored flows.")

    col_sig, col_proto = st.columns(2)
    with col_sig:
        st.subheader("Signature rule hits")
        if has_alerts and "signature_match" in alerts_df.columns:
            sig_hits = (
                alerts_df["signature_match"]
                .dropna()
                .str.split(":", n=1).str[0]
                .value_counts()
                .head(12)
                .reset_index()
                .rename(columns={"signature_match": "Rule", "count": "Hits"})
            )
            if not sig_hits.empty:
                fig7 = px.bar(
                    sig_hits, x="Hits", y="Rule", orientation="h",
                    color_discrete_sequence=["#f97316"],
                )
                fig7.update_layout(**DARK_LAYOUT, yaxis={"autorange": "reversed"})
                st.plotly_chart(fig7, use_container_width=True)
            else:
                st.info("No signature matches recorded yet.")
        else:
            st.info("Signature match data will appear here once the monitor is running.")
            
    with col_proto:
        st.subheader("Top destination ports (all flows)")
        if has_flows and "dst_port" in flows_df.columns:
            top_ports = (
                flows_df["dst_port"]
                .dropna()
                .astype(int)
                .value_counts()
                .head(10)
                .reset_index()
                .rename(columns={"dst_port": "Port", "count": "Flows"})
            )
            fig5 = px.bar(
                top_ports, x="Flows", y="Port", orientation="h",
                color_discrete_sequence=["#6366f1"],
                labels={"Port": "Destination port"},
            )
            fig5.update_layout(**DARK_LAYOUT, yaxis={"autorange": "reversed", "type": "category"})
            st.plotly_chart(fig5, use_container_width=True)
        else:
            st.info("Waiting for flow data.")

# ── Footer ────────────────────────────────────────────────────────────────────

if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
