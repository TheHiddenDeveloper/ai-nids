"""
AI-NIDS Live Dashboard
----------------------
Launch: streamlit run dashboard/app.py

Full real-time view:
  - KPI row: packets, flows, alerts, attack rate, uptime
  - Alert severity timeline (last 10 min)
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
REFRESH    = 3   # seconds


# ── Data helpers ──────────────────────────────────────────────────────────────

def load_jsonl(path: Path, n: int = 1000) -> pd.DataFrame:
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    try:
        lines = path.read_text().strip().split("\n")
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

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "Other"}

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
    initial_sidebar_state="collapsed",
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

# ── Header ────────────────────────────────────────────────────────────────────

col_title, col_time = st.columns([3, 1])
col_title.markdown("## 🛡️ AI-NIDS  —  Live Dashboard")
col_time.markdown(
    f"<div style='text-align:right;padding-top:14px;color:#888;font-size:13px'>"
    f"{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}</div>",
    unsafe_allow_html=True,
)

# ── Load data ─────────────────────────────────────────────────────────────────

alerts_df = load_jsonl(ALERT_LOG, n=2000)
flows_df  = load_jsonl(FLOW_LOG,  n=2000)

has_alerts = not alerts_df.empty
has_flows  = not flows_df.empty

# Compute session-level stats from logs (dashboard works even without live monitor)
total_alerts  = len(alerts_df)
total_flows   = len(flows_df)
high_count    = int((alerts_df["severity"] == "high").sum())   if has_alerts and "severity" in alerts_df.columns else 0
attack_rate   = f"{total_alerts / max(total_flows, 1) * 100:.1f}%"

# Estimate uptime from log timestamps
uptime_str = "—"
if has_alerts and "_alerted_at" in alerts_df.columns:
    ts = alerts_df["_alerted_at"].dropna()
    if len(ts) > 1:
        uptime_str = fmt_uptime(ts.max() - ts.min())

# ── KPI row ───────────────────────────────────────────────────────────────────

k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("Total Flows",     f"{total_flows:,}")
k2.metric("Total Alerts",    f"{total_alerts:,}")
k3.metric("🔴 High Severity", f"{high_count:,}")
k4.metric("Attack Rate",     attack_rate)
k5.metric("Flows Logged",    f"{total_flows:,}")
k6.metric("Session Span",    uptime_str)

st.divider()

# ── Row 1: Timeline + Alert table ─────────────────────────────────────────────

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
        st.info("No alerts yet — start the monitor and alerts will appear here.")

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
        st.info("Waiting for alerts.")

st.divider()

# ── Row 2: Alert table ────────────────────────────────────────────────────────

st.subheader("Recent alerts")
if has_alerts:
    show_cols = [c for c in [
        "_alerted_at", "severity", "_src_ip", "_src_port",
        "_dst_ip", "_dst_port", "score", "label",
        "signature_match", "suppression_note",
    ] if c in alerts_df.columns]

    display = alerts_df[show_cols].tail(50).copy()

    if "_alerted_at" in display.columns:
        display["_alerted_at"] = pd.to_datetime(
            display["_alerted_at"], unit="s", utc=True
        ).dt.strftime("%H:%M:%S")
        display.rename(columns={"_alerted_at": "time"}, inplace=True)

    if "score" in display.columns:
        display["score"] = display["score"].round(3)

    if "severity" in display.columns:
        display.insert(0, "  ", display["severity"].map(SEV_ICON).fillna("⚪"))

    st.dataframe(
        display.sort_values("time", ascending=False) if "time" in display.columns else display,
        use_container_width=True,
        hide_index=True,
        height=280,
    )
else:
    st.info(
        "No alerts logged yet.\n\n"
        "Start the monitor with:\n"
        "```\nsudo python scripts/run_monitor.py --interface eth0\n```"
    )

st.divider()

# ── Row 3: Score histogram + Top IPs ─────────────────────────────────────────

col_score, col_ips = st.columns([3, 2])

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

with col_ips:
    st.subheader("Top alert sources")
    if has_alerts and "_src_ip" in alerts_df.columns:
        top = (
            alerts_df["_src_ip"].value_counts()
            .head(8).reset_index()
            .rename(columns={"_src_ip": "Source IP", "count": "Alerts"})
        )
        fig4 = px.bar(
            top, x="Alerts", y="Source IP", orientation="h",
            color_discrete_sequence=["#ef4444"],
        )
        fig4.update_layout(**DARK_LAYOUT, yaxis={"autorange": "reversed"})
        st.plotly_chart(fig4, use_container_width=True)
    else:
        st.info("Waiting for alerts.")

st.divider()

# ── Row 4: Protocol distribution + Score percentiles ─────────────────────────

col_proto, col_perc = st.columns(2)

with col_proto:
    st.subheader("Protocol mix (all flows)")
    if has_flows and "protocol_type" in flows_df.columns:
        proto = flows_df["protocol_type"].map(
            lambda x: PROTO_NAMES.get(int(x) if pd.notna(x) else 0, f"Proto {int(x) if pd.notna(x) else '?'}")
        ).value_counts()
        fig5 = px.pie(
            names=proto.index, values=proto.values, hole=0.4,
            color_discrete_sequence=["#6366f1", "#22c55e", "#f97316", "#888"],
        )
        fig5.update_layout(**DARK_LAYOUT, showlegend=True)
        st.plotly_chart(fig5, use_container_width=True)
    else:
        st.info("Waiting for flow data.")

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

        col_a, col_b, col_c = st.columns(3)
        col_a.metric("Mean score",  f"{scores.mean():.4f}")
        col_b.metric("p90 score",   f"{scores.quantile(0.90):.4f}")
        col_c.metric("p99 score",   f"{scores.quantile(0.99):.4f}")
    else:
        st.info("Waiting for scored flows.")

# ── Row 5: Signature rule hits ───────────────────────────────────────────────

st.divider()
st.subheader("Signature rule hits")

if has_alerts and "signature_match" in alerts_df.columns:
    sig_hits = (
        alerts_df["signature_match"]
        .dropna()
        .str.split(":", n=1).str[0]   # rule name before the colon
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

# ── Footer ────────────────────────────────────────────────────────────────────

st.caption(
    f"Refreshes every {REFRESH}s  ·  "
    f"Alert log: {ALERT_LOG}  ·  "
    f"Flow log: {FLOW_LOG}"
)

time.sleep(REFRESH)
st.rerun()
