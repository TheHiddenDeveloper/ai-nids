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

import sys
from pathlib import Path

# Add project root to path so 'monitor' can be imported
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import time
import math
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ── Paths ─────────────────────────────────────────────────────────────────────
ALERT_LOG  = Path("data/alerts.jsonl")
FLOW_LOG   = Path("data/flows.jsonl")

# ── Data helpers ──────────────────────────────────────────────────────────────

import sqlite3
from monitor.db import clear_db_data

@st.cache_data(ttl=1)  # cache lightly for UI interactions
def load_from_db(table: str, limit: int = 2000) -> pd.DataFrame:
    db_path = Path("data/nids.db")
    if not db_path.exists():
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(db_path)
        # Fast indexed limit query
        df_raw = pd.read_sql_query(f"SELECT raw_json FROM {table} ORDER BY timestamp DESC LIMIT {limit}", conn)
        conn.close()
        
        if df_raw.empty:
            return pd.DataFrame()
            
        # Parse JSON and reverse to restore chronological time-series order
        records = [json.loads(j) for j in df_raw["raw_json"].iloc[::-1]]
        return pd.DataFrame(records)
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


SEV_COLOR = {"high": "#ef4444", "medium": "#f59e0b", "low": "#10b981"}
SEV_ICON  = {"high": "🔥", "medium": "⚠️", "low": "🛡️"}

DARK_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font_color="#aab",
    margin=dict(t=40, b=10, l=10, r=10),
    xaxis=dict(gridcolor="#222", zeroline=False),
    yaxis=dict(gridcolor="#222", zeroline=False),
)

def draw_metric_card(label: str, value: str, icon: str, color: str = "#10b981"):
    st.markdown(f"""
    <div style="
        background: rgba(30, 41, 59, 0.4);
        padding: 1.25rem;
        border-radius: 12px;
        border-top: 1px solid rgba(255,255,255,0.1);
        border-left: 4px solid {color};
        backdrop-filter: blur(12px);
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        margin-bottom: 1rem;
    ">
        <div style="color: #64748b; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.2px; font-weight: 600;">{label}</div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 0.5rem;">
            <div style="font-size: 1.7rem; font-weight: 700; color: #f1f5f9; font-family: 'Inter', sans-serif;">{value}</div>
            <div style="font-size: 1.4rem; opacity: 0.8;">{icon}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def draw_alert_ticker(df):
    if df.empty: return
    recent = df.sort_values("_alerted_at", ascending=False).head(8)
    items = []
    for _, row in recent.iterrows():
        sev = row.get("severity", "low").upper()
        msg = row.get("signature_match") or f"Anomaly: {row.get('score', 0):.3f}"
        items.append(f"<span style='color:{SEV_COLOR.get(row.get('severity'), '#888')}; font-weight:bold;'>[{sev}]</span> {msg[:50]}...")
    
    ticker_html = f"""
    <div style="background: rgba(15, 23, 42, 0.6); padding: 8px 0; border-top: 1px solid #1e293b; border-bottom: 1px solid #1e293b; margin: 10px 0 25px 0; overflow: hidden; white-space: nowrap;">
        <div style="display: inline-block; animation: ticker-scroll 40s linear infinite;">
            {' &nbsp;&nbsp;&nbsp; • &nbsp;&nbsp;&nbsp; '.join(items)} &nbsp;&nbsp;&nbsp; • &nbsp;&nbsp;&nbsp; {' &nbsp;&nbsp;&nbsp; • &nbsp;&nbsp;&nbsp; '.join(items)}
        </div>
    </div>
    <style>
    @keyframes ticker-scroll {{
        0% {{ transform: translateX(0); }}
        100% {{ transform: translateX(-50%); }}
    }}
    </style>
    """
    st.markdown(ticker_html, unsafe_allow_html=True)


def draw_sankey(df):
    if df.empty or "_src_ip" not in df.columns: return
    links = df.groupby(["_src_ip", "_dst_ip"]).size().reset_index(name="value")
    top_src = links.groupby("_src_ip")["value"].sum().nlargest(6).index
    top_dst = links.groupby("_dst_ip")["value"].sum().nlargest(6).index
    links = links[links["_src_ip"].isin(top_src) & links["_dst_ip"].isin(top_dst)]
    
    all_nodes = list(pd.concat([links["_src_ip"], links["_dst_ip"]]).unique())
    node_map = {n: i for i, n in enumerate(all_nodes)}
    
    fig = go.Figure(data=[go.Sankey(
        node=dict(pad=15, thickness=20, line=dict(color="black", width=0.5), label=all_nodes, color="#10b981"),
        link=dict(source=links["_src_ip"].map(node_map), target=links["_dst_ip"].map(node_map), value=links["value"], color="rgba(16, 185, 129, 0.2)")
    )])
    fig.update_layout(title_text="Network Traffic Flow", font_size=10, **DARK_LAYOUT)
    st.plotly_chart(fig, use_container_width=True)

def draw_intensity_heatmap(df):
    if df.empty or "_alerted_at" not in df.columns: return
    tdf = df.copy()
    tdf["dt"] = pd.to_datetime(tdf["_alerted_at"], unit="s", utc=True)
    tdf["hour"] = tdf["dt"].dt.hour
    tdf["day"] = tdf["dt"].dt.day_name()
    
    days_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    pivot = tdf.groupby(["day", "hour"]).size().unstack(fill_value=0)
    pivot = pivot.reindex([d for d in days_order if d in pivot.index]).fillna(0)
    
    fig = px.imshow(pivot, labels=dict(x="Hour of Day", y="Day of Week", color="Alerts"), x=pivot.columns, y=pivot.index, color_continuous_scale="Viridis")
    fig.update_layout(**DARK_LAYOUT, height=250)
    fig.update_coloraxes(showscale=False)
    st.plotly_chart(fig, use_container_width=True)

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="AI-NIDS Dashboard",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
        background-color: #0f172a;
        color: #f1f5f9;
    }
    .stApp {
        background: radial-gradient(circle at 50% -20%, #1e293b 0%, #0f172a 100%);
    }
    
    /* Metrics Overrides */
    [data-testid="stMetricValue"]  { font-size: 1.8rem !important; font-weight: 700; color: #f8fafc; }
    [data-testid="stMetricLabel"]  { font-size: 0.85rem !important; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
    
    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        height: 45px;
        background-color: rgba(30, 41, 59, 0.5);
        border-radius: 8px 8px 0 0;
        border: 1px solid rgba(255,255,255,0.05);
        color: #94a3b8;
        padding: 0 20px;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(16, 185, 129, 0.1) !important;
        color: #10b981 !important;
        border-bottom: 2px solid #10b981 !important;
    }

    div[data-testid="column"] { padding: 0 8px; }
    
    /* Table styling */
    .stDataFrame { border: 1px solid rgba(255,255,255,0.05); border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar & Basic Controls ──────────────────────────────────────────────────
st.sidebar.title("🛡️ AI-NIDS Controls")
auto_refresh = st.sidebar.checkbox("Live Auto-Refresh", value=True, help="Toggle to pause log tailing")
refresh_rate = st.sidebar.slider("Refresh Rate (seconds)", 1, 60, 3, disabled=not auto_refresh)
history_lim  = st.sidebar.select_slider("Log History Size", options=[500, 1000, 2000, 5000, 10000], value=2000)
sev_filter   = st.sidebar.multiselect("Severity Filter", ["high", "medium", "low"], default=["high", "medium", "low"])

# ── Data Loading (Initial) ────────────────────────────────────────────────────
alerts_df = load_from_db("alerts", limit=history_lim)
flows_df  = load_from_db("flows",  limit=history_lim)

# ── Advanced Sidebar Filters (Require data) ───────────────────────────────────
st.sidebar.markdown("---")
st.sidebar.subheader("Advanced Filters")
all_ips = sorted(alerts_df["_src_ip"].dropna().unique().tolist()) if not alerts_df.empty else []
ip_filter = st.sidebar.multiselect("Filter by Source IP", all_ips)

all_sigs = []
if not alerts_df.empty and "signature_match" in alerts_df.columns:
    all_sigs = sorted(alerts_df["signature_match"].dropna().unique().tolist())
sig_filter = st.sidebar.multiselect("Filter by Signature", all_sigs)

# ── System Maintenance ────────────────────────────────────────────────────────
st.sidebar.markdown("---")
with st.sidebar.expander("🛠️ System Maintenance"):
    st.warning("Destructive Actions")
    confirm_wipe = st.checkbox("Confirm Data Wipe")
    if st.button("Wipe System Data", disabled=not confirm_wipe, type="primary"):
        if clear_db_data():
            st.success("Internal data wiped successfully!")
            time.sleep(1)
            st.rerun()
        else:
            st.error("Failed to wipe data. Check logs.")

# ── Apply Filtering ───────────────────────────────────────────────────────────
if not alerts_df.empty and "severity" in alerts_df.columns and sev_filter:
    alerts_df = alerts_df[alerts_df["severity"].isin(sev_filter)]

if not alerts_df.empty and ip_filter:
    alerts_df = alerts_df[alerts_df["_src_ip"].isin(ip_filter)]

if not alerts_df.empty and sig_filter:
    alerts_df = alerts_df[alerts_df["signature_match"].isin(sig_filter)]

has_alerts = not alerts_df.empty
has_flows  = not flows_df.empty

total_alerts  = len(alerts_df)
total_flows   = len(flows_df)
high_count    = int((alerts_df["severity"] == "high").sum()) if has_alerts and "severity" in alerts_df.columns else 0
attack_rate   = f"{total_alerts / max(total_flows, 1) * 100:.1f}%"

uptime_str = "—"
if has_alerts and "_alerted_at" in alerts_df.columns:
    ts = alerts_df["_alerted_at"].dropna()
    if len(ts) > 1:
        uptime_str = fmt_uptime(ts.max() - ts.min())

# ── Header ────────────────────────────────────────────────────────────────────

# Dynamic status header
sys_status = "SECURE"
status_color = "#10b981"
if total_alerts > 0:
    recent_count = len(alerts_df[alerts_df["_alerted_at"] > time.time() - 3600])
    if recent_count > 5:
        sys_status = "UNDER ATTACK"
        status_color = "#ef4444"
    elif recent_count > 0:
        sys_status = "WARNING"
        status_color = "#f59e0b"

col_title, col_time = st.columns([3, 1])
col_title.markdown(f"""
    <div style="display: flex; align-items: center; gap: 15px;">
        <h1 style="margin: 0; font-size: 2.2rem; font-weight: 800; letter-spacing: -1px; color: #f8fafc;">NETWORK COMMAND</h1>
        <div style="background: {status_color}22; color: {status_color}; border: 1px solid {status_color}44; 
                    padding: 6px 14px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; margin-top: 5px;">
            ● SYSTEM {sys_status}
        </div>
    </div>
""", unsafe_allow_html=True)

col_time.markdown(
    f"<div style='text-align:right;padding-top:10px;color:#64748b;font-size:12px; font-family:JetBrains Mono'>"
    f"NODE_SYS_CLK: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}</div>",
    unsafe_allow_html=True,
)

# ── Alert Ticker ──────────────────────────────────────────────────────────────
draw_alert_ticker(alerts_df)

# ── KPI row ───────────────────────────────────────────────────────────────────

k1, k2, k3, k4, k5, k6 = st.columns(6)
with k1: draw_metric_card("Total Traffic", f"{total_flows:,}", "📊", "#6366f1")
with k2: draw_metric_card("Total Alerts",  f"{total_alerts:,}", "🚨", "#f59e0b")
with k3: draw_metric_card("Critical Hits", f"{high_count:,}", "🔥", "#ef4444")
with k4: draw_metric_card("Threat %",      attack_rate, "📉", "#ef4444" if total_alerts > 10 else "#10b981")
with k5: draw_metric_card("Monitoring",    f"{len(sev_filter)} types", "🔍", "#10b981")
with k6: draw_metric_card("Session Uptime", uptime_str, "⏱️", "#a855f7")

st.markdown("<br>", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_overview, tab_alerts, tab_analytics = st.tabs(["📊 Overview", "🚨 Alerts Explorer", "📈 Analytics & ML"])

# == TAB 1: OVERVIEW ==
with tab_overview:
    # Row 1: Timeline and Sankey
    col_tl, col_sk = st.columns([3, 2])
    with col_tl:
        st.subheader("Alert timeline")
        if has_alerts and "_alerted_at" in alerts_df.columns and "severity" in alerts_df.columns:
            tdf = alerts_df[["_alerted_at", "severity"]].dropna().copy()
            tdf["time"] = pd.to_datetime(tdf["_alerted_at"], unit="s", utc=True)
            tdf = tdf.set_index("time").resample("30s")["severity"].count().reset_index()
            tdf.columns = ["time", "count"]
            fig = px.area(tdf, x="time", y="count", color_discrete_sequence=["#10b981"], labels={"count": "Alerts", "time": ""})
            fig.update_traces(line_width=2, fillcolor="rgba(16,185,129,0.1)")
            fig.update_layout(**DARK_LAYOUT)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No matching alerts found.")
    
    with col_sk:
        draw_sankey(flows_df)

    # Row 2: Severity and Intensity Heatmap
    col_sev, col_hm = st.columns([2, 3])
    with col_sev:
        st.subheader("Severity breakdown")
        if has_alerts and "severity" in alerts_df.columns:
            sev = alerts_df["severity"].value_counts()
            fig2 = go.Figure(go.Pie(labels=sev.index.tolist(), values=sev.values.tolist(), hole=0.6,
                                    marker_colors=[SEV_COLOR.get(s, "#888") for s in sev.index],
                                    textinfo="label+percent", textfont_size=11))
            fig2.update_layout(**DARK_LAYOUT)
            fig2.update_layout(showlegend=False, margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No severity data available.")
            
    with col_hm:
        st.subheader("Attack Intensity")
        draw_intensity_heatmap(alerts_df)

    # Row 3: Sources
    st.subheader("Top alert sources")
    if has_alerts and "_src_ip" in alerts_df.columns:
        top = alerts_df["_src_ip"].value_counts().head(5).reset_index().rename(columns={"_src_ip": "Source IP", "count": "Alerts"})
        fig4 = px.bar(top, x="Alerts", y="Source IP", orientation="h", color="Alerts", color_continuous_scale="Reds")
        fig4.update_layout(**DARK_LAYOUT)
        fig4.update_layout(yaxis={"autorange": "reversed"}, height=250, coloraxis_showscale=False)
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
            ).dt.strftime("%Y-%m-%d %H:%M:%S")
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
        st.info("No matching alerts. Check your filters or start the monitor.")

    st.markdown("---")
    st.subheader("🔍 Alert Object Inspector")
    if has_alerts:
        selected_ts = st.selectbox("Select Alert to Inspect (Time)", 
                                  options=display.index, 
                                  format_func=lambda x: f"{display.loc[x, 'time']} | {display.loc[x, '_src_ip']} → {display.loc[x, '_dst_ip']}")
        if selected_ts is not None:
            st.json(alerts_df.loc[selected_ts].to_dict())
    else:
        st.write("No alerts to inspect.")

# == TAB 3: ANALYTICS & ML ==
with tab_analytics:
    col_score, col_perc = st.columns([3, 2])
    with col_score:
        st.subheader("ML score distribution")
        if has_flows and "score" in flows_df.columns:
            fig3 = px.histogram(
                flows_df, x="score", nbins=60,
                color_discrete_sequence=["#10b981"],
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
                color_continuous_scale=["#10b981", "#f59e0b", "#f97316", "#ef4444"],
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
                fig7.update_layout(**DARK_LAYOUT)
                fig7.update_layout(yaxis={"autorange": "reversed"})
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
            fig5.update_layout(**DARK_LAYOUT)
            fig5.update_layout(yaxis={"autorange": "reversed", "type": "category"})
            st.plotly_chart(fig5, use_container_width=True)
        else:
            st.info("Waiting for flow data.")

# ── Footer ────────────────────────────────────────────────────────────────────

if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
