import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from dashboard.utils.data import load_from_db, get_comparison_stats, subscribe_live_events, fmt_uptime
from dashboard.components.metrics import draw_metric_card, draw_alert_ticker, SEV_COLOR
from dashboard.components.charts import draw_sankey, draw_intensity_heatmap, draw_threat_map, DARK_LAYOUT
import time

st.set_page_config(page_title="AI-NIDS | Overview", page_icon=":material/dashboard:", layout="wide")
subscribe_live_events()

# Pre-fetch data
alerts_df = load_from_db("alerts", limit=2000)
flows_df = load_from_db("flows", limit=5000)

has_alerts = not alerts_df.empty
has_flows = not flows_df.empty

# Filter to match global functionality if session state holds filters
sev_filter = st.session_state.get('sev_filter', ["high", "medium", "low"])

if has_alerts and "severity" in alerts_df.columns:
    alerts_df = alerts_df[alerts_df["severity"].isin(sev_filter)]
    has_alerts = not alerts_df.empty

total_flows = len(flows_df) if has_flows else 0
total_alerts = len(alerts_df) if has_alerts else 0
high_count = len(alerts_df[alerts_df["severity"].isin(["high", "medium"])]) if has_alerts and "severity" in alerts_df.columns else 0
attack_rate = "0.0%"
if total_flows > 0:
    attack_rate = f"{(total_alerts / total_flows) * 100:.1f}%"

start_time = st.session_state.get('start_time', time.time())
uptime_str = fmt_uptime(time.time() - start_time)

st.title("Network Overview")

# ── KPI row ───────────────────────────────────────────────────────────────────

# Calculate Trends
comp = get_comparison_stats()
def get_delta(key):
    if not comp: return None
    cur, prev = comp[key]
    if prev == 0: return 100.0 if cur > 0 else 0.0
    return ((cur - prev) / prev) * 100.0

k1, k2, k3, k4, k5, k6 = st.columns(6)
with k1: draw_metric_card("Total Traffic", f"{total_flows:,}", "swap_calls", "#6366f1", delta=get_delta("flows"))
with k2: draw_metric_card("Total Alerts",  f"{total_alerts:,}", "campaign", "#f59e0b", delta=get_delta("alerts"), invert_delta=True)
with k3: draw_metric_card("Critical Hits", f"{high_count:,}", "local_fire_department", "#ef4444", delta=get_delta("high"), invert_delta=True)
with k4: draw_metric_card("Threat %",      attack_rate, "query_stats", "#ef4444" if total_alerts > 10 else "#10b981")
with k5: draw_metric_card("Monitoring",    f"{len(sev_filter)} types", "travel_explore", "#10b981")
with k6: draw_metric_card("Session Uptime", uptime_str, "timer", "#a855f7")

st.markdown("<br>", unsafe_allow_html=True)
draw_alert_ticker(alerts_df)
st.markdown("<br>", unsafe_allow_html=True)

# Row 1: Timeline and Maps
col_tl, col_tr = st.columns([3, 2])
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
        st.plotly_chart(fig, use_container_width=True, key="main_timeline")
    else:
        st.info("No matching alerts found.")

with col_tr:
    st.subheader("Global Attack Hotspots")
    draw_threat_map(alerts_df)

# Row 2: Sankey and Heatmap
col_sk, col_hm = st.columns([2, 3])
with col_sk:
    st.subheader("Network Traffic Flow")
    draw_sankey(flows_df)

with col_hm:
    st.subheader("Attack Intensity")
    draw_intensity_heatmap(alerts_df)

# Row 3: Sources
col_pie, col_bar = st.columns([2, 3])
with col_pie:
    st.subheader("Severity breakdown")
    if has_alerts and "severity" in alerts_df.columns:
        sev = alerts_df["severity"].value_counts()
        fig2 = go.Figure(go.Pie(labels=sev.index.tolist(), values=sev.values.tolist(), hole=0.6,
                                marker_colors=[SEV_COLOR.get(s, "#888") for s in sev.index],
                                textinfo="label+percent", textfont_size=11))
        fig2.update_layout(**DARK_LAYOUT)
        fig2.update_layout(showlegend=False, margin=dict(t=0, b=0, l=0, r=0))
        st.plotly_chart(fig2, use_container_width=True, key="severity_pie")
    else:
        st.info("No severity data available.")
        
with col_bar:
    st.subheader("Top alert sources")
    if has_alerts and "_src_ip" in alerts_df.columns:
        top = alerts_df["_src_ip"].value_counts().head(5).reset_index().rename(columns={"_src_ip": "Source IP", "count": "Alerts"})
        fig4 = px.bar(top, x="Alerts", y="Source IP", orientation="h", color="Alerts", color_continuous_scale="Reds")
        fig4.update_layout(**DARK_LAYOUT)
        fig4.update_layout(yaxis={"autorange": "reversed"}, height=250, coloraxis_showscale=False)
        st.plotly_chart(fig4, use_container_width=True, key="top_sources_bar")
    else:
        st.info("Waiting for alerts.")
