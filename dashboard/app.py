"""
AI-NIDS Live Dashboard
----------------------
Modular Application with Tabs using Material Symbols.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import time

from dashboard.utils.data import (
   load_from_db, load_incidents, get_comparison_stats, subscribe_live_events, 
   fmt_uptime, get_redis_client, send_firewall_command
)
from dashboard.components.metrics import draw_metric_card, draw_alert_ticker, SEV_COLOR
from dashboard.components.charts import draw_sankey, draw_intensity_heatmap, draw_threat_map, draw_port_distribution, DARK_LAYOUT
from monitor.db import clear_db_data

st.set_page_config(page_title="AI-NIDS Central", page_icon=":material/security:", layout="wide", initial_sidebar_state="expanded")
subscribe_live_events()

# Global CSS override
st.markdown("""
<style>
    .stApp { background-color: #0f172a; color: #f8fafc; font-family: 'Inter', sans-serif; }
    [data-testid="stMetricValue"]  { font-size: 1.8rem !important; font-weight: 700; color: #f8fafc; }
    [data-testid="stMetricLabel"]  { font-size: 0.85rem !important; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; background-color: transparent; }
    .stTabs [data-baseweb="tab"] { height: 45px; background-color: rgba(30, 41, 59, 0.5); border-radius: 8px 8px 0 0; border: 1px solid rgba(255,255,255,0.05); color: #94a3b8; padding: 0 20px; }
    .stTabs [aria-selected="true"] { background-color: rgba(16, 185, 129, 0.1) !important; color: #10b981 !important; border-bottom: 2px solid #10b981 !important; }
    div[data-testid="column"] { padding: 0 8px; }
    .stDataFrame { border: 1px solid rgba(255,255,255,0.05); border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

# ── Global Sidebar ─────────────────────────────────────────────────────────
st.sidebar.title("AI-NIDS Navigation")
st.sidebar.caption("Use the tabs on the right to navigate the main dashboard.")
auto_refresh = st.sidebar.checkbox("Live Auto-Refresh", value=True)
history_lim  = st.sidebar.select_slider("Log History Size", options=[500, 1000, 2000, 5000], value=2000)

st.sidebar.markdown("---")
st.sidebar.subheader("Global Filters")
sev_filter = st.sidebar.multiselect("Severity Filter", ["high", "medium", "low"], default=["high", "medium", "low"])

# ── Data Loading ───────────────────────────────────────────────────────────
alerts_df = load_from_db("alerts", limit=history_lim)
flows_df = load_from_db("flows", limit=5000)
incidents_df = load_incidents(limit=100)

has_alerts = not alerts_df.empty
has_flows = not flows_df.empty

if has_alerts and "severity" in alerts_df.columns:
    alerts_df = alerts_df[alerts_df["severity"].isin(sev_filter)]
    has_alerts = not alerts_df.empty

# ── Tabs Configuration ─────────────────────────────────────────────────────
tab_overview, tab_alerts, tab_incidents, tab_analytics, tab_settings = st.tabs([
    "Overview", "Alerts Explorer", "Active Incidents", "Analytics & ML", "Settings"
])

# ==============================================================================
# TAB 1: OVERVIEW
# ==============================================================================
with tab_overview:
    total_flows = len(flows_df) if has_flows else 0
    total_alerts = len(alerts_df) if has_alerts else 0
    high_count = len(alerts_df[alerts_df["severity"].isin(["high", "medium"])]) if has_alerts and "severity" in alerts_df.columns else 0
    attack_rate = "0.0%"
    if total_flows > 0:
        attack_rate = f"{(total_alerts / total_flows) * 100:.1f}%"
    
    start_time = st.session_state.get('start_time', time.time())
    uptime_str = fmt_uptime(time.time() - start_time)
    
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
    
    col_tl, col_tr = st.columns([3, 2])
    with col_tl:
        st.subheader("Alert timeline")
        if has_alerts and "_alerted_at" in alerts_df.columns and "severity" in alerts_df.columns:
            tdf = alerts_df[["_alerted_at", "severity"]].dropna().copy()
            tdf["time"] = pd.to_datetime(tdf["_alerted_at"], unit="s", utc=True)
            tdf = tdf.set_index("time").resample("30s")["severity"].count().reset_index()
            tdf.columns = ["time", "count"]
            if not tdf.empty:
                fig = px.area(tdf, x="time", y="count", color_discrete_sequence=["#10b981"], labels={"count": "Alerts", "time": ""})
                fig.update_traces(line_width=2, fillcolor="rgba(16,185,129,0.1)")
                fig.update_layout(**DARK_LAYOUT)
                st.plotly_chart(fig, use_container_width=True, key="main_timeline")
        else:
            st.info("No matching alerts found.")
            
    with col_tr:
        st.subheader("Attack Intensity")
        draw_intensity_heatmap(alerts_df)
        
    st.markdown("<hr style='opacity: 0.2;'>", unsafe_allow_html=True)
    st.subheader("Global Attack Hotspots")
    draw_threat_map(alerts_df)
        
    st.markdown("<hr style='opacity: 0.2;'>", unsafe_allow_html=True)
    col_pie, col_bar = st.columns([1, 2])
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
            fig4.update_yaxes(autorange="reversed")
            fig4.update_layout(height=250, coloraxis_showscale=False)
            st.plotly_chart(fig4, use_container_width=True, key="top_sources_bar")
        else:
            st.info("Waiting for alerts.")

    st.markdown("<hr style='opacity: 0.2;'>", unsafe_allow_html=True)
    st.subheader("Network Traffic Flow")
    draw_sankey(flows_df)

# ==============================================================================
# TAB 2: ALERTS EXPLORER
# ==============================================================================
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
            display["_alerted_at"] = pd.to_datetime(display["_alerted_at"], unit="s", utc=True).dt.strftime("%Y-%m-%d %H:%M:%S")
            display.rename(columns={"_alerted_at": "time"}, inplace=True)
            
        if "time" in display.columns:
            display = display.sort_values("time", ascending=False)
            
        if "score" in display.columns:
            display["score"] = display["score"].round(3)

        csv_data = display.to_csv(index=False).encode('utf-8')
        st.download_button("Download Alerts to CSV", data=csv_data, file_name="ai_nids_alerts.csv", mime="text/csv", icon=":material/download:")
        
        st.dataframe(display, use_container_width=True, hide_index=True, height=500)
    else:
        st.info("No matching alerts.")
        
    st.markdown("---")
    st.subheader("Alert Object Inspector")
    if has_alerts:
        display_idx = display.index if 'display' in locals() else alerts_df.index
        selected_ts = st.selectbox("Select Alert to Inspect (Time)", 
                                  options=display_idx, 
                                  format_func=lambda x: f"{alerts_df.loc[x, '_alerted_at']} | {alerts_df.loc[x, '_src_ip']} → {alerts_df.loc[x, '_dst_ip']}")
        if selected_ts is not None:
            alert = alerts_df.loc[selected_ts]
            try:
                raw_data = json.loads(alert.get("raw_json", "{}"))
                if "score" in raw_data:
                    st.markdown("### AI Analysis")
                    a1, a2, a3 = st.columns(3)
                    a1.metric("Ensemble Score", f"{raw_data.get('score', 0):.2%}")
                    a2.metric("RF Confidence", f"{raw_data.get('rf_score', 0):.2%}")
                    a3.metric("Anomaly Score", f"{raw_data.get('ae_score', 0):.2%}")
            except:
                pass
            
            st.json(alert.to_dict())
            
            src_ip = alert.get("_src_ip")
            if src_ip:
                redis_conn = get_redis_client()
                is_blocked = redis_conn.sismember("nids:blocked:ips", src_ip) if redis_conn else False
                
                if not is_blocked:
                    if st.button(f"BAN IP: {src_ip}", type="primary", icon=":material/block:"):
                        send_firewall_command("block", src_ip)
                else:
                    st.success(f"IP {src_ip} is currently BLOCKED.", icon=":material/gpp_bad:")
    else:
        st.write("No alerts to inspect.")

# ==============================================================================
# TAB 3: INCIDENTS
# ==============================================================================
with tab_incidents:
    st.subheader("Correlation Engine: Detected Incidents")
    redis_conn = get_redis_client()
    if not incidents_df.empty:
        for idx, row in incidents_df.iterrows():
            with st.container():
                sc1, sc2, sc3, sc4 = st.columns([2, 1, 1, 2])
                sev_label = row.get('max_severity', 'low').lower()
                sev_symbols = {"high": ":material/gpp_bad:", "medium": ":material/warning:", "low": ":material/security:"}
                icon = sev_symbols.get(sev_label, ":material/info:")
                status_icon = ":material/circle:" if row.get('status') == 'active' else ":material/inventory_2:"
                
                country = row.get("country", "Unknown")
                city = row.get("city", "")
                loc_str = f"{city}, {country}" if city else country
                malicious_badge = " **[MALICIOUS]**" if row.get('threat_level') == 'high' else ""
                
                sc1.markdown(f"### {status_icon} {icon} {row.get('src_ip')}{malicious_badge}")
                sc1.caption(f":material/location_on: {loc_str}")
                
                sc2.metric("Alerts Mapped", row.get('alert_count', 0))
                sc2.caption(f"Status: {row.get('status', 'unknown').capitalize()}")
                
                try:
                    duration = row['end_time'] - row['start_time']
                except:
                    duration = 0
                dur_str = fmt_uptime(duration) if duration > 0 else "Instant"
                
                sc4.markdown(f"**Max Severity:** `{sev_label.upper()}`  \n**Duration:** `{dur_str}`")
                if row.get('asn'):
                    sc4.caption(f"Organization: {row.get('asn')}")
                
                src_ip = row.get('src_ip')
                if src_ip:
                    is_blocked = redis_conn.sismember("nids:blocked:ips", src_ip) if redis_conn else False
                    if not is_blocked:
                        if st.button(f"BAN ATTACKER: {src_ip}", key=f"ban_{src_ip}_{row.get('id', idx)}", type="primary", icon=":material/block:"):
                            send_firewall_command("block", src_ip)
                            st.rerun()
                    else:
                        st.success(f"ENTITY {src_ip} PROVISIONALLY DROPPED", icon=":material/shield:")
                st.divider()
    else:
        st.info("No incidents detected yet. The correlator groups alerts from the same IP into incidents.")

# ==============================================================================
# TAB 4: ANALYTICS & ML
# ==============================================================================
with tab_analytics:
    st.subheader("ML score distribution")
    if has_flows and "score" in flows_df.columns:
        fig3 = px.histogram( flows_df, x="score", nbins=60, color_discrete_sequence=["#10b981"], labels={"score": "Attack probability score"})
        for thresh, color, name in [(0.65, "#facc15", "Low"), (0.80, "#f97316", "Medium"), (0.92, "#ef4444", "High")]:
            fig3.add_vline(x=thresh, line_dash="dash", line_color=color, line_width=1.5, annotation_text=name, annotation_font_color=color, annotation_position="top right")
        fig3.update_layout(**DARK_LAYOUT, showlegend=False)
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("Waiting for scored flows.")

    st.markdown("<hr style='opacity: 0.2;'>", unsafe_allow_html=True)
    
    col_port, col_perc = st.columns([3, 1])
    with col_port:
        st.subheader("Port Vulnerability Distribution")
        draw_port_distribution(flows_df)

    with col_perc:
        st.subheader("Score percentiles")
        if has_flows and "score" in flows_df.columns:
            scores = flows_df["score"].dropna()
            p_vals = [50, 75, 90, 95, 99]
            p_data = {f"p{p}": round(float(scores.quantile(p/100)), 4) for p in p_vals}
            p_df = pd.DataFrame({"Percentile": list(p_data.keys()), "Score": list(p_data.values())})
            st.dataframe(p_df, use_container_width=True, hide_index=True)
        else:
            st.info("N/A")

# ==============================================================================
# TAB 5: SETTINGS
# ==============================================================================
with tab_settings:
    st.subheader("Engine Health")
    redis_conn = get_redis_client()
    redis_status = "Connected" if redis_conn else "Disconnected"
    redis_icon = ":material/check_circle:" if redis_conn else ":material/error:"

    rf_exists = Path("data/models/nids_model.joblib").exists()
    ae_exists = Path("data/models/autoencoder.keras").exists()

    if rf_exists and ae_exists:
        ai_status, ai_icon = "High-Precision Active", ":material/psychology:"
    elif rf_exists:
        ai_status, ai_icon = "RF Only", ":material/shield:"
    elif ae_exists:
        ai_status, ai_icon = "AE Only", ":material/search:"
    else:
        ai_status, ai_icon = "Inactive", ":material/radio_button_unchecked:"

    col1, col2 = st.columns(2)
    with col1: st.info(f"**Redis Cache:** {redis_status}", icon=redis_icon)
    with col2: st.info(f"**AI Engine:** {ai_status}", icon=ai_icon)

    st.markdown("---")
    st.subheader("Managed Blocked IPs")
    if redis_conn:
        blocked_ips = redis_conn.smembers("nids:blocked:ips")
        if blocked_ips:
            for ip in sorted(list(blocked_ips)):
                bc1, bc2 = st.columns([3, 1])
                bc1.code(ip)
                if bc2.button("Unblock", key=f"unblock_settings_{ip}", icon=":material/lock_open:"):
                    send_firewall_command("unblock", ip)
                    time.sleep(0.5)
                    st.rerun()
        else:
            st.success("No active IP blocks.", icon=":material/check:")
    else:
        st.error("Redis down — cannot fetch blocks.", icon=":material/cloud_off:")

    st.markdown("---")
    st.subheader("System Maintenance")
    st.warning("Destructive Actions", icon=":material/warning:")
    confirm_wipe = st.checkbox("Confirm Data Wipe")
    if st.button("Wipe System Data", disabled=not confirm_wipe, type="primary", icon=":material/delete_forever:"):
        if clear_db_data():
            st.success("Internal data wiped successfully!")
            time.sleep(1)
            st.rerun()
        else:
            st.error("Failed to wipe data. Check logs.")

if auto_refresh:
    time.sleep(3)
    st.rerun()
