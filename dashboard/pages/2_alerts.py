import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import json
import streamlit as st
import pandas as pd
from dashboard.utils.data import load_from_db, send_firewall_command, get_redis_client

st.set_page_config(page_title="AI-NIDS | Alerts Explorer", page_icon=":material/policy:", layout="wide")

st.title("Alerts Explorer")

# Filter Sidebar (Local to this page or global via session state? In multipage, local is cleaner but we can keep it here)
st.sidebar.subheader("Exploration Filters")
sev_filter = st.sidebar.multiselect("Severity", ["high", "medium", "low"], default=["high", "medium", "low"])

alerts_df = load_from_db("alerts", limit=2000)
has_alerts = not alerts_df.empty

if has_alerts and "severity" in alerts_df.columns:
    alerts_df = alerts_df[alerts_df["severity"].isin(sev_filter)]
    has_alerts = not alerts_df.empty

redis_conn = get_redis_client()

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

    if "time" in display.columns:
        display = display.sort_values("time", ascending=False)
        
    csv_data = display.to_csv(index=False).encode('utf-8')
    st.download_button("Download Alerts to CSV", data=csv_data, file_name="ai_nids_alerts.csv", mime="text/csv", icon=":material/download:")
    
    st.dataframe(
        display,
        use_container_width=True,
        hide_index=True,
        height=500,
    )
else:
    st.info("No matching alerts. Check your filters or start the monitor.")

st.markdown("---")
st.subheader("Alert Object Inspector")
if has_alerts:
    selected_ts = st.selectbox("Select Alert to Inspect (Time)", 
                              options=display.index, 
                              format_func=lambda x: f"{display.loc[x, 'time']} | {display.loc[x, '_src_ip']} → {display.loc[x, '_dst_ip']}")
    if selected_ts is not None:
        alert = alerts_df.loc[selected_ts]
        
        # AI Details Enrichment
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
            is_blocked = False
            if redis_conn:
                is_blocked = redis_conn.sismember("nids:blocked:ips", src_ip)
            
            if not is_blocked:
                if st.button(f"BAN IP: {src_ip}", type="primary", icon=":material/block:"):
                    send_firewall_command("block", src_ip)
            else:
                st.success(f"IP {src_ip} is currently BLOCKED.", icon=":material/gpp_bad:")
else:
    st.write("No alerts to inspect.")
