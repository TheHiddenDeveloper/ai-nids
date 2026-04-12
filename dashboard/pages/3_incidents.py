import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
import pandas as pd
from dashboard.utils.data import load_incidents, send_firewall_command, get_redis_client, fmt_uptime

st.set_page_config(page_title="AI-NIDS | Incidents", page_icon=":material/local_fire_department:", layout="wide")

st.title("Active Incidents Engine")

incidents_df = load_incidents(limit=100)
redis_conn = get_redis_client()

st.subheader("Correlation Engine: Detected Incidents")
if not incidents_df.empty:
    for idx, row in incidents_df.iterrows():
        with st.container():
            sc1, sc2, sc3, sc4 = st.columns([2, 1, 1, 2])
            sev_label = row['max_severity'].lower()
            
            # Map severity to sensible material icons
            sev_symbols = {"high": ":material/gpp_bad:", "medium": ":material/warning:", "low": ":material/security:"}
            icon = sev_symbols.get(sev_label, ":material/info:")
            status_icon = ":material/circle:" if row['status'] == 'active' else ":material/inventory_2:"
            
            # Enrichment
            country = row.get("country", "Unknown")
            city = row.get("city", "")
            loc_str = f"{city}, {country}" if city else country
            
            malicious_badge = " **[MALICIOUS]**" if row.get('threat_level') == 'high' else ""
            
            sc1.markdown(f"### {status_icon} {icon} {row['src_ip']}{malicious_badge}")
            sc1.caption(f":material/location_on: {loc_str}")
            
            sc2.metric("Alerts Mapped", row['alert_count'])
            sc2.caption(f"Status: {row['status'].capitalize()}")
            
            duration = row['end_time'] - row['start_time']
            dur_str = fmt_uptime(duration) if duration > 0 else "Instant"
            
            sc4.markdown(f"**Max Severity:** `{sev_label.upper()}`  \n**Duration:** `{dur_str}`")
            if row.get('asn'):
                sc4.caption(f"Organization: {row['asn']}")
            
            src_ip = row['src_ip']
            is_blocked = False
            if redis_conn:
                is_blocked = redis_conn.sismember("nids:blocked:ips", src_ip)
            
            if not is_blocked:
                if st.button(f"BAN ATTACKER: {src_ip}", key=f"ban_{src_ip}_{row['id']}", type="primary", icon=":material/block:"):
                    send_firewall_command("block", src_ip)
                    st.rerun()
            else:
                st.success(f"ENTITY {src_ip} PROVISIONALLY DROPPED", icon=":material/shield:")
            
            st.divider()
else:
    st.info("No incidents detected yet. The correlator groups alerts from the same IP into incidents.")
