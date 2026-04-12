import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
import time
from pathlib import Path
from monitor.db import clear_db_data
from dashboard.utils.data import get_redis_client, send_firewall_command

st.set_page_config(page_title="AI-NIDS | Settings", page_icon=":material/settings:", layout="wide")

st.title("Settings & Maintenance")

# ── Health Section ────────────────────────────────────────────────────────
st.subheader("Engine Health")
redis_conn = get_redis_client()
redis_status = "Connected" if redis_conn else "Disconnected"
redis_icon = ":material/check_circle:" if redis_conn else ":material/error:"

# AI Status
rf_exists = Path("data/models/nids_model.joblib").exists()
ae_exists = Path("data/models/autoencoder.keras").exists()

if rf_exists and ae_exists:
    ai_status = "High-Precision Active"
    ai_icon = ":material/psychology:"
elif rf_exists:
    ai_status = "RF Only"
    ai_icon = ":material/shield:"
elif ae_exists:
    ai_status = "AE Only"
    ai_icon = ":material/search:"
else:
    ai_status = "Inactive"
    ai_icon = ":material/radio_button_unchecked:"

col1, col2 = st.columns(2)
with col1:
    st.info(f"**Redis Cache:** {redis_status}", icon=redis_icon)
with col2:
    st.info(f"**AI Engine:** {ai_status}", icon=ai_icon)

st.markdown("---")

# ── Firewall Rules ────────────────────────────────────────────────────────
st.subheader("Managed Blocked IPs")
if redis_conn:
    blocked_ips = redis_conn.smembers("nids:blocked:ips")
    if blocked_ips:
        for ip in sorted(list(blocked_ips)):
            bc1, bc2 = st.columns([3, 1])
            bc1.code(ip)
            if bc2.button("Unblock", key=f"unblock_{ip}", icon=":material/lock_open:"):
                send_firewall_command("unblock", ip)
                time.sleep(0.5)
                st.rerun()
    else:
        st.success("No active IP blocks.", icon=":material/check:")
else:
    st.error("Redis down — cannot fetch blocks.", icon=":material/cloud_off:")

st.markdown("---")

# ── System Maintenance ────────────────────────────────────────────────────
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
