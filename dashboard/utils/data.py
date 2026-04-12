"""
Dashboard Data Utilities
------------------------
Handles DB connections, Redis interactions, and API payloads
for the UI layer.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import sqlite3
import json
import time
import pandas as pd
import streamlit as st
from datetime import datetime
from pathlib import Path
from loguru import logger

from core.event_bus import bus
from core.redis_client import get_redis_client

def load_from_db(table: str, limit: int = 2000) -> pd.DataFrame:
    """Fetch recent records from SQLite natively, parsing JSON."""
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
    except Exception as e:
        logger.error(f"Error loading {table}: {e}")
        return pd.DataFrame()

def load_incidents(limit: int = 100) -> pd.DataFrame:
    """Fetch incidents mapping."""
    db_path = Path("data/nids.db")
    if not db_path.exists():
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query(f"SELECT * FROM incidents ORDER BY end_time DESC LIMIT {limit}", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def get_comparison_stats() -> dict:
    """Returns (current_24h, prev_24h) for key metrics."""
    db_path = Path("data/nids.db")
    if not db_path.exists(): return None
    
    try:
        conn = sqlite3.connect(db_path)
        now = time.time()
        c24 = now - 86400
        p24 = c24 - 86400
        
        cur = conn.cursor()
        
        # Flows
        cur.execute("SELECT count(*) FROM flows WHERE timestamp >= ?", (c24,))
        cur_flows = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM flows WHERE timestamp >= ? AND timestamp < ?", (p24, c24))
        prev_flows = cur.fetchone()[0]
        
        # Alerts
        cur.execute("SELECT count(*) FROM alerts WHERE timestamp >= ?", (c24,))
        cur_alerts = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM alerts WHERE timestamp >= ? AND timestamp < ?", (p24, c24))
        prev_alerts = cur.fetchone()[0]
        
        # Critical alerts (High/Medium)
        cur.execute("SELECT count(*) FROM alerts WHERE timestamp >= ? AND (raw_json LIKE '%\"severity\": \"high\"%' OR raw_json LIKE '%\"severity\": \"medium\"%')", (c24,))
        cur_high = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM alerts WHERE timestamp >= ? AND timestamp < ? AND (raw_json LIKE '%\"severity\": \"high\"%' OR raw_json LIKE '%\"severity\": \"medium\"%')", (p24, c24))
        prev_high = cur.fetchone()[0]
        
        conn.close()
        return {
            "flows": (cur_flows, prev_flows),
            "alerts": (cur_alerts, prev_alerts),
            "high": (cur_high, prev_high)
        }
    except Exception as e:
        logger.error(f"Error getting config stats: {e}")
        return None

def fmt_uptime(secs: float) -> str:
    h, rem = divmod(int(secs), 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"

def send_firewall_command(action, ip):
    """Sends a block/unblock command to the FirewallEngine via Redis."""
    redis = get_redis_client()
    if redis:
        try:
            cmd = {"action": action, "ip": ip}
            redis.publish("nids:commands", json.dumps(cmd))
            st.toast(f"RULE EMITTED: {action.upper()} {ip}", icon=":material/security:")
        except Exception as e:
            st.error(f"Firewall Communication Error: {e}")
    else:
        st.error("Redis disconnected. Cannot send commands.")

def subscribe_live_events():
    """Subscribe to Redis Pub/Sub if not already subscribed."""
    if "console_logs" not in st.session_state:
        st.session_state.console_logs = []
    if "engine_stats" not in st.session_state:
        st.session_state.engine_stats = {}

    def live_log_handler(alert):
        ts = datetime.now().strftime("%H:%M:%S")
        sev = alert.get("severity", "low")
        icon = "🛡️" if sev == "low" else "⚠️" if sev == "medium" else "🔥"
        msg = f"{icon} [{ts}] {alert.get('label', 'ALERT')} | {alert.get('_src_ip', '?')} -> {alert.get('_dst_ip', '?')} ({alert.get('signature_match', 'Unknown Sig')})"
        st.session_state.console_logs.append(msg)
        if len(st.session_state.console_logs) > 40:
            st.session_state.console_logs.pop(0)

    def live_stats_handler(stats):
        st.session_state.engine_stats = stats

    if "subscribed" not in st.session_state:
        bus.subscribe("alert", live_log_handler)
        bus.subscribe("stats", live_stats_handler)
        st.session_state.subscribed = True
