"""
FastAPI Data Utilities
----------------------
Handles DB connections, Redis interactions, and payload structuring
for the REST API.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import sqlite3
import json
import time
from loguru import logger
from core.redis_client import get_redis_client

DB_PATH = Path("data/nids.db")

def load_from_db(table: str, limit: int = 2000) -> list:
    """Fetch recent records from SQLite natively, returning parsed JSON list."""
    if not DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(f"SELECT raw_json FROM {table} ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        
        if not rows:
            return []
            
        # Parse JSON and reverse to restore chronological time-series order
        records = [json.loads(row[0]) for row in reversed(rows)]
        return records
    except Exception as e:
        logger.error(f"Error loading {table}: {e}")
        return []

def load_incidents(limit: int = 100) -> list:
    """Fetch incidents mapping."""
    if not DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM incidents ORDER BY end_time DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error loading incidents: {e}")
        return []

def get_comparison_stats() -> dict:
    """Returns (current_24h, prev_24h) for key metrics."""
    if not DB_PATH.exists(): return None
    
    try:
        conn = sqlite3.connect(DB_PATH)
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
        logger.error(f"Error getting comparison stats: {e}")
        return None

def send_firewall_command(action: str, ip: str) -> bool:
    """Sends a block/unblock command to the FirewallEngine via Redis."""
    redis = get_redis_client()
    if redis:
        try:
            cmd = {"action": action, "ip": ip}
            redis.publish("nids:commands", json.dumps(cmd))
            return True
        except Exception as e:
            logger.error(f"Firewall Communication Error: {e}")
            return False
    else:
        logger.error("Redis disconnected. Cannot send commands.")
        return False
