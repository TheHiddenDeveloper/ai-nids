"""
================================================================================
API DATA UTILITIES — DB + Redis Queries for REST Endpoints
================================================================================
Purpose:
  Helper functions used by api/main.py endpoints to query SQLite and Redis
  for alerts, flows, incidents, comparison stats, and firewall commands.

Functions:
  load_from_db(table, limit, offset)  — H3: fetch paginated records
  count_rows(table)                   — H3: total count for pagination header
  load_incidents(limit)               — fetch incident mapping from SQLite
  get_comparison_stats()              — current_24h vs prev_24h metrics
  send_firewall_command(action, ip)   — Redis pub/sub to FirewallEngine

Design:
  - Read-only connections via file: URI to avoid WAL SHM contention when
    the monitor (root) and API (non-root) share the same SQLite DB.
  - get_comparison_stats(): H2 — queries structured columns (severity) for
    high/medium count, not raw_json parsing
  - send_firewall_command() publishes to "nids:commands" Redis channel
  - All functions handle missing DB gracefully (return empty lists/None)
================================================================================
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

# URI for read-only access — avoids WAL SHM contention with root-owned DB
_DB_URI = f"file:{DB_PATH.resolve()}?mode=ro"


def _get_ro_conn() -> sqlite3.Connection:
    """Open a read-only SQLite connection via file: URI."""
    return sqlite3.connect(_DB_URI, uri=True, check_same_thread=False)


def load_from_db(table: str, limit: int = 2000, offset: int = 0) -> list:
    """H3: fetch records from SQLite with offset/limit pagination."""
    if not DB_PATH.exists():
        return []
    try:
        conn = _get_ro_conn()
        cur = conn.cursor()
        cur.execute(
            f"SELECT raw_json FROM {table} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = cur.fetchall()
        conn.close()
        if not rows:
            return []
        records = [json.loads(r[0]) for r in reversed(rows)]
        return records
    except Exception as e:
        logger.error(f"Error loading {table}: {e}")
        return []

def count_rows(table: str) -> int:
    """H3: return total row count for pagination header."""
    if not DB_PATH.exists():
        return 0
    try:
        conn = _get_ro_conn()
        cur = conn.cursor()
        cur.execute(f"SELECT count(*) FROM {table}")
        row = cur.fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception as e:
        logger.error(f"Error counting {table}: {e}")
        return 0

def load_incidents(limit: int = 100) -> list:
    """Fetch incidents mapping."""
    if not DB_PATH.exists():
        return []
    try:
        conn = _get_ro_conn()
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
        conn = _get_ro_conn()
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
        
        # Critical alerts (High/Medium) — query structured column (H2)
        cur.execute("SELECT count(*) FROM alerts WHERE timestamp >= ? AND severity IN ('high', 'medium')", (c24,))
        cur_high = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM alerts WHERE timestamp >= ? AND timestamp < ? AND severity IN ('high', 'medium')", (p24, c24))
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
