"""
================================================================================
DATABASE LAYER — SQLite Auto-Init + Schema
================================================================================
Purpose:
  Manages the SQLite database (data/nids.db) with auto-initialization on first
  import. Schema includes flows, alerts, and incidents tables with automatic
  migration support for new columns.

Usage:
  from monitor.db import get_db_connection, clear_db_data, cleanup_old_data
  conn = get_db_connection()  # lazily initializes schema

Tables:
  flows     — timestamp, src_ip, dst_ip, dst_port, score, direction, raw_json
  alerts    — timestamp, severity, src_ip/port, dst_ip/port, score, label,
              signature_match, suppression_note, direction, incident_id,
              country, city, asn, threat_level, raw_json
  incidents — start/end_time, src_ip, alert_count, max_severity, status,
              country, city, asn, threat_level, raw_data

Design:
  - Schema auto-creates on first get_db_connection() call (import-time init)
  - WAL journal mode + NORMAL synchronous for concurrent read performance
  - init_db() runs migrations: adds missing columns via ALTER TABLE IF NOT EXISTS
  - clear_db_data(): wipes all tables + truncates JSONL log files (used by tests)
  - cleanup_old_data(retention_days): S1 — DELETE rows older than retention, then VACUUM
  - check_same_thread=False allows cross-thread connections from pipeline + API
================================================================================
"""

import sqlite3
import threading
from pathlib import Path

DB_PATH = Path("data/nids.db")
_db_initialized = False
_db_init_lock = threading.Lock()


def get_db_connection() -> sqlite3.Connection:
    """Returns a thread-safe, WAL-enabled SQLite connection.
    Lazily initializes the schema on first call."""
    global _db_initialized
    if not _db_initialized:
        with _db_init_lock:
            if not _db_initialized:
                DB_PATH.parent.mkdir(parents=True, exist_ok=True)
                init_db()
                _db_initialized = True
    
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    """Initializes the database schema if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                score REAL,
                direction TEXT,
                raw_json TEXT
            )
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                severity TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                score REAL,
                label TEXT,
                signature_match TEXT,
                suppression_note TEXT,
                direction TEXT,
                incident_id INTEGER,
                country TEXT,
                city TEXT,
                asn TEXT,
                threat_level TEXT,
                raw_json TEXT
            )
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time REAL,
                end_time REAL,
                src_ip TEXT,
                alert_count INTEGER DEFAULT 0,
                max_severity TEXT,
                status TEXT DEFAULT 'active',
                country TEXT,
                city TEXT,
                asn TEXT,
                threat_level TEXT,
                raw_data TEXT
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents(src_ip);
        """)

        # Migration: Add direction column if it doesn't exist
        columns_flows = [c[1] for c in conn.execute("PRAGMA table_info(flows)").fetchall()]
        if "direction" not in columns_flows:
            conn.execute("ALTER TABLE flows ADD COLUMN direction TEXT")
        
        columns_alerts = [c[1] for c in conn.execute("PRAGMA table_info(alerts)").fetchall()]
        if "direction" not in columns_alerts:
            conn.execute("ALTER TABLE alerts ADD COLUMN direction TEXT")
        if "incident_id" not in columns_alerts:
            conn.execute("ALTER TABLE alerts ADD COLUMN incident_id INTEGER")
        
        # Threat Intel columns for alerts
        new_cols = ["country", "city", "asn", "threat_level"]
        for col in new_cols:
            if col not in columns_alerts:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
                
        # Threat Intel columns for incidents
        columns_incidents = [c[1] for c in conn.execute("PRAGMA table_info(incidents)").fetchall()]
        for col in new_cols:
            if col not in columns_incidents:
                conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} TEXT")

def clear_db_data():
    """Wipes all data from flows and alerts tables, and truncates log files."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM flows")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM incidents")
        
        for filename in ["data/flows.jsonl", "data/alerts.jsonl", "data/nids.log"]:
            p = Path(filename)
            if p.exists():
                p.write_text("")
                
        return True
    except Exception as e:
        print(f"Failed to clear data: {e}")
        return False


def cleanup_old_data(retention_days: int = 30):
    """S1: delete rows older than retention_days, then VACUUM."""
    conn = get_db_connection()
    cutoff = time.time() - retention_days * 86400
    try:
        with conn:
            conn.execute("DELETE FROM flows WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
        # VACUUM outside the transaction to avoid blocking
        conn.execute("VACUUM")
        return True
    except Exception as e:
        print(f"Failed to cleanup old data: {e}")
        return False
