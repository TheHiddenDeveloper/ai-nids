import sqlite3
import json
from pathlib import Path

DB_PATH = Path("data/nids.db")

def get_db_connection() -> sqlite3.Connection:
    """Returns a thread-safe, WAL-enabled SQLite connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    # isolation_level=None sets autocommit mode
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    
    # Enable Write-Ahead Logging for high-concurrency read/writes
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")  # Speed optimization for WAL
    
    return conn

def init_db():
    """Initializes the database schema if it doesn't exist."""
    conn = get_db_connection()
    
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

# Initialize schema on module import
init_db()

def clear_db_data():
    """Wipes all data from flows and alerts tables, and truncates log files."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM flows")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM incidents")
            # Vacuum to reclaim space
            conn.execute("VACUUM")
        
        # Also clear jsonl files and log file
        for filename in ["data/flows.jsonl", "data/alerts.jsonl", "data/nids.log"]:
            p = Path(filename)
            if p.exists():
                p.write_text("")
                
        return True
    except Exception as e:
        print(f"Failed to clear data: {e}")
        return False
