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
                raw_json TEXT
            )
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        """)

# Initialize schema on module import
init_db()
