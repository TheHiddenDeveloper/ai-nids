"""
Migration Script
----------------
Converts legacy AI-NIDS .jsonl data to the new SQLite database.
"""

import json
from pathlib import Path
import sys

# Ensure project root is in PYTHONPATH
sys.path.append(str(Path(__file__).parent.parent))

from monitor.db import get_db_connection
from monitor.logger import _dumps

def migrate_file(filepath: str, table: str, limit: int = None):
    p = Path(filepath)
    if not p.exists() or p.stat().st_size == 0:
        print(f"File {filepath} not found or empty, skipping.")
        return 0

    conn = get_db_connection()
    count = 0
    with open(p, "r") as f:
        rows = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            timestamp = record.get("_logged_at") or record.get("_alerted_at") or 0.0
            src_ip = record.get("_src_ip")
            dst_ip = record.get("dst_ip") or record.get("_dst_ip")
            dst_port = record.get("dst_port") or record.get("_dst_port")
            score = record.get("score")
            raw_json = _dumps(record)

            if table == "flows":
                rows.append((timestamp, src_ip, dst_ip, dst_port, score, raw_json))
                if len(rows) >= 500:
                    conn.executemany("INSERT INTO flows (timestamp, src_ip, dst_ip, dst_port, score, raw_json) VALUES (?, ?, ?, ?, ?, ?)", rows)
                    count += len(rows)
                    rows = []
            elif table == "alerts":
                severity = record.get("severity", "?")
                src_port = record.get("_src_port")
                label = record.get("label")
                sig_match = record.get("signature_match")
                suppression_note = record.get("suppression_note")
                
                rows.append((timestamp, severity, src_ip, src_port, dst_ip, dst_port, score, label, sig_match, suppression_note, raw_json))
                if len(rows) >= 500:
                    conn.executemany("INSERT INTO alerts (timestamp, severity, src_ip, src_port, dst_ip, dst_port, score, label, signature_match, suppression_note, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
                    count += len(rows)
                    rows = []
                    
            if limit and count >= limit:
                break
                
        # Insert remaining
        if rows:
            if table == "flows":
                conn.executemany("INSERT INTO flows (timestamp, src_ip, dst_ip, dst_port, score, raw_json) VALUES (?, ?, ?, ?, ?, ?)", rows)
            elif table == "alerts":
                conn.executemany("INSERT INTO alerts (timestamp, severity, src_ip, src_port, dst_ip, dst_port, score, label, signature_match, suppression_note, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
            count += len(rows)

    print(f"Migrated {count} records into {table}.")
    return count

if __name__ == "__main__":
    print("Starting database migration...")
    
    # Try reading the alerts file
    migrate_file("data/alerts.jsonl", "alerts")
    # Try reading the flows file
    migrate_file("data/flows.jsonl", "flows")
    
    print("Migration complete!")
