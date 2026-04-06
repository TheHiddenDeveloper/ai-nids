"""
Flow Logger
-----------
Persists raw flow feature records and inference results to a SQLite database.
"""

import json
import time
from loguru import logger

from .db import get_db_connection

# Reusing the dictionary serialization logic using a custom encoder for NumPy types
import numpy as np

class _NumpySafeEncoder(json.JSONEncoder):
    """Converts numpy scalars and arrays to native Python types."""
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, np.bool_):
            return bool(obj)
        return super().default(obj)

def _dumps(record: dict) -> str:
    return json.dumps(record, cls=_NumpySafeEncoder)

class FlowLogger:
    """Logs enriched flow records (features + alert info) to SQLite."""

    def __init__(self):
        self.conn = get_db_connection()

    def log(self, record: dict):
        timestamp = time.time()
        record["_logged_at"] = timestamp
        
        src_ip = record.get("_src_ip")
        dst_ip = record.get("dst_ip") or record.get("_dst_ip") # sometimes the extractor maps it differently, fallback check
        dst_port = record.get("dst_port")
        score = record.get("score")
        
        raw_json = _dumps(record)
        
        self.conn.execute(
            "INSERT INTO flows (timestamp, src_ip, dst_ip, dst_port, score, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, src_ip, dst_ip, dst_port, score, raw_json)
        )

    def log_batch(self, records: list):
        if not records:
            return
            
        timestamp = time.time()
        rows = []
        for record in records:
            record["_logged_at"] = timestamp
            
            src_ip = record.get("_src_ip")
            dst_ip = record.get("dst_ip") or record.get("_dst_ip")
            dst_port = record.get("dst_port")
            score = record.get("score")
            raw_json = _dumps(record)
            
            rows.append((timestamp, src_ip, dst_ip, dst_port, score, raw_json))
            
        self.conn.executemany(
            "INSERT INTO flows (timestamp, src_ip, dst_ip, dst_port, score, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
            rows
        )


class AlertLogger:
    """Logs confirmed alerts to the SQLite database."""

    def __init__(self):
        self.conn = get_db_connection()

    def log_alert(self, alert: dict):
        timestamp = time.time()
        alert["_alerted_at"] = timestamp
        
        severity = alert.get("severity", "?")
        src_ip = alert.get("_src_ip")
        src_port = alert.get("_src_port")
        dst_ip = alert.get("_dst_ip")
        dst_port = alert.get("_dst_port")
        score = alert.get("score")
        label = alert.get("label")
        sig_match = alert.get("signature_match")
        suppression_note = alert.get("suppression_note")
        
        raw_json = _dumps(alert)
        
        self.conn.execute(
            "INSERT INTO alerts (timestamp, severity, src_ip, src_port, dst_ip, dst_port, score, label, signature_match, suppression_note, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, severity, src_ip, src_port, dst_ip, dst_port, score, label, sig_match, suppression_note, raw_json)
        )
        
        logger.warning(
            f"[ALERT] {severity.upper()} | "
            f"{src_ip}:{src_port} → "
            f"{dst_ip}:{dst_port} | "
            f"score={score if score is not None else 0:.3f} | label={label or '?'}"
        )

    def recent(self, n: int = 50) -> list:
        """Return last n alerts by selecting them from the SQLite DB."""
        try:
            cursor = self.conn.execute(
                "SELECT raw_json FROM alerts ORDER BY timestamp DESC LIMIT ?", 
                (n,)
            )
            rows = cursor.fetchall()
            # Rows are returned latest-first, reverse to match exact old list semantics
            return [json.loads(row[0]) for row in reversed(rows)]
        except Exception as e:
            logger.error(f"Failed to read recent alerts: {e}")
            return []
