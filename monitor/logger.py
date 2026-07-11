"""
================================================================================
LOGGERS — SQLite Persistence for Flows + Alerts
================================================================================
Purpose:
  Persists enriched flow records and confirmed alerts to the SQLite database.
  These are the dual persistence layer alongside the event bus (Redis/pub-sub
  for real-time consumers, SQLite for historical query by the API).

Usage:
  flow_logger = FlowLogger()
  flow_logger.log(record) / log_batch(records)

  alert_logger = AlertLogger()
  alert_logger.log_alert(alert_dict)
  recent_alerts = alert_logger.recent(n=50)

Design:
  - FlowLogger.log_batch() uses executemany for batch inserts (better perf)
  - AlertLogger.log_alert() also prints a formatted log line via logger.warning
  - Both use NumpyEncoder for safe JSON serialization of raw_json field
  - alert_logger.recent() reads from SQLite descending by timestamp, returns
    in chronological order (reversed for compatibility)
  - No JSONL file writes here — JSONL path is deprecated (legacy only)
================================================================================
"""

import json
import time
from loguru import logger

from .db import get_db_connection
from core.json_utils import NumpyEncoder

def _dumps(record: dict) -> str:
    return json.dumps(record, cls=NumpyEncoder)

_FLOW_INSERT = "INSERT INTO flows (timestamp, src_ip, dst_ip, dst_port, score, direction, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?)"


def _flow_row(record: dict, timestamp: float) -> tuple:
    """Extract flow DB columns from a record dict, with key fallback."""
    record["_logged_at"] = timestamp
    return (
        timestamp,
        record.get("_src_ip"),
        record.get("dst_ip") or record.get("_dst_ip"),
        record.get("dst_port"),
        record.get("score"),
        record.get("direction"),
        _dumps(record),
    )


class FlowLogger:
    """Logs enriched flow records (features + alert info) to SQLite."""

    def __init__(self):
        self.conn = get_db_connection()

    def log(self, record: dict):
        self.conn.execute(_FLOW_INSERT, _flow_row(record, time.time()))
        self.conn.commit()

    def log_batch(self, records: list):
        if not records:
            return
        timestamp = time.time()
        rows = [_flow_row(r, timestamp) for r in records]
        self.conn.executemany(_FLOW_INSERT, rows)
        self.conn.commit()


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
        direction = alert.get("direction")
        incident_id = alert.get("incident_id")
        country = alert.get("country")
        city = alert.get("city")
        asn = alert.get("asn")
        threat_level = alert.get("threat_level")
        
        raw_json = _dumps(alert)
        
        self.conn.execute(
            "INSERT INTO alerts (timestamp, severity, src_ip, src_port, dst_ip, dst_port, score, label, signature_match, suppression_note, direction, incident_id, country, city, asn, threat_level, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, severity, src_ip, src_port, dst_ip, dst_port, score, label, sig_match, suppression_note, direction, incident_id, country, city, asn, threat_level, raw_json)
        )
        self.conn.commit()
        
        logger.warning(
            f"[ALERT] {severity.upper()} | "
            f"{src_ip}:{src_port} → "
            f"{dst_ip}:{dst_port} | "
            f"score={'?' if score is None else f'{score:.3f}'} | label={label or '?'}"
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
