"""
Flow Logger
-----------
Persists raw flow feature records and inference results to disk.
Supports JSONL (append-friendly) format.

Includes a numpy-safe JSON encoder so int64/float32 values from the
feature extractor serialize correctly without crashing.
"""

import json
import time
import numpy as np
from pathlib import Path
from loguru import logger


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
    """Logs enriched flow records (features + alert info) to JSONL."""

    def __init__(self, log_path: str = "data/flows.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, record: dict):
        record["_logged_at"] = time.time()
        with open(self.log_path, "a") as f:
            f.write(_dumps(record) + "\n")

    def log_batch(self, records: list):
        with open(self.log_path, "a") as f:
            for record in records:
                record["_logged_at"] = time.time()
                f.write(_dumps(record) + "\n")


class AlertLogger:
    """Logs confirmed alerts to a separate JSONL file."""

    def __init__(self, alert_path: str = "data/alerts.jsonl"):
        self.alert_path = Path(alert_path)
        self.alert_path.parent.mkdir(parents=True, exist_ok=True)

    def log_alert(self, alert: dict):
        alert["_alerted_at"] = time.time()
        with open(self.alert_path, "a") as f:
            f.write(_dumps(alert) + "\n")
        logger.warning(
            f"[ALERT] {alert.get('severity', '?').upper()} | "
            f"{alert.get('_src_ip')}:{alert.get('_src_port')} → "
            f"{alert.get('_dst_ip')}:{alert.get('_dst_port')} | "
            f"score={alert.get('score', 0):.3f} | label={alert.get('label', '?')}"
        )

    def recent(self, n: int = 50) -> list:
        """Return last n alerts from the log file."""
        if not self.alert_path.exists():
            return []
        lines = self.alert_path.read_text().strip().split("\n")
        lines = [l for l in lines if l]
        return [json.loads(l) for l in lines[-n:]]
