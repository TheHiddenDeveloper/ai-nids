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
import logging
from logging.handlers import RotatingFileHandler
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


def get_rotating_logger(name: str, filepath: str, max_mb: int = 50, backups: int = 5) -> logging.Logger:
    """Creates a basic python logger mapped strictly to a rolling file."""
    p = Path(filepath)
    p.parent.mkdir(parents=True, exist_ok=True)
    
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    log.propagate = False
    
    if not log.handlers:
        handler = RotatingFileHandler(
            filepath, 
            maxBytes=max_mb * 1024 * 1024, 
            backupCount=backups
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(handler)
        
    return log


class FlowLogger:
    """Logs enriched flow records (features + alert info) safely to disk."""

    def __init__(self, log_path: str = "data/flows.jsonl"):
        self.log_path = log_path
        self._logger = get_rotating_logger("flow_logger", log_path)

    def log(self, record: dict):
        record["_logged_at"] = time.time()
        self._logger.info(_dumps(record))

    def log_batch(self, records: list):
        for record in records:
            record["_logged_at"] = time.time()
            self._logger.info(_dumps(record))


class AlertLogger:
    """Logs confirmed alerts to a separate JSONL file."""

    def __init__(self, alert_path: str = "data/alerts.jsonl"):
        self.alert_path = Path(alert_path)
        self._logger = get_rotating_logger("alert_logger", str(self.alert_path))

    def log_alert(self, alert: dict):
        alert["_alerted_at"] = time.time()
        self._logger.info(_dumps(alert))
        logger.warning(
            f"[ALERT] {alert.get('severity', '?').upper()} | "
            f"{alert.get('_src_ip')}:{alert.get('_src_port')} → "
            f"{alert.get('_dst_ip')}:{alert.get('_dst_port')} | "
            f"score={alert.get('score', 0):.3f} | label={alert.get('label', '?')}"
        )

    def recent(self, n: int = 50) -> list:
        """Return last n alerts. Safely scans the current active file."""
        if not self.alert_path.exists():
            return []
        try:
            lines = self.alert_path.read_text().strip().split("\n")
            lines = [l for l in lines if l]
            return [json.loads(l) for l in lines[-n:]]
        except Exception as e:
            logger.error(f"Failed to read recent alerts: {e}")
            return []
