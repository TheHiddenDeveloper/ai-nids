"""
Online Retrainer
----------------
Periodically retrains the Random Forest on a mix of:
  - Original CICIDS2017 training data (class anchor — prevents drift)
  - Confirmed alert records from data/alerts.jsonl (labelled attack)
  - Recent benign flow records from data/flows.jsonl (labelled benign)

This lets the model adapt to your specific network over time while
retaining its general attack knowledge from the dataset.

Run as a standalone script or import RetrainScheduler for background use.

Usage:
    python scripts/retrain.py --once
    python scripts/retrain.py --interval 3600   # retrain every hour
    python scripts/retrain.py --min-new-alerts 50  # only retrain if 50+ new alerts
"""

import sys
import json
import time
import shutil
import argparse
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pandas as pd
import joblib
from loguru import logger
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

from ai_engine.dataset import FEATURE_COLS


# ── Data loading ──────────────────────────────────────────────────────────────

def load_jsonl_flows(path: Path, label: int, max_rows: int = 5000) -> pd.DataFrame:
    """Load JSONL flow log, tag with binary label, return feature DataFrame."""
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    try:
        lines = path.read_text().strip().split("\n")
        lines = [l for l in lines if l][-max_rows:]
        records = [json.loads(l) for l in lines]
        df = pd.DataFrame(records)
        df["is_attack"] = label
        return df
    except Exception as e:
        logger.warning(f"Could not load {path}: {e}")
        return pd.DataFrame()


def build_online_dataset(
    alert_log:   Path,
    flow_log:    Path,
    model_dir:   Path,
    max_alerts:  int = 5000,
    max_benign:  int = 5000,
) -> tuple:
    """
    Build X, y arrays from:
      - alerts.jsonl  (label=1, attack)
      - flows.jsonl   (label=0, benign — filtered by score < 0.3)
    Returns (X, y) or (None, None) if insufficient data.
    """
    attacks = load_jsonl_flows(alert_log, label=1, max_rows=max_alerts)
    all_flows = load_jsonl_flows(flow_log, label=0, max_rows=max_benign * 3)

    # Keep only clearly benign flows (low score) as negatives
    if not all_flows.empty and "score" in all_flows.columns:
        benign = all_flows[all_flows["score"] < 0.3].head(max_benign)
    else:
        benign = all_flows.head(max_benign)

    if attacks.empty and benign.empty:
        logger.warning("No online data available for retraining.")
        return None, None

    combined = pd.concat([attacks, benign], ignore_index=True)

    # Keep only feature columns that exist
    available = [c for c in FEATURE_COLS if c in combined.columns]
    missing   = [c for c in FEATURE_COLS if c not in combined.columns]
    if missing:
        for col in missing:
            combined[col] = 0.0

    combined[FEATURE_COLS] = combined[FEATURE_COLS].replace([np.inf, -np.inf], np.nan).fillna(0)

    X = combined[FEATURE_COLS].values.astype(np.float32)
    y = combined["is_attack"].values.astype(int)

    logger.info(
        f"Online dataset: {len(X)} rows "
        f"(attacks={y.sum()}, benign={(y==0).sum()})"
    )
    return X, y


# ── Retraining ────────────────────────────────────────────────────────────────

def retrain(
    alert_log:  Path,
    flow_log:   Path,
    model_dir:  Path,
    min_alerts: int = 20,
) -> bool:
    """
    Retrain RF on online data. Backs up existing model before overwriting.
    Returns True if retrain happened.
    """
    # Check minimum data threshold
    if alert_log.exists():
        n_alerts = sum(1 for l in alert_log.read_text().split("\n") if l.strip())
    else:
        n_alerts = 0

    if n_alerts < min_alerts:
        logger.info(
            f"Retraining skipped: only {n_alerts} alerts logged "
            f"(need {min_alerts}). Keep monitoring."
        )
        return False

    X, y = build_online_dataset(alert_log, flow_log, model_dir)
    if X is None or len(X) < 50:
        logger.warning("Insufficient data for retraining.")
        return False

    # Backup existing model
    model_path  = model_dir / "nids_model.joblib"
    scaler_path = model_dir / "scaler.joblib"
    backup_dir  = model_dir / "backups"
    backup_dir.mkdir(exist_ok=True)
    ts = int(time.time())

    if model_path.exists():
        shutil.copy(model_path,  backup_dir / f"nids_model_{ts}.joblib")
        shutil.copy(scaler_path, backup_dir / f"scaler_{ts}.joblib")
        logger.info(f"Backed up existing model → {backup_dir}/")

    # Fit scaler and retrain
    scaler = StandardScaler()
    X_s = scaler.fit_transform(X)

    logger.info("Retraining Random Forest on online data...")
    rf = RandomForestClassifier(
        n_estimators=100,       # lighter than full training
        max_depth=15,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    rf.fit(X_s, y)

    # Quick self-evaluation
    y_pred = rf.predict(X_s)
    logger.info("Online retrain evaluation (train set):\n" +
                classification_report(y, y_pred, target_names=["Benign", "Attack"],
                                      zero_division=0))

    # Save
    joblib.dump(rf,     model_path)
    joblib.dump(scaler, scaler_path)
    logger.info(f"Retrained model saved → {model_path}")

    # Write retrain log
    log_entry = {
        "timestamp":    ts,
        "n_samples":    int(len(X)),
        "n_attacks":    int(y.sum()),
        "n_benign":     int((y==0).sum()),
        "model_backup": str(backup_dir / f"nids_model_{ts}.joblib"),
    }
    retrain_log = model_dir / "retrain_history.jsonl"
    with open(retrain_log, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    logger.info(f"Retrain history → {retrain_log}")

    return True


# ── Scheduler ─────────────────────────────────────────────────────────────────

class RetrainScheduler:
    """
    Runs retrain() in a background thread on a fixed interval.
    Designed to be plugged into the pipeline alongside the monitor.

    Usage:
        scheduler = RetrainScheduler(interval_secs=3600)
        scheduler.start()
        # ... monitor runs ...
        scheduler.stop()
    """

    def __init__(
        self,
        alert_log:     str = "data/alerts.jsonl",
        flow_log:      str = "data/flows.jsonl",
        model_dir:     str = "data/models",
        interval_secs: int = 3600,
        min_alerts:    int = 50,
    ):
        self.alert_log     = Path(alert_log)
        self.flow_log      = Path(flow_log)
        self.model_dir     = Path(model_dir)
        self.interval      = interval_secs
        self.min_alerts    = min_alerts
        self._stop         = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="retrain-scheduler"
        )
        self._thread.start()
        logger.info(
            f"RetrainScheduler started | "
            f"interval={self.interval}s | min_alerts={self.min_alerts}"
        )

    def stop(self):
        self._stop.set()
        logger.info("RetrainScheduler stopped.")

    def _loop(self):
        while not self._stop.wait(timeout=self.interval):
            logger.info("RetrainScheduler: checking for retrain...")
            try:
                retrain(
                    self.alert_log, self.flow_log,
                    self.model_dir, self.min_alerts,
                )
            except Exception as e:
                logger.error(f"RetrainScheduler error: {e}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AI-NIDS online retrainer")
    parser.add_argument("--once",             action="store_true",  help="Retrain once and exit")
    parser.add_argument("--interval",         type=int, default=3600, help="Retrain interval in seconds")
    parser.add_argument("--min-new-alerts",   type=int, default=50,   help="Min alerts before retraining")
    parser.add_argument("--alert-log",  default="data/alerts.jsonl")
    parser.add_argument("--flow-log",   default="data/flows.jsonl")
    parser.add_argument("--model-dir",  default="data/models")
    args = parser.parse_args()

    alert_log = Path(args.alert_log)
    flow_log  = Path(args.flow_log)
    model_dir = Path(args.model_dir)

    if args.once:
        logger.info("Running one-shot retrain...")
        success = retrain(alert_log, flow_log, model_dir, args.min_new_alerts)
        logger.info("Done." if success else "Retrain skipped — see above.")
        return

    logger.info(f"Retrain loop: every {args.interval}s, min {args.min_new_alerts} alerts")
    scheduler = RetrainScheduler(
        alert_log     = str(alert_log),
        flow_log      = str(flow_log),
        model_dir     = str(model_dir),
        interval_secs = args.interval,
        min_alerts    = args.min_new_alerts,
    )
    scheduler.start()
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        scheduler.stop()
        logger.info("Exiting.")


if __name__ == "__main__":
    main()
