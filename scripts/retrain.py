"""
================================================================================
ONLINE RETRAINER — Periodic Background Model Updates
================================================================================
Purpose:
  Periodically retrains the Random Forest and Autoencoder on a mix of:
  - Confirmed alert records from live data (labelled as attack)
  - Recent benign flow records (labelled as benign)
  Updates model registry with new version entries.

  Can run as a one-shot script or as a background scheduler thread.

Usage:
  python scripts/retrain.py --once
  python scripts/retrain.py --interval 3600   # retrain every hour
  python scripts/retrain.py --min-new-alerts 50

Design:
  - RT1: AE retrained on benign-only subset alongside RF
  - RT2: registry.json updated with new version entry
  - RT3: 20% of online data held out for evaluation
  - RT4: data stratified across time chunks to avoid single-source overfit
  - RT5: backs up existing models before overwriting
  - Retrain history logged to data/models/retrain_history.jsonl
  - O2: prefers SQLite over JSONL for data loading
  - RetrainScheduler: background thread that checks and retrains on interval
  - min_alert_score threshold (default 0.80) avoids FP contamination of training
================================================================================
"""

import sys
import json
import time
import shutil
import argparse
import threading
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pandas as pd
import joblib
from loguru import logger
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support

from core.features import FEATURE_COLS


# ── Data loading ──────────────────────────────────────────────────────────────

def load_jsonl_flows(path: Path, label: int, max_rows: int = 5000, min_score: float = None) -> pd.DataFrame:
    """Load JSONL flow log, tag with binary label, return feature DataFrame."""
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    try:
        lines = path.read_text().strip().split("\n")
        lines = [l for l in lines if l][-max_rows:]
        records = [json.loads(l) for l in lines]
        df = pd.DataFrame(records)

        if min_score is not None and "score" in df.columns:
            before = len(df)
            df = df[df["score"] >= min_score]
            kept = len(df)
            if kept < before:
                logger.info(f"Filtered attacks by score >= {min_score}: {kept}/{before} kept")

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
    min_alert_score: float = 0.80,
    db_path:     Optional[Path] = None,
) -> tuple:
    """
    Build X, y arrays from:
      - alerts (label=1, attack — filtered by min_alert_score)
      - flows  (label=0, benign — filtered by score < 0.3)

    O2: reads from SQLite (db_path) if available, falls back to JSONL.
    RT4: stratify by sampling across time chunks to avoid single-source overfit.
    Returns (X, y) or (None, None) if insufficient data.
    """
    attacks = load_jsonl_flows(alert_log, label=1, max_rows=max_alerts, min_score=min_alert_score)
    all_flows = load_jsonl_flows(flow_log, label=0, max_rows=max_benign * 3)

    # O2: prefer reading from SQLite
    if db_path and db_path.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            # Load attacks (alerts with score >= min_alert_score)
            df_attacks_sql = pd.read_sql_query(
                f"SELECT raw_json FROM alerts WHERE score >= ? ORDER BY timestamp DESC LIMIT ?",
                conn, params=(min_alert_score, max_alerts)
            )
            df_benign_sql = pd.read_sql_query(
                "SELECT raw_json FROM flows WHERE score < 0.3 ORDER BY timestamp DESC LIMIT ?",
                conn, params=(max_benign,)
            )
            conn.close()
            if not df_attacks_sql.empty:
                attack_records = [json.loads(r["raw_json"]) for _, r in df_attacks_sql.iterrows()]
                attacks = pd.DataFrame(attack_records)
                attacks["is_attack"] = 1
                logger.info(f"Loaded {len(attacks)} attack rows from SQLite")
            if not df_benign_sql.empty:
                benign_records = [json.loads(r["raw_json"]) for _, r in df_benign_sql.iterrows()]
                all_flows = pd.DataFrame(benign_records)
                all_flows["is_attack"] = 0
                logger.info(f"Loaded {len(all_flows)} benign rows from SQLite")
        except Exception as e:
            logger.warning(f"SQLite read failed, using JSONL fallback: {e}")

    if not all_flows.empty and "score" in all_flows.columns:
        benign = all_flows[all_flows["score"] < 0.3].head(max_benign)
    else:
        benign = all_flows.head(max_benign) if not all_flows.empty else pd.DataFrame()

    if attacks.empty and benign.empty:
        logger.warning("No online data available for retraining.")
        return None, None

    # RT4: stratified sampling — take evenly across time buckets
    for df_part, name in [(attacks, "attacks"), (benign, "benign")]:
        if not df_part.empty and "_logged_at" in df_part.columns:
            try:
                df_part["_time_bucket"] = pd.qcut(df_part["_logged_at"], q=min(4, len(df_part)), labels=False, duplicates="drop")
                sampled = df_part.groupby("_time_bucket", group_keys=False).apply(lambda g: g.sample(min(len(g), max(1, int(len(df_part) * 0.25))), random_state=42))
                if not sampled.empty:
                    df_part = sampled.reset_index(drop=True)
            except Exception:
                pass

    combined = pd.concat([attacks, benign], ignore_index=True)

    available = [c for c in FEATURE_COLS if c in combined.columns]
    missing = [c for c in FEATURE_COLS if c not in combined.columns]
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

def _train_ae_online(X_benign, model_dir: Path, epochs=20):
    """RT1: retrain AE on benign-only online data."""
    try:
        import tensorflow as tf
        from tensorflow import keras
    except ImportError:
        logger.warning("TensorFlow not available — skipping AE retrain.")
        return

    scaler = StandardScaler()
    X_s = scaler.fit_transform(X_benign)
    nf = X_s.shape[1]

    inputs = keras.Input(shape=(nf,))
    x = keras.layers.Dense(64, activation="relu")(inputs)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(32, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(16, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(8, activation="relu")(x)
    x = keras.layers.Dense(16, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(32, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(64, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    outputs = keras.layers.Dense(nf, activation="linear")(x)

    ae = keras.Model(inputs, outputs)
    ae.compile(optimizer=keras.optimizers.Adam(learning_rate=0.001), loss="mse")
    ae.fit(X_s, X_s, epochs=epochs, batch_size=64, validation_split=0.1, verbose=0)

    reconstructions = ae.predict(X_s, verbose=0)
    mse = np.mean(np.power(X_s - reconstructions, 2), axis=1)
    threshold = float(np.percentile(mse, 95.0))

    ae.save(str(model_dir / "autoencoder.keras"))
    joblib.dump(scaler, model_dir / "ae_scaler.joblib")
    joblib.dump(threshold, model_dir / "ae_threshold.joblib")
    cal_data = {"mse_mean": float(np.mean(mse)), "mse_std": float(np.std(mse))}
    joblib.dump(cal_data, model_dir / "ae_calibration.joblib")
    logger.info(f"AE retrained and saved to {model_dir}/")


def retrain(
    alert_log:  Path,
    flow_log:   Path,
    model_dir:  Path,
    min_alerts: int = 20,
    min_alert_score: float = 0.80,
    reg_version: str = None,
    db_path:    Optional[Path] = None,
) -> bool:
    """
    Retrain RF + AE on online data.
    RT3: hold out 20% for evaluation.
    RT1: AE trained on benign-only subset + saved with updated calibration.
    Returns True if retrain happened.
    """
    # O2: count alerts from SQLite first, then fall back to JSONL
    n_alerts = 0
    if db_path and db_path.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM alerts WHERE score >= ?", (min_alert_score,))
            n_alerts = cursor.fetchone()[0]
            conn.close()
        except Exception:
            pass
    if n_alerts == 0 and alert_log.exists():
        n_alerts = sum(1 for l in alert_log.read_text().split("\n") if l.strip())

    if n_alerts < min_alerts:
        logger.info(f"Retraining skipped: only {n_alerts} alerts (need {min_alerts}).")
        return False

    X, y = build_online_dataset(alert_log, flow_log, model_dir, min_alert_score=min_alert_score, db_path=db_path)
    if X is None or len(X) < 50:
        logger.warning("Insufficient data for retraining.")
        return False

    # Backup
    model_path  = model_dir / "nids_model.joblib"
    scaler_path = model_dir / "scaler.joblib"
    backup_dir  = model_dir / "backups"
    backup_dir.mkdir(exist_ok=True)
    ts = int(time.time())
    for src in [model_path, scaler_path]:
        if src.exists():
            shutil.copy(src, backup_dir / f"{src.name}_{ts}.joblib")
    logger.info(f"Backed up existing models → {backup_dir}/")

    # RT3: holdout 20% for evaluation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info(f"Retrain split: train={len(X_train)}, holdout={len(X_test)}")

    # ── RF retrain ──
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    logger.info("Retraining Random Forest on online data...")
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=15, n_jobs=-1,
        random_state=42, class_weight="balanced",
    )
    rf.fit(X_train_s, y_train)

    # ── AE retrain (RT1) ──
    X_benign_train = X_train[y_train == 0]
    if len(X_benign_train) >= 100:
        _train_ae_online(X_benign_train, model_dir, epochs=20)

    # ── Evaluate on holdout ──
    y_pred = rf.predict(X_test_s)
    logger.info("Holdout evaluation:\n" +
                classification_report(y_test, y_pred, target_names=["Benign", "Attack"], zero_division=0))

    accuracy = float(accuracy_score(y_test, y_pred))
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)

    # ── Save ──
    joblib.dump(rf, model_path)
    joblib.dump(scaler, scaler_path)
    # Also update feature metadata for hash consistency
    meta_path = model_dir / "feature_metadata.joblib"
    fhash = hashlib.md5(":".join(FEATURE_COLS).encode()).hexdigest()
    joblib.dump({"feature_hash": fhash, "feature_cols": list(FEATURE_COLS)}, meta_path)

    # ── Update registry (RT2) ──
    version_name = reg_version or f"retrain_{ts}"
    version_dir = model_dir / "versions" / version_name
    version_dir.mkdir(parents=True, exist_ok=True)
    for art in ["nids_model.joblib", "scaler.joblib", "autoencoder.keras",
                "ae_scaler.joblib", "ae_threshold.joblib"]:
        src = model_dir / art
        if src.exists():
            shutil.copy(src, version_dir / art)

    registry_path = model_dir / "registry.json"
    registry = []
    if registry_path.exists():
        try:
            with open(registry_path) as f:
                registry = json.load(f)
        except Exception:
            registry = []
    for reg in registry:
        reg["status"] = "available"
    registry.append({
        "version": version_name,
        "timestamp": ts,
        "accuracy": accuracy,
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "eval_source": "online_retrain",
        "eval_note": f"Holdout evaluation on {len(X_test)} online samples",
        "data_sources": {"retrain_attacks": int(y.sum()), "retrain_benign": int((y==0).sum())},
        "status": "deployed",
    })
    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)
    logger.info(f"Registry updated → {registry_path} (version={version_name})")

    # Retrain log
    log_entry = {
        "timestamp": ts, "n_samples": int(len(X_train)),
        "n_attacks": int(y_train.sum()), "n_benign": int((y_train==0).sum()),
        "holdout_accuracy": accuracy, "holdout_f1": float(f1),
        "version": version_name,
    }
    retrain_log = model_dir / "retrain_history.jsonl"
    with open(retrain_log, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

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
        alert_log:       str = "data/alerts.jsonl",
        flow_log:        str = "data/flows.jsonl",
        model_dir:       str = "data/models",
        interval_secs:   int = 3600,
        min_alerts:      int = 50,
        min_alert_score: float = 0.80,
        db_path:         Optional[str] = None,
    ):
        self.alert_log       = Path(alert_log)
        self.flow_log        = Path(flow_log)
        self.model_dir       = Path(model_dir)
        self.interval        = interval_secs
        self.min_alerts      = min_alerts
        self.min_alert_score = min_alert_score
        self.db_path         = Path(db_path) if db_path else None
        self._stop           = threading.Event()
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
                    self.model_dir, self.min_alerts, self.min_alert_score,
                    db_path=self.db_path,
                )
            except Exception as e:
                logger.error(f"RetrainScheduler error: {e}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AI-NIDS online retrainer")
    parser.add_argument("--once",             action="store_true",  help="Retrain once and exit")
    parser.add_argument("--interval",         type=int, default=3600, help="Retrain interval in seconds")
    parser.add_argument("--min-new-alerts",   type=int,   default=50,   help="Min alerts before retraining")
    parser.add_argument("--min-alert-score",  type=float, default=0.80, help="Min score to consider alert a real attack (avoids FP contamination)")
    parser.add_argument("--alert-log",  default="data/alerts.jsonl")
    parser.add_argument("--flow-log",   default="data/flows.jsonl")
    parser.add_argument("--model-dir",  default="data/models")
    parser.add_argument("--db-path",    default=None, help="SQLite DB path for online data (preferred over JSONL)")
    args = parser.parse_args()

    alert_log = Path(args.alert_log)
    flow_log  = Path(args.flow_log)
    model_dir = Path(args.model_dir)
    db_path   = Path(args.db_path) if args.db_path else None

    if args.once:
        logger.info("Running one-shot retrain...")
        success = retrain(alert_log, flow_log, model_dir, args.min_new_alerts, args.min_alert_score, db_path=db_path)
        logger.info("Done." if success else "Retrain skipped — see above.")
        return

    logger.info(f"Retrain loop: every {args.interval}s, min {args.min_new_alerts} alerts, min_score={args.min_alert_score}")
    scheduler = RetrainScheduler(
        alert_log       = str(alert_log),
        flow_log        = str(flow_log),
        model_dir       = str(model_dir),
        interval_secs   = args.interval,
        min_alerts      = args.min_new_alerts,
        min_alert_score = args.min_alert_score,
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
