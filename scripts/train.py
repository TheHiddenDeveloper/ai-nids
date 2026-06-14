"""
Universal AI Trainer
--------------------
Unified command to train Random Forest and Deep Autoencoder models.
Combines seed data with live network traffic from SQLite.

Usage:
    python scripts/train.py --precision high
"""

import argparse
import pandas as pd
import numpy as np
import sqlite3
import json
import joblib
import sys
import os
from pathlib import Path

# ── Virtual Environment Check ────────────────────────────────────────────────
def check_venv():
    try:
        import loguru
    except ImportError:
        print("\033[91m" + "!" * 60 + "\033[0m")
        print("\033[91mERROR: Missing dependencies (loguru not found).\033[0m")
        print("\033[93mIt looks like you are not running this script inside the project virtual environment.\033[0m")
        print("\nFix:")
        print(f"  1. Use the explicit venv path: \033[1m./ai-venv/bin/python {sys.argv[0]}\033[0m")
        print("  2. Or activate the venv first: \033[1msource ai-venv/bin/activate && python {sys.argv[0]}\033[0m")
        print("\033[91m" + "!" * 60 + "\033[0m")
        sys.exit(1)

check_venv()

from loguru import logger
from sklearn.model_selection import train_test_split

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_engine.trainer import train_random_forest, train_autoencoder
from ai_engine.dataset import FEATURE_COLS, load_cicids2017

def fetch_live_data(db_path="data/nids.db"):
    """TD3: label flows via high-confidence alerts (score>=0.95) within a 30s window."""
    if not Path(db_path).exists():
        logger.warning(f"Database {db_path} not found. Skipping live data.")
        return pd.DataFrame()

    conn = sqlite3.connect(db_path)
    try:
        query = """
        SELECT DISTINCT f.raw_json,
               CASE WHEN a.score >= 0.95 THEN a.label ELSE 'BENIGN' END as alert_label
        FROM flows f
        LEFT JOIN alerts a ON 
            f.src_ip = a.src_ip AND 
            f.dst_ip = a.dst_ip AND 
            f.dst_port = a.dst_port AND
            ABS(f.timestamp - a.timestamp) < 30
        """
        df_raw = pd.read_sql_query(query, conn)
        
        live_features = []
        seen = set()
        for _, row in df_raw.iterrows():
            try:
                raw_data = json.loads(row['raw_json'])
                feat = {k: raw_data.get(k, 0) for k in FEATURE_COLS}
                feat['label'] = row['alert_label'] if row['alert_label'] else "BENIGN"
                # Deduplicate by feature tuple
                key = tuple(feat[k] for k in FEATURE_COLS)
                if key in seen:
                    continue
                seen.add(key)
                live_features.append(feat)
            except Exception:
                continue
        
        return pd.DataFrame(live_features)
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="AI-NIDS Model Trainer")
    parser.add_argument("--precision", type=str, default="high", choices=["standard", "high"])
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch_size", type=int, default=128)
    parser.add_argument("--learning_rate", type=float, default=0.001)
    parser.add_argument("--smote_ratio", type=float, default=1.0)
    parser.add_argument("--ae-threshold-percentile", type=float, default=95.0, help="EV3: percentile for AE anomaly threshold")
    parser.add_argument("--use-bootstrap", action="store_true", help="Include synthetic seed data from bootstrap_data.py")
    parser.add_argument("--use-pca", action="store_true", help="Apply PCA before AE training (FV1)")
    parser.add_argument("--pca-components", type=int, default=12, help="Number of PCA components (FV1)")
    args = parser.parse_args()

    # 1. Load Research Data (CICIDS2017)
    try:
        df_research = load_cicids2017()
        logger.info(f"Loaded {len(df_research):,} research samples (CICIDS2017).")
    except Exception as e:
        logger.error(f"Failed to load research data: {e}. Check scripts/fetch_cicids.py")
        return

    # 1b. Optionally load bootstrap seed data (TD2)
    df_bootstrap = pd.DataFrame()
    if args.use_bootstrap:
        boot_path = Path("data/training_seed.csv")
        if boot_path.exists():
            df_bootstrap = pd.read_csv(boot_path)
            logger.info(f"Loaded {len(df_bootstrap):,} bootstrap seed samples from {boot_path}")
        else:
            logger.warning(f"Bootstrap file not found at {boot_path}. Run scripts/bootstrap_data.py first.")

    # 2. Load Live Data
    df_live = fetch_live_data()
    sources = [df_research]
    if not df_bootstrap.empty:
        sources.append(df_bootstrap)
    if not df_live.empty:
        logger.info(f"Loaded {len(df_live):,} live samples from DB.")
        sources.append(df_live)
    df_combined = pd.concat(sources, ignore_index=True)

    # 3. Preprocess
    df_combined["is_attack"] = (df_combined["label"].str.upper() != "BENIGN").astype(int)
    
    # Clean data (NaN/Inf)
    df_combined.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_combined.dropna(inplace=True)
    
    X = df_combined[FEATURE_COLS].values.astype(np.float32)
    y = df_combined["is_attack"].values
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 4. Train Random Forest (Supervised)
    logger.info("+++ PHASE 1: Training Random Forest (Supervised) +++")
    rf_estimators = 500 if args.precision == "high" else 100
    rf, rf_scaler = train_random_forest(
        X_train, y_train, X_test, y_test,
        n_estimators=rf_estimators,
        smote_ratio=args.smote_ratio
    )

    # 5. Train Autoencoder (Unsupervised - Benign Only)
    logger.info("+++ PHASE 2: Training Semi-Supervised Autoencoder (Anomaly Detection) +++")
    X_benign = X_train[y_train == 0]
    ae, ae_threshold = train_autoencoder(
        X_benign, X_test, y_test,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        threshold_percentile=args.ae_threshold_percentile,
        use_pca=args.use_pca,
        pca_components=args.pca_components,
    )

    # 6. Evaluate overall Ensemble performance on test set
    logger.info("+++ PHASE 3: Evaluating Ensemble Performance +++")
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    import shutil
    import time
    
    model_dir = Path("data/models")
    
    # Read production weights from config.yaml so eval matches inference
    import yaml
    try:
        with open("config.yaml") as f:
            _cfg = yaml.safe_load(f) or {}
        _model_cfg = _cfg.get("model", {})
        rf_w = _model_cfg.get("rf_weight", 0.65)
        ae_w = _model_cfg.get("ae_weight", 0.35)
        cls_thresh = _model_cfg.get("anomaly_threshold", 0.5)
        logger.info(f"Using production weights from config: rf={rf_w}, ae={ae_w}, threshold={cls_thresh}")
    except Exception:
        rf_w, ae_w, cls_thresh = 0.65, 0.35, 0.5
        logger.warning("Could not read config.yaml, falling back to rf=0.65, ae=0.35")
    
    # Scale test set with RF scaler
    X_test_rf_s = rf_scaler.transform(X_test)
    rf_scores = rf.predict_proba(X_test_rf_s)[:, 1]
    
    # Load and score via AE if successfully trained
    ae_scaler = joblib.load(model_dir / "ae_scaler.joblib")
    X_test_ae_s = ae_scaler.transform(X_test)
    ae_reconstructions = ae.predict(X_test_ae_s, verbose=0)
    ae_mse = np.mean(np.power(X_test_ae_s - ae_reconstructions, 2), axis=1)
    ae_scores = np.clip(ae_mse / (ae_threshold * 3.0), 0.0, 1.0)
    
    # Combined Ensemble Score (weighted from config)
    ensemble_scores = rf_w * rf_scores + ae_w * ae_scores
    y_pred = (ensemble_scores >= cls_thresh).astype(int)
    
    accuracy = float(accuracy_score(y_test, y_pred))
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
    precision = float(precision)
    recall = float(recall)
    f1 = float(f1)
    
    logger.info(f"Ensemble Test Set Metrics:")
    logger.info(f"  Accuracy:  {accuracy:.4f}")
    logger.info(f"  Precision: {precision:.4f}")
    logger.info(f"  Recall:    {recall:.4f}")
    logger.info(f"  F1-Score:  {f1:.4f}")

    # EV2: per-class metrics using detailed labels
    try:
        if "label" in df_combined.columns:
            le_path = model_dir / "label_encoder.joblib"
            if le_path.exists():
                le = joblib.load(le_path)
            else:
                from sklearn.preprocessing import LabelEncoder
                le = LabelEncoder()
                le.fit(df_combined["label"])
                joblib.dump(le, le_path)
            y_true_labels = le.inverse_transform(y_test)
            per_class = {}
            from collections import defaultdict
            class_correct = defaultdict(int)
            class_total = defaultdict(int)
            for true_lbl, pred_lbl in zip(y_true_labels, y_pred):
                class_total[true_lbl] += 1
                if (pred_lbl == 1 and true_lbl != "BENIGN") or (pred_lbl == 0 and true_lbl == "BENIGN"):
                    class_correct[true_lbl] += 1
                else:
                    class_correct[true_lbl] += 0
            for label_name in sorted(class_total):
                acc = class_correct[label_name] / max(class_total[label_name], 1)
                per_class[label_name] = round(acc, 4)
            logger.info(f"Per-class accuracy: {per_class}")
    except Exception as e:
        logger.warning(f"EV2: per-class metrics unavailable: {e}")

    logger.success("--- MODELS TRAINED AND SAVED TO data/models/ ---")

    # 7. Versioning Registry
    ts = int(time.time())
    version_name = f"v_{ts}"
    version_dir = model_dir / "versions" / version_name
    version_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Saving model version → {version_dir}")
    artifacts = [
        "nids_model.joblib",
        "scaler.joblib",
        "autoencoder.keras",
        "ae_scaler.joblib",
        "ae_threshold.joblib"
    ]
    for art in artifacts:
        src = model_dir / art
        if src.exists():
            if src.is_dir():
                shutil.copytree(src, version_dir / art, dirs_exist_ok=True)
            else:
                shutil.copy(src, version_dir / art)
                
    # Update registry.json
    registry_path = model_dir / "registry.json"
    registry = []
    if registry_path.exists():
        try:
            with open(registry_path, "r") as f:
                registry = json.load(f)
        except Exception:
            registry = []
            
    # Mark other versions as not active
    for reg in registry:
        reg["status"] = "available"
        
    entry = {
        "version": version_name,
        "timestamp": ts,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "eval_source": "cicids2017_holdout",
        "eval_note": "Metrics are from CICIDS2017 test split only — live performance will differ",
        "data_sources": {
            "research": "CICIDS2017",
            "live_db": not df_live.empty,
        },
        "hyperparameters": {
            "precision": args.precision,
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "smote_ratio": args.smote_ratio
        },
        "status": "deployed"
    }
    registry.append(entry)
    
    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)
        
    logger.success(f"Registered model version {version_name} in {registry_path}")

if __name__ == "__main__":
    main()
