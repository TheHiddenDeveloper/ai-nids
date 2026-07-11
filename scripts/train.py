"""
================================================================================
TRAIN — Unified Model Training (RF + Autoencoder)
================================================================================
Purpose:
  Trains the full ensemble (Random Forest + Autoencoder) on CICIDS2017 research
  data, optionally augmented with live data from SQLite and bootstrap seed data.
  Saves models, scalers, thresholds, feature metadata, version registry, and
  evaluates ensemble performance on a holdout test set.

  Also produces per-class accuracy metrics (EV2) and registers the version in
  data/models/registry.json.

Usage:
  python scripts/train.py --precision high
  python scripts/train.py --precision standard --epochs 5 --smote-ratio 0.5

Phases:
  1. Load CICIDS2017 research data (+ optional bootstrap + live data)
  2. Preprocess: combine, clean NaN/Inf, train/test split
  3. Train Random Forest (SMOTE-balanced)
  4. Train Autoencoder on benign-only subset
  5. Evaluate ensemble on test set (accuracy, precision, recall, F1, per-class)
  6. Version and register in data/models/registry.json

Design notes:
  - TD2: optional bootstrap seed data (data/training_seed.csv)
  - TD3: live data labeling via high-confidence alerts (score >= 0.95) within 30s window
  - FV1: optional PCA before AE training (--use-pca, --pca-components)
  - EV2: per-class accuracy using detailed LabelEncoder labels
  - Model registry: each training run creates a version directory with all artifacts
================================================================================
"""

import argparse
import pandas as pd
import numpy as np
import sqlite3
import json
import sys
import os
from pathlib import Path

# Suppress joblib/loky "cat not found" warning on WSL/minimal environments
# MUST be before import joblib, which triggers loky core detection at import time
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(os.cpu_count() or 4))

import joblib

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
from ai_engine.dataset import FEATURE_COLS, load_cicids2017, load_ciciot2023, load_all_datasets


def save_training_report(
    y_test, y_pred, ensemble_scores, rf_scores, ae_scores,
    accuracy, precision, recall, f1, version_name,
    per_class_acc=None, label_distribution=None, datasets_used=None,
):
    """
    Save a comprehensive training report after each run:
      - data/models/reports/{version}/report.json   (all metrics)
      - data/models/reports/{version}/confusion_matrix.png  (heatmap)
      - data/models/reports/{version}/classification_report.txt
    """
    from sklearn.metrics import (
        confusion_matrix, classification_report, roc_auc_score, roc_curve,
    )
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns

    report_dir = Path("data/models/reports") / version_name
    report_dir.mkdir(parents=True, exist_ok=True)

    # ── Confusion matrix ──────────────────────────────────────────────────
    cm = confusion_matrix(y_test, y_pred)
    cm_list = cm.tolist()

    # ── Classification report (per-class precision/recall/f1) ─────────────
    cls_report_str = classification_report(
        y_test, y_pred,
        target_names=["BENIGN", "ATTACK"],
        zero_division=0,
    )
    cls_report_dict = classification_report(
        y_test, y_pred,
        target_names=["BENIGN", "ATTACK"],
        output_dict=True,
        zero_division=0,
    )

    # ── AUC-ROC ───────────────────────────────────────────────────────────
    try:
        auc_roc = float(roc_auc_score(y_test, ensemble_scores))
    except Exception:
        auc_roc = None

    # ── Build JSON report ─────────────────────────────────────────────────
    report = {
        "version": version_name,
        "overall": {
            "accuracy": round(accuracy, 6),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1_score": round(f1, 6),
            "auc_roc": round(auc_roc, 6) if auc_roc is not None else None,
            "test_samples": int(len(y_test)),
            "attack_samples": int(y_test.sum()),
            "benign_samples": int(len(y_test) - y_test.sum()),
        },
        "confusion_matrix": {
            "labels": ["BENIGN", "ATTACK"],
            "matrix": cm_list,
            "tn": int(cm[0][0]),
            "fp": int(cm[0][1]),
            "fn": int(cm[1][0]),
            "tp": int(cm[1][1]),
        },
        "per_class": cls_report_dict,
    }
    if per_class_acc:
        report["per_class_accuracy"] = per_class_acc
    if label_distribution:
        report["attack_types"] = label_distribution
    if datasets_used:
        report["datasets_used"] = datasets_used

    with open(report_dir / "report.json", "w") as f:
        json.dump(report, f, indent=2)

    # ── Classification report (human-readable) ────────────────────────────
    with open(report_dir / "classification_report.txt", "w") as f:
        f.write(f"AI-NIDS Training Report — {version_name}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Accuracy:   {accuracy:.4f}\n")
        f.write(f"Precision:  {precision:.4f}\n")
        f.write(f"Recall:     {recall:.4f}\n")
        f.write(f"F1-Score:   {f1:.4f}\n")
        if auc_roc is not None:
            f.write(f"AUC-ROC:    {auc_roc:.4f}\n")
        f.write(f"\nTest samples: {len(y_test)} "
                f"(attack={int(y_test.sum())}, benign={int(len(y_test)-y_test.sum())})\n\n")
        f.write(cls_report_str)
        f.write(f"\nConfusion Matrix:\n")
        f.write(f"  TN={cm[0][0]}  FP={cm[0][1]}\n")
        f.write(f"  FN={cm[1][0]}  TP={cm[1][1]}\n")

    # ── Confusion matrix heatmap PNG ──────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Left: raw counts
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["BENIGN", "ATTACK"],
                yticklabels=["BENIGN", "ATTACK"],
                ax=axes[0])
    axes[0].set_xlabel("Predicted")
    axes[0].set_ylabel("Actual")
    axes[0].set_title("Confusion Matrix (Counts)")

    # Right: normalised (percentages)
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)
    sns.heatmap(cm_norm, annot=True, fmt=".2%", cmap="Blues",
                xticklabels=["BENIGN", "ATTACK"],
                yticklabels=["BENIGN", "ATTACK"],
                ax=axes[1])
    axes[1].set_xlabel("Predicted")
    axes[1].set_ylabel("Actual")
    axes[1].set_title("Confusion Matrix (Normalised)")

    fig.suptitle(f"AI-NIDS Ensemble — {version_name}", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(report_dir / "confusion_matrix.png", dpi=150, bbox_inches="tight")
    plt.close(fig)

    # ── ROC curve PNG ─────────────────────────────────────────────────────
    if auc_roc is not None:
        fpr, tpr, _ = roc_curve(y_test, ensemble_scores)
        fig2, ax2 = plt.subplots(figsize=(7, 6))
        ax2.plot(fpr, tpr, linewidth=2, label=f"Ensemble (AUC = {auc_roc:.4f})")

        # Also plot RF-only and AE-only ROC if scores available
        if rf_scores is not None:
            try:
                rf_auc = float(roc_auc_score(y_test, rf_scores))
                rf_fpr, rf_tpr, _ = roc_curve(y_test, rf_scores)
                ax2.plot(rf_fpr, rf_tpr, linewidth=1.5, linestyle="--",
                         label=f"RF only (AUC = {rf_auc:.4f})")
            except Exception:
                pass
        if ae_scores is not None:
            try:
                ae_auc = float(roc_auc_score(y_test, ae_scores))
                ae_fpr, ae_tpr, _ = roc_curve(y_test, ae_scores)
                ax2.plot(ae_fpr, ae_tpr, linewidth=1.5, linestyle=":",
                         label=f"AE only (AUC = {ae_auc:.4f})")
            except Exception:
                pass

        ax2.plot([0, 1], [0, 1], "k--", linewidth=1, alpha=0.5)
        ax2.set_xlabel("False Positive Rate")
        ax2.set_ylabel("True Positive Rate")
        ax2.set_title(f"ROC Curves — {version_name}")
        ax2.legend(loc="lower right")
        ax2.grid(True, alpha=0.3)
        fig2.tight_layout()
        fig2.savefig(report_dir / "roc_curve.png", dpi=150, bbox_inches="tight")
        plt.close(fig2)

    logger.info(f"Training report saved → {report_dir}/")
    return report_dir

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
    parser.add_argument("--dataset", type=str, nargs="+", default=["cicids2017"],
                        choices=["cicids2017", "ciciot2023", "both"],
                        help="Research dataset(s) to train on. 'both' = cicids2017 + ciciot2023")
    parser.add_argument("--ae-threshold-percentile", type=float, default=95.0, help="EV3: percentile for AE anomaly threshold")
    parser.add_argument("--use-bootstrap", action="store_true", help="Include synthetic seed data from bootstrap_data.py")
    parser.add_argument("--use-pca", action="store_true", help="Apply PCA before AE training (FV1)")
    parser.add_argument("--pca-components", type=int, default=12, help="Number of PCA components (FV1)")
    args = parser.parse_args()

    # 1. Load Research Data
    # Resolve 'both' shorthand
    dataset_names = args.dataset
    if "both" in dataset_names:
        dataset_names = ["cicids2017", "ciciot2023"]

    try:
        if len(dataset_names) == 1:
            if dataset_names[0] == "cicids2017":
                df_research = load_cicids2017()
            elif dataset_names[0] == "ciciot2023":
                df_research = load_ciciot2023()
            else:
                df_research = load_all_datasets(dataset_names)
        else:
            df_research = load_all_datasets(dataset_names)
        logger.info(f"Loaded {len(df_research):,} research samples from {dataset_names}.")
    except Exception as e:
        logger.error(f"Failed to load research data: {e}. Check data directories and fetch scripts.")
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
    ae_scores = np.clip(ae_mse / (ae_threshold * 2.0), 0.0, 1.0)
    
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

            for label_name in sorted(class_total):
                acc = class_correct[label_name] / max(class_total[label_name], 1)
                per_class[label_name] = round(acc, 4)
            logger.info(f"Per-class accuracy: {per_class}")
    except Exception as e:
        logger.warning(f"EV2: per-class metrics unavailable: {e}")

    logger.success("--- MODELS TRAINED AND SAVED TO data/models/ ---")

    # 7. Save comprehensive training report (confusion matrix, AUC-ROC, per-class)
    ts = int(time.time())
    version_name = f"v_{ts}"

    # Compute attack type distribution from combined dataset
    label_dist = {}
    try:
        if "label" in df_combined.columns:
            label_counts = df_combined["label"].value_counts()
            label_dist = {k: int(v) for k, v in label_counts.items()}
    except Exception:
        pass

    try:
        save_training_report(
            y_test=y_test,
            y_pred=y_pred,
            ensemble_scores=ensemble_scores,
            rf_scores=rf_scores,
            ae_scores=ae_scores,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            version_name=version_name,
            per_class_acc=per_class if "per_class" in dir() else None,
            label_distribution=label_dist,
            datasets_used=dataset_names,
        )
    except Exception as e:
        logger.warning(f"Training report generation failed (non-fatal): {e}")

    # 8. Versioning Registry
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
        "eval_source": "holdout",
        "eval_note": "Metrics are from test split only — live performance will differ",
        "data_sources": {
            "research": ", ".join(dataset_names),
            "live_db": not df_live.empty,
        },
        "attack_types": label_dist,
        "hyperparameters": {
            "precision": args.precision,
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "smote_ratio": args.smote_ratio,
            "datasets": dataset_names,
        },
        "status": "deployed"
    }
    registry.append(entry)
    
    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)
        
    logger.success(f"Registered model version {version_name} in {registry_path}")

if __name__ == "__main__":
    main()
