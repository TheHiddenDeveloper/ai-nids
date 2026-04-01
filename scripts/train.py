#!/usr/bin/env python3
"""
AI-NIDS Training Script
-----------------------
Automates the full training pipeline from the exploration notebook.
Trains Random Forest and/or Autoencoder on CICIDS2017 data.
Saves models + evaluation plots to data/models/.

Usage:
    python scripts/train.py --model rf
    python scripts/train.py --model autoencoder
    python scripts/train.py --model both
    python scripts/train.py --model rf --data-dir /path/to/cicids2017
    python scripts/train.py --model rf --no-plots
"""

import sys
import argparse
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")   # headless — no display needed
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, roc_curve, ConfusionMatrixDisplay,
    precision_score, recall_score, f1_score,
)
from imblearn.over_sampling import SMOTE
from loguru import logger

from ai_engine.dataset import CICIDS_COLUMN_MAP, FEATURE_COLS


# ── Plot theme ────────────────────────────────────────────────────────────────

plt.rcParams.update({
    "figure.facecolor": "#0f1117",
    "axes.facecolor":   "#0f1117",
    "axes.edgecolor":   "#444",
    "axes.labelcolor":  "#ccc",
    "xtick.color":      "#aaa",
    "ytick.color":      "#aaa",
    "text.color":       "#eee",
    "grid.color":       "#2a2a2a",
    "grid.linestyle":   "--",
    "font.size":        11,
})
ACCENT   = "#6366f1"
POSITIVE = "#22c55e"
NEGATIVE = "#ef4444"


# ── Data loading ──────────────────────────────────────────────────────────────

def load_and_clean(data_dir: Path) -> pd.DataFrame:
    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir}\n"
            "Download CICIDS2017 from https://www.unb.ca/cic/datasets/ids-2017.html"
        )

    logger.info(f"Loading {len(csv_files)} CSV file(s) from {data_dir}")
    dfs = []
    for f in csv_files:
        logger.info(f"  {f.name}")
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"Raw rows: {len(combined):,}")

    combined.rename(columns=CICIDS_COLUMN_MAP, inplace=True)

    needed    = FEATURE_COLS + ["label"]
    available = [c for c in needed if c in combined.columns]
    missing   = [c for c in needed if c not in combined.columns]
    if missing:
        logger.warning(f"Columns not found (check CICIDS_COLUMN_MAP): {missing}")

    combined = combined[available].copy()
    combined[FEATURE_COLS] = combined[FEATURE_COLS].replace([np.inf, -np.inf], np.nan)
    combined.dropna(subset=FEATURE_COLS, inplace=True)
    combined["label"]     = combined["label"].str.strip()
    combined["is_attack"] = (combined["label"].str.upper() != "BENIGN").astype(int)

    logger.info(f"Clean rows  : {len(combined):,}")
    logger.info(f"Benign      : {(combined['is_attack']==0).sum():,}")
    logger.info(f"Attack      : {(combined['is_attack']==1).sum():,}")
    return combined


# ── Plots ─────────────────────────────────────────────────────────────────────

def _save(fig, model_dir: Path, name: str):
    path = model_dir / name
    fig.savefig(path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"  Plot → {path}")


def plot_class_distribution(df: pd.DataFrame, model_dir: Path):
    counts = df["label"].value_counts()
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    colors = [POSITIVE if l.upper() == "BENIGN" else NEGATIVE for l in counts.index]
    axes[0].barh(counts.index, counts.values, color=colors)
    axes[0].set_title("Samples per label")
    axes[0].set_xlabel("Count")
    axes[0].grid(axis="x")
    binary = df["is_attack"].value_counts()
    axes[1].pie(binary.values, labels=["Benign", "Attack"], colors=[POSITIVE, NEGATIVE],
                autopct="%1.1f%%", startangle=90,
                wedgeprops={"edgecolor": "#0f1117", "linewidth": 2},
                textprops={"color": "#eee"})
    axes[1].set_title("Binary split")
    plt.tight_layout()
    _save(fig, model_dir, "plot_class_distribution.png")


def plot_feature_distributions(df: pd.DataFrame, model_dir: Path):
    sample = df.sample(min(20_000, len(df)), random_state=42)
    fig, axes = plt.subplots(4, 4, figsize=(16, 12))
    axes = axes.flatten()
    for i, col in enumerate(FEATURE_COLS):
        ax = axes[i]
        cap = sample[col].quantile(0.99)
        ax.hist(sample.loc[sample["is_attack"]==0, col].clip(upper=cap),
                bins=40, alpha=0.6, color=POSITIVE, density=True, label="Benign")
        ax.hist(sample.loc[sample["is_attack"]==1, col].clip(upper=cap),
                bins=40, alpha=0.6, color=NEGATIVE, density=True, label="Attack")
        ax.set_title(col, fontsize=9)
        ax.set_yticks([])
        if i == 0:
            ax.legend(fontsize=8)
    plt.suptitle("Feature distributions: benign vs attack (capped at p99)", y=1.01, fontsize=13)
    plt.tight_layout()
    _save(fig, model_dir, "plot_feature_distributions.png")


def plot_correlation(df: pd.DataFrame, model_dir: Path):
    corr = df[FEATURE_COLS + ["is_attack"]].corr()
    fig, ax = plt.subplots(figsize=(12, 10))
    sns.heatmap(corr, ax=ax, cmap="RdYlGn", center=0, vmin=-1, vmax=1,
                annot=True, fmt=".2f", annot_kws={"size": 7},
                linewidths=0.4, linecolor="#1a1a2e", cbar_kws={"shrink": 0.7})
    ax.set_title("Feature correlation matrix", fontsize=13)
    plt.tight_layout()
    _save(fig, model_dir, "plot_correlation.png")


def plot_rf_evaluation(y_test, y_pred, y_proba, model_dir: Path) -> float:
    auc = roc_auc_score(y_test, y_proba)
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    cm = confusion_matrix(y_test, y_pred)
    ConfusionMatrixDisplay(cm, display_labels=["Benign", "Attack"]).plot(
        ax=axes[0], colorbar=False, cmap="Blues")
    axes[0].set_title("Confusion matrix")
    axes[0].set_facecolor("#0f1117")

    fpr, tpr, thresholds = roc_curve(y_test, y_proba)
    axes[1].plot(fpr, tpr, color=ACCENT, linewidth=2, label=f"RF  (AUC={auc:.3f})")
    axes[1].plot([0, 1], [0, 1], linestyle="--", color="#555", linewidth=1)
    for thresh, label, color in [(0.65, "Low", "#facc15"), (0.80, "Medium", "#f97316"), (0.92, "High", "#ef4444")]:
        idx = np.argmin(np.abs(thresholds - thresh))
        axes[1].scatter(fpr[idx], tpr[idx], s=80, color=color, zorder=5, label=f"Threshold {label} ({thresh})")
    axes[1].set_xlabel("False Positive Rate")
    axes[1].set_ylabel("True Positive Rate")
    axes[1].set_title("ROC Curve")
    axes[1].legend(fontsize=9)
    axes[1].grid(True)
    plt.tight_layout()
    _save(fig, model_dir, "plot_rf_evaluation.png")
    return auc


def plot_feature_importance(rf, model_dir: Path):
    importances = pd.Series(rf.feature_importances_, index=FEATURE_COLS).sort_values()
    fig, ax = plt.subplots(figsize=(9, 6))
    bars = ax.barh(importances.index, importances.values, color=ACCENT, edgecolor="none")
    ax.set_title("Random Forest — feature importances")
    ax.set_xlabel("Importance (Gini)")
    ax.grid(axis="x")
    for bar, val in zip(bars, importances.values):
        ax.text(val + 0.001, bar.get_y() + bar.get_height()/2,
                f"{val:.3f}", va="center", fontsize=8, color="#ccc")
    plt.tight_layout()
    _save(fig, model_dir, "plot_feature_importance.png")
    logger.info("Top 5 features by importance:")
    for feat, imp in importances.tail(5).items():
        logger.info(f"  {feat:<30} {imp:.4f}")


def plot_threshold_tuning(y_test, y_proba, model_dir: Path):
    thresholds = np.arange(0.30, 0.96, 0.05)
    rows = []
    for t in thresholds:
        y_t = (y_proba >= t).astype(int)
        rows.append({
            "threshold": round(t, 2),
            "precision": precision_score(y_test, y_t, zero_division=0),
            "recall":    recall_score(y_test, y_t, zero_division=0),
            "f1":        f1_score(y_test, y_t, zero_division=0),
            "fpr":       ((y_t==1) & (y_test==0)).sum() / max((y_test==0).sum(), 1),
        })
    tdf = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(tdf["threshold"], tdf["precision"], color=POSITIVE,  linewidth=2, label="Precision")
    ax.plot(tdf["threshold"], tdf["recall"],    color=NEGATIVE,  linewidth=2, label="Recall")
    ax.plot(tdf["threshold"], tdf["f1"],        color=ACCENT,    linewidth=2, label="F1")
    ax.plot(tdf["threshold"], tdf["fpr"],       color="#f97316", linewidth=2, linestyle="--", label="FPR")
    for t, c in [(0.65, "#facc15"), (0.80, "#f97316"), (0.92, "#ef4444")]:
        ax.axvline(x=t, color=c, linestyle=":", linewidth=1.2)
    ax.set_xlabel("Threshold")
    ax.set_ylabel("Score")
    ax.set_title("Precision / Recall / F1 / FPR vs Decision Threshold")
    ax.legend()
    ax.grid(True)
    plt.tight_layout()
    _save(fig, model_dir, "plot_threshold_tuning.png")

    best = tdf.loc[tdf["f1"].idxmax()]
    logger.info(f"Best F1 threshold: {best['threshold']}  "
                f"F1={best['f1']:.4f}  P={best['precision']:.4f}  R={best['recall']:.4f}")


# ── Training functions ────────────────────────────────────────────────────────

def train_rf(df, model_dir, save_plots=True):
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["is_attack"].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    logger.info(f"Train: {len(X_train):,} | Test: {len(X_test):,}")

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    logger.info("Applying SMOTE...")
    X_res, y_res = SMOTE(random_state=42).fit_resample(X_train_s, y_train)
    logger.info(f"After SMOTE: {len(X_res):,} samples")

    logger.info("Training Random Forest (n_estimators=200, max_depth=20)...")
    rf = RandomForestClassifier(n_estimators=200, max_depth=20, n_jobs=-1, random_state=42, class_weight="balanced")
    rf.fit(X_res, y_res)

    y_pred  = rf.predict(X_test_s)
    y_proba = rf.predict_proba(X_test_s)[:, 1]
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    auc = roc_auc_score(y_test, y_proba)
    logger.info(f"TP={tp:,} TN={tn:,} FP={fp:,} FN={fn:,}  |  FPR={fp/(fp+tn)*100:.2f}%  FNR={fn/(fn+tp)*100:.2f}%  AUC={auc:.4f}")

    if save_plots:
        plot_rf_evaluation(y_test, y_pred, y_proba, model_dir)
        plot_feature_importance(rf, model_dir)
        plot_threshold_tuning(y_test, y_proba, model_dir)

    model_path  = model_dir / "nids_model.joblib"
    scaler_path = model_dir / "scaler.joblib"
    joblib.dump(rf, model_path)
    joblib.dump(scaler, scaler_path)
    logger.info(f"Model  → {model_path}  ({model_path.stat().st_size/1024/1024:.1f} MB)")
    logger.info(f"Scaler → {scaler_path}")

    return rf, scaler, X_train_s, X_test_s, y_train, y_test


def train_ae(X_train_s, X_test_s, y_train, y_test, scaler, model_dir, epochs=30, save_plots=True):
    try:
        import tensorflow as tf
        from tensorflow import keras
        logger.info(f"TensorFlow {tf.__version__}")
    except ImportError:
        logger.error("TensorFlow not installed: pip install tensorflow")
        return None, None

    X_benign = X_train_s[y_train == 0]
    logger.info(f"Autoencoder training on {len(X_benign):,} benign samples")

    n = X_benign.shape[1]
    inp = keras.Input(shape=(n,))
    x = keras.layers.Dense(32, activation="relu")(inp)
    x = keras.layers.Dense(16, activation="relu")(x)
    x = keras.layers.Dense(8,  activation="relu")(x)
    x = keras.layers.Dense(16, activation="relu")(x)
    x = keras.layers.Dense(32, activation="relu")(x)
    out = keras.layers.Dense(n, activation="linear")(x)
    ae = keras.Model(inp, out, name="nids_autoencoder")
    ae.compile(optimizer="adam", loss="mse")

    history = ae.fit(X_benign, X_benign, epochs=epochs, batch_size=256, validation_split=0.1, verbose=1)

    if save_plots:
        fig, ax = plt.subplots(figsize=(9, 4))
        ax.plot(history.history["loss"],     color=ACCENT,    linewidth=2, label="Train loss")
        ax.plot(history.history["val_loss"], color="#f97316", linewidth=2, linestyle="--", label="Val loss")
        ax.set_title("Autoencoder training loss")
        ax.set_xlabel("Epoch")
        ax.set_ylabel("MSE")
        ax.legend()
        ax.grid(True)
        plt.tight_layout()
        _save(fig, model_dir, "plot_ae_loss.png")

    reconstructions = ae.predict(X_test_s, verbose=0)
    mse = np.mean(np.power(X_test_s - reconstructions, 2), axis=1)

    if save_plots:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.hist(mse[y_test==0], bins=80, alpha=0.65, color=POSITIVE, density=True, label="Benign")
        ax.hist(mse[y_test==1], bins=80, alpha=0.65, color=NEGATIVE, density=True, label="Attack")
        ax.set_xlabel("Reconstruction MSE")
        ax.set_ylabel("Density")
        ax.set_title("Autoencoder: reconstruction error distribution")
        ax.set_xlim(left=0)
        ax.legend()
        ax.grid(True)
        plt.tight_layout()
        _save(fig, model_dir, "plot_ae_mse_distribution.png")

    # Pick threshold by best F1
    thresholds = np.percentile(mse, np.arange(50, 100, 1))
    best_f1, best_thresh = 0.0, thresholds[0]
    for t in thresholds:
        score = f1_score(y_test, (mse > t).astype(int), zero_division=0)
        if score > best_f1:
            best_f1, best_thresh = score, t

    ae_threshold = float(best_thresh)
    y_ae_pred = (mse > ae_threshold).astype(int)
    logger.info(f"Best AE threshold: {ae_threshold:.6f}  F1={best_f1:.4f}")
    logger.info("\n" + classification_report(y_test, y_ae_pred, target_names=["Benign", "Attack"]))

    ae_path    = model_dir / "autoencoder.keras"
    ae_sc_path = model_dir / "ae_scaler.joblib"
    ae_th_path = model_dir / "ae_threshold.joblib"
    ae.save(ae_path)
    joblib.dump(scaler,       ae_sc_path)
    joblib.dump(ae_threshold, ae_th_path)
    logger.info(f"Autoencoder  → {ae_path}")
    logger.info(f"AE scaler    → {ae_sc_path}")
    logger.info(f"AE threshold → {ae_th_path}  ({ae_threshold:.6f})")
    return ae, ae_threshold


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AI-NIDS model training")
    parser.add_argument("--model",     choices=["rf", "autoencoder", "both"], default="rf")
    parser.add_argument("--data-dir",  default="data/raw/cicids2017")
    parser.add_argument("--model-dir", default="data/models")
    parser.add_argument("--epochs",    type=int, default=30, help="Autoencoder epochs (default: 30)")
    parser.add_argument("--no-plots",  action="store_true", help="Skip evaluation plots")
    args = parser.parse_args()

    data_dir  = Path(args.data_dir)
    model_dir = Path(args.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    save_plots = not args.no_plots

    logger.info("=" * 55)
    logger.info(f"  AI-NIDS Training  |  model={args.model}")
    logger.info("=" * 55)

    df = load_and_clean(data_dir)

    if save_plots:
        logger.info("Saving exploratory plots...")
        plot_class_distribution(df, model_dir)
        plot_feature_distributions(df, model_dir)
        plot_correlation(df, model_dir)

    rf_outputs = None

    if args.model in ("rf", "both"):
        logger.info("--- Random Forest ---")
        rf_outputs = train_rf(df, model_dir, save_plots=save_plots)

    if args.model in ("autoencoder", "both"):
        logger.info("--- Autoencoder ---")
        if rf_outputs is not None:
            _, scaler, X_train_s, X_test_s, y_train, y_test = rf_outputs
        else:
            X = df[FEATURE_COLS].values.astype(np.float32)
            y = df["is_attack"].values
            X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
            scaler = StandardScaler()
            X_train_s = scaler.fit_transform(X_tr)
            X_test_s  = scaler.transform(X_te)
            y_train, y_test = y_tr, y_te

        train_ae(X_train_s, X_test_s, y_train, y_test, scaler, model_dir,
                 epochs=args.epochs, save_plots=save_plots)

    logger.info("=" * 55)
    logger.info("  Training complete.")
    logger.info(f"  Artefacts saved to: {model_dir}/")
    logger.info("  Next step → Step 4: Inference pipeline")
    logger.info("    Run: sudo python scripts/run_monitor.py --interface eth0")
    logger.info("=" * 55)


if __name__ == "__main__":
    main()
