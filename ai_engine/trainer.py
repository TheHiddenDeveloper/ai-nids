"""
Model Trainer
-------------
Trains a Random Forest classifier and/or Autoencoder on CICIDS2017.
Saves trained models + scaler to data/models/.
"""

import hashlib
import joblib
import numpy as np
from pathlib import Path
from loguru import logger

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE

from core.features import FEATURE_COLS


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    n_estimators: int = 200,
    max_depth: int = 20,
    model_dir: str = "data/models",
    smote_ratio: float = 1.0,
) -> tuple:
    """
    Train a Random Forest binary classifier.
    Uses SMOTE to handle class imbalance (attacks << benign).
    Returns (model, scaler).
    """
    Path(model_dir).mkdir(parents=True, exist_ok=True)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    logger.info(f"Applying SMOTE to balance classes (smote_ratio={smote_ratio})...")
    sm = SMOTE(random_state=42, sampling_strategy=smote_ratio)
    X_res, y_res = sm.fit_resample(X_train_s, y_train)
    logger.info(f"After SMOTE: {len(X_res):,} samples")

    logger.info(f"Training Random Forest (n_estimators={n_estimators}, max_depth={max_depth})...")
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    rf.fit(X_res, y_res)

    y_pred = rf.predict(X_test_s)
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))
    logger.info(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

    model_path = Path(model_dir) / "nids_model.joblib"
    scaler_path = Path(model_dir) / "scaler.joblib"
    meta_path   = Path(model_dir) / "feature_metadata.joblib"
    joblib.dump(rf, model_path)
    joblib.dump(scaler, scaler_path)
    feature_hash = hashlib.md5(":".join(FEATURE_COLS).encode()).hexdigest()
    joblib.dump({
        "feature_hash": feature_hash,
        "feature_cols": list(FEATURE_COLS),
    }, meta_path)
    logger.info(f"Saved model → {model_path}")
    logger.info(f"Saved scaler → {scaler_path}")
    logger.info(f"Saved feature metadata (hash={feature_hash[:12]}..., {len(FEATURE_COLS)} cols) → {meta_path}")

    return rf, scaler


def train_autoencoder(
    X_train_benign: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_dir: str = "data/models",
    epochs: int = 30,
    threshold_percentile: float = 95.0,
    batch_size: int = 128,
    learning_rate: float = 0.001,
    cal_ratio: float = 0.2,
    use_pca: bool = False,
    pca_components: int = 12,
) -> tuple:
    """
    Train an Autoencoder on BENIGN traffic only.
    Flags anomalies when reconstruction error exceeds the threshold.

    FV1: when use_pca=True, applies PCA before AE to reduce multicollinearity.
    Separate calibration holdout prevents test set leakage.

    Returns (autoencoder, threshold).
    """
    try:
        import tensorflow as tf
        from tensorflow import keras
        from sklearn.model_selection import train_test_split
        from sklearn.decomposition import PCA
    except ImportError:
        logger.error("tensorflow not installed: pip install tensorflow")
        return None, None

    Path(model_dir).mkdir(parents=True, exist_ok=True)

    # Split test set: cal_ratio for threshold calibration, remainder for eval
    X_cal, X_eval, y_cal, y_eval = train_test_split(
        X_test, y_test, test_size=1.0 - cal_ratio, random_state=42, stratify=y_test
    )
    logger.info(
        f"AE test split: cal={len(X_cal)} (threshold selection), "
        f"eval={len(X_eval)} (final metrics)"
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train_benign)

    # FV1: optional PCA
    pca_model = None
    if use_pca:
        logger.info(f"Applying PCA ({pca_components} components) before AE...")
        pca_model = PCA(n_components=pca_components, random_state=42)
        X_train_s = pca_model.fit_transform(X_train_s)
        joblib.dump(pca_model, Path(model_dir) / "ae_pca.joblib")
        logger.info(f"PCA explained variance ratio: {pca_model.explained_variance_ratio_.sum():.3f}")

    X_cal_s = scaler.transform(X_cal)
    X_eval_s = scaler.transform(X_eval)
    if use_pca and pca_model is not None:
        X_cal_s = pca_model.transform(X_cal_s)
        X_eval_s = pca_model.transform(X_eval_s)

    n_features = X_train_s.shape[1]

    inputs = keras.Input(shape=(n_features,))
    x = keras.layers.Dense(64, activation="relu")(inputs)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(32, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(16, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(8, activation="relu")(x) # Latent space — no dropout
    x = keras.layers.Dense(16, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(32, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    x = keras.layers.Dense(64, activation="relu")(x)
    x = keras.layers.Dropout(0.2)(x)
    outputs = keras.layers.Dense(n_features, activation="linear")(x)

    autoencoder = keras.Model(inputs, outputs)
    optimizer = keras.optimizers.Adam(learning_rate=learning_rate)
    autoencoder.compile(optimizer=optimizer, loss="mse")

    class MetricLoggingCallback(keras.callbacks.Callback):
        def on_epoch_end(self, epoch, logs=None):
            logs = logs or {}
            print(f"[METRIC] epoch: {epoch + 1}, loss: {logs.get('loss', 0):.6f}, val_loss: {logs.get('val_loss', 0):.6f}", flush=True)

    logger.info(f"Training High-Precision Autoencoder (epochs={epochs}, batch_size={batch_size}, learning_rate={learning_rate})...")
    autoencoder.fit(
        X_train_s, X_train_s,
        epochs=epochs,
        batch_size=batch_size,
        validation_split=0.1,
        verbose=1,
        callbacks=[MetricLoggingCallback()],
    )

    # Threshold from calibration set (never seen during training or eval)
    cal_reconstructions = autoencoder.predict(X_cal_s, verbose=0)
    cal_mse = np.mean(np.power(X_cal_s - cal_reconstructions, 2), axis=1)
    threshold = float(np.percentile(cal_mse, threshold_percentile))
    logger.info(f"Anomaly threshold (p{threshold_percentile} on cal set): {threshold:.6f}")

    # Evaluation on holdout set
    eval_reconstructions = autoencoder.predict(X_eval_s, verbose=0)
    eval_mse = np.mean(np.power(X_eval_s - eval_reconstructions, 2), axis=1)
    y_pred = (eval_mse > threshold).astype(int)
    logger.info(f"AE threshold evaluation (holdout set, n={len(X_eval)}):\n" +
                classification_report(y_eval, y_pred, target_names=["Benign", "Attack"], zero_division=0))

    ae_path = Path(model_dir) / "autoencoder.keras"
    autoencoder.save(ae_path)
    joblib.dump(scaler, Path(model_dir) / "ae_scaler.joblib")
    joblib.dump(threshold, Path(model_dir) / "ae_threshold.joblib")
    # M4: save calibration MSE distribution for principled score normalisation
    cal_data = {"mse_mean": float(np.mean(cal_mse)), "mse_std": float(np.std(cal_mse))}
    joblib.dump(cal_data, Path(model_dir) / "ae_calibration.joblib")
    logger.info(f"Saved autoencoder → {ae_path}")
    logger.info(f"Saved AE calibration (mse_mean={cal_data['mse_mean']:.6f}, mse_std={cal_data['mse_std']:.6f})")

    return autoencoder, threshold
