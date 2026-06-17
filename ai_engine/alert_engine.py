"""
================================================================================
ALERT ENGINE — Severity Classification + Signature Merge
================================================================================
Purpose:
  Takes raw ensemble inference results (score, rf_score, ae_score, metadata),
  applies configurable severity thresholds, optionally enriches with signature
  rule matches, and produces final alert records.

Usage:
  alerts = process_results(inference_results, signature_checker=checker)

Design:
  - A1: severity thresholds (high=0.92, medium=0.80, low=0.65) are loaded from
    config.yaml and reloadable at runtime via reload_severity_thresholds()
  - A2: if a signature rule matches, the rule's severity overrides the ML-based
    severity classification
  - Alerts below the "low" threshold are dropped (score < 0.65 AND no sig match)
  - Label is always set to "ATTACK" for any alerting record; model_label preserves
    the original ML prediction
================================================================================
"""

import json
from typing import List, Optional
from loguru import logger


SEVERITY_THRESHOLDS = {"high": 0.92, "medium": 0.80, "low": 0.65}


def _load_severity_thresholds() -> dict:
    """Read severity thresholds from config.yaml, fall back to defaults."""
    defaults = dict(SEVERITY_THRESHOLDS)
    try:
        import yaml
        with open("config.yaml") as f:
            cfg = yaml.safe_load(f) or {}
        overrides = cfg.get("alerts", {}).get("severity_levels", {})
        if overrides:
            return {**defaults, **overrides}
    except Exception:
        pass
    return defaults


def reload_severity_thresholds():
    """A1: reload severity thresholds from config.yaml at runtime."""
    global SEVERITY_THRESHOLDS
    SEVERITY_THRESHOLDS = _load_severity_thresholds()
    logger.debug(f"Severity thresholds reloaded: {SEVERITY_THRESHOLDS}")


# Initial load
SEVERITY_THRESHOLDS = _load_severity_thresholds()


def classify_severity(score: float) -> Optional[str]:
    """Return severity level string, or None if below alert threshold."""
    if score >= SEVERITY_THRESHOLDS["high"]:
        return "high"
    elif score >= SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    elif score >= SEVERITY_THRESHOLDS["low"]:
        return "low"
    return None


def process_results(
    inference_results: List[dict],
    signature_checker=None,
) -> List[dict]:
    """
    Takes inference results, classifies severity, and optionally
    enriches with signature match info.
    Returns only records that cross the alert threshold.
    """
    alerts = []
    for result in inference_results:
        score = result.get("score", 0.0)
        severity = classify_severity(score)

        # Check signature rules regardless of ML score (use check_with_metadata for severity — A2)
        sig_matches = None
        if signature_checker:
            sig_matches = signature_checker.check_with_metadata(result)

        if severity is None and not sig_matches:
            continue

        alert = {**result}
        alert["severity"] = severity or "low"
        alert["model_label"] = alert.get("label", "BENIGN")
        alert["label"]    = "ATTACK"

        if sig_matches:
            alert["signature_match"] = json.dumps(sig_matches)
            # A2: use the first matching rule's severity, fall back to "high"
            alert["severity"] = sig_matches[0].get("severity", "high")

        alerts.append(alert)

    return alerts
