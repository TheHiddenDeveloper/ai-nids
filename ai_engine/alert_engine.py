"""
Alert Engine
------------
Applies severity thresholds to ML inference scores.
Merges signature-based rules with ML results.
"""

from typing import List, Optional
from loguru import logger


SEVERITY_THRESHOLDS = {
    "high":   0.92,
    "medium": 0.80,
    "low":    0.65,
}


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

        # Check signature rules regardless of ML score
        sig_match = None
        if signature_checker:
            sig_match = signature_checker.check(result)

        if severity is None and sig_match is None:
            continue

        alert = {**result}
        alert["severity"] = severity or "low"

        if sig_match:
            alert["signature_match"] = sig_match
            alert["severity"] = "high"  # Signature hits always escalate to high

        alerts.append(alert)

    return alerts
