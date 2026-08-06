"""
================================================================================
ALERT ENGINE — Severity Classification + Signature Confidence Fusion
================================================================================
Purpose:
  Takes raw ensemble inference results (score, rf_score, ae_score, metadata),
  applies configurable severity thresholds, and merges explicit per-rule
  signature confidence. The AI stays the primary attack/normal judge; signature
  matches add their own confidence instead of silently forcing an alert.

Decision matrix (AI score = ensemble `score`, sig = signature_confidence):

    AI < 0.30                      → BENIGN (no alert), even with a rule match
    AI >= 0.65                     → ALERT (driver "ai" | "both")
    0.30 <= AI < 0.65, sig >= 0.50 → ALERT (driver "signature")
    otherwise                      → no alert

signature_confidence = probabilistic OR across matched rules: 1 - prod(1 - c_i),
where c_i is the per-rule `confidence` declared in rules.yaml (0-1). Multiple
matching rules combine; a rule match alone no longer forces an alert when the
AI is near-certain the flow is benign.

Each alert carries: ai score, signature_confidence, driver ("ai"|"signature"|"both"),
and the matched rules.

Usage:
  alerts = process_results(inference_results, signature_checker=checker)
================================================================================
"""

import json
from typing import List, Optional
from loguru import logger


SEVERITY_THRESHOLDS = {"high": 0.92, "medium": 0.80, "low": 0.65}

# Decision-matrix thresholds (see module docstring)
AI_SUPPRESS = 0.30      # AI below this = confident benign → never alert
AI_ALERT_MIN = 0.65     # AI at/above this alerts on its own
SIG_ALERT_MIN = 0.50    # signature_confidence needed to alert in the 0.30-0.65 band
RULE_CONF_DEFAULT = 0.7  # per-rule confidence when rules.yaml omits it

_RULE_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}


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


def signature_confidence(matches: List[dict]) -> float:
    """Probabilistic OR across matched rules: 1 - prod(1 - c_i)."""
    if not matches:
        return 0.0
    p = 1.0
    for m in matches:
        try:
            c = float(m.get("confidence", RULE_CONF_DEFAULT))
        except (TypeError, ValueError):
            c = RULE_CONF_DEFAULT
        c = min(max(c, 0.0), 1.0)
        p *= (1.0 - c)
    return round(1.0 - p, 4)


def should_alert(ai_score: float, sig_conf: float) -> bool:
    """Apply the decision matrix. Returns True if this flow should alert."""
    if ai_score < AI_SUPPRESS:
        return False
    if ai_score >= AI_ALERT_MIN:
        return True
    return sig_conf >= SIG_ALERT_MIN


def _driver(ai_score: float, sig_conf: float) -> str:
    if ai_score >= AI_ALERT_MIN:
        return "both" if sig_conf >= SIG_ALERT_MIN else "ai"
    return "signature"


def _highest_severity(matches: List[dict]) -> Optional[str]:
    best, best_rank = None, -1
    for m in matches:
        sev = m.get("severity", "low")
        rank = _RULE_RANK.get(sev, 0)
        if rank > best_rank:
            best, best_rank = sev, rank
    return best


def process_results(
    inference_results: List[dict],
    signature_checker=None,
) -> List[dict]:
    """
    Takes inference results, fuses AI score with signature confidence, and
    returns only records that cross the alert decision matrix.
    """
    alerts = []
    for result in inference_results:
        score = result.get("score", 0.0)

        sig_matches = None
        if signature_checker:
            sig_matches = signature_checker.check_with_metadata(result)

        sig_conf = signature_confidence(sig_matches) if sig_matches else 0.0

        if not should_alert(score, sig_conf):
            continue

        alert = {**result}
        alert["signature_confidence"] = sig_conf
        alert["driver"] = _driver(score, sig_conf)
        alert["model_label"] = alert.get("label", "BENIGN")
        alert["label"]    = "ATTACK"

        if sig_matches:
            alert["signature_match"] = json.dumps(sig_matches)
            alert["matched_rules"] = [
                {
                    "rule_id":     m.get("rule_id"),
                    "name":        m.get("name"),
                    "severity":    m.get("severity"),
                    "tags":        m.get("tags"),
                    "confidence":  m.get("confidence", RULE_CONF_DEFAULT),
                }
                for m in sig_matches
            ]
            alert["severity"] = _highest_severity(sig_matches) or "low"
        else:
            alert["severity"] = classify_severity(score) or "low"

        alerts.append(alert)

    return alerts
