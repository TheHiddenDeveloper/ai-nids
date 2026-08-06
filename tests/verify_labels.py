"""
===============================================================================
TEST: VERIFY LABELS — Signature Confidence Fusion in AlertEngine
===============================================================================
Purpose:
  Verifies the new decision matrix in process_results():

  - AI score >= 0.65 alerts on its own (driver "ai", or "both" with a rule match)
  - In the uncertain band (0.30 <= AI < 0.65), a rule match with sufficient
    signature_confidence alerts (driver "signature")
  - AI < 0.30 means confident benign: even a rule match is suppressed
  - Alerts always carry label=ATTACK, model_label (original ML), driver,
    signature_confidence, and the matched rules

Run:
  python tests/verify_labels.py    # standalone
===============================================================================
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_engine.alert_engine import process_results

def test_signature_suppressed_when_ai_confident_benign():
    print("Testing AI-confident-benign suppression...")

    # AI is maximally confident benign — even a rule match must not alert
    results = [{
        "score": 0.0,
        "label": "BENIGN",
        "_src_ip": "1.2.3.4",
        "_dst_ip": "5.6.7.8",
        "_src_port": 1234,
        "_dst_port": 80,
    }]

    class MockChecker:
        def check_with_metadata(self, flow):
            return [{"severity": "high", "name": "Test Signature",
                     "description": "Malicious activity detected", "confidence": 0.95}]

    alerts = process_results(results, signature_checker=MockChecker())

    assert len(alerts) == 0, "Rule match must NOT alert when AI score < 0.30"
    print("SUCCESS: AI < 0.30 suppresses rule-forced alerts.\n")

def test_signature_drives_in_uncertain_band():
    print("Testing signature-driven alert in the uncertain band...")

    results = [{
        "score": 0.50,
        "label": "BENIGN",
        "_src_ip": "1.2.3.4",
        "_dst_ip": "5.6.7.8",
        "_src_port": 1234,
        "_dst_port": 80,
    }]

    class MockChecker:
        def check_with_metadata(self, flow):
            return [{"severity": "high", "name": "Test Signature",
                     "description": "Malicious activity detected", "confidence": 0.95}]

    alerts = process_results(results, signature_checker=MockChecker())

    assert len(alerts) == 1
    alert = alerts[0]
    print(f"Alert Label: {alert['label']}")
    print(f"Alert Severity: {alert['severity']}")
    print(f"Alert Driver: {alert['driver']}")
    print(f"Signature Confidence: {alert['signature_confidence']}")

    assert alert["label"] == "ATTACK"
    assert alert["model_label"] == "BENIGN"
    assert alert["severity"] == "high"
    assert alert["driver"] == "signature"
    assert alert["signature_confidence"] >= 0.5
    print("SUCCESS: Uncertain-band rule match alerts with driver=signature.\n")

def test_high_score_labels():
    print("Testing high score labeling...")

    results = [{
        "score": 0.95,
        "label": "ATTACK", # This would be set by ensemble.py
        "_src_ip": "1.2.3.4",
        "_dst_ip": "5.6.7.8",
    }]

    alerts = process_results(results)

    assert len(alerts) == 1
    alert = alerts[0]
    print(f"Alert Label: {alert['label']}")
    print(f"Alert Severity: {alert['severity']}")
    print(f"Alert Driver: {alert['driver']}")

    assert alert["label"] == "ATTACK"
    assert alert["severity"] == "high"
    assert alert["driver"] == "ai"
    print("SUCCESS: High score correctly labeled as ATTACK.\n")

if __name__ == "__main__":
    try:
        test_signature_suppressed_when_ai_confident_benign()
        test_signature_drives_in_uncertain_band()
        test_high_score_labels()
        print("All tests passed!")
    except AssertionError as e:
        print(f"TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
