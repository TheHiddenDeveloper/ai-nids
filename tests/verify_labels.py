import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_engine.alert_engine import process_results

def test_signature_match_labels():
    print("Testing signature match labeling...")
    
    # Mock result that is BENIGN according to model/default
    results = [{
        "score": 0.0,
        "label": "BENIGN",
        "_src_ip": "1.2.3.4",
        "_dst_ip": "5.6.7.8",
        "_src_port": 1234,
        "_dst_port": 80,
    }]
    
    # Mock signature checker that returns a match
    class MockChecker:
        def check(self, flow):
            return "Test Signature: Malicious activity detected"
            
    alerts = process_results(results, signature_checker=MockChecker())
    
    assert len(alerts) == 1
    alert = alerts[0]
    print(f"Alert Label: {alert['label']}")
    print(f"Alert Severity: {alert['severity']}")
    print(f"Alert Signature: {alert.get('signature_match')}")
    
    assert alert["label"] == "ATTACK"
    assert alert["severity"] == "high"
    print("SUCCESS: Signature match correctly promoted to ATTACK label.\n")

def test_high_score_labels():
    print("Testing high score labeling...")
    
    # Mock result with high score
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
    
    assert alert["label"] == "ATTACK"
    assert alert["severity"] == "high"
    print("SUCCESS: High score correctly labeled as ATTACK.\n")

if __name__ == "__main__":
    try:
        test_signature_match_labels()
        test_high_score_labels()
        print("All tests passed!")
    except AssertionError as e:
        print(f"TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
