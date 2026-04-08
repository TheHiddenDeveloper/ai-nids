import time
import json
import threading
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.event_bus import bus
from core.deduplicator import AlertDeduplicator

def test_redis_pubsub():
    print("\n--- Testing Redis Pub/Sub ---")
    received = []
    
    def on_alert(payload):
        print(f"  [Subscriber] Received alert: {payload['id']}")
        received.append(payload)

    # Subscribe (this starts the Redis listener thread)
    bus.subscribe("alert", on_alert)
    time.sleep(1) # Wait for thread to start

    # Publish
    alert_data = {"id": "test-123", "msg": "Redis Test Alert"}
    print("  [Publisher] Publishing alert...")
    bus.publish("alert", alert_data)
    
    # Wait for roundtrip
    time.sleep(1)
    
    if len(received) > 0:
        print("✅ Pub/Sub Verification SUCCESS.")
    else:
        print("❌ Pub/Sub Verification FAILED (no message received).")
        return False
    return True

def test_redis_persistence():
    print("\n--- Testing Redis Deduplication Persistence ---")
    alert = {"_src_ip": "1.1.1.1", "_dst_ip": "2.2.2.2", "_dst_port": 80, "label": "ATTACK"}
    
    # Instance 1: Fire an alert
    dedup1 = AlertDeduplicator(suppress_window_secs=5)
    if dedup1.redis is None:
        print("⚠️ Redis not available, skipping persistence test.")
        return True
        
    print("  [Instance 1] Firing alert...")
    fire1 = dedup1.should_fire(alert)
    
    # Instance 2: (Simulated restart) Try firing the same alert immediately
    dedup2 = AlertDeduplicator(suppress_window_secs=5)
    print("  [Instance 2] Firing same alert immediately (suppression should persist)...")
    fire2 = dedup2.should_fire(alert)
    
    note = dedup2.suppression_note(alert)
    print(f"  [Instance 2] Suppression Note: {note}")

    if fire1 == True and fire2 == False and note is not None:
        print("✅ Deduplication Persistence SUCCESS.")
    else:
        print(f"❌ Deduplication Persistence FAILED. (Instance1: {fire1}, Instance2: {fire2})")
        return False
    return True

if __name__ == "__main__":
    s1 = test_redis_pubsub()
    s2 = test_redis_persistence()
    
    if s1 and s2:
        print("\n🏆 ALL REDIS INTEGRATION TESTS PASSED.")
        sys.exit(0)
    else:
        print("\n🚨 SOME TESTS FAILED.")
        sys.exit(1)
