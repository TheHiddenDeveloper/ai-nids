import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.correlator import IncidentCorrelator
from monitor.db import clear_db_data

def test_incident_grouping():
    print("Running Incident Grouping Test...")
    clear_db_data()
    
    # Use a small window for testing
    WINDOW = 100
    correlator = IncidentCorrelator(inactivity_window=WINDOW)
    base_time = 1700000000.0
    
    # 1. First alert from 1.1.1.1
    a1 = {"_src_ip": "1.1.1.1", "severity": "low"}
    id1 = correlator.process_alert(a1, now=base_time)
    assert id1 > 0
    print(f"Alert 1 (IP 1.1.1.1) -> Incident #{id1}")
    
    # 2. Second alert from 1.1.1.1 (within window)
    a2 = {"_src_ip": "1.1.1.1", "severity": "medium"}
    id2 = correlator.process_alert(a2, now=base_time + 50)
    assert id2 == id1
    print(f"Alert 2 (IP 1.1.1.1, +50s) -> Reused Incident #{id2}")
    
    # 3. Alert from different IP
    a3 = {"_src_ip": "2.2.2.2", "severity": "high"}
    id3 = correlator.process_alert(a3, now=base_time + 60)
    assert id3 != id1
    print(f"Alert 3 (IP 2.2.2.2, +60s) -> New Incident #{id3}")
    
    # Check memory
    assert len(correlator.active_incidents) == 2
    
    # 4. Evict stale (IP 1.1.1.1 should expire after WINDOW since its last seen at +50s)
    # now = base_time + 160. (Delta to a1 last seen = 110s > 100s)
    closed = correlator.evict_stale(now=base_time + 160)
    assert id1 in closed
    assert id3 not in closed
    assert len(correlator.active_incidents) == 1
    print(f"Eviction (+160s) -> Closed Incident #{id1}")
    
    # 5. New alert from 1.1.1.1 (should start NEW incident)
    a4 = {"_src_ip": "1.1.1.1", "severity": "high"}
    id4 = correlator.process_alert(a4, now=base_time + 170)
    # In SQLite AUTOINCREMENT, ID should be higher than previous ones
    assert id4 != id1
    assert id4 > id3
    print(f"Alert 4 (IP 1.1.1.1, +170s) -> New Incident #{id4}")
    
    print("\n--- ALL CORRELATION TESTS PASSED ---")

if __name__ == "__main__":
    try:
        test_incident_grouping()
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nAN ERROR OCCURRED: {e}")
        sys.exit(1)
