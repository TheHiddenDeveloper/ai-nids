import sys
import time
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.threat_intel import ThreatIntelManager
from core.redis_client import get_redis_client

def test_threat_intel():
    print("Running Threat Intel Manager Tests...")
    intel = ThreatIntelManager()
    redis = get_redis_client()
    
    if not redis:
        print("SKIP: Redis not available.")
        return

    # 1. Test GeoIP Lookup (Real API)
    print("Testing GeoIP Lookup (8.8.8.8)...")
    res = intel.get_enrichment("8.8.8.8")
    assert res is not None
    assert res.get("country") == "United States"
    print(f"  OK: Found {res.get('city')}, {res.get('country')}")

    # 2. Test Blocklist Ingestion (Mocking logic via Redis)
    print("Testing Reputation Engine (Mock Malicious IP)...")
    MOCK_IP = "1.2.3.4"
    redis.sadd(intel.BLOCKLIST_KEY, MOCK_IP)
    
    res_mal = intel.get_enrichment(MOCK_IP)
    assert res_mal["is_malicious"] is True
    assert res_mal["threat_level"] == "high"
    print(f"  OK: Properly flagged {MOCK_IP} as malicious")

    # 3. Test Cache
    print("Testing Redis Caching...")
    cache_key = f"{intel.GEO_PREFIX}:8.8.8.8"
    assert redis.exists(cache_key)
    print("  OK: Cache entry exists")

    # 4. Cleanup
    redis.srem(intel.BLOCKLIST_KEY, MOCK_IP)
    print("\n--- ALL THREAT INTEL TESTS PASSED ---")

if __name__ == "__main__":
    try:
        test_threat_intel()
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nAN ERROR OCCURRED: {e}")
        sys.exit(1)
