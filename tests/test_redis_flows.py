import time
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from monitor.flow_aggregator import FlowAggregator
from core.redis_client import get_redis_client

def test_distributed_flow_aggregation():
    print("\n--- Testing Distributed Flow Aggregation ---")
    
    redis = get_redis_client()
    if redis is None:
        print("⚠️ Redis not available, skipping test.")
        return
    
    # Clean up any existing test flows in Redis
    redis.flushdb()
    
    # 5-tuple for our test flow
    pkt_base = {
        "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1",
        "src_port": 12345, "dst_port": 443,
        "protocol": 6, "ip_len": 500, "syn": 0, "ack": 1,
        "timestamp": time.time()
    }

    # Simulate Sensor A
    print("  [Sensor A] Ingesting packet...")
    agg_a = FlowAggregator(flow_timeout=2)
    agg_a.ingest(pkt_base)
    
    # Simulate Sensor B (same flow, same packet stats)
    print("  [Sensor B] Ingesting packet for same flow...")
    agg_b = FlowAggregator(flow_timeout=2)
    agg_b.ingest(pkt_base)
    
    # Verify Redis middle-state
    flow_key = agg_a._flows[list(agg_a._flows.keys())[0]]._get_redis_key()
    count = int(redis.hget(flow_key, "packet_count"))
    print(f"  [Redis] Global packet_count: {count}")
    assert count == 2
    
    # Wait for expiry
    print("  Waiting for flow to expire...")
    time.sleep(3)
    
    # Sensor A performs eviction
    print("  [Sensor A] Evicting flow...")
    completed = agg_a.ingest({"src_ip": "OTHER", "dst_ip": "OTHER", "protocol": 0}) 
    
    if len(completed) > 0:
        f = completed[0]
        print(f"  [Result] Total Packet Count in features: {f['packet_count']}")
        print(f"  [Result] Total Bytes: {f['src_bytes'] + f['dst_bytes']}")
        
        # Should be 2 packets (1 from A, 1 from B)
        assert f["packet_count"] == 2
        assert f["src_bytes"] == 1000 # 500 + 500
        print("✅ Distributed Flow Aggregation SUCCESS.")
    else:
        print("❌ Distributed Flow Aggregation FAILED (no flow evicted).")

if __name__ == "__main__":
    test_distributed_flow_aggregation()
