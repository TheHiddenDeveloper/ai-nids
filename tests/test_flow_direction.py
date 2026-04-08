import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from monitor.flow_aggregator import FlowAggregator

def test_direction_correction():
    agg = FlowAggregator()
    
    # 1. Simulate a flow where we see a response packet FIRST
    # (Attacker: 8.8.8.8, User: 192.168.1.10)
    pkt1 = {
        "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
        "src_port": 443, "dst_port": 54321,
        "protocol": 6, "syn": 0, "ack": 1, "ip_len": 100,
        "timestamp": 1000.0
    }
    agg.ingest(pkt1)
    
    # 2. Simulate the SYN packet seen SECOND (delayed or out of order)
    pkt2 = {
        "src_ip": "8.8.8.8", "dst_ip": "192.168.1.10",
        "src_port": 54321, "dst_port": 443,
        "protocol": 6, "syn": 1, "ack": 0, "ip_len": 60,
        "timestamp": 1000.1
    }
    agg.ingest(pkt2)
    
    # Force eviction to check features
    flows = agg.flush_all()
    assert len(flows) == 1
    f = flows[0]
    
    print(f"Oriented Source: {f['_src_ip']}")
    print(f"Oriented Dest:   {f['_dst_ip']}")
    print(f"Src Bytes (Attacker -> User): {f['src_bytes']}")
    print(f"Dst Bytes (User -> Attacker): {f['dst_bytes']}")
    
    # The SYN packet from 8.8.8.8 should have forced it to be the source
    assert f["_src_ip"] == "8.8.8.8"
    assert f["_dst_ip"] == "192.168.1.10"
    
    # pkt2 (60 bytes) is now forward, pkt1 (100 bytes) is now backward
    assert f["src_bytes"] == 60
    assert f["dst_bytes"] == 100
    assert f["fwd_packet_count"] == 1
    assert f["bwd_packet_count"] == 1

if __name__ == "__main__":
    try:
        test_direction_correction()
        print("\n✅ Verification SUCCESS: Flow directionality corrected by SYN.")
    except Exception as e:
        print(f"\n❌ Verification FAILED: {e}")
        sys.exit(1)
