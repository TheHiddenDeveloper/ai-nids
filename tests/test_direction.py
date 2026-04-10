import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from monitor.flow_aggregator import FlowAggregator

def test_direction_logic():
    print("Running Directional Awareness Logic Test...")
    
    home_net = ["192.168.0.0/16", "10.0.0.0/8"]
    
    # Test Case 1: Inbound (External -> Internal)
    agg1 = FlowAggregator(home_net=home_net)
    pkt_in = {
        "src_ip": "8.8.8.8",
        "dst_ip": "192.168.1.5",
        "src_port": 45678,
        "dst_port": 80,
        "protocol": 6,
        "ip_len": 60,
        "syn": 1, "ack": 0,
        "timestamp": 100.0
    }
    agg1.ingest(pkt_in)
    flow1 = list(agg1._flows.values())[0]
    print(f"Test 1 (Inbound): {flow1._src_ip} -> {flow1._dst_ip} | Direction: {flow1._direction}")
    assert flow1._direction == "inbound", f"Expected inbound, got {flow1._direction}"

    # Test Case 2: Outbound (Internal -> External)
    agg2 = FlowAggregator(home_net=home_net)
    pkt_out = {
        "src_ip": "10.0.0.50",
        "dst_ip": "142.250.190.46",
        "src_port": 55555,
        "dst_port": 443,
        "protocol": 6,
        "ip_len": 60,
        "syn": 1, "ack": 0,
        "timestamp": 200.0
    }
    agg2.ingest(pkt_out)
    flow2 = list(agg2._flows.values())[0]
    print(f"Test 2 (Outbound): {flow2._src_ip} -> {flow2._dst_ip} | Direction: {flow2._direction}")
    assert flow2._direction == "outbound", f"Expected outbound, got {flow2._direction}"

    # Test Case 3: Internal (Internal -> Internal)
    agg3 = FlowAggregator(home_net=home_net)
    pkt_int = {
        "src_ip": "192.168.10.1",
        "dst_ip": "10.10.10.10",
        "src_port": 1234,
        "dst_port": 1234,
        "protocol": 17,
        "ip_len": 100,
        "timestamp": 300.0
    }
    agg3.ingest(pkt_int)
    flow3 = list(agg3._flows.values())[0]
    print(f"Test 3 (Internal): {flow3._src_ip} -> {flow3._dst_ip} | Direction: {flow3._direction}")
    assert flow3._direction == "internal", f"Expected internal, got {flow3._direction}"

    # Test Case 4: Re-orientation handling
    # If the first packet seen is a response (B -> A), direction should still be correct
    agg4 = FlowAggregator(home_net=home_net)
    # External IP (A) sends to Internal IP (B), but we see the SYN/ACK first (B -> A)
    pkt_resp = {
        "src_ip": "192.168.1.5",
        "dst_ip": "8.8.8.8",
        "src_port": 80,
        "dst_port": 45678,
        "protocol": 6,
        "ip_len": 60,
        "syn": 1, "ack": 1, # Response
        "timestamp": 400.0
    }
    agg4.ingest(pkt_resp)
    # At this point, src=192.168.1.5, dst=8.8.8.8
    flow4 = list(agg4._flows.values())[0]
    
    # Now see the actual initiator SYN (A -> B)
    pkt_init = {
        "src_ip": "8.8.8.8",
        "dst_ip": "192.168.1.5",
        "src_port": 45678,
        "dst_port": 80,
        "protocol": 6,
        "ip_len": 60,
        "syn": 1, "ack": 0, # Initiator
        "timestamp": 401.0
    }
    agg4.ingest(pkt_init)
    # The flow should have re-oriented src to 8.8.8.8
    print(f"Test 4 (Re-oriented Inbound): {flow4._src_ip} -> {flow4._dst_ip} | Direction: {flow4._direction}")
    assert flow4._src_ip == "8.8.8.8"
    assert flow4._direction == "inbound"

    print("\n--- ALL DIRECTION TESTS PASSED ---")

if __name__ == "__main__":
    try:
        test_direction_logic()
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nAN ERROR OCCURRED: {e}")
        sys.exit(1)
