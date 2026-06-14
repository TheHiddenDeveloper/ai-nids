"""
Canonical feature column definitions.
Single source of truth — all other modules import from here.
"""

FEATURE_COLS = [
    "dst_port", "duration", "src_bytes", "dst_bytes",
    "packet_count", "avg_packet_len", "std_packet_len",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "fwd_packet_len_max", "bwd_packet_len_max",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count",
]

HUMAN_FEATURE_NAMES = {
    "dst_port": "Destination Port",
    "duration": "Flow Duration",
    "src_bytes": "Sent Bytes",
    "dst_bytes": "Received Bytes",
    "packet_count": "Packet Count",
    "avg_packet_len": "Average Packet Length",
    "std_packet_len": "Packet Length Std Dev",
    "flow_bytes_per_sec": "Flow Bytes/Sec",
    "flow_packets_per_sec": "Flow Packets/Sec",
    "fwd_packet_len_max": "Max Forward Packet Length",
    "bwd_packet_len_max": "Max Backward Packet Length",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std Dev",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fin_flag_count": "FIN Flags",
    "syn_flag_count": "SYN Flags",
    "rst_flag_count": "RST Flags",
    "psh_flag_count": "PSH Flags",
    "ack_flag_count": "ACK Flags",
}

META_COLS = ["_src_ip", "_dst_ip", "_src_port", "_dst_port", "_timestamp"]

# Verify the two lists are in sync (compiled at import time to catch drift)
assert len(FEATURE_COLS) == len(HUMAN_FEATURE_NAMES), (
    f"FEATURE_COLS ({len(FEATURE_COLS)}) and HUMAN_FEATURE_NAMES ({len(HUMAN_FEATURE_NAMES)}) out of sync"
)
assert set(FEATURE_COLS) == set(HUMAN_FEATURE_NAMES.keys()), (
    "FEATURE_COLS and HUMAN_FEATURE_NAMES keys differ"
)
