"""
================================================================================
FEATURE DEFINITIONS — Single Source of Truth
================================================================================
Purpose:
  Defines FEATURE_COLS (30 float features for ML), META_COLS (string metadata
  fields attached to each flow for routing/reporting), and HUMAN_FEATURE_NAMES
  (display names for the dashboard).

Design:
  - FEATURE_COLS: the EXACT 30 columns used by Random Forest and Autoencoder.
    All other modules (feature_extractor, dataset, trainer, ensemble, flows)
    import from here — never duplicate the list.
  - config.yaml:features.selected_features is a documentation-only mirror.
    The code IGNORES it.
  - Includes FV2 (port category one-hot) and FV3 (flag ratio) features.
  - Assertions at import time verify FEATURE_COLS and HUMAN_FEATURE_NAMES
    are in sync — drift causes an immediate crash rather than silent bugs.

Adding a new feature:
  1. Add to FEATURE_COLS
  2. Add display name to HUMAN_FEATURE_NAMES
  3. Add extraction logic to monitor/feature_extractor.py
  4. Re-train models (FEATURE_COLS change invalidates old models)
================================================================================
"""

FEATURE_COLS = [
    "dst_port", "duration", "src_bytes", "dst_bytes",
    "packet_count", "avg_packet_len", "std_packet_len",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "fwd_packet_len_max", "bwd_packet_len_max",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count",
    # FV3 — flag ratios (normalized by packet_count)
    "syn_ratio", "fin_ratio", "rst_ratio", "ack_ratio", "psh_ratio",
    # FV2 — port category one-hot (known-service flags)
    "port_is_web", "port_is_mail", "port_is_admin", "port_is_db", "port_is_dns",
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
    "syn_ratio": "SYN Ratio",
    "fin_ratio": "FIN Ratio",
    "rst_ratio": "RST Ratio",
    "ack_ratio": "ACK Ratio",
    "psh_ratio": "PSH Ratio",
    "port_is_web": "Port is Web (80,443,8080,8443)",
    "port_is_mail": "Port is Mail (25,110,143,587,993,995)",
    "port_is_admin": "Port is Admin (22,23,21,3389,5900)",
    "port_is_db": "Port is DB (3306,5432,27017,6379)",
    "port_is_dns": "Port is DNS (53)",
}

META_COLS = [
    "_src_ip", "_dst_ip", "_src_port", "_dst_port",
    "_protocol", "_timestamp", "direction", "_is_malformed",
]

# Verify the two lists are in sync (compiled at import time to catch drift)
assert len(FEATURE_COLS) == len(HUMAN_FEATURE_NAMES), (
    f"FEATURE_COLS ({len(FEATURE_COLS)}) and HUMAN_FEATURE_NAMES ({len(HUMAN_FEATURE_NAMES)}) out of sync"
)
assert set(FEATURE_COLS) == set(HUMAN_FEATURE_NAMES.keys()), (
    "FEATURE_COLS and HUMAN_FEATURE_NAMES keys differ"
)
