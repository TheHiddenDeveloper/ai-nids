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
    import from here — never duplicate the list.  - config.yaml:features.selected_features is a documentation-only mirror.
    The code IGNORES it.
  - Includes FV2 (port category one-hot) and FV3 (flag ratio) features.
  - Assertions at import time verify FEATURE_COLS and HUMAN_FEATURE_NAMES
    are in sync — drift causes an immediate crash rather than silent bugs.

Adding a new feature:
  1. Add to FEATURE_COLS
  2. Add display name to HUMAN_FEATURE_NAMES
  3. Add extraction logic to monitor/feature_extractor.py
  4. Re-train models (FEATURE_COLS change invalidates old models)
===============================================================================
"""

import pandas as pd
import numpy as np

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
    # FV4 — probe/scan indicators (near-zero in training data, 1.0 for
    # single-packet probes not present in CICIDS2017)
    "is_syn_probe", "is_fin_probe", "is_rst_probe", "is_unidirectional",
    # FV6 — replied scan indicator (SYN sent + RST reply = closed-port recon).
    # CICIDS2017 PortScan flows are long multi-packet aggregates; real scans
    # produce per-port 2-packet SYN→RST exchanges that RF cannot distinguish
    # from a failed legitimate connection without an explicit flag.
    "is_syn_rst_scan",
    # FV5 — flood/DoS indicators (CICIDS2017's DDoS class is HTTP-POST-flood
    # shaped; raw TCP SYN floods with high SYN ratio + small packets are absent)
    "is_syn_flood", "is_small_pkt_high_rate", "is_handshake_incomplete",
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
    "is_syn_probe": "Single SYN Probe",
    "is_fin_probe": "Single FIN Probe",
    "is_rst_probe": "Single RST Probe",
    "is_unidirectional": "Unidirectional (No Reply)",
    "is_syn_rst_scan": "SYN+RST Scan (Closed-Port Recon)",
    "is_syn_flood": "SYN Flood (High SYN Ratio, Small Packets)",
    "is_small_pkt_high_rate": "Small-Packet High-Rate Flood",
    "is_handshake_incomplete": "Incomplete Handshake (SYNs without ACKs)",
}

META_COLS = [
    "_src_ip", "_dst_ip", "_src_port", "_dst_port",
    "_protocol", "_timestamp", "direction", "_is_malformed",
]


def compute_probe_features(flow: dict) -> dict:
    """Compute FV4 probe/scan indicator features from a flow dict.

    Single source of truth for probe detection so training (ai_engine/dataset.py)
    and production (monitor/feature_extractor.py) compute identical values.
    A probe = an unresponded, near-one-way exchange (e.g. an nmap SYN/FIN/RST
    probe that gets no reply), which CICIDS2017 never contains.

    Expects keys: packet_count, syn_flag_count, fin_flag_count, rst_flag_count,
    ack_flag_count, dst_bytes. Missing keys are treated as 0.
    """
    pc = float(flow.get("packet_count", 0.0) or 0.0)
    syn = float(flow.get("syn_flag_count", 0.0) or 0.0)
    fin = float(flow.get("fin_flag_count", 0.0) or 0.0)
    rst = float(flow.get("rst_flag_count", 0.0) or 0.0)
    ack = float(flow.get("ack_flag_count", 0.0) or 0.0)
    dst_bytes = float(flow.get("dst_bytes", 0.0) or 0.0)
    avg_len = float(flow.get("avg_packet_len", 0.0) or 0.0)

    # Probe = small exchange with no ACK handshake and no reply payload
    no_reply = (dst_bytes == 0.0) and (pc >= 1.0)
    syn_probe = (syn >= 1.0) and (ack == 0.0) and (pc <= 2.0) and no_reply
    fin_probe = (fin >= 1.0) and (ack == 0.0) and (pc <= 2.0) and no_reply
    rst_probe = (rst >= 1.0) and (ack == 0.0) and (pc <= 2.0) and no_reply

    # FV6 — replied scan: a SYN that draws a RST-ACK back (closed port).
    # Distinct from probes (which get no reply); real scanners hitting closed
    # ports emit this exact 2-packet exchange per port.
    syn_rst_scan = (syn >= 1.0) and (rst >= 1.0) and (pc <= 3.0) and (avg_len <= 120.0)

    return {
        "is_syn_probe": float(syn_probe),
        "is_fin_probe": float(fin_probe),
        "is_rst_probe": float(rst_probe),
        "is_unidirectional": float(no_reply),
        "is_syn_rst_scan": float(syn_rst_scan),
    }


def compute_flood_features(flow: dict) -> dict:
    """Compute FV5 flood/DoS indicator features from a flow dict.

    Single source of truth for flood detection so training and production
    compute identical values. Catches raw TCP SYN floods / high-rate
    small-packet floods that CICIDS2017 (HTTP-POST-flood DDoS) never contains.

    is_syn_flood:            many SYNs, mostly-SYN packet mix, tiny packets.
    is_small_pkt_high_rate:  high packet rate with small average packets.
    is_handshake_incomplete: SYNs without corresponding ACKs (half-open).

    Expects keys: packet_count, syn_flag_count, ack_flag_count, avg_packet_len,
    flow_packets_per_sec. Missing keys are treated as 0.
    """
    pc = float(flow.get("packet_count", 0.0) or 0.0)
    syn = float(flow.get("syn_flag_count", 0.0) or 0.0)
    ack = float(flow.get("ack_flag_count", 0.0) or 0.0)
    avg_len = float(flow.get("avg_packet_len", 0.0) or 0.0)
    pps = float(flow.get("flow_packets_per_sec", 0.0) or 0.0)

    if pc <= 0.0:
        return {
            "is_syn_flood": 0.0,
            "is_small_pkt_high_rate": 0.0,
            "is_handshake_incomplete": 0.0,
        }

    syn_ratio = syn / pc
    ack_ratio = ack / pc

    is_syn_flood = (syn >= 3.0) and (syn_ratio >= 0.4) and (ack_ratio <= 0.5) and (avg_len <= 120.0)
    is_small_pkt_high_rate = (pc >= 5.0) and (pps >= 100.0) and (avg_len <= 120.0)
    is_handshake_incomplete = (syn >= 3.0) and (ack_ratio <= 0.5)

    return {
        "is_syn_flood": float(is_syn_flood),
        "is_small_pkt_high_rate": float(is_small_pkt_high_rate),
        "is_handshake_incomplete": float(is_handshake_incomplete),
    }


def compute_probe_features_vec(df) -> dict:
    """Vectorized FV4 probe features for a DataFrame with the same columns.

    Mirrors compute_probe_features() but operates on whole columns (training
    datasets are millions of rows — per-row dict calls would be too slow).
    Missing columns are treated as all-zero.
    """
    def col(name, default=0.0):
        if name in df.columns:
            return df[name].astype(float).fillna(0.0)
        return pd.Series(default, index=df.index)

    pc = col("packet_count")
    syn = col("syn_flag_count")
    fin = col("fin_flag_count")
    rst = col("rst_flag_count")
    ack = col("ack_flag_count")
    dst_bytes = col("dst_bytes")
    avg_len = col("avg_packet_len")

    no_reply = (dst_bytes == 0.0) & (pc >= 1.0)
    return {
        "is_syn_probe": (((syn >= 1.0) & (ack == 0.0) & (pc <= 2.0) & no_reply).astype(float)),
        "is_fin_probe": (((fin >= 1.0) & (ack == 0.0) & (pc <= 2.0) & no_reply).astype(float)),
        "is_rst_probe": (((rst >= 1.0) & (ack == 0.0) & (pc <= 2.0) & no_reply).astype(float)),
        "is_unidirectional": (no_reply.astype(float)),
        "is_syn_rst_scan": (((syn >= 1.0) & (rst >= 1.0) & (pc <= 3.0) & (avg_len <= 120.0)).astype(float)),
    }


def compute_flood_features_vec(df) -> dict:
    """Vectorized FV5 flood features for a DataFrame (training path)."""
    def col(name, default=0.0):
        if name in df.columns:
            return df[name].astype(float).fillna(0.0)
        return pd.Series(default, index=df.index)

    pc = col("packet_count")
    syn = col("syn_flag_count")
    ack = col("ack_flag_count")
    avg_len = col("avg_packet_len")
    pps = col("flow_packets_per_sec")

    pc_gt0 = pc > 0.0
    syn_ratio = np.where(pc_gt0, syn / pc.clip(lower=1.0), 0.0)
    ack_ratio = np.where(pc_gt0, ack / pc.clip(lower=1.0), 0.0)

    return {
        "is_syn_flood": (((syn >= 3.0) & (syn_ratio >= 0.4) & (ack_ratio <= 0.5) & (avg_len <= 120.0)).astype(float)),
        "is_small_pkt_high_rate": (((pc >= 5.0) & (pps >= 100.0) & (avg_len <= 120.0)).astype(float)),
        "is_handshake_incomplete": (((syn >= 3.0) & (ack_ratio <= 0.5)).astype(float)),
    }


# Verify the two lists are in sync (compiled at import time to catch drift)
assert len(FEATURE_COLS) == len(HUMAN_FEATURE_NAMES), (
    f"FEATURE_COLS ({len(FEATURE_COLS)}) and HUMAN_FEATURE_NAMES ({len(HUMAN_FEATURE_NAMES)}) out of sync"
)
assert set(FEATURE_COLS) == set(HUMAN_FEATURE_NAMES.keys()), (
    "FEATURE_COLS and HUMAN_FEATURE_NAMES keys differ"
)
