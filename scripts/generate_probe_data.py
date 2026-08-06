"""
================================================================================
GENERATE PROBE DATA — Synthetic Probe/Scan Flow Generator
================================================================================
Purpose:
  Generates realistic single-packet probe/scan flows that CICIDS2017 NEVER
  contains (CICIDS2017 has zero flows with packet_count == 1). These are the
  nmap/zmap style probes (SYN, FIN, RST, XMAS, UDP) that real scanners emit
  against closed/filtered hosts and that the current model cannot see.

  Feeding these as labelled attack flows closes the probe-detection gap: the
  RF learns the FV4 probe features, and the AE (benign-only training) will
  flag their reconstruction error as anomalous. SYN+RST (closed-port recon)
  and raw SYN-flood rows cover FV6/FV5 shapes absent from CICIDS2017.

Usage:
  python scripts/generate_probe_data.py                 # data/probe_data.csv
  python scripts/train.py ... --use-probes              # include them in training

Feature values mirror monitor/flow_aggregator.to_features() exactly:
  - Single packet -> duration = 1e-6 (duration<=0 clamp in to_features)
  - flow_bytes_per_sec = src_bytes / duration
  - flow_packets_per_sec = 1 / duration
  - flow_iat_* = 0 (single packet, no inter-arrival interval)
  - dst_bytes = 0 (no reply), fwd/bwd stats reflect a lone probe
================================================================================
"""

import sys
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import numpy as np
from loguru import logger

from core.features import FEATURE_COLS, compute_probe_features_vec, compute_flood_features_vec


# Ports that a scanner might hit (mixed: well-known + random high)
SCAN_PORTS = [
    random.randint(1, 1023),          # privileged (most filtered → no reply)
    random.randint(1024, 65535),      # random ephemeral (zmap style)
    random.randint(1024, 65535),
    random.randint(1, 65535),
]
WEB_PORTS = {80, 443, 8080, 8443}
MAIL_PORTS = {25, 110, 143, 587, 993, 995}
ADMIN_PORTS = {22, 23, 21, 3389, 5900}
DB_PORTS = {3306, 5432, 27017, 6379}
DNS_PORTS = {53}
# Real scanners hit well-known ports (21/22/23/3389/80/443/53) far more often
# than random ephemeral ports. Mixing these into probe targets teaches the RF
# that probe shapes are attacks regardless of destination port category.
KNOWN_PORTS = sorted(WEB_PORTS | MAIL_PORTS | ADMIN_PORTS | DB_PORTS | DNS_PORTS)
PROBE_PORTS = SCAN_PORTS + KNOWN_PORTS


def _port_categories(port: int) -> dict:
    return {
        "port_is_web":   int(port in WEB_PORTS),
        "port_is_mail":  int(port in MAIL_PORTS),
        "port_is_admin": int(port in ADMIN_PORTS),
        "port_is_db":    int(port in DB_PORTS),
        "port_is_dns":   int(port in DNS_PORTS),
    }


def _flag_ratios(fin, syn, rst, psh, ack, pkt_count):
    denom = max(pkt_count, 1)
    return {
        "syn_ratio": syn / denom,
        "fin_ratio": fin / denom,
        "rst_ratio": rst / denom,
        "ack_ratio": ack / denom,
        "psh_ratio": psh / denom,
    }


def _base_probe_row(dst_port: int, flags: dict) -> dict:
    """Build a single-packet probe row matching FlowAggregator.to_features().
    flags = {fin, syn, rst, psh, ack} bit values for the lone packet."""
    src_bytes = 60.0  # typical IP header + 20-byte TCP header
    duration = 1e-6   # to_features clamps duration<=0 to 1e-6 for 1-packet flows

    fin = int(flags.get("fin", 0))
    syn = int(flags.get("syn", 0))
    rst = int(flags.get("rst", 0))
    psh = int(flags.get("psh", 0))
    ack = int(flags.get("ack", 0))

    row = {
        "dst_port": float(dst_port),
        "duration": duration,
        "src_bytes": src_bytes,
        "dst_bytes": 0.0,
        "packet_count": 1.0,
        "avg_packet_len": 60.0,
        "std_packet_len": 0.0,
        "flow_bytes_per_sec": src_bytes / duration,
        "flow_packets_per_sec": 1.0 / duration,
        "fwd_packet_len_max": 60.0,
        "bwd_packet_len_max": 0.0,
        "flow_iat_mean": 0.0,
        "flow_iat_std": 0.0,
        "flow_iat_max": 0.0,
        "flow_iat_min": 0.0,
        "fin_flag_count": float(fin),
        "syn_flag_count": float(syn),
        "rst_flag_count": float(rst),
        "psh_flag_count": float(psh),
        "ack_flag_count": float(ack),
        **_flag_ratios(fin, syn, rst, psh, ack, 1),
        **_port_categories(dst_port),
        "label": "PortScan",
    }
    return row


def _base_flood_row(dst_port: int, n_pkts: int, replied: bool, rng: random.Random) -> dict:
    """Build a raw TCP SYN-flood row matching FlowAggregator.to_features().

    A SYN flood sends many 54-byte SYNs to a single port. If the target is
    up (replied=True) each SYN draws a SYN-ACK back, so packet_count doubles
    and ack_flag_count ≈ syn count (the replies carry ACK). If filtered
    (replied=False) the flow is one-way with dst_bytes == 0.
    """
    syn = n_pkts
    if replied:
        pc = 2 * n_pkts
        ack = n_pkts
        fwd = n_pkts
        bwd = n_pkts
        src_bytes = n_pkts * 54.0
        dst_bytes = n_pkts * 60.0
        avg_len = (src_bytes + dst_bytes) / pc
    else:
        pc = n_pkts
        ack = 0.0
        fwd = n_pkts
        bwd = 0.0
        src_bytes = n_pkts * 54.0
        dst_bytes = 0.0
        avg_len = 54.0

    duration = rng.uniform(0.5, 5.0)
    row = {
        "dst_port": float(dst_port),
        "duration": round(duration, 6),
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "packet_count": float(pc),
        "avg_packet_len": avg_len,
        "std_packet_len": 6.0,
        "flow_bytes_per_sec": (src_bytes + dst_bytes) / duration,
        "flow_packets_per_sec": pc / duration,
        "fwd_packet_len_max": 54.0,
        "bwd_packet_len_max": 60.0 if replied else 0.0,
        "flow_iat_mean": duration / pc,
        "flow_iat_std": (duration / pc) * 0.5,
        "flow_iat_max": (duration / pc) * 3.0,
        "flow_iat_min": 0.0001,
        "fin_flag_count": 0.0,
        "syn_flag_count": float(syn),
        "rst_flag_count": 0.0,
        "psh_flag_count": 0.0,
        "ack_flag_count": ack,
        **_flag_ratios(0, syn, 0, 0, ack, pc),
        **_port_categories(dst_port),
        "label": "DoS",
    }
    return row


def _base_syn_rst_scan_row(dst_port: int, rng: random.Random) -> dict:
    """Build a 2-packet SYN→RST-ACK scan row (closed-port recon).

    Mirrors the real production shape seen in live captures: a single SYN
    (44 B) draws a RST reply (40 B), so packet_count=2, rst=1, dst_bytes=40.
    Closed ports usually reply RST-ACK, but some tools send a pure RST, so
    ack is allowed to be 0 or 1. Duration is ~2-10ms (one round trip), giving
    flow_packets_per_sec in the low-hundreds-to-low-thousands range.
    """
    duration = rng.uniform(0.0015, 0.010)
    pc = 2.0
    src_bytes = 44.0
    dst_bytes = 40.0
    ack = 1.0 if rng.random() < 0.6 else 0.0
    row = {
        "dst_port": float(dst_port),
        "duration": round(duration, 6),
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "packet_count": pc,
        "avg_packet_len": (src_bytes + dst_bytes) / pc,
        "std_packet_len": 2.0,
        "flow_bytes_per_sec": (src_bytes + dst_bytes) / duration,
        "flow_packets_per_sec": pc / duration,
        "fwd_packet_len_max": 44.0,
        "bwd_packet_len_max": 40.0,
        "flow_iat_mean": duration,
        "flow_iat_std": 0.0,
        "flow_iat_max": duration,
        "flow_iat_min": duration,
        "fin_flag_count": 0.0,
        "syn_flag_count": 1.0,
        "rst_flag_count": 1.0,
        "psh_flag_count": 0.0,
        "ack_flag_count": ack,
        **_flag_ratios(0, 1, 1, 0, ack, 2),
        **_port_categories(dst_port),
        "label": "PortScan",
    }
    return row


def generate_probes(n=20000, seed: int = 7) -> pd.DataFrame:
    """Generate probe + SYN-flood flows across scan/flood types.

    Probe flows (SYN/FIN/RST/XMAS/UDP) cover FV4; SYN-flood flows cover FV5.
    """
    rng = random.Random(seed)
    rows = []

    # SYN scan (nmap -sS): the most common probe type
    for _ in range(int(n * 0.40)):
        rows.append(_base_probe_row(rng.choice(PROBE_PORTS), {"syn": 1}))

    # FIN scan (nmap -sF): stealthy, no reply expected
    for _ in range(int(n * 0.16)):
        rows.append(_base_probe_row(rng.choice(PROBE_PORTS), {"fin": 1}))

    # XMAS scan (nmap -sX): FIN + PSH + URG set
    for _ in range(int(n * 0.05)):
        rows.append(_base_probe_row(rng.choice(PROBE_PORTS), {"fin": 1, "psh": 1, "urg": 1}))

    # RST probe
    for _ in range(int(n * 0.09)):
        rows.append(_base_probe_row(rng.choice(PROBE_PORTS), {"rst": 1}))

    # SYN+RST scan (closed-port recon): SYN draws a RST back. This is the
    # exact shape real scanners produce per closed port (2-packet flows) that
    # CICIDS2017's long-flow PortScan class never contains — covers FV6.
    for _ in range(int(n * 0.10)):
        rows.append(_base_syn_rst_scan_row(rng.choice(PROBE_PORTS), rng))

    # UDP probe (zmap -p 53/random): single UDP datagram, no reply
    for _ in range(int(n * 0.10)):
        p = rng.choice(SCAN_PORTS + list(DNS_PORTS))
        row = _base_probe_row(p, {"ack": 0})
        row["avg_packet_len"] = 40.0
        row["fwd_packet_len_max"] = 40.0
        row["src_bytes"] = 40.0
        row["flow_bytes_per_sec"] = 40.0 / 1e-6
        row["label"] = "PortScan"
        rows.append(row)

    # SYN flood (DoS): raw TCP SYN floods absent from CICIDS2017 (which has
    # HTTP-POST DDoS instead). Varied intensities, replied (live host) and
    # unresponded (filtered target) — covers FV5.
    flood_n = int(n * 0.10)
    for _ in range(flood_n):
        p = rng.choice(SCAN_PORTS + list(WEB_PORTS) + list(ADMIN_PORTS))
        n_pkts = rng.choice([5, 10, 20, 50, 100, 250, 500])
        replied = rng.random() < 0.5
        rows.append(_base_flood_row(p, n_pkts, replied, rng))

    df = pd.DataFrame(rows)

    # FV4 probe indicators MUST come from the shared helper so train and
    # production compute identical values for these flows.
    for feat, val in compute_probe_features_vec(df).items():
        df[feat] = val

    # FV5 flood indicators — shared helper (train/production identical).
    for feat, val in compute_flood_features_vec(df).items():
        df[feat] = val

    # Final column order to match FEATURE_COLS + label
    df = df[FEATURE_COLS + ["label"]]
    df["is_attack"] = (df["label"].str.upper() != "BENIGN").astype(int)
    return df


if __name__ == "__main__":
    df = generate_probes(20000)
    out_path = Path("data/probe_data.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    probe_counts = {c: int(df[c].sum()) for c in ("is_syn_probe", "is_fin_probe", "is_rst_probe")}
    flood_counts = {c: int(df[c].sum()) for c in ("is_syn_flood", "is_small_pkt_high_rate", "is_handshake_incomplete")}
    syn_rst_count = int(df["is_syn_rst_scan"].sum())
    logger.success(
        f"Generated {len(df):,} probe/flood flows → {out_path} "
        f"(syn_probe={probe_counts['is_syn_probe']}, fin_probe={probe_counts['is_fin_probe']}, "
        f"rst_probe={probe_counts['is_rst_probe']}, syn_rst_scan={syn_rst_count} | "
        f"syn_flood={flood_counts['is_syn_flood']}, small_pkt={flood_counts['is_small_pkt_high_rate']}, "
        f"incomplete_hs={flood_counts['is_handshake_incomplete']})"
    )
