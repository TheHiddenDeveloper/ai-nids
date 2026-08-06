"""
===============================================================================
TEST: ATTACK MATRIX — AI Confidence >= 0.85 Acceptance Harness
===============================================================================
Purpose:
  The acceptance gate for the "AI confidence 85%+" goal. Replays labeled
  deliberate-attack and benign flow families through the PRODUCTION inference
  path (monitor.feature_extractor.FeatureExtractor -> EnsembleInferenceEngine),
  and reports the distribution of the AI `score` per family.

  A family PASSES only when >=85% of its flows score >= 0.85.

  This is the harness we iterate against: every training / fusion / AE change
  must first close a red family here before it is trusted.

Run:
  python tests/test_attack_matrix.py                        # exit 1 on any red
  NIDS_85_GATE=strict python tests/test_attack_matrix.py    # also gate untrained
  pytest tests/test_attack_matrix.py -v

Design:
  - Flows are built in the raw shape produced by
    monitor/flow_aggregator.FlowAggregator.to_features() (counts, bytes, IAT,
    duration, ports, flag counts) so the production FeatureExtractor derives
    ratios / port one-hots / probe / flood features identically to live
    capture. No pcap replay-timing artifact.
  - AI score = the ensemble `score` returned by EnsembleInferenceEngine.predict
    (dynamic per-flow RF/AE split). Exactly what the monitor surfaces.
===============================================================================
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np

from ai_engine.ensemble import EnsembleInferenceEngine
from ai_engine.dataset import FEATURE_COLS
from monitor.feature_extractor import FeatureExtractor

TARGET = 0.85
PASS_PCT = 85.0
STRICT = os.environ.get("NIDS_85_GATE", "") == "strict"

SRC = "198.51.100.77"
VICTIM = "192.168.1.1"

# Ports a scanner would hit on a host with mostly-closed ports.
SYN_RST_PORTS_RANDOM = [6666, 7777, 8888, 9000, 10000, 137, 139, 445, 514,
                        2222, 33434, 12345, 31337, 45000, 6060, 7000]
WEB_PORTS = [80, 443, 8080, 8443, 80, 443, 8080, 8443, 443, 80, 8080, 8443]
ADMIN_DB = [22, 23, 21, 3306, 5432, 3389, 6379, 27017, 5900, 22, 3306]


def _base(dst_port, **kw):
    """Raw to_features()-shaped flow initialized to zero for all FEATURE_COLS."""
    flow = {k: 0.0 for k in FEATURE_COLS}
    flow["dst_port"] = float(dst_port)
    flow["_src_ip"] = SRC
    flow["_dst_ip"] = VICTIM
    flow["_src_port"] = int(kw.pop("src_port", 40000))
    flow["_dst_port"] = int(dst_port)
    flow["_timestamp"] = float(kw.pop("ts", 1000.0))
    flow["_min_ttl"] = 64
    flow["direction"] = "outgoing"
    flow.update(kw)
    return flow


def _finish(flow, counts, duration, bwd_pk=None, pc_override=None):
    for name, cnt in counts.items():
        flow[name] = float(cnt)
    flow["duration"] = max(duration, 1e-6)
    dur = flow["duration"]
    pc = int(pc_override) if pc_override is not None else int(sum(counts.values()))
    flow["packet_count"] = float(pc)
    flow["fwd_packet_count"] = float(counts.get("syn_flag_count", 0) + counts.get("psh_flag_count", 0))
    flow["bwd_packet_count"] = float(bwd_pk) if bwd_pk is not None else float(pc - flow["fwd_packet_count"])
    flow["flow_packets_per_sec"] = float(pc) / dur
    flow["flow_bytes_per_sec"] = (flow["src_bytes"] + flow["dst_bytes"]) / dur
    return flow


# ── Attack families (deliberate attack shapes) ──────────────────────────────

def _syn_flood_responded(seed=0):
    """100 SYN -> SYN-ACK against a live host. One long-lived flow."""
    n = 100
    flow = _base(80, src_bytes=n * 54, dst_bytes=n * 60, avg_packet_len=57.0, std_packet_len=3.0,
                 fwd_packet_len_max=54.0, bwd_packet_len_max=60.0,
                 flow_iat_mean=0.001, flow_iat_std=0.0005, flow_iat_max=0.005, flow_iat_min=0.0002)
    return _finish(flow, {"syn_flag_count": n, "ack_flag_count": n}, 1.0)


def _syn_flood_filtered(seed=1):
    """SYN flood with no replies (firewalled/filtered target)."""
    n = 100
    flow = _base(80, src_bytes=n * 54, dst_bytes=0.0, avg_packet_len=54.0, std_packet_len=0.0,
                 fwd_packet_len_max=54.0, bwd_packet_len_max=0.0,
                 flow_iat_mean=0.001, flow_iat_std=0.0003, flow_iat_max=0.004, flow_iat_min=0.0002)
    return _finish(flow, {"syn_flag_count": n}, 1.0)


def _syn_rst_scan(ports):
    """A SYN that draws a RST-ACK (closed port): 2 pkts per scanned port = 1 flow each.

    Mirrors to_features() for a 2-packet flow: a single inter-arrival gap, so
    flow_iat_mean == flow_iat_min == flow_iat_max == duration, flow_iat_std == 0.
    """
    import random as _random
    rng = _random.Random(7)
    flows = []
    for dp in ports:
        dur = rng.uniform(0.0015, 0.010)
        ack = 1.0 if rng.random() < 0.6 else 0.0
        flow = _base(dp, src_bytes=44.0, dst_bytes=40.0, avg_packet_len=42.0, std_packet_len=2.0,
                     fwd_packet_len_max=44.0, bwd_packet_len_max=40.0,
                     flow_iat_mean=dur, flow_iat_std=0.0, flow_iat_max=dur, flow_iat_min=dur)
        flows.append(_finish(flow, {"syn_flag_count": 1, "rst_flag_count": 1, "ack_flag_count": ack},
                             dur, bwd_pk=1))
    return flows


def _syn_probe(ports):
    """Stealthy single SYN, no reply (filtered scan).

    Mirrors to_features() for a single-packet flow: no inter-arrival gaps,
    so all flow_iat_* are exactly 0.0 and duration clamps to 1e-6.
    """
    flows = []
    for dp in ports:
        flow = _base(dp, src_bytes=60.0, dst_bytes=0.0, avg_packet_len=60.0, std_packet_len=0.0,
                     fwd_packet_len_max=60.0, bwd_packet_len_max=0.0,
                     flow_iat_mean=0.0, flow_iat_std=0.0, flow_iat_max=0.0, flow_iat_min=0.0)
        flows.append(_finish(flow, {"syn_flag_count": 1}, 1e-6))
    return flows


def _single_probe(dst_port, counts, avg_len, pc=1):
    """A single unresponded 1-2 pkt probe (XMAS/FIN/UDP). Single IAT == 0."""
    flow = _base(dst_port, src_bytes=60.0, dst_bytes=0.0, avg_packet_len=avg_len, std_packet_len=0.0,
                 fwd_packet_len_max=60.0, bwd_packet_len_max=0.0,
                 flow_iat_mean=0.0, flow_iat_std=0.0, flow_iat_max=0.0, flow_iat_min=0.0)
    return _finish(flow, counts, 1e-6, pc_override=pc)


def _http_ddos(seed=1):
    """CICIDS2017 HTTP-POST-flood DDoS shape (RF p>=0.99 from real holdout rows)."""
    flow = _base(80, src_bytes=328.0, dst_bytes=11595.0, avg_packet_len=917.6, std_packet_len=1813.7,
                 fwd_packet_len_max=316.0, bwd_packet_len_max=5792.0,
                 flow_iat_mean=8.97, flow_iat_std=29.7, flow_iat_max=98.7, flow_iat_min=0.000006)
    return _finish(flow, {"fin_flag_count": 1, "ack_flag_count": 1}, 0.4686, bwd_pk=6)


def _ssh_brute(seed=1):
    """Real CICIDS2017 SSH-Patator rows (Tuesday file): 2-packet handshake-only
    attempts on :22. This is the exact distribution the RF learned SSH brute
    force from — synthetic hand-authoring does not match it."""
    return _cicids_rows("data/raw/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv",
                        "SSH", 40)


_CICIDS_CACHE = {}
_CICIDS_MAP = {
    " Destination Port": "dst_port", " Flow Duration": "duration",
    "Total Length of Fwd Packets": "src_bytes", " Total Length of Bwd Packets": "dst_bytes",
    " Packet Length Mean": "avg_packet_len", " Packet Length Std": "std_packet_len",
    " Flow Bytes/s": "flow_bytes_per_sec", " Flow Packets/s": "flow_packets_per_sec",
    " Fwd Packet Length Max": "fwd_packet_len_max", " Bwd Packet Length Max": "bwd_packet_len_max",
    " Flow IAT Mean": "flow_iat_mean", " Flow IAT Std": "flow_iat_std",
    " Flow IAT Max": "flow_iat_max", " Flow IAT Min": "flow_iat_min",
    "FIN Flag Count": "fin_flag_count", "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count", "PSH Flag Count": "psh_flag_count",
    "ACK Flag Count": "ack_flag_count",
    " Total Fwd Packets": "fwd_count", " Total Backward Packets": "bwd_count",
    " Label": "label",
}
_CICIDS_TIME_COLS = ("duration", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min")


def _cicids_rows(csv_path, label_substr, n, seed=0):
    """Sample real CICIDS2017 rows of a given label as to_features-shaped flows.

    Applies the same unit conversion the trainer does (CICIDS time features are
    microseconds; production is seconds). The raw count columns are kept so the
    production FeatureExtractor derives ratios / probe / flood identically.
    """
    import random as _random
    import pandas as pd

    key = csv_path
    if key not in _CICIDS_CACHE:
        df = pd.read_csv(csv_path, low_memory=False, encoding="latin1")
        df.columns = df.columns.str.strip()
        mapped = {k.strip(): v for k, v in _CICIDS_MAP.items()}
        df = df.rename(columns={k: v for k, v in mapped.items() if k in df.columns})
        _CICIDS_CACHE[key] = df

    df = _CICIDS_CACHE[key]
    sub = df[df["label"].astype(str).str.contains(label_substr, case=False, na=False)]
    if len(sub) == 0:
        raise RuntimeError(f"No CICIDS rows for label~{label_substr!r} in {csv_path}")

    internal = set(_CICIDS_MAP.values())
    rows = sub.sample(min(n, len(sub)), random_state=seed)
    flows = []
    for _, r in rows.iterrows():
        d = {}
        for k, v in r.to_dict().items():
            if k not in internal:
                continue
            try:
                fv = float(v)
            except (TypeError, ValueError):
                fv = 0.0
            if fv != fv:  # NaN -> 0.0 (matches trainer _clean)
                fv = 0.0
            d[k] = fv
        for tcol in _CICIDS_TIME_COLS:
            if tcol in d:
                d[tcol] = d[tcol] / 1e6
        d["packet_count"] = d.get("fwd_count", 0.0) + d.get("bwd_count", 0.0)
        d.pop("fwd_count", None)
        d.pop("bwd_count", None)
        d.pop("label", None)
        d["_src_ip"] = SRC
        d["_dst_ip"] = VICTIM
        d["_src_port"] = 40000
        d["_dst_port"] = int(d.get("dst_port", 0))
        d["_timestamp"] = float(2000.0)
        d["_min_ttl"] = 64
        d["direction"] = "outgoing"
        flows.append(d)
    return flows


ATTACK_FAMILIES = [
    ("SYN_PROBE",            lambda s: _syn_probe(SYN_RST_PORTS_RANDOM)),
    ("SYN_RST_SCAN_RANDOM",  lambda s: _syn_rst_scan(SYN_RST_PORTS_RANDOM)),
    ("SYN_RST_SCAN_WEB",     lambda s: _syn_rst_scan(WEB_PORTS)),
    ("SYN_RST_SCAN_ADMIN_DB", lambda s: _syn_rst_scan(ADMIN_DB)),
    ("SYN_FLOOD_RESPONDED",  lambda s: [_syn_flood_responded(s)]),
    ("SYN_FLOOD_FILTERED",   lambda s: [_syn_flood_filtered(s)]),
    ("HTTP_DDOS_CICIDS",     lambda s: [_http_ddos(s)]),
    ("SSH_BRUTE_CICIDS",     lambda s: _ssh_brute(s)),
    # Untrained probe shapes — reported always, gated only under strict
    ("XMAS_SCAN",            lambda s: [_single_probe(p, {"fin_flag_count": 1}, 60.0, pc=1)
                                        for p in SYN_RST_PORTS_RANDOM[:6]]),
    ("FIN_PROBE",            lambda s: [_single_probe(p, {"fin_flag_count": 1}, 60.0, pc=1)
                                        for p in SYN_RST_PORTS_RANDOM[6:12]]),
    ("UDP_SCAN",             lambda s: [_single_probe(p, {}, 32.0, pc=1)
                                        for p in SYN_RST_PORTS_RANDOM[:8]]),
]

# Families gated only when NIDS_85_GATE=strict (their synthetic training is a
# known gap; they still show in the matrix report).
DEFERRED = {"XMAS_SCAN", "FIN_PROBE", "UDP_SCAN"}


# ── Benign families (report only, never gated) ──────────────────────────────

def _benign_dns(seed=2):
    flow = _base(53, src_bytes=90.0, dst_bytes=210.0, avg_packet_len=75.0, std_packet_len=30.0,
                 fwd_packet_len_max=100.0, bwd_packet_len_max=200.0,
                 flow_iat_mean=0.006, flow_iat_std=0.004, flow_iat_max=0.02, flow_iat_min=0.0002)
    return _finish(flow, {"syn_flag_count": 1, "ack_flag_count": 1}, 0.012, bwd_pk=2)


def _benign_https(seed=3):
    flow = _base(443, src_bytes=1200.0, dst_bytes=3400.0, avg_packet_len=290.0, std_packet_len=180.0,
                 fwd_packet_len_max=1400.0, bwd_packet_len_max=1500.0,
                 flow_iat_mean=0.05, flow_iat_std=0.04, flow_iat_max=0.4, flow_iat_min=0.0003)
    return _finish(flow, {"syn_flag_count": 1, "ack_flag_count": 7, "fin_flag_count": 1}, 0.8, bwd_pk=8)


def _benign_mdns(seed=4):
    flow = _base(5353, src_bytes=120.0, dst_bytes=90.0, avg_packet_len=105.0, std_packet_len=40.0,
                 fwd_packet_len_max=160.0, bwd_packet_len_max=150.0,
                 flow_iat_mean=0.01, flow_iat_std=0.008, flow_iat_max=0.06, flow_iat_min=0.001)
    return _finish(flow, {}, 0.02)


def _benign_stream(seed=5):
    n = 300
    flow = _base(443, src_bytes=0.2 * n * 1400, dst_bytes=0.8 * n * 1400,
                 avg_packet_len=1120.0, std_packet_len=300.0,
                 fwd_packet_len_max=1500.0, bwd_packet_len_max=1500.0,
                 flow_iat_mean=0.012, flow_iat_std=0.009, flow_iat_max=0.08, flow_iat_min=0.0001)
    return _finish(flow, {"syn_flag_count": 1, "ack_flag_count": n - 1}, 3.0, bwd_pk=int(0.8 * n))


def _benign_ssh(seed=6):
    flow = _base(22, src_bytes=600.0, dst_bytes=1400.0, avg_packet_len=66.0, std_packet_len=30.0,
                 fwd_packet_len_max=160.0, bwd_packet_len_max=240.0,
                 flow_iat_mean=1.5, flow_iat_std=2.0, flow_iat_max=12.0, flow_iat_min=0.01)
    return _finish(flow, {"syn_flag_count": 1, "ack_flag_count": 12, "fin_flag_count": 1}, 30, bwd_pk=15)


BENIGN_FAMILIES = [
    ("BENIGN_DNS",    lambda s: [_benign_dns(s)]),
    ("BENIGN_HTTPS",  lambda s: [_benign_https(s)]),
    ("BENIGN_MDNS",   lambda s: [_benign_mdns(s)]),
    ("BENIGN_STREAM", lambda s: [_benign_stream(s)]),
    ("BENIGN_SSH",    lambda s: [_benign_ssh(s)]),
]


# ── Runner ──────────────────────────────────────────────────────────────────

def _score_families(families, extractor, engine):
    report = {}
    for name, builder in families:
        flows = builder(0)
        if not flows:
            continue
        df = extractor.transform(flows)
        if df is None:
            report[name] = {"scores": []}
            continue
        results = engine.predict(df)
        report[name] = {"scores": [r["score"] for r in results]}
    return report


def _stats(scores):
    if not scores:
        return {}
    s = np.array(scores)
    return {
        "n": len(s),
        "mean": round(float(s.mean()), 4),
        "min": round(float(s.min()), 4),
        "pct_ge85": round(float((s >= TARGET).mean() * 100.0), 1),
        "pct_ge80": round(float((s >= 0.8).mean() * 100.0), 1),
    }


def matrix_result(attack):
    """Return (families_failed, failure_list) given the attack report."""
    failures = []
    for name, data in attack.items():
        stats = _stats(data["scores"])
        if stats["n"] == 0:
            continue
        if name in DEFERRED and not STRICT:
            continue
        if stats["pct_ge85"] < PASS_PCT:
            failures.append(name)
    return failures


def print_summary(attack, benign, engine):
    print("\n" + "=" * 76)
    print("ATTACK MATRIX — AI score >= 0.85 goal  (" + engine.mode + ")")
    print(engine.describe())
    print("=" * 76)
    fmt = "{:<24}{:>5}{:>9}{:>9}{:>10}{:>9}  {}"
    print(fmt.format("family", "n", "mean", "min", "%>=0.85", "%>=0.80", "verdict"))
    print("-" * 76)
    for name, data in attack.items():
        st = _stats(data["scores"])
        gated = name not in DEFERRED or STRICT
        ok = st.get("n", 0) > 0 and st["pct_ge85"] >= PASS_PCT
        if gated and st.get("n", 0) > 0:
            verdict = "PASS" if ok else "FAIL"
        elif not gated:
            verdict = "gap*"
        else:
            verdict = "-"
        print(fmt.format(name, st.get("n", 0), st.get("mean", 0.0), st.get("min", 0.0),
                         st.get("pct_ge85", 0.0), st.get("pct_ge80", 0.0), verdict))
    print("-" * 76)
    print("BENIGN (report only, not gated):")
    print(fmt.format("family", "n", "mean", "min", "%>=0.85", "%>=0.80", "note"))
    for name, data in benign.items():
        st = _stats(data["scores"])
        note = "FP risk" if st.get("pct_ge85", 0.0) >= PASS_PCT else "ok"
        print(fmt.format(name, st.get("n", 0), st.get("mean", 0.0), st.get("min", 0.0),
                         st.get("pct_ge85", 0.0), st.get("pct_ge80", 0.0), note))
    print("-" * 76)
    print("* = untrained probe shape (gated only with NIDS_85_GATE=strict)")


# ── Entry points ────────────────────────────────────────────────────────────

def run_matrix():
    engine = EnsembleInferenceEngine()
    if not engine.load():
        print("FAIL: Could not load ensemble models (train first).")
        return 2
    extractor = FeatureExtractor()
    attack = _score_families(ATTACK_FAMILIES, extractor, engine)
    benign = _score_families(BENIGN_FAMILIES, extractor, engine)
    print_summary(attack, benign, engine)
    failures = matrix_result(attack)
    if failures:
        print(f"\nGATE FAIL — {len(failures)} family(ies) below {TARGET}: {sorted(failures)}")
        return 1
    print(f"\nGATE PASS — all deliberate-attack families >= {TARGET} for >=85% of flows")
    return 0


def test_attack_matrix():
    rc = run_matrix()
    if rc == 1:
        raise AssertionError("Attack matrix gate failed: one or more deliberate-attack "
                             "families score below 0.85 on >=85% of flows. See report.")
    assert rc == 0, f"attack matrix could not run (rc={rc})"


if __name__ == "__main__":
    sys.exit(run_matrix())
