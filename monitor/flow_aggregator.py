"""
Flow Aggregator
---------------
Groups packets into bidirectional network flows (5-tuple key).
Computes statistical features per flow for ML input.
"""

import time
import numpy as np
from typing import Dict, List, Optional
from loguru import logger


class Flow:
    """Represents a single bidirectional network flow."""

    def __init__(self):
        self.start_time: float = time.time()
        self.last_seen: float = self.start_time
        self.packets: List[dict] = []

    def add_packet(self, pkt: dict):
        self.packets.append(pkt)
        self.last_seen = pkt["timestamp"]

    def is_expired(self, timeout: int = 60) -> bool:
        return (time.time() - self.last_seen) > timeout

    def to_features(self) -> Optional[dict]:
        """Convert flow packets into a feature vector for ML inference."""
        if len(self.packets) < 2:
            return None

        pkt_lens = [p.get("ip_len", 0) for p in self.packets]
        duration = self.last_seen - self.start_time
        if duration <= 0:
            duration = 1e-6

        first = self.packets[0]
        return {
            "dst_port": first.get("dst_port", 0),
            "duration": round(duration, 6),
            "src_bytes": sum(pkt_lens),
            "dst_bytes": sum(pkt_lens),
            "packet_count": len(self.packets),
            "avg_packet_len": float(np.mean(pkt_lens)),
            "std_packet_len": float(np.std(pkt_lens)),
            "flow_bytes_per_sec": sum(pkt_lens) / duration,
            "flow_packets_per_sec": len(self.packets) / duration,
            "fwd_packet_len_max": float(np.max(pkt_lens)),
            "bwd_packet_len_max": float(np.max(pkt_lens)),
            "fin_flag_count": sum(p.get("fin", 0) for p in self.packets),
            "syn_flag_count": sum(p.get("syn", 0) for p in self.packets),
            "rst_flag_count": sum(p.get("rst", 0) for p in self.packets),
            "psh_flag_count": sum(p.get("psh", 0) for p in self.packets),
            "ack_flag_count": sum(p.get("ack", 0) for p in self.packets),
            # Metadata (not fed to model)
            "_src_ip": first.get("src_ip"),
            "_dst_ip": first.get("dst_ip"),
            "_src_port": first.get("src_port"),
            "_dst_port": first.get("dst_port"),
            "_timestamp": self.start_time,
        }


class FlowAggregator:
    """
    Maintains a table of active flows.
    Evicts expired flows and returns their feature vectors.
    """

    def __init__(self, flow_timeout: int = 60):
        self.timeout = flow_timeout
        self._flows: Dict[tuple, Flow] = {}

    @staticmethod
    def _flow_key(pkt: dict) -> tuple:
        """Bidirectional 5-tuple key (sorted so A→B == B→A)."""
        src = (pkt.get("src_ip", ""), pkt.get("src_port", 0))
        dst = (pkt.get("dst_ip", ""), pkt.get("dst_port", 0))
        proto = pkt.get("protocol", 0)
        return (min(src, dst), max(src, dst), proto)

    def ingest(self, pkt: dict) -> List[dict]:
        """
        Add packet to matching flow. Returns list of completed flow features
        from any flows that expired since last call.
        """
        key = self._flow_key(pkt)
        if key not in self._flows:
            self._flows[key] = Flow()
        self._flows[key].add_packet(pkt)
        return self._evict_expired()

    def _evict_expired(self) -> List[dict]:
        completed = []
        expired_keys = [k for k, f in self._flows.items() if f.is_expired(self.timeout)]
        for k in expired_keys:
            flow = self._flows.pop(k)
            features = flow.to_features()
            if features:
                completed.append(features)
        return completed

    def flush_all(self) -> List[dict]:
        """Force-complete all active flows (e.g. on shutdown)."""
        completed = []
        for flow in self._flows.values():
            features = flow.to_features()
            if features:
                completed.append(features)
        self._flows.clear()
        return completed

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)
