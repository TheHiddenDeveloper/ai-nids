"""
Flow Aggregator
---------------
Groups packets into bidirectional network flows (5-tuple key).
Computes statistical features per flow for ML input.
"""

import time
import math
import ipaddress
import numpy as np
from typing import Dict, List, Optional, Set
import json
from loguru import logger
from core.redis_client import get_redis_client


class Flow:
    """Represents a single bidirectional network flow (O(1) memory footprint)."""

    def __init__(self):
        self.start_time: float = time.time()
        self.last_seen: float = self.start_time
        
        # O(1) state variables instead of storing all packets
        self.packet_count: int = 0
        self.fwd_packet_count: int = 0
        self.bwd_packet_count: int = 0
        
        self.fwd_sum_len: float = 0.0
        self.bwd_sum_len: float = 0.0
        self.sum_sq_len: float = 0.0
        self.fwd_packet_len_max: float = 0.0
        self.bwd_packet_len_max: float = 0.0
        
        # Inter-arrival Time (IAT) stats
        self.sum_iat: float = 0.0
        self.sum_sq_iat: float = 0.0
        self.max_iat: float = 0.0
        self.min_iat: float = float('inf')
        
        # Flag counters
        self.fin_flag_count: int = 0
        self.syn_flag_count: int = 0
        self.rst_flag_count: int = 0
        self.psh_flag_count: int = 0
        self.ack_flag_count: int = 0
        
        self._dst_port: Optional[int] = None
        self._is_init_labeled: bool = False
        self._protocol: Optional[int] = None
        self._direction: str = "uncertain"

    def _get_redis_key(self) -> str:
        # Generate a stable string key from the 5-tuple
        src = (self._src_ip or "", self._src_port or 0)
        dst = (self._dst_ip or "", self._dst_port or 0)
        p1 = min(src, dst)
        p2 = max(src, dst)
        return f"nids:flow:{p1[0]}:{p1[1]}_{p2[0]}:{p2[1]}_{self._protocol or 0}"

    def add_packet(self, pkt: dict):
        current_ts = pkt.get("timestamp", time.time())
        is_syn_init = (pkt.get("syn") == 1 and pkt.get("ack") == 0)
        
        if self.packet_count == 0:
            self.start_time = current_ts
            self._src_ip = pkt.get("src_ip")
            self._dst_ip = pkt.get("dst_ip")
            self._src_port = pkt.get("src_port")
            self._dst_port = pkt.get("dst_port")
            if is_syn_init: self._is_init_labeled = True
        elif is_syn_init and not self._is_init_labeled:
            # Re-orient! We saw a response/middle packet first, now we see the initiator.
            self._src_ip, self._dst_ip = self._dst_ip, self._src_ip
            self._src_port, self._dst_port = self._dst_port, self._src_port
            # Swap accumulated directional counters
            self.fwd_packet_count, self.bwd_packet_count = self.bwd_packet_count, self.fwd_packet_count
            self.fwd_sum_len, self.bwd_sum_len = self.bwd_sum_len, self.fwd_sum_len
            self.fwd_packet_len_max, self.bwd_packet_len_max = self.bwd_packet_len_max, self.fwd_packet_len_max
            self._is_init_labeled = True
        else:
            iat = max(0.0, current_ts - self.last_seen)
            self.sum_iat += iat
            self.sum_sq_iat += iat * iat
            if iat > self.max_iat: self.max_iat = float(iat)
            if iat < self.min_iat: self.min_iat = float(iat)
            
        self.last_seen = current_ts
        self.packet_count += 1
        
        ip_len = pkt.get("ip_len", 0)
        is_fwd = (pkt.get("src_ip") == self._src_ip)
        
        if is_fwd:
            self.fwd_packet_count += 1
            self.fwd_sum_len += ip_len
            if ip_len > self.fwd_packet_len_max:
                self.fwd_packet_len_max = float(ip_len)
        else:
            self.bwd_packet_count += 1
            self.bwd_sum_len += ip_len
            if ip_len > self.bwd_packet_len_max:
                self.bwd_packet_len_max = float(ip_len)
                
        self.sum_sq_len += ip_len * ip_len
            
        self.fin_flag_count += pkt.get("fin", 0)
        self.syn_flag_count += pkt.get("syn", 0)
        self.rst_flag_count += pkt.get("rst", 0)
        self.psh_flag_count += pkt.get("psh", 0)
        self.ack_flag_count += pkt.get("ack", 0)
        if self._protocol is None:
            self._protocol = pkt.get("protocol")
        
        # Calculate direction on first packet or when initiator is re-oriented
        if self.packet_count == 1 or (is_syn_init and self._is_init_labeled):
            self._direction = self._calculate_direction(pkt.get("home_nets", []))

    def _calculate_direction(self, home_nets: List[str]) -> str:
        """Determines flow direction based on HOME_NET configuration."""
        if not home_nets or not self._src_ip or not self._dst_ip:
            return "uncertain"
            
        try:
            networks = [ipaddress.ip_network(net) for net in home_nets]
            src_ip = ipaddress.ip_address(self._src_ip)
            dst_ip = ipaddress.ip_address(self._dst_ip)
            
            src_internal = any(src_ip in net for net in networks)
            dst_internal = any(dst_ip in net for net in networks)
            
            if src_internal and not dst_internal:
                return "outbound"
            if not src_internal and dst_internal:
                return "inbound"
            if src_internal and dst_internal:
                return "internal"
            return "external"
        except Exception:
            return "uncertain"

    def sync_to_redis(self, redis_client, pkt: dict):
        """Push atomic updates to Redis for distributed aggregation."""
        try:
            rky = self._get_redis_key()
            ip_len = pkt.get("ip_len", 0)
            is_fwd = (pkt.get("src_ip") == self._src_ip)
            
            pipe = redis_client.pipeline()
            # Basic stats
            pipe.hsetnx(rky, "start_time", self.start_time)
            pipe.hset(rky, "last_seen", self.last_seen)
            pipe.hincrby(rky, "packet_count", 1)
            pipe.hincrbyfloat(rky, "sum_sq_len", ip_len * ip_len)
            
            # Directional sums
            if is_fwd:
                pipe.hincrby(rky, "fwd_packet_count", 1)
                pipe.hincrbyfloat(rky, "fwd_sum_len", ip_len)
            else:
                pipe.hincrby(rky, "bwd_packet_count", 1)
                pipe.hincrbyfloat(rky, "bwd_sum_len", ip_len)
            
            # Flags
            for flag in ["fin", "syn", "rst", "psh", "ack"]:
                if pkt.get(flag):
                    pipe.hincrby(rky, f"{flag}_flag_count", 1)
            
            # Metadata (only needed once but hset is fine)
            meta = {
                "_src_ip": self._src_ip, "_dst_ip": self._dst_ip,
                "_src_port": self._src_port, "_dst_port": self._dst_port,
                "_protocol": self._protocol, "_direction": self._direction
            }
            pipe.hset(rky, mapping={k: str(v) for k, v in meta.items() if v is not None})
            
            # Global expiry tracking
            pipe.zadd("nids:active_flows", {rky: self.last_seen})
            pipe.execute()
        except Exception as e:
            logger.error(f"Flow: Redis sync failed: {e}")

    def load_from_redis(self, redis_client):
        """Pull global stats from Redis to enrich local flow data."""
        try:
            rky = self._get_redis_key()
            data = redis_client.hgetall(rky)
            if not data: return
            
            self.start_time = float(data.get("start_time", self.start_time))
            self.last_seen = float(data.get("last_seen", self.last_seen))
            self.packet_count = int(data.get("packet_count", self.packet_count))
            self.fwd_packet_count = int(data.get("fwd_packet_count", self.fwd_packet_count))
            self.bwd_packet_count = int(data.get("bwd_packet_count", self.bwd_packet_count))
            self.fwd_sum_len = float(data.get("fwd_sum_len", self.fwd_sum_len))
            self.bwd_sum_len = float(data.get("bwd_sum_len", self.bwd_sum_len))
            self.sum_sq_len = float(data.get("sum_sq_len", self.sum_sq_len))
            
            # Load flags
            self.fin_flag_count = int(data.get("fin_flag_count", self.fin_flag_count))
            self.syn_flag_count = int(data.get("syn_flag_count", self.syn_flag_count))
            self.rst_flag_count = int(data.get("rst_flag_count", self.rst_flag_count))
            self.psh_flag_count = int(data.get("psh_flag_count", self.psh_flag_count))
            self.ack_flag_count = int(data.get("ack_flag_count", self.ack_flag_count))
            
            # Metadata
            self._src_ip = data.get("_src_ip", self._src_ip)
            self._dst_ip = data.get("_dst_ip", self._dst_ip)
            self._src_port = int(data.get("_src_port")) if data.get("_src_port") else self._src_port
            self._dst_port = int(data.get("_dst_port")) if data.get("_dst_port") else self._dst_port
            self._protocol = int(data.get("_protocol")) if data.get("_protocol") else self._protocol
            self._direction = data.get("_direction", self._direction)
        except Exception as e:
            logger.error(f"Flow: Redis load failed: {e}")

    def is_expired(self, timeout: int = 60, current_time: float = None) -> bool:
        if current_time is None:
            current_time = time.time()
        return (current_time - self.last_seen) > timeout

    def to_features(self) -> Optional[dict]:
        """Convert flow statistics into a feature vector for ML inference."""
        if self.packet_count < 2:
            return None

        duration = self.last_seen - self.start_time
        if duration <= 0:
            duration = 1e-6

        total_len = self.fwd_sum_len + self.bwd_sum_len
        avg_packet_len = total_len / self.packet_count
        
        # Variance = (sum_sq / count) - (mean^2)
        variance = (self.sum_sq_len / self.packet_count) - (avg_packet_len * avg_packet_len)
        std_packet_len = float(math.sqrt(max(0.0, variance)))

        iat_count = max(1, self.packet_count - 1)
        flow_iat_mean = self.sum_iat / iat_count
        iat_variance = (self.sum_sq_iat / iat_count) - (flow_iat_mean * flow_iat_mean)
        flow_iat_std = float(math.sqrt(max(0.0, iat_variance)))
        flow_iat_min = 0.0 if self.min_iat == float('inf') else self.min_iat

        return {
            "dst_port": self._dst_port or 0,
            "duration": round(duration, 6),
            "src_bytes": self.fwd_sum_len,
            "dst_bytes": self.bwd_sum_len,
            "packet_count": self.packet_count,
            "fwd_packet_count": self.fwd_packet_count,
            "bwd_packet_count": self.bwd_packet_count,
            "avg_packet_len": float(avg_packet_len),
            "std_packet_len": std_packet_len,
            "flow_bytes_per_sec": total_len / duration,
            "flow_packets_per_sec": self.packet_count / duration,
            "fwd_packet_len_max": self.fwd_packet_len_max,
            "bwd_packet_len_max": self.bwd_packet_len_max,
            "flow_iat_mean": float(flow_iat_mean),
            "flow_iat_std": flow_iat_std,
            "flow_iat_max": float(self.max_iat),
            "flow_iat_min": float(flow_iat_min),
            "fin_flag_count": self.fin_flag_count,
            "syn_flag_count": self.syn_flag_count,
            "rst_flag_count": self.rst_flag_count,
            "psh_flag_count": self.psh_flag_count,
            "ack_flag_count": self.ack_flag_count,
            # Metadata (not fed to model)
            "_src_ip": self._src_ip,
            "_dst_ip": self._dst_ip,
            "_src_port": self._src_port,
            "_dst_port": self._dst_port,
            "_timestamp": self.start_time,
            "direction": self._direction,
        }


class FlowAggregator:
    """
    Maintains a table of active flows.
    Evicts expired flows and returns their feature vectors.
    """

    def __init__(self, flow_timeout: int = 60, eviction_interval: float = 1.0, home_net: List[str] = None):
        self.timeout = flow_timeout
        self.eviction_interval = eviction_interval
        self.home_net = home_net or []
        self._flows: Dict[tuple, Flow] = {}
        self._last_evict: float = time.time()
        self.redis = get_redis_client()

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
        
        flow = self._flows[key]
        # Inject home_nets into packet temporarily so flow can calculate direction
        pkt["home_nets"] = self.home_net
        flow.add_packet(pkt)
        
        if self.redis:
            flow.sync_to_redis(self.redis, pkt)

        # Rate-limited eviction
        now = time.time()
        if now - self._last_evict > self.eviction_interval:
            self._last_evict = now
            return self._evict_expired(now)
        
        return []

    def _evict_expired(self, current_time: float = None) -> List[dict]:
        if current_time is None:
            current_time = time.time()
            
        completed = []
        
        # 1. Check local flows
        expired_keys = [k for k, f in self._flows.items() if f.is_expired(self.timeout, current_time)]
        for k in expired_keys:
            flow = self._flows.pop(k)
            if self.redis:
                flow.load_from_redis(self.redis)
                # Cleanup Redis Global State
                self.redis.delete(flow._get_redis_key())
                self.redis.zrem("nids:active_flows", flow._get_redis_key())
            
            features = flow.to_features()
            if features:
                completed.append(features)
        
        # 2. Check Global flows (in case another sensor saw the last packet)
        # This part is optional for a simple distributed setup, but ensures consistency.
        
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
