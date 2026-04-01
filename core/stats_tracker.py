"""
Stats Tracker
-------------
Maintains rolling-window statistics for the live dashboard:
  - Flows per second
  - Alerts per second
  - Top talker IPs
  - Attack type distribution
  - Score percentiles

Thread-safe: all public methods acquire a lock.
The dashboard reads a snapshot dict via .snapshot() — never the live state.
"""

import time
import threading
from collections import defaultdict, deque
from typing import Dict, Any


class StatsTracker:
    """
    Rolling statistics over the last `window_secs` seconds.
    """

    def __init__(self, window_secs: int = 300):
        self.window = window_secs
        self._lock  = threading.Lock()

        # Timestamped event queues (pruned on snapshot)
        self._flow_times:  deque = deque()   # timestamps of completed flows
        self._alert_times: deque = deque()   # timestamps of alerts

        # Cumulative counters (never reset)
        self._total_flows:  int = 0
        self._total_alerts: int = 0
        self._total_packets: int = 0

        # Distribution counters
        self._src_ip_counts:   defaultdict = defaultdict(int)
        self._dst_ip_counts:   defaultdict = defaultdict(int)
        self._label_counts:    defaultdict = defaultdict(int)
        self._severity_counts: defaultdict = defaultdict(int)
        self._protocol_counts: defaultdict = defaultdict(int)

        # Recent scores for percentile calculation (ring buffer)
        self._recent_scores: deque = deque(maxlen=1000)

        # Startup time
        self._started_at = time.time()

    def record_packet(self):
        with self._lock:
            self._total_packets += 1

    def record_flow(self, flow: dict):
        with self._lock:
            now = time.time()
            self._flow_times.append(now)
            self._total_flows += 1
            proto = flow.get("protocol_type", 0)
            self._protocol_counts[proto] += 1

    def record_alert(self, alert: dict):
        with self._lock:
            now = time.time()
            self._alert_times.append(now)
            self._total_alerts += 1

            src = alert.get("_src_ip", "unknown")
            dst = alert.get("_dst_ip", "unknown")
            label    = alert.get("label", "UNKNOWN")
            severity = alert.get("severity", "low")
            score    = alert.get("score", 0.0)

            self._src_ip_counts[src]     += 1
            self._dst_ip_counts[dst]     += 1
            self._label_counts[label]    += 1
            self._severity_counts[severity] += 1
            self._recent_scores.append(score)

    def _prune(self, q: deque, cutoff: float):
        while q and q[0] < cutoff:
            q.popleft()

    def snapshot(self) -> Dict[str, Any]:
        """
        Return a plain dict snapshot safe to pass across threads.
        Prunes stale entries from rolling queues.
        """
        with self._lock:
            now    = time.time()
            cutoff = now - self.window
            self._prune(self._flow_times,  cutoff)
            self._prune(self._alert_times, cutoff)

            uptime = now - self._started_at
            flows_in_window  = len(self._flow_times)
            alerts_in_window = len(self._alert_times)

            fps = flows_in_window  / self.window
            aps = alerts_in_window / self.window

            top_src = sorted(self._src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_dst = sorted(self._dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

            scores = list(self._recent_scores)

            return {
                # Totals
                "total_flows":   self._total_flows,
                "total_alerts":  self._total_alerts,
                "total_packets": self._total_packets,
                "uptime_secs":   round(uptime, 1),

                # Rolling window
                "window_secs":       self.window,
                "flows_in_window":   flows_in_window,
                "alerts_in_window":  alerts_in_window,
                "flows_per_sec":     round(fps, 2),
                "alerts_per_sec":    round(aps, 3),

                # Attack rate
                "attack_rate_pct": round(
                    self._total_alerts / max(self._total_flows, 1) * 100, 2
                ),

                # Distributions
                "top_src_ips":       top_src,
                "top_dst_ips":       top_dst,
                "label_counts":      dict(self._label_counts),
                "severity_counts":   dict(self._severity_counts),
                "protocol_counts":   dict(self._protocol_counts),

                # Score stats
                "score_count": len(scores),
                "score_mean":  round(sum(scores) / len(scores), 4) if scores else 0.0,
                "score_p90":   round(sorted(scores)[int(len(scores)*0.9)], 4) if len(scores) > 10 else 0.0,
                "score_p99":   round(sorted(scores)[int(len(scores)*0.99)], 4) if len(scores) > 100 else 0.0,

                "snapshot_at": now,
            }
