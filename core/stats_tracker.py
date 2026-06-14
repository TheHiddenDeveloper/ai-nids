"""
Stats Tracker
-------------
Maintains rolling-window statistics for the live dashboard:
  - Flows per second
  - Alerts per second
  - Top talker IPs
  - Score distributions (per-host + global)
  - Concept drift detection

Thread-safe: all public methods acquire a lock.
The dashboard reads a snapshot dict via .snapshot() — never the live state.
"""

import time
import threading
import statistics
from collections import defaultdict, deque
from typing import Dict, Any, Optional


class StatsTracker:
    """
    Rolling statistics over the last `window_secs` seconds.
    Includes per-host score tracking for drift detection.

    T1: baseline is re-calculated every `baseline_interval` benign scores
        so it tracks long-term drift instead of freezing at first 50 samples.
    T2: deque capacities are configurable via `score_capacity` / `host_score_capacity`.
    T3: at most `max_hosts` unique hosts tracked in `_host_scores`; oldest evicted.
    """

    def __init__(
        self,
        window_secs: int = 300,
        score_capacity: int = 5000,
        host_score_capacity: int = 500,
        max_hosts: int = 1000,
        baseline_interval: int = 1000,
    ):
        self.window = window_secs
        self._lock  = threading.RLock()

        self._score_capacity = score_capacity
        self._host_score_capacity = host_score_capacity
        self._max_hosts = max_hosts
        self._baseline_interval = baseline_interval

        # Timestamped event queues (pruned on snapshot)
        self._flow_times:  deque = deque()
        self._alert_times: deque = deque()

        # Cumulative counters
        self._total_flows:  int = 0
        self._total_alerts: int = 0
        self._total_packets: int = 0

        # Distribution counters
        self._src_ip_counts:   defaultdict = defaultdict(int)
        self._dst_ip_counts:   defaultdict = defaultdict(int)
        self._label_counts:    defaultdict = defaultdict(int)
        self._severity_counts: defaultdict = defaultdict(int)
        self._protocol_counts: defaultdict = defaultdict(int)

        self._all_scores: deque = deque(maxlen=self._score_capacity)
        self._benign_scores: deque = deque(maxlen=self._score_capacity)
        self._host_scores: dict = {}

        # Drift baseline
        self._drift_baseline_mean: Optional[float] = None
        self._drift_baseline_std:  Optional[float] = None
        self._samples_since_baseline: int = 0

        self._started_at = time.time()

    def record_packet(self):
        with self._lock:
            self._total_packets += 1

    def record_flow(self, flow: dict):
        with self._lock:
            now = time.time()
            self._flow_times.append(now)
            self._total_flows += 1
            proto = flow.get("dst_port", 0)
            self._protocol_counts[proto] += 1

    def record_flows_batch(self, flows: list):
        """L1: record multiple flows in a single lock acquisition."""
        with self._lock:
            now = time.time()
            for flow in flows:
                self._flow_times.append(now)
                self._total_flows += 1
                proto = flow.get("dst_port", 0)
                self._protocol_counts[proto] += 1

    def record_flow_score(self, score: float, label: str, src_ip: str = None):
        """
        Record a score for ALL flows (not just alerts).
        Used for benign baseline tracking and per-host drift detection.
        """
        with self._lock:
            self._all_scores.append(score)
            if label == "BENIGN":
                self._benign_scores.append(score)
                # T1: re-baseline every baseline_interval samples
                self._samples_since_baseline += 1
                if self._samples_since_baseline >= self._baseline_interval and self._drift_baseline_mean is not None:
                    scores = list(self._benign_scores)
                    if len(scores) >= self._baseline_interval:
                        self._drift_baseline_mean = self._safe_mean(scores)
                        self._drift_baseline_std  = self._safe_stdev(scores)
                    self._samples_since_baseline = 0
            if src_ip:
                if src_ip not in self._host_scores:
                    if len(self._host_scores) >= self._max_hosts:
                        self._host_scores.pop(next(iter(self._host_scores)))
                    self._host_scores[src_ip] = deque(maxlen=self._host_score_capacity)
                self._host_scores[src_ip].append(score)

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
            self._all_scores.append(score)

    def _prune(self, q: deque, cutoff: float):
        while q and q[0] < cutoff:
            q.popleft()

    def _safe_mean(self, scores) -> float:
        return sum(scores) / len(scores) if scores else 0.0

    def _safe_stdev(self, scores) -> float:
        if len(scores) < 2:
            return 0.0
        return statistics.stdev(scores)

    def check_drift(self) -> Dict[str, Any]:
        """
        Compare recent benign score distribution to the baseline.
        Initialises baseline on first call; subsequent calls flag drift.

        Returns:
            drift_detected: bool
            baseline_mean / baseline_std / recent_mean / recent_std
            shift: absolute change in mean
        """
        with self._lock:
            scores = list(self._benign_scores)

        result = {
            "drift_detected": False,
            "baseline_mean":  self._drift_baseline_mean,
            "baseline_std":   self._drift_baseline_std,
            "recent_mean":    None,
            "recent_std":     None,
            "shift":          0.0,
        }

        if len(scores) < 50:
            result["recent_mean"] = self._safe_mean(scores)
            return result

        # Initialise baseline on first call
        if self._drift_baseline_mean is None:
            self._drift_baseline_mean = self._safe_mean(scores)
            self._drift_baseline_std  = self._safe_stdev(scores)
            result["baseline_mean"] = self._drift_baseline_mean
            result["baseline_std"]  = self._drift_baseline_std
            result["recent_mean"]   = self._drift_baseline_mean
            result["recent_std"]    = self._drift_baseline_std
            return result

        # Compare recent half vs baseline
        mid = len(scores) // 2
        recent = scores[mid:]
        recent_mean = self._safe_mean(recent)
        recent_std  = self._safe_stdev(recent)
        shift = abs(recent_mean - self._drift_baseline_mean)

        result["recent_mean"] = recent_mean
        result["recent_std"]  = recent_std
        result["shift"]       = round(shift, 4)

        # Flag drift if mean shifted by > 2 baseline stds (or > 0.1 absolute)
        threshold = max(self._drift_baseline_std * 2, 0.1)
        result["drift_detected"] = shift > threshold

        return result

    def host_score_stats(self, src_ip: str) -> Dict[str, Any]:
        """Return score statistics for a specific host."""
        with self._lock:
            scores = list(self._host_scores.get(src_ip, []))
        if not scores:
            return {"count": 0}
        return {
            "count": len(scores),
            "mean":  round(self._safe_mean(scores), 4),
            "max":   round(max(scores), 4),
            "min":   round(min(scores), 4),
        }

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

            all_scores = list(self._all_scores)
            benign_scores = list(self._benign_scores)

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

                # All-scores stats
                "score_count": len(all_scores),
                "score_mean":  round(self._safe_mean(all_scores), 4) if all_scores else 0.0,

                # Benign baseline stats
                "benign_score_count": len(benign_scores),
                "benign_score_mean":  round(self._safe_mean(benign_scores), 4) if benign_scores else 0.0,

                # Drift check
                "drift": self.check_drift(),

                "snapshot_at": now,
            }
