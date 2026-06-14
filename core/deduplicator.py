"""
Alert Deduplicator
------------------
Suppresses repeated alerts for the same (src_ip, dst_ip, dst_port) tuple
within a configurable time window. Prevents alert storms from a single
attacker flooding the logs.

Without this, a SYN flood from one IP can generate thousands of alerts
per minute for the same target, burying real events.
"""

import time
from typing import Optional
from loguru import logger
from .redis_client import get_redis_client


class AlertDeduplicator:
    """
    Tracks recently seen alert keys and suppresses duplicates.
    Uses Redis keys with TTL if available, ensuring persistence across restarts.
    """

    REDIS_PREFIX = "nids:dedup:"

    def __init__(self, suppress_window_secs: int = 60):
        self.window = suppress_window_secs
        self.redis = get_redis_client()
        
        # Fallback memory state (used if Redis is unavailable)
        self._seen: dict = {}           
        self._suppressed_counts: dict = {}

    def _make_key(self, alert: dict) -> str:
        """
        Generate a fingerprint for the alert.

        Design (D3): src_port is deliberately excluded. An attacker using
        multiple source ports (e.g., port scan) from the same source IP to
        the same destination would generate N distinct keys if src_port
        were included, disabling suppression entirely. By grouping on
        src_ip + dst_ip + dst_port + protocol + label, we suppress the
        storm while still allowing different targets to produce distinct
        alerts.
        """
        return (
            f"{alert.get('_src_ip', '?')}|"
            f"{alert.get('_dst_ip', '?')}|"
            f"{alert.get('_dst_port', '?')}|"
            f"{alert.get('_protocol', '?')}|"
            f"{alert.get('label', '?')}"
        )

    def should_fire(self, alert: dict) -> bool:
        """
        Returns True if this alert should be forwarded.
        Returns False if a similar alert was seen within the window.
        """
        key = self._make_key(alert)

        if self.redis:
            try:
                redis_key = f"{self.REDIS_PREFIX}{key}"
                was_set = self.redis.set(redis_key, "seen", ex=self.window, nx=True)
                if not was_set:
                    self.redis.incr(f"{redis_key}:count")
                    self.redis.expire(f"{redis_key}:count", self.window)
                    return False
                else:
                    return True
            except Exception as e:
                logger.error(f"Deduplicator: Redis error, falling back to memory: {e}")

        now = time.time()
        last = self._seen.get(key, 0)

        if now - last < self.window:
            self._suppressed_counts[key] = self._suppressed_counts.get(key, 0) + 1
            return False

        self._seen[key] = now
        self._suppressed_counts.pop(key, None)
        return True

    def suppression_note(self, alert: dict) -> Optional[str]:
        """Return a human-readable note about suppression count, if any."""
        key = self._make_key(alert)

        count = 0
        if self.redis:
            try:
                val = self.redis.get(f"{self.REDIS_PREFIX}{key}:count")
                count = int(val) if val else 0
            except Exception:
                count = self._suppressed_counts.get(key, 0)
        else:
            count = self._suppressed_counts.get(key, 0)

        if count > 0:
            return f"{count} similar alert(s) suppressed in last {self.window}s"
        return None

    def evict_expired(self) -> int:
        """Memory cleanup (only needed for in-memory mode)."""
        if self.redis:
            return 0

        now = time.time()
        cutoff = now - self.window
        # D2: evict stale suppression counts independently of _seen
        stale_counts = [k for k in list(self._suppressed_counts) if k not in self._seen]
        for k in stale_counts:
            self._suppressed_counts.pop(k, None)
        expired = [k for k, t in self._seen.items() if now - t > self.window * 2]
        for k in expired:
            self._seen.pop(k, None)
            self._suppressed_counts.pop(k, None)
        return len(expired) + len(stale_counts)

    @property
    def active_keys(self) -> int:
        if self.redis:
            try:
                # This is expensive in Redis (scan), so we return a rough estimate or 0
                return 0 
            except Exception:
                return len(self._seen)
        return len(self._seen)
