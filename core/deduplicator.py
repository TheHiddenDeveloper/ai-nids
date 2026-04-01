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


class AlertDeduplicator:
    """
    Tracks recently seen alert keys and suppresses duplicates.

    Key   = (src_ip, dst_ip, dst_port, label)
    Window = suppress_window_secs (default 60s)

    Suppressed alerts are counted so the dashboard can show
    "N similar alerts suppressed" rather than silently dropping them.
    """

    def __init__(self, suppress_window_secs: int = 60):
        self.window = suppress_window_secs
        self._seen: dict = {}           # key → last_seen timestamp
        self._suppressed_counts: dict = {}   # key → suppression count

    def _make_key(self, alert: dict) -> str:
        return (
            f"{alert.get('_src_ip', '?')}|"
            f"{alert.get('_dst_ip', '?')}|"
            f"{alert.get('_dst_port', '?')}|"
            f"{alert.get('label', '?')}"
        )

    def should_fire(self, alert: dict) -> bool:
        """
        Returns True if this alert should be forwarded.
        Returns False if a similar alert was seen within the window.
        """
        key = self._make_key(alert)
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
        count = self._suppressed_counts.get(key, 0)
        if count > 0:
            return f"{count} similar alert(s) suppressed in last {self.window}s"
        return None

    def evict_expired(self) -> int:
        """Remove stale entries to keep memory bounded. Returns evicted count."""
        now = time.time()
        expired = [k for k, t in self._seen.items() if now - t > self.window * 2]
        for k in expired:
            self._seen.pop(k, None)
            self._suppressed_counts.pop(k, None)
        return len(expired)

    @property
    def active_keys(self) -> int:
        return len(self._seen)
