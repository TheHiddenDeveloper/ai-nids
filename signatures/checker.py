"""
Signature Checker  (Step 7 — YAML-backed, hot-reloadable)
----------------------------------------------------------
Replaces the old hardcoded checker with one that reads from rules.yaml.

Hot-reload:
  - Call checker.reload() explicitly, OR
  - Instantiate with watch=True and the checker polls the file every
    watch_interval seconds in a background thread.

Usage:
    checker = SignatureChecker()                 # load once
    checker = SignatureChecker(watch=True)       # auto-reload on file change
    result  = checker.check(flow_dict)           # first matching rule, or None
    results = checker.check_all(flow_dict)       # all matching rule names
"""

import threading
import time
from pathlib import Path
from typing import List, Optional
from loguru import logger

from signatures.loader import load_rules, Rule


DEFAULT_RULES_PATH = "signatures/rules.yaml"


class SignatureChecker:
    """
    Evaluates a flow feature dict against all loaded signature rules.
    Optionally watches the rules file for changes and reloads automatically.
    """

    def __init__(
        self,
        rules_path: str = DEFAULT_RULES_PATH,
        watch: bool = False,
        watch_interval: int = 10,
    ):
        self.rules_path = rules_path
        self._rules: List[Rule] = []
        self._lock = threading.RLock()
        self._last_mtime = 0.0
        self._stop_watch = threading.Event()
        self._watch_thread: Optional[threading.Thread] = None

        self.reload()

        if watch:
            self._start_watcher(watch_interval)

    # ── Public interface ──────────────────────────────────────────────────────

    def check(self, flow: dict) -> Optional[str]:
        """Return description of the first matching rule, or None."""
        with self._lock:
            rules = list(self._rules)
        for rule in rules:
            try:
                if rule.matches(flow):
                    return f"{rule.name}: {rule.description.strip()}"
            except Exception as exc:
                logger.debug(f"Rule {rule.id} error: {exc}")
        return None

    def check_all(self, flow: dict) -> List[str]:
        """Return descriptions for ALL matching rules."""
        with self._lock:
            rules = list(self._rules)
        matches = []
        for rule in rules:
            try:
                if rule.matches(flow):
                    matches.append(f"{rule.name}: {rule.description.strip()}")
            except Exception as exc:
                logger.debug(f"Rule {rule.id} error: {exc}")
        return matches

    def check_with_metadata(self, flow: dict) -> List[dict]:
        """Return full metadata dicts for all matching rules (useful for dashboard)."""
        with self._lock:
            rules = list(self._rules)
        matches = []
        for rule in rules:
            try:
                if rule.matches(flow):
                    matches.append({
                        "rule_id":     rule.id,
                        "name":        rule.name,
                        "severity":    rule.severity,
                        "tags":        rule.tags,
                        "description": rule.description.strip(),
                    })
            except Exception:
                pass
        return matches

    def reload(self) -> bool:
        """
        Re-read rules.yaml and replace the active rule set.
        Returns True on success.
        """
        try:
            new_rules = load_rules(self.rules_path)
            mtime = Path(self.rules_path).stat().st_mtime
            with self._lock:
                self._rules = new_rules
                self._last_mtime = mtime
            return True
        except Exception as exc:
            logger.error(f"SignatureChecker reload failed: {exc}")
            return False

    def stop_watching(self):
        """Stop the background file-watcher thread."""
        self._stop_watch.set()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def rule_count(self) -> int:
        with self._lock:
            return len(self._rules)

    @property
    def enabled_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._rules if r.enabled)

    @property
    def rules_summary(self) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in self._rules]

    # ── File watcher ──────────────────────────────────────────────────────────

    def _start_watcher(self, interval: int):
        self._watch_thread = threading.Thread(
            target=self._watch_loop,
            args=(interval,),
            daemon=True,
            name="sig-watcher",
        )
        self._watch_thread.start()
        logger.info(f"SignatureChecker: watching {self.rules_path} every {interval}s")

    def _watch_loop(self, interval: int):
        while not self._stop_watch.wait(timeout=interval):
            try:
                mtime = Path(self.rules_path).stat().st_mtime
                if mtime != self._last_mtime:
                    logger.info("SignatureChecker: rules.yaml changed — reloading...")
                    self.reload()
            except FileNotFoundError:
                logger.warning(f"SignatureChecker: rules file missing: {self.rules_path}")
            except Exception as exc:
                logger.debug(f"SignatureChecker watcher error: {exc}")
