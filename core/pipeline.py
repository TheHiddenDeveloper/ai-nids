"""
Pipeline Orchestrator
---------------------
Central Step 4 component. Wires together:
  capture → flow aggregation → feature extraction →
  inference → deduplication → alert engine →
  event bus (→ loggers, stats, dashboard)

Run this in a background thread or directly from run_monitor.py.
"""

import time
import threading
from pathlib import Path
from typing import Optional
from loguru import logger

from monitor.flow_aggregator import FlowAggregator
from monitor.feature_extractor import FeatureExtractor
from monitor.logger import FlowLogger, AlertLogger
from ai_engine.inference import InferenceEngine
from ai_engine.alert_engine import process_results
from signatures.checker import SignatureChecker
from core.event_bus import EventBus
from core.deduplicator import AlertDeduplicator
from core.stats_tracker import StatsTracker


class NIDSPipeline:
    """
    Stateful pipeline that processes packets end-to-end.

    Usage:
        pipeline = NIDSPipeline()
        pipeline.start()
        pipeline.ingest_packet(pkt)
        pipeline.stop()
    """

    def __init__(
        self,
        model_path:     str = "data/models/nids_model.joblib",
        scaler_path:    str = "data/models/scaler.joblib",
        flow_log_path:  str = "data/flows.jsonl",
        alert_log_path: str = "data/alerts.jsonl",
        flow_timeout:   int = 60,
        dedup_window:   int = 60,
        use_signatures: bool = True,
        use_model:      bool = True,
        event_bus:      Optional[EventBus] = None,
        stats_tracker:  Optional[StatsTracker] = None,
    ):
        self.use_model      = use_model
        self.use_signatures = use_signatures

        # Core processing components
        self.aggregator  = FlowAggregator(flow_timeout=flow_timeout)
        self.extractor   = FeatureExtractor()
        self.deduplicator = AlertDeduplicator(suppress_window_secs=dedup_window)
        self.sig_checker = SignatureChecker() if use_signatures else None

        # AI inference
        self.engine = None
        if use_model:
            self.engine = InferenceEngine(
                model_path=model_path,
                scaler_path=scaler_path,
            )

        # Loggers
        self.flow_logger  = FlowLogger(flow_log_path)
        self.alert_logger = AlertLogger(alert_log_path)

        # Event bus and stats (can be injected or created fresh)
        self.bus   = event_bus   or EventBus()
        self.stats = stats_tracker or StatsTracker()

        # Eviction maintenance — runs periodically in background
        self._stop_event   = threading.Event()
        self._maint_thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Load model and start background maintenance thread."""
        if self.engine and not self.engine.load():
            logger.warning(
                "Model not found — running in signature-only mode.\n"
                "Train first: python scripts/train.py --model rf"
            )
            self.engine = None

        mode = []
        if self.engine:       mode.append("AI inference")
        if self.sig_checker:  mode.append("signature rules")
        if not mode:
            logger.error("No detection mode available. Aborting.")
            return False

        logger.info(f"Pipeline started | detection: {' + '.join(mode)}")

        # Background thread: evicts stale dedup keys every 60s
        self._maint_thread = threading.Thread(
            target=self._maintenance_loop, daemon=True, name="nids-maintenance"
        )
        self._maint_thread.start()
        return True

    def stop(self):
        """Flush remaining flows and shut down."""
        self._stop_event.set()
        remaining = self.aggregator.flush_all()
        if remaining:
            self._process_flows(remaining)
        logger.info(
            f"Pipeline stopped | "
            f"total flows={self.stats._total_flows:,} | "
            f"total alerts={self.stats._total_alerts:,}"
        )

    def ingest_packet(self, pkt: dict) -> None:
        """
        Main entry point — called once per captured packet.
        """
        self.stats.record_packet()
        completed_flows = self.aggregator.ingest(pkt)
        if completed_flows:
            self._process_flows(completed_flows)

    def _process_flows(self, flows: list) -> None:
        """Run feature extraction, inference and alerting on a batch of flows."""
        df = self.extractor.transform(flows)
        if df is None:
            return

        # Record flow stats
        for flow in flows:
            self.stats.record_flow(flow)

        if self.engine:
            raw_results = self.engine.predict(df)
        else:
            # Build minimal result dicts from raw flow dicts for sig-only path
            raw_results = []
            for flow in flows:
                raw_results.append({
                    "score": 0.0,
                    "label": "BENIGN",
                    "_src_ip":    flow.get("_src_ip"),
                    "_dst_ip":    flow.get("_dst_ip"),
                    "_src_port":  flow.get("_src_port"),
                    "_dst_port":  flow.get("_dst_port"),
                    "_timestamp": flow.get("_timestamp"),
                })
                # Inject flow features so sig_checker can inspect them
                raw_results[-1].update({k: v for k, v in flow.items() if not k.startswith("_")})

        # Publish all scored flows
        self.flow_logger.log_batch(raw_results)
        for r in raw_results:
            self.bus.publish("flow", r)

        # Alert path
        alerts = process_results(raw_results, signature_checker=self.sig_checker)
        for alert in alerts:
            if not self.deduplicator.should_fire(alert):
                continue

            note = self.deduplicator.suppression_note(alert)
            if note:
                alert["suppression_note"] = note

            self.alert_logger.log_alert(alert)
            self.stats.record_alert(alert)
            self.bus.publish("alert", alert)

        # Periodic stats snapshot
        self.bus.publish("stats", self.stats.snapshot())

    def _maintenance_loop(self):
        """Background: evict stale dedup keys every 60s."""
        while not self._stop_event.wait(timeout=60):
            evicted = self.deduplicator.evict_expired()
            if evicted:
                logger.debug(f"Maintenance: evicted {evicted} stale dedup keys")

    @property
    def active_flows(self) -> int:
        return self.aggregator.active_flow_count

    @property
    def is_model_loaded(self) -> bool:
        return self.engine is not None and self.engine.is_loaded
