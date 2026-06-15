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
import yaml
import threading
import concurrent.futures
from pathlib import Path
from typing import Optional
from loguru import logger

from monitor.flow_aggregator import FlowAggregator
from monitor.feature_extractor import FeatureExtractor
from monitor.logger import FlowLogger, AlertLogger
from ai_engine.ensemble import EnsembleInferenceEngine
from ai_engine.alert_engine import process_results
from signatures.checker import SignatureChecker
from core.event_bus import EventBus
from core.deduplicator import AlertDeduplicator
from core.stats_tracker import StatsTracker
from core.correlator import IncidentCorrelator
from core.threat_intel import ThreatIntelManager
from monitor.db import cleanup_old_data


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
        model_dir:       str = "data/models",
        flow_log_path:   str = "data/flows.jsonl",
        alert_log_path:  str = "data/alerts.jsonl",
        flow_timeout:    int = 20,
        dedup_window:    int = 60,
        use_signatures:  bool = True,
        use_model:       bool = True,
        event_bus:       Optional[EventBus] = None,
        stats_tracker:   Optional[StatsTracker] = None,
        home_net:        Optional[list] = None,
        max_active_flows: int = 50000,
        retention_days:  int = 30,
    ):
        self.use_model      = use_model
        self.use_signatures = use_signatures
        self.home_net       = home_net or []
        self.max_active_flows = max_active_flows  # L4

        # Core processing components
        self.aggregator  = FlowAggregator(flow_timeout=flow_timeout, home_net=self.home_net)
        self.extractor   = FeatureExtractor()
        self.deduplicator = AlertDeduplicator(suppress_window_secs=dedup_window)
        self.sig_checker = SignatureChecker(watch=True) if use_signatures else None
        self.correlator  = IncidentCorrelator(inactivity_window=180) # 3-minute window
        self.intel       = ThreatIntelManager()

        # AI inference (ensemble: RF + Autoencoder, weights from config.yaml)
        self.engine = None
        if use_model:
            self.engine = EnsembleInferenceEngine(
                model_dir = model_dir,
            )

        # Loggers (now use SQLite via monitor.db)
        self.flow_logger  = FlowLogger()
        self.alert_logger = AlertLogger()

        # Event bus and stats (can be injected or created fresh)
        self.bus   = event_bus   or EventBus()
        self.stats = stats_tracker or StatsTracker()

        # Thread pool for async enrichment (max 4 concurrent lookups)
        self._intel_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="nids-intel")

        # O1: data retention (0 = keep forever)
        self.retention_days = retention_days
        self._cleanup_counter = 0

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
        self._intel_pool.shutdown(wait=True)
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
        L4: drops packet if flow table exceeds max_active_flows (backpressure).
        """
        if self.aggregator.active_flow_count >= self.max_active_flows:
            return
        self.stats.record_packet()
        self.aggregator.ingest(pkt)

    def _process_flows(self, flows: list) -> None:
        """Run feature extraction, inference and alerting on a batch of flows."""
        df = self.extractor.transform(flows)
        if df is None:
            return

        # L1: batch stats in a single lock acquisition
        self.stats.record_flows_batch(flows)

        if self.engine:
            raw_results = self.engine.predict(df)
        else:
            # Build minimal result dicts from raw flow dicts for sig-only path
            raw_results = []
            for flow in flows:
                raw_results.append({
                    "score": 0.0,
                    "label": "UNCERTAIN",
                    "_src_ip":    flow.get("_src_ip"),
                    "_dst_ip":    flow.get("_dst_ip"),
                    "_src_port":  flow.get("_src_port"),
                    "_dst_port":  flow.get("_dst_port"),
                    "_timestamp": flow.get("_timestamp"),
                    "direction":  flow.get("direction", "uncertain"),
                })
                # Inject flow features so sig_checker can inspect them
                raw_results[-1].update({k: v for k, v in flow.items() if not k.startswith("_")})

        # Publish all scored flows and track scores for drift detection
        self.flow_logger.log_batch(raw_results)
        for r in raw_results:
            self.stats.record_flow_score(
                score=r.get("score", 0.0),
                label=r.get("label", "BENIGN"),
                src_ip=r.get("_src_ip"),
            )
            self.bus.publish("flow", r)

        # Alert path
        alerts = process_results(raw_results, signature_checker=self.sig_checker)

        # Filter out deduplicated alerts
        active_alerts = []
        for alert in alerts:
            if not self.deduplicator.should_fire(alert):
                continue
            note = self.deduplicator.suppression_note(alert)
            if note:
                alert["suppression_note"] = note
            active_alerts.append(alert)

        # Threat Intel Enrichment — parallel HTTP lookups off the hot path
        if active_alerts:
            futures = {}
            for alert in active_alerts:
                ip = alert.get("_src_ip")
                fut = self._intel_pool.submit(self.intel.get_enrichment, ip)
                futures[fut] = alert

            for fut in concurrent.futures.as_completed(futures):
                alert = futures[fut]
                try:
                    intel = fut.result(timeout=10)
                except Exception as e:
                    logger.warning(f"ThreatIntel enrichment failed: {e}")
                    intel = {}

                if intel:
                    alert.update({
                        "country":      intel.get("country"),
                        "city":         intel.get("city"),
                        "asn":          intel.get("asn"),
                        "threat_level": intel.get("threat_level"),
                        "is_malicious": intel.get("is_malicious"),
                        "isp":          intel.get("isp")
                    })

                alert["incident_id"] = self.correlator.process_alert(alert, intel=intel)

                self.alert_logger.log_alert(alert)
                self.stats.record_alert(alert)
                self.bus.publish("alert", alert)

        # Periodic stats snapshot
        self.bus.publish("stats", self.stats.snapshot())

    def _maintenance_loop(self):
        """Background: evict stale flows, dedup keys, incidents, old data."""
        while not self._stop_event.wait(timeout=10):
            expired_flows = self.aggregator.flush_expired()
            if expired_flows:
                logger.debug(f"Maintenance: evicted {len(expired_flows)} expired flows")
                self._process_flows(expired_flows)

            evicted = self.deduplicator.evict_expired()
            if evicted:
                logger.debug(f"Maintenance: evicted {evicted} stale dedup keys")

            closed = self.correlator.evict_stale()
            if closed:
                logger.info(f"Maintenance: closed {len(closed)} stale incidents")
                for cid in closed:
                    self.bus.publish("incident_update", {"id": cid, "status": "closed"})

            # O1: periodic data retention cleanup (~every 100 iterations ≈ 17min)
            self._cleanup_counter += 1
            if self.retention_days > 0 and self._cleanup_counter % 100 == 0:
                cleanup_old_data(retention_days=self.retention_days)

    @property
    def active_flows(self) -> int:
        return self.aggregator.active_flow_count

    @property
    def is_model_loaded(self) -> bool:
        return self.engine is not None and self.engine.is_loaded
