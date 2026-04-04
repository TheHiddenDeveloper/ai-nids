#!/usr/bin/env python3
"""
AI-NIDS Live Monitor
--------------------
Captures live traffic or replays a pcap, runs the full inference
pipeline, and writes alerts to disk and the event bus.

Usage:
    sudo python scripts/run_monitor.py --interface eth0
    sudo python scripts/run_monitor.py --interface eth0 --timeout 60
    python scripts/run_monitor.py --pcap data/raw/sample.pcap
    sudo python scripts/run_monitor.py --interface eth0 --no-model
    sudo python scripts/run_monitor.py --interface eth0 --verbose
"""

import sys
import time
import signal
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger
from monitor.capture import PacketCapture, PcapReplay
from core.pipeline import NIDSPipeline
from core.stats_tracker import StatsTracker
from core.event_bus import EventBus


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AI-NIDS live monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python scripts/run_monitor.py --interface eth0
  sudo python scripts/run_monitor.py --interface wlan0 --timeout 60
  python scripts/run_monitor.py --pcap data/raw/sample.pcap
  sudo python scripts/run_monitor.py --interface eth0 --no-model
        """,
    )
    p.add_argument("--interface", "-i",  default="eth0",   help="NIC for live capture (default: eth0)")
    p.add_argument("--pcap",             default=None,      help="Replay a .pcap file instead of live capture")
    p.add_argument("--timeout",   type=int, default=30,    help="Capture window seconds (default: 30)")
    p.add_argument("--flow-timeout", type=int, default=20, help="Seconds before a flow is considered complete (default: 20)")
    p.add_argument("--no-model",  action="store_true",     help="Signature-only mode (no AI inference)")
    p.add_argument("--dedup",     type=int, default=60,    help="Alert dedup window seconds (default: 60)")
    p.add_argument("--model-dir", default="data/models",  help="Path to trained models directory")
    p.add_argument("--verbose",   action="store_true",     help="Debug-level logging")
    return p


def configure_logging(verbose: bool):
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | {message}",
        colorize=True,
    )
    logger.add(
        "data/nids.log",
        level="DEBUG",
        rotation="10 MB",
        retention="7 days",
        compression="gz",
    )


def print_banner(args, pipeline: NIDSPipeline):
    mode = "pcap replay" if args.pcap else f"live capture on {args.interface}"
    ai   = "AI + signatures" if pipeline.is_model_loaded else "signatures only"
    logger.info("=" * 52)
    logger.info("  AI-NIDS Monitor")
    logger.info(f"  Mode     : {mode}")
    logger.info(f"  Detection: {ai}")
    logger.info(f"  Dedup    : {args.dedup}s window")
    logger.info("  Dashboard: streamlit run dashboard/app.py")
    logger.info("=" * 52)


def main():
    args = build_parser().parse_args()
    configure_logging(args.verbose)

    model_dir = Path(args.model_dir)
    bus   = EventBus()
    stats = StatsTracker(window_secs=300)

    pipeline = NIDSPipeline(
        model_dir      = str(model_dir),
        flow_log_path  = "data/flows.jsonl",
        alert_log_path = "data/alerts.jsonl",
        flow_timeout   = args.flow_timeout,
        dedup_window   = args.dedup,
        use_model      = not args.no_model,
        use_signatures = True,
        event_bus      = bus,
        stats_tracker  = stats,
    )

    if not pipeline.start():
        sys.exit(1)

    print_banner(args, pipeline)

    # ── Graceful shutdown on Ctrl-C / SIGTERM ─────────────────────────────────
    def _shutdown(sig, frame):
        logger.info("Shutdown signal received — flushing pipeline...")
        pipeline.stop()
        snap = stats.snapshot()
        logger.info(
            f"Session summary | "
            f"packets={snap['total_packets']:,} | "
            f"flows={snap['total_flows']:,} | "
            f"alerts={snap['total_alerts']:,} | "
            f"uptime={snap['uptime_secs']}s"
        )
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── PCAP replay mode ──────────────────────────────────────────────────────
    if args.pcap:
        replay = PcapReplay(args.pcap)
        replay.play(callback=pipeline.ingest_packet)
        pipeline.stop()
        snap = stats.snapshot()
        logger.info(
            f"Replay complete | "
            f"packets={snap['total_packets']:,} | "
            f"flows={snap['total_flows']:,} | "
            f"alerts={snap['total_alerts']:,}"
        )
        return

    # ── Live capture loop ─────────────────────────────────────────────────────
    cap = PacketCapture(interface=args.interface, timeout=args.timeout)
    window = 0
    while True:
        window += 1
        cap.start(callback=pipeline.ingest_packet)
        snap = stats.snapshot()
        logger.info(
            f"Window {window:>4} | "
            f"active_flows={pipeline.active_flows:>4} | "
            f"alerts/s={snap['alerts_per_sec']:.3f} | "
            f"flows/s={snap['flows_per_sec']:.2f} | "
            f"total_alerts={snap['total_alerts']:,}"
        )


if __name__ == "__main__":
    main()
