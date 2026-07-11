#!/usr/bin/env python3
"""
================================================================================
RUN MONITOR — Main Entry Point for Live/Replay Detection
================================================================================
Purpose:
  Primary entry point for running the AI-NIDS detection pipeline. Two modes:
  1. Live capture: sniffs packets from a network interface in a background
     thread, processes through the full pipeline, reports stats every batch
     window
  2. Pcap replay: replays a pcap file through the pipeline (no live traffic,
     no root required)

Usage:
  sudo python scripts/run_monitor.py --interface eth0
  sudo python scripts/run_monitor.py --interface eth0 --timeout 60
  python scripts/run_monitor.py --pcap data/raw/sample.pcap
  python scripts/run_monitor.py --interface eth0 --no-model
  python scripts/run_monitor.py --interface eth0 --verbose

Options:
  --interface/-i       NIC for live capture (default: eth0)
  --pcap              Replay .pcap instead of live capture
  --timeout           Reporting interval in seconds (default: 30)
  --flow-timeout      Seconds before flow considered complete (default: 20)
  --no-model          Signature-only mode (no AI inference)
  --dedup             Alert dedup window (default: 60s)
  --model-dir         Path to trained models (default: data/models)
  --dashboard         Launch Next.js + FastAPI alongside capture
  --verbose           Debug-level logging

Design:
  - Runs PacketCapture in a background daemon thread for continuous capture
  - NIDSPipeline handles flow aggregation, feature extraction, inference, alerts
  - Stats reported in configurable batch windows via EventBus
  - Graceful shutdown on SIGINT/SIGTERM: flushes pipeline, prints summary
  - --dashboard flag launches FastAPI + Next.js as subprocesses
  - Virtual environment check runs first to prevent "wrong python" errors
================================================================================
"""

import sys
from pathlib import Path

# Must insert project root into sys.path BEFORE any local imports
_project_root = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, _project_root)

import time
import signal
import argparse
import os
import psutil
from core.network_auto import auto_detect_network
import yaml
import subprocess
import threading

# ── Virtual Environment Check ────────────────────────────────────────────────
def check_venv():
    try:
        import loguru
    except ImportError:
        print("\033[91m" + "!" * 60 + "\033[0m")
        print("\033[91mERROR: Missing dependencies (loguru not found).\033[0m")
        print("\033[93mIt looks like you are not running this script inside the project virtual environment.\033[0m")
        print("\nFix:")
        print(f"  1. Use the explicit venv path: \033[1msudo ./ai-venv/bin/python {sys.argv[0]}\033[0m")
        print("  2. Or activate the venv first: \033[1msource ai-venv/bin/activate && sudo -E python scripts/run_monitor.py\033[0m")
        print("\033[91m" + "!" * 60 + "\033[0m")
        sys.exit(1)

check_venv()

from loguru import logger
from monitor.capture import PacketCapture, PcapReplay
from core.pipeline import NIDSPipeline
from core.stats_tracker import StatsTracker
from core.event_bus import EventBus
from core.config_validator import validate_config


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
    p.add_argument("--interface", "-i",  default="auto",   help="NIC for live capture (default: auto-detect)")
    p.add_argument("--pcap",             default=None,      help="Replay a .pcap file instead of live capture")
    p.add_argument("--timeout",   type=int, default=30,    help="Capture window seconds (default: 30)")
    p.add_argument("--flow-timeout", type=int, default=20, help="Seconds before a flow is considered complete (default: 20)")
    p.add_argument("--no-model",  action="store_true",     help="Signature-only mode (no AI inference)")
    p.add_argument("--dedup",     type=int, default=60,    help="Alert dedup window seconds (default: 60)")
    p.add_argument("--model-dir", default="data/models",  help="Path to trained models directory")
    p.add_argument("--dashboard", action="store_true",     help="Launch Next.js dashboard & FastAPI backend")
    p.add_argument("--verbose",   action="store_true",     help="Debug-level logging")
    return p


def configure_logging(verbose: bool):
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level:<8}</level> | {message}",
        colorize=True,
    )
    logger.add(
        "data/nids.log",
        level="DEBUG",
        rotation="10 MB",
        retention="7 days",
        compression="gz",
        serialize=True,
    )


def print_banner(args, pipeline: NIDSPipeline, config: dict, net_config: dict = None):
    if args.pcap:
        mode = "pcap replay"
    elif net_config and net_config.get("auto_detected"):
        mode = f"live capture on {net_config['interface']} (auto)"
    else:
        mode = f"live capture on {args.interface}"
    ai   = "AI + signatures" if pipeline.is_model_loaded else "signatures only"
    logger.info("=" * 52)
    logger.info("  AI-NIDS Monitor")
    logger.info(f"  Mode     : {mode}")
    logger.info(f"  Detection: {ai}")
    logger.info(f"  Dedup    : {args.dedup}s window")
    if args.dashboard:
        api_port = config.get("dashboard", {}).get("api_port", 8000)
        frontend_port = config.get("dashboard", {}).get("frontend_port", 3000)
        logger.info(f"  Dashboard: http://localhost:{frontend_port}")
        logger.info(f"  API      : http://localhost:{api_port}")
    else:
        logger.info(f"  Dashboard: (disabled) Use --dashboard to launch")
    logger.info("=" * 52)


def main():
    args = build_parser().parse_args()
    configure_logging(args.verbose)
    
    # Load and validate config.yaml
    config = {}
    if Path("config.yaml").exists():
        with open("config.yaml") as f:
            config = yaml.safe_load(f)
        if not validate_config(config):
            logger.warning("config.yaml validation failed — continuing with loaded values")

    model_dir = Path(args.model_dir)
    bus   = EventBus()
    stats = StatsTracker(window_secs=300)

    cfg_home_net = config.get("network", {}).get("home_net")
    net_config = auto_detect_network(
        explicit_interface=args.interface,
        explicit_home_net=cfg_home_net,
    )
    effective_interface = net_config["interface"]
    effective_home_net = net_config["home_net"]

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
        home_net       = effective_home_net,
    )

    if not pipeline.start():
        sys.exit(1)

    if net_config.get("ip"):
        pipeline.set_network_monitoring(effective_interface, net_config)

    print_banner(args, pipeline, config, net_config)

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

    # ── Dashboard Orchestration ───────────────────────────────────────────────
    ui_procs = []
    if args.dashboard:
        logger.info("Launching Next.js Dashboard and API...")
        
        # 1. Launch FastAPI
        api_port = config.get("dashboard", {}).get("api_port", 8000)
        try:
            api_proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", str(api_port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
            ui_procs.append(api_proc)
            logger.info(f"  [+] FastAPI backend started on port {api_port}")
        except Exception as e:
            logger.error(f"  [-] Failed to start FastAPI: {e}")

        # 2. Launch Next.js
        try:
            # Check if node_modules exists, if not, skip or warn
            frontend_dir = Path("frontend")
            if (frontend_dir / "node_modules").exists():
                frontend_port = config.get("dashboard", {}).get("frontend_port", 3000)
                ui_proc = subprocess.Popen(
                    ["npm", "run", "dev", "--", "-p", str(frontend_port)],
                    cwd=str(frontend_dir),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT
                )
                ui_procs.append(ui_proc)
                logger.info(f"  [+] Next.js frontend started on port {frontend_port}")
            else:
                logger.warning("  [-] Next.js frontend skip: node_modules not found. Run 'npm install' in frontend/")
        except Exception as e:
            logger.error(f"  [-] Failed to start Next.js: {e}")

    # Inject cleanup into shutdown
    def _shutdown_with_ui(sig, frame):
        for p in ui_procs:
            try:
                p.terminate()
                logger.debug(f"Terminated background process {p.pid}")
            except Exception:
                logger.debug(f"Failed to terminate background process {p.pid}")
        _shutdown(sig, frame)

    signal.signal(signal.SIGINT,  _shutdown_with_ui)
    signal.signal(signal.SIGTERM, _shutdown_with_ui)

    # ── Dashboard Orchestration ───────────────────────────────────────────────
    ui_procs = []
    if args.dashboard:
        logger.info("Launching Next.js Dashboard and API...")
        
        # 1. Launch FastAPI
        api_port = config.get("dashboard", {}).get("api_port", 8000)
        try:
            api_proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", str(api_port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
            ui_procs.append(api_proc)
            logger.info(f"  [+] FastAPI backend started on port {api_port}")
        except Exception as e:
            logger.error(f"  [-] Failed to start FastAPI: {e}")

        # 2. Launch Next.js
        try:
            # Check if node_modules exists, if not, skip or warn
            frontend_dir = Path("frontend")
            if (frontend_dir / "node_modules").exists():
                frontend_port = config.get("dashboard", {}).get("frontend_port", 3000)
                ui_proc = subprocess.Popen(
                    ["npm", "run", "dev", "--", "-p", str(frontend_port)],
                    cwd=str(frontend_dir),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT
                )
                ui_procs.append(ui_proc)
                logger.info(f"  [+] Next.js frontend started on port {frontend_port}")
            else:
                logger.warning("  [-] Next.js frontend skip: node_modules not found. Run 'npm install' in frontend/")
        except Exception as e:
            logger.error(f"  [-] Failed to start Next.js: {e}")

    # Inject cleanup into shutdown
    def _shutdown_with_ui(sig, frame):
        for p in ui_procs:
            try:
                p.terminate()
                logger.debug(f"Terminated background process {p.pid}")
            except: pass
        _shutdown(sig, frame)

    signal.signal(signal.SIGINT,  _shutdown_with_ui)
    signal.signal(signal.SIGTERM, _shutdown_with_ui)

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

    # ── Live capture ──────────────────────────────────────────────────────────
    # Run sniff in a background thread for continuous capture.
    # Use a large timeout so the socket is periodically recycled cleanly.
    cap = PacketCapture(interface=effective_interface, timeout=3600)

    def _sniff_loop():
        while True:
            try:
                cap.start(callback=pipeline.ingest_packet)
            except Exception as e:
                logger.error(f"Capture error: {e}")
                time.sleep(1)

    sniff_thread = threading.Thread(target=_sniff_loop, daemon=True, name="nids-sniff")
    sniff_thread.start()
    logger.info(f"Continuous capture started on {effective_interface} (background thread)")

    process = psutil.Process(os.getpid())
    window = 0

    while True:
        window += 1
        time.sleep(args.timeout)  # wait for the batch window

        snap = stats.snapshot()
        
        try:
            health = {
                "cpu_percent": process.cpu_percent(),
                "mem_rss_mb": process.memory_info().rss / (1024 * 1024),
                "threads": process.num_threads(),
                "active_flows": pipeline.active_flows,
                "metrics": snap,
            }
            bus.publish("stats", health)
        except Exception as e:
            logger.warning(f"Failed to publish health stats: {e}")

        logger.info(
            f"Window {window:>4} | "
            f"active_flows={pipeline.active_flows:>4} | "
            f"alerts/s={snap['alerts_per_sec']:.3f} | "
            f"flows/s={snap['flows_per_sec']:.2f} | "
            f"total_alerts={snap['total_alerts']:,}"
        )


if __name__ == "__main__":
    main()
