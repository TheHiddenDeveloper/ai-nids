#!/usr/bin/env python3
"""
AI-NIDS Demo Mode
-----------------
Self-contained demonstration of the full detection pipeline.
No root required, no live interface needed.

What it does:
  1. Generates a synthetic attack pcap (SYN flood, port scan, bad ports, C2)
  2. Loads the trained model
  3. Replays the pcap through the full pipeline
  4. Displays a live terminal report as alerts fire
  5. Prints a final summary with statistics

Usage:
    python scripts/demo.py
    python scripts/demo.py --no-model          # signature-only mode
    python scripts/demo.py --keep-pcap         # don't delete the generated pcap
    python scripts/demo.py --pcap my.pcap      # use an existing pcap
"""

import sys
import time
import argparse
import tempfile
import threading
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger

# ── Terminal colours ──────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA = "\033[95m"

SEV_COLOR  = {"high": RED, "medium": YELLOW, "low": CYAN}
SEV_ICON   = {"high": "●", "medium": "◆", "low": "▲"}

def c(text, color): return f"{color}{text}{RESET}"
def bold(text):     return f"{BOLD}{text}{RESET}"
def dim(text):      return f"{DIM}{text}{RESET}"


# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = f"""
{BOLD}{BLUE}╔══════════════════════════════════════════════════════╗
║          AI-NIDS — Live Detection Demo               ║
║   Ensemble RF + Autoencoder + Signature Rules        ║
╚══════════════════════════════════════════════════════╝{RESET}
"""

def print_banner():
    print(BANNER)


# ── Live alert display ────────────────────────────────────────────────────────

class DemoReporter:
    """
    Subscribes to the event bus and prints formatted alerts
    to the terminal as they arrive.
    """

    def __init__(self):
        self._alerts  = []
        self._flows   = 0
        self._lock    = threading.Lock()
        self._start   = time.time()

    def on_flow(self, payload: dict):
        with self._lock:
            self._flows += 1

    def on_alert(self, payload: dict):
        with self._lock:
            self._alerts.append(payload)
        self._print_alert(payload)

    def _print_alert(self, alert: dict):
        sev    = alert.get("severity", "low")
        score  = alert.get("score", 0.0)
        src    = f"{alert.get('_src_ip', '?')}:{alert.get('_src_port', '?')}"
        dst    = f"{alert.get('_dst_ip', '?')}:{alert.get('_dst_port', '?')}"
        label  = alert.get("label", "?")
        sig    = alert.get("signature_match", "")
        rf_s   = alert.get("rf_score")
        ae_s   = alert.get("ae_score")

        icon  = SEV_ICON.get(sev, "?")
        color = SEV_COLOR.get(sev, "")

        score_bar_len = int(score * 20)
        score_bar = c("█" * score_bar_len, color) + dim("░" * (20 - score_bar_len))

        sev_padded = f"{sev.upper():<8}"
        print(f"\n  {c(icon, color)} {c(sev_padded, color)} {bold(label)}")
        print(f"  {dim('src')} {CYAN}{src:<28}{RESET} {dim('→')} {CYAN}{dst}{RESET}")
        print(f"  {dim('score')}  [{score_bar}] {c(f'{score:.3f}', color)}", end="")

        if rf_s is not None and ae_s is not None:
            print(f"  {dim(f'(RF:{rf_s:.2f} AE:{ae_s:.2f})')}", end="")
        print()

        if sig:
            rule_name = sig.split(":")[0]
            print(f"  {dim('rule')}   {MAGENTA}{rule_name}{RESET}")

        print(f"  {dim('─' * 54)}")

    def print_summary(self, model_mode: str):
        elapsed = time.time() - self._start

        with self._lock:
            alerts   = list(self._alerts)
            n_flows  = self._flows

        by_sev   = defaultdict(int)
        by_rule  = defaultdict(int)
        src_ips  = defaultdict(int)

        for a in alerts:
            by_sev[a.get("severity", "low")] += 1
            src_ips[a.get("_src_ip", "?")] += 1
            sig = a.get("signature_match", "")
            if sig:
                by_rule[sig.split(":")[0]] += 1

        print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════════════════════╗")
        print(f"║                  Demo Summary                        ║")
        print(f"╚══════════════════════════════════════════════════════╝{RESET}\n")

        print(f"  {bold('Detection mode')}  : {CYAN}{model_mode}{RESET}")
        print(f"  {bold('Duration')}        : {elapsed:.1f}s")
        print(f"  {bold('Flows processed')}: {n_flows:,}")
        print(f"  {bold('Alerts fired')}   : {len(alerts):,}")

        if n_flows > 0:
            rate = len(alerts) / n_flows * 100
            print(f"  {bold('Alert rate')}     : {rate:.1f}%")

        print()
        print(f"  {bold('By severity:')}")
        for sev in ("high", "medium", "low"):
            count = by_sev.get(sev, 0)
            bar   = c("█" * count, SEV_COLOR.get(sev, ""))
            print(f"    {SEV_ICON.get(sev,'')} {sev:<8}  {bar} {count}")

        if by_rule:
            print()
            print(f"  {bold('Signature rules fired:')}")
            for rule, count in sorted(by_rule.items(), key=lambda x: -x[1]):
                print(f"    {MAGENTA}{rule:<30}{RESET} {count}×")

        if src_ips:
            print()
            print(f"  {bold('Top attacker IPs:')}")
            for ip, count in sorted(src_ips.items(), key=lambda x: -x[1])[:5]:
                print(f"    {RED}{ip:<20}{RESET} {count} alerts")

        print()
        if len(alerts) > 0:
            print(c("  Detection pipeline is working correctly.", GREEN))
        else:
            print(c("  No alerts generated — check model and rules.", YELLOW))

        print()
        print(f"  {dim('Logs written to:')}")
        print(f"    {dim('data/alerts.jsonl')}")
        print(f"    {dim('data/flows.jsonl')}")
        print(f"\n  {dim('Launch dashboard:')}")
        print(f"    {CYAN}streamlit run dashboard/app.py{RESET}\n")


# ── Pcap generation ───────────────────────────────────────────────────────────

def generate_pcap(out_path: Path) -> bool:
    try:
        from scripts.gen_test_pcap import gen_packets
        from scapy.all import wrpcap
        packets = gen_packets()
        packets.sort(key=lambda p: p.time)
        wrpcap(str(out_path), packets)
        logger.info(f"Generated {len(packets)} test packets → {out_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to generate pcap: {e}")
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AI-NIDS demo mode")
    parser.add_argument("--pcap",      default=None, help="Use existing pcap instead of generating one")
    parser.add_argument("--no-model",  action="store_true", help="Signature-only mode (no AI model)")
    parser.add_argument("--keep-pcap", action="store_true", help="Don't delete the generated test pcap")
    parser.add_argument("--model-dir", default="data/models", help="Path to trained models")
    args = parser.parse_args()

    # Silence loguru during demo — we print our own formatted output
    logger.remove()
    logger.add(sys.stderr, level="WARNING",
               format="<yellow>{level}</yellow> | {message}")

    print_banner()

    # Determine pcap source
    tmp_pcap = None
    if args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            print(c(f"  Error: pcap file not found: {pcap_path}", RED))
            sys.exit(1)
        print(f"  Using existing pcap: {CYAN}{pcap_path}{RESET}\n")
    else:
        print(f"  {bold('Step 1')} — Generating synthetic attack traffic...\n")
        tmp_pcap  = Path("data/raw/demo_test.pcap")
        tmp_pcap.parent.mkdir(parents=True, exist_ok=True)
        if not generate_pcap(tmp_pcap):
            print(c("  Could not generate test pcap. Is scapy installed?", RED))
            sys.exit(1)
        pcap_path = tmp_pcap
        print(f"  {GREEN}✓{RESET} Generated: {dim(str(pcap_path))}\n")

    # Build pipeline
    print(f"  {bold('Step 2')} — Initialising detection pipeline...\n")

    from core.pipeline import NIDSPipeline
    from core.event_bus import EventBus
    from core.stats_tracker import StatsTracker

    bus      = EventBus()
    stats    = StatsTracker()
    reporter = DemoReporter()

    bus.subscribe("flow",  reporter.on_flow)
    bus.subscribe("alert", reporter.on_alert)

    pipeline = NIDSPipeline(
        model_dir      = args.model_dir,
        flow_log_path  = "data/flows.jsonl",
        alert_log_path = "data/alerts.jsonl",
        flow_timeout   = 15,
        dedup_window   = 5,     # shorter dedup for demo so all alerts show
        use_model      = not args.no_model,
        use_signatures = True,
        event_bus      = bus,
        stats_tracker  = stats,
    )

    if not pipeline.start():
        print(c("  Pipeline failed to start.", RED))
        sys.exit(1)

    model_mode = pipeline.engine.mode if pipeline.engine else "signatures only"
    mode_label = {
        "ensemble": "RF + Autoencoder ensemble",
        "rf_only":  "Random Forest only",
        "ae_only":  "Autoencoder only",
        "unloaded": "signatures only",
    }.get(model_mode, model_mode)

    print(f"  {GREEN}✓{RESET} Pipeline ready | {CYAN}{mode_label}{RESET}\n")

    # Replay
    print(f"  {bold('Step 3')} — Replaying pcap through detection pipeline...")
    print(f"  {dim('Alerts will appear below as they fire:')}\n")
    print(f"  {'─' * 54}")

    from monitor.capture import PcapReplay
    replay = PcapReplay(str(pcap_path))
    replay.play(callback=pipeline.ingest_packet)

    # Flush remaining flows
    remaining = pipeline.aggregator.flush_all()
    if remaining:
        df = pipeline.extractor.transform(remaining)
        if df is not None:
            pipeline._process_flows(remaining)

    pipeline.stop()

    # Clean up temp pcap unless asked to keep it
    if tmp_pcap and not args.keep_pcap:
        try:
            tmp_pcap.unlink()
        except Exception:
            pass

    reporter.print_summary(model_mode=mode_label)


if __name__ == "__main__":
    main()
