#!/usr/bin/env python3
import sys
import time
import argparse
import pandas as pd
from pathlib import Path
from loguru import logger

sys.path.insert(0, str(Path(__file__).parent.parent))

from monitor.capture import PacketCapture, PcapReplay
from monitor.flow_aggregator import FlowAggregator
from monitor.feature_extractor import FeatureExtractor

def main():
    p = argparse.ArgumentParser(description="Capture network baseline dataset")
    p.add_argument("--label", required=True, help="Label to apply (e.g. BENIGN or ATTACK_DOS)")
    p.add_argument("--out", required=True, help="Path to output CSV")
    p.add_argument("--interface", default="eth0", help="Live capture interface")
    p.add_argument("--pcap", help="Read from PCAP instead of live capture")
    p.add_argument("--timeout", type=int, default=60, help="Live capture timeout in seconds")
    args = p.parse_args()

    agg = FlowAggregator(flow_timeout=15)
    
    def packet_callback(pkt):
        agg.ingest(pkt)
        
    if args.pcap:
        logger.info(f"Replaying PCAP into local dataset: {args.pcap}")
        cap = PcapReplay(args.pcap)
        cap.play(callback=packet_callback)
    else:
        logger.info(f"Live capturing on {args.interface} for {args.timeout}s... DO NOT CLOSE")
        cap = PacketCapture(interface=args.interface, timeout=args.timeout)
        cap.start(callback=packet_callback)

    logger.info("Session finished. Extracting IAT features from captured flows...")
    flows = agg.flush_all()
    if not flows:
        logger.warning("No flows captured!")
        return
        
    fe = FeatureExtractor()
    df = fe.transform(flows)
    
    if df is not None and not df.empty:
        df["label"] = args.label
        
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        header = not out_path.exists()
        df.to_csv(out_path, mode='a', index=False, header=header)
        logger.info(f"SUCCESS: Appended {len(df)} records to {out_path}")
    
if __name__ == "__main__":
    main()
