#!/usr/bin/env python3
"""
Generate Test PCAP
------------------
Creates a synthetic .pcap file containing known attack patterns so you
can test the full pipeline end-to-end without needing live traffic or
root permissions.

Includes:
  - Normal HTTP/HTTPS traffic (benign baseline)
  - SYN flood pattern (should trigger SYN_FLOOD_001)
  - Port scan pattern (should trigger PORT_SCAN_001)
  - Traffic to bad ports: 445, 4444 (should trigger signature rules)
  - C2 beacon pattern (tiny periodic flows)

Usage:
    python scripts/gen_test_pcap.py
    python scripts/gen_test_pcap.py --out data/raw/my_test.pcap
"""

import sys
import argparse
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from scapy.all import (
        IP, TCP, UDP, Ether,
        wrpcap, RandShort, RandMAC,
    )
except ImportError:
    print("scapy is required: pip install scapy")
    sys.exit(1)

from loguru import logger


def make_tcp(src_ip, dst_ip, sport, dport, flags, payload=b"", ts=None):
    pkt = (
        Ether() /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, flags=flags)
    )
    if payload:
        pkt = pkt / payload
    if ts is not None:
        pkt.time = ts
    return pkt


def make_udp(src_ip, dst_ip, sport, dport, payload=b"", ts=None):
    pkt = (
        Ether() /
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=sport, dport=dport) /
        payload
    )
    if ts is not None:
        pkt.time = ts
    return pkt


def gen_packets():
    packets = []
    now = time.time()
    t = now

    # ── 1. Normal HTTP traffic (benign) ──────────────────────────────────────
    logger.info("Generating benign HTTP flows...")
    for i in range(30):
        src = f"192.168.1.{10 + i % 20}"
        dst = f"93.184.216.{34 + i % 5}"
        sp  = 50000 + i
        # SYN
        packets.append(make_tcp(src, dst, sp, 80, "S", ts=t));        t += 0.001
        # SYN-ACK
        packets.append(make_tcp(dst, src, 80, sp, "SA", ts=t));       t += 0.001
        # ACK
        packets.append(make_tcp(src, dst, sp, 80, "A", ts=t));        t += 0.001
        # Data
        packets.append(make_tcp(src, dst, sp, 80, "PA",
                                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", ts=t)); t += 0.01
        packets.append(make_tcp(dst, src, 80, sp, "PA",
                                b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 512, ts=t));       t += 0.01
        # FIN
        packets.append(make_tcp(src, dst, sp, 80, "FA", ts=t));       t += 0.001
        packets.append(make_tcp(dst, src, 80, sp, "FA", ts=t));       t += 0.002

    # ── 2. SYN flood — should trigger SYN_FLOOD_001 ──────────────────────────
    logger.info("Generating SYN flood pattern...")
    attacker = "10.0.0.99"
    victim   = "192.168.1.100"
    for i in range(80):
        sp = 20000 + i
        packets.append(make_tcp(attacker, victim, sp, 80, "S", ts=t))
        t += 0.005

    # ── 3. Port scan — should trigger PORT_SCAN_001 ──────────────────────────
    logger.info("Generating port scan pattern...")
    scanner = "10.0.0.50"
    target  = "192.168.1.200"
    for port in range(20, 45):
        packets.append(make_tcp(scanner, target, 54321, port, "S",  ts=t)); t += 0.01
        packets.append(make_tcp(target, scanner, port, 54321, "R",  ts=t)); t += 0.005

    # ── 4. Bad port traffic ───────────────────────────────────────────────────
    logger.info("Generating bad-port flows...")

    # Port 445 (SMB) — BAD_PORT_SMB
    for i in range(5):
        packets.append(make_tcp("10.0.0.77", "192.168.1.5", 60000+i, 445, "S",  ts=t)); t += 0.01
        packets.append(make_tcp("192.168.1.5", "10.0.0.77", 445, 60000+i, "SA", ts=t)); t += 0.01
        packets.append(make_tcp("10.0.0.77", "192.168.1.5", 60000+i, 445, "A",  ts=t)); t += 0.05
        packets.append(make_tcp("10.0.0.77", "192.168.1.5", 60000+i, 445, "PA",
                                b"\x00" * 64, ts=t)); t += 0.1
        packets.append(make_tcp("10.0.0.77", "192.168.1.5", 60000+i, 445, "FA", ts=t)); t += 0.01

    # Port 4444 (Meterpreter) — BAD_PORT_METERPRETER
    for i in range(3):
        packets.append(make_tcp("10.0.0.88", "192.168.1.5", 61000+i, 4444, "S",  ts=t)); t += 0.01
        packets.append(make_tcp("192.168.1.5", "10.0.0.88", 4444, 61000+i, "SA", ts=t)); t += 0.01
        packets.append(make_tcp("10.0.0.88", "192.168.1.5", 61000+i, 4444, "A",  ts=t)); t += 0.05
        packets.append(make_tcp("10.0.0.88", "192.168.1.5", 61000+i, 4444, "PA",
                                b"\xff" * 32, ts=t)); t += 0.1
        packets.append(make_tcp("10.0.0.88", "192.168.1.5", 61000+i, 4444, "FA", ts=t)); t += 0.01

    # Port 23 (Telnet) — BAD_PORT_TELNET
    for i in range(2):
        packets.append(make_tcp("172.16.0.9", "192.168.1.1", 62000+i, 23, "S",  ts=t)); t += 0.01
        packets.append(make_tcp("192.168.1.1", "172.16.0.9", 23, 62000+i, "SA", ts=t)); t += 0.01
        packets.append(make_tcp("172.16.0.9", "192.168.1.1", 62000+i, 23, "PA",
                                b"login: ", ts=t)); t += 0.2
        packets.append(make_tcp("172.16.0.9", "192.168.1.1", 62000+i, 23, "FA", ts=t)); t += 0.01

    # ── 5. C2 beacon pattern — C2_BEACON_001 (tiny, fast flows) ──────────────
    logger.info("Generating C2 beacon pattern...")
    bot = "192.168.1.77"
    c2  = "185.220.101.1"
    for i in range(10):
        sp = 63000 + i
        packets.append(make_tcp(bot, c2, sp, 443, "S",  ts=t)); t += 0.05
        packets.append(make_tcp(c2, bot, 443, sp, "SA", ts=t)); t += 0.05
        packets.append(make_tcp(bot, c2, sp, 443, "FA", ts=t)); t += 30.0   # 30s between beacons

    logger.info(f"Total packets generated: {len(packets)}")
    return packets


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic test pcap")
    parser.add_argument("--out", default="data/raw/test_attack.pcap",
                        help="Output pcap path (default: data/raw/test_attack.pcap)")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Generating synthetic attack pcap...")
    packets = gen_packets()

    # Sort by timestamp
    packets.sort(key=lambda p: p.time)

    wrpcap(str(out), packets)
    logger.info(f"Saved {len(packets)} packets → {out}")
    logger.info("")
    logger.info("Expected signature hits when replayed:")
    logger.info("  SYN_FLOOD_001       — SYN flood from 10.0.0.99")
    logger.info("  PORT_SCAN_001       — RST-based scan from 10.0.0.50")
    logger.info("  BAD_PORT_SMB        — traffic to port 445")
    logger.info("  BAD_PORT_METERPRETER— traffic to port 4444")
    logger.info("  BAD_PORT_TELNET     — traffic to port 23")
    logger.info("  C2_BEACON_001       — tiny periodic flows from 192.168.1.77")
    logger.info("")
    logger.info("Replay with:")
    logger.info(f"  python scripts/run_monitor.py --pcap {out} --no-model")
    logger.info(f"  python scripts/run_monitor.py --pcap {out}  # with AI model")


if __name__ == "__main__":
    main()
