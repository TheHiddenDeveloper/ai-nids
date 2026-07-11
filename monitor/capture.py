"""
================================================================================
PACKET CAPTURE — Live + Pcap Replay
================================================================================
Purpose:
  Captures raw packets from a network interface using scapy (live mode) or
  replays packets from a .pcap file. Emits packet dictionaries with extracted
  fields for downstream processing in the pipeline.

Usage:
  # Live capture
  cap = PacketCapture(interface="eth0")
  cap.start(callback=my_packet_handler)  # blocks until timeout

  # PCAP replay
  replay = PcapReplay("data/raw/sample.pcap")
  replay.play(callback=my_packet_handler)

Packet dict structure:
  {timestamp, src_ip, dst_ip, protocol, ip_len, ttl,
   src_port, dst_port, tcp_flags, fin, syn, rst, psh, ack, urg}

Supported: IPv4, IPv6, TCP, UDP, ICMP
  - TCP: extracts all 6 flag bits (fin, syn, rst, psh, ack, urg)
  - UDP: extracts src/dst ports only
  - ICMP: protocol set to 1, src_port=icmp.type, dst_port=icmp.code
  - Non-IP/IPv6 frames are silently dropped
================================================================================
"""

import time
from typing import Callable, Optional
from loguru import logger

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not installed. Run: pip install scapy")


class PacketCapture:
    """
    Live packet capture using scapy.

    Usage:
        cap = PacketCapture(interface="eth0")
        cap.start(callback=my_handler)
    """

    def __init__(self, interface: str = "eth0", timeout: Optional[int] = None, max_packets: int = 1000):
        self.interface = interface
        self.timeout = timeout
        self.max_packets = max_packets
        self._running = False

    def _parse_packet(self, pkt) -> Optional[dict]:
        """Extract relevant fields from a raw scapy packet (IPv4, IPv6, TCP, UDP, ICMP)."""
        if pkt.haslayer(IP):
            ip = pkt[IP]
            record = {
                "timestamp": time.time(),
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "protocol": ip.proto,
                "ip_len": ip.len,
                "ttl": ip.ttl,
                "src_port": None,
                "dst_port": None,
                "tcp_flags": None,
                "fin": 0, "syn": 0, "rst": 0, "psh": 0, "ack": 0, "urg": 0,
            }
        elif pkt.haslayer(IPv6):
            ipv6 = pkt[IPv6]
            record = {
                "timestamp": time.time(),
                "src_ip": ipv6.src,
                "dst_ip": ipv6.dst,
                "protocol": ipv6.nh,
                "ip_len": ipv6.plen,
                "ttl": ipv6.hlim,
                "src_port": None,
                "dst_port": None,
                "tcp_flags": None,
                "fin": 0, "syn": 0, "rst": 0, "psh": 0, "ack": 0, "urg": 0,
            }
        else:
            return None

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            record["src_port"] = tcp.sport
            record["dst_port"] = tcp.dport
            record["tcp_flags"] = str(tcp.flags)
            flags = tcp.flags
            record["fin"] = 1 if flags & 0x01 else 0
            record["syn"] = 1 if flags & 0x02 else 0
            record["rst"] = 1 if flags & 0x04 else 0
            record["psh"] = 1 if flags & 0x08 else 0
            record["ack"] = 1 if flags & 0x10 else 0
            record["urg"] = 1 if flags & 0x20 else 0

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            record["src_port"] = udp.sport
            record["dst_port"] = udp.dport

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            record["protocol"] = 1
            record["src_port"] = icmp.type
            record["dst_port"] = icmp.code

        return record

    def start(self, callback: Callable[[dict], None]) -> None:
        """
        Start sniffing. Calls callback(packet_dict) for every parsed packet.
        Runs until timeout is reached (count=0 means no packet cap within window).
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required for packet capture.")

        self._running = True
        logger.info(f"Starting capture on {self.interface} "
                    f"(timeout={self.timeout}s, max={self.max_packets})")

        def _handler(pkt):
            parsed = self._parse_packet(pkt)
            if parsed:
                callback(parsed)

        sniff(
            iface=self.interface,
            prn=_handler,
            timeout=self.timeout,
            count=0,               # 0 = infinite capture within timeout window
            store=False,
        )
        self._running = False
        logger.info("Capture window closed.")

    def stop(self):
        self._running = False


class PcapReplay:
    """
    Replay packets from a .pcap file (offline testing without live traffic).

    Usage:
        replay = PcapReplay("data/raw/sample.pcap")
        replay.play(callback=my_handler)
    """

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def play(self, callback: Callable[[dict], None]) -> None:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required.")
        from scapy.all import rdpcap

        logger.info(f"Replaying pcap: {self.pcap_path}")
        packets = rdpcap(self.pcap_path)
        cap = PacketCapture()

        for pkt in packets:
            parsed = cap._parse_packet(pkt)
            if parsed:
                callback(parsed)

        logger.info(f"Replayed {len(packets)} packets from {self.pcap_path}")
