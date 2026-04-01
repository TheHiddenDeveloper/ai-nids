"""
Packet Capture Module
---------------------
Captures raw packets from a network interface using scapy.
Emits packet dictionaries for downstream processing.
"""

import time
from typing import Callable, Optional
from loguru import logger

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
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

    def __init__(self, interface: str = "eth0", timeout: int = 10, max_packets: int = 1000):
        self.interface = interface
        self.timeout = timeout
        self.max_packets = max_packets
        self._running = False

    def _parse_packet(self, pkt) -> Optional[dict]:
        """Extract relevant fields from a raw scapy packet."""
        if not pkt.haslayer(IP):
            return None

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

        return record

    def start(self, callback: Callable[[dict], None]) -> None:
        """
        Start sniffing. Calls callback(packet_dict) for every parsed packet.
        Runs until max_packets captured or timeout reached.
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
            count=self.max_packets,
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
