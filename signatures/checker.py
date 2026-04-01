"""
Signature Checker
-----------------
Rule-based layer on top of ML inference.
Catches known attack patterns even before the model is trained.
Add your own rules to SIGNATURE_RULES below.
"""

from typing import Optional


# Ports associated with historically exploited or suspicious services
KNOWN_BAD_PORTS = {
    23,     # Telnet (plaintext)
    445,    # SMB (EternalBlue, WannaCry)
    3389,   # RDP (brute-force target)
    5900,   # VNC
    6667,   # IRC (often used by C2 bots)
    31337,  # Back Orifice
    12345,  # NetBus
    4444,   # Metasploit default listener
}

SIGNATURE_RULES = [
    {
        "name": "SYN flood",
        "description": "High SYN count with low ACK — possible SYN flood attack",
        "check": lambda f: f.get("syn_flag_count", 0) > 50 and f.get("ack_flag_count", 0) < 5,
    },
    {
        "name": "Port scan",
        "description": "Many RST packets from single source — possible port scan",
        "check": lambda f: f.get("rst_flag_count", 0) > 20,
    },
    {
        "name": "Suspicious destination port",
        "description": "Traffic destined for a known malicious/risky port",
        "check": lambda f: f.get("_dst_port") in KNOWN_BAD_PORTS,
    },
    {
        "name": "C2 beacon pattern",
        "description": "Very small, short periodic flows — possible C2 beacon",
        "check": lambda f: f.get("packet_count", 0) <= 3 and f.get("duration", 1) < 0.5,
    },
    {
        "name": "FIN scan",
        "description": "FIN packets without prior SYN/ACK — possible stealth FIN scan",
        "check": lambda f: (
            f.get("fin_flag_count", 0) > 5
            and f.get("syn_flag_count", 0) == 0
            and f.get("ack_flag_count", 0) == 0
        ),
    },
    {
        "name": "High-volume flow",
        "description": "Unusually large data transfer — possible exfiltration or DDoS",
        "check": lambda f: f.get("flow_bytes_per_sec", 0) > 10_000_000,  # 10 MB/s
    },
]


class SignatureChecker:
    """Checks a flow feature dict against all defined signature rules."""

    def check(self, flow: dict) -> Optional[str]:
        """Return the first matching rule description, or None."""
        for rule in SIGNATURE_RULES:
            try:
                if rule["check"](flow):
                    return f"{rule['name']}: {rule['description']}"
            except Exception:
                pass
        return None

    def check_all(self, flow: dict) -> list:
        """Return descriptions of ALL matching rules (may be multiple)."""
        matches = []
        for rule in SIGNATURE_RULES:
            try:
                if rule["check"](flow):
                    matches.append(f"{rule['name']}: {rule['description']}")
            except Exception:
                pass
        return matches
