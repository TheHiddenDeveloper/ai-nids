"""
===============================================================================
NETWORK AUTO-DETECTION — Find active interface and derive HOME_NET
===============================================================================
Purpose:
  Auto-detect the active network interface and derive HOME_NET from it.
  This enables "plug-and-play" operation — no manual config.yaml editing
  when changing WiFi networks.

  Detection strategy (in order):
    1. Parse /proc/net/route for the default gateway interface
    2. Fall back to first UP, non-loopback interface with IPv4

Usage:
    from core.network_auto import auto_detect_network

    config = auto_detect_network()
    # => {"interface": "wlp4s0", "ip": "10.177.31.176",
    #     "cidr": "10.177.31.176/24", "home_net": ["10.177.31.176/32"]}

  Explicit overrides take precedence:
    config = auto_detect_network(interface="eth0", home_net=["10.0.0.0/8"])
===============================================================================
"""

import ipaddress
import os
import socket
import struct
from typing import Optional

from loguru import logger

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def _parse_proc_net_route() -> Optional[str]:
    """Return the interface name of the default route, or None.

    Reads /proc/net/route (Linux only) and looks for the entry with
    destination 0.0.0.0 (the default gateway).
    """
    try:
        with open("/proc/net/route") as f:
            next(f, None)
            for line in f:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                iface = parts[0]
                dest_hex = parts[1]
                if dest_hex == "00000000":
                    return iface
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return None


def _list_up_interfaces() -> list[tuple[str, str]]:
    """Return list of (interface_name, ip_address) for UP, non-loopback interfaces.

    Uses psutil if available, falls back to socket-based enumeration.
    """
    if not HAS_PSUTIL:
        logger.warning("psutil not available — cannot enumerate network interfaces")
        return []

    result = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for iface in stats:
        s = stats[iface]
        if not s.isup:
            continue
        if iface == "lo" or iface.startswith("lo"):
            continue
        for addr in addrs.get(iface, []):
            if addr.family == socket.AF_INET:
                result.append((iface, addr.address))
                break
    return result


def _ip_and_cidr(interface: str) -> tuple[Optional[str], Optional[str]]:
    """Return (ip_address, cidr_string) for the given interface.

    CIDR is derived from the IP and netmask. Returns (None, None) if not found.
    """
    if not HAS_PSUTIL:
        addr = None
        for iface, ip in _list_up_interfaces():
            if iface == interface:
                addr = ip
                break
        if not addr:
            return None, None
        return addr, f"{addr}/32"

    addrs = psutil.net_if_addrs()
    for addr in addrs.get(interface, []):
        if addr.family == socket.AF_INET:
            ip = addr.address
            netmask = addr.netmask or "255.255.255.0"
            try:
                cidr_bits = sum(bin(int(x)).count("1") for x in netmask.split("."))
                return ip, f"{ip}/{cidr_bits}"
            except Exception:
                return ip, f"{ip}/32"
    return None, None


def detect_active_interface() -> Optional[str]:
    """Detect the active network interface name.

    Priority:
      1. Default route from /proc/net/route
      2. First UP, non-loopback interface with IPv4
      3. None (caller should fall back)
    """
    iface = _parse_proc_net_route()
    if iface:
        logger.debug(f"Default route interface: {iface}")
        return iface

    interfaces = _list_up_interfaces()
    if interfaces:
        best = interfaces[0][0]
        logger.debug(f"Fallback interface (first UP with IPv4): {best}")
        return best

    logger.warning("No active interface detected")
    return None


def detect_interface_network(interface: str) -> Optional[dict]:
    """Return network info dict for the given interface.

    Returns:
        {"interface": "wlp4s0", "ip": "10.177.31.176",
         "cidr": "10.177.31.176/24", "netmask": "255.255.255.0",
         "home_net": ["10.177.31.176/32"]}
    or None if the interface is not found.
    """
    ip, cidr = _ip_and_cidr(interface)
    if not ip:
        return None

    netmask = None
    if HAS_PSUTIL:
        addrs = psutil.net_if_addrs()
        for addr in addrs.get(interface, []):
            if addr.family == socket.AF_INET:
                netmask = addr.netmask
                break

    return {
        "interface": interface,
        "ip": ip,
        "cidr": cidr,
        "netmask": netmask or "255.255.255.0",
        "home_net": [f"{ip}/32"],
    }


def auto_detect_network(
    explicit_interface: Optional[str] = None,
    explicit_home_net: Optional[list[str]] = None,
    fallback_interface: str = "eth0",
    fallback_home_net: Optional[list[str]] = None,
) -> dict:
    """Auto-detect or validate network configuration.

    Args:
        explicit_interface: User-specified interface (takes precedence).
        explicit_home_net: User-specified home_net (takes precedence).
        fallback_interface: Interface to use if auto-detection fails.
        fallback_home_net: home_net to use if auto-detection fails.

    Returns:
        {
            "interface": "wlp4s0",
            "home_net": ["10.177.31.176/32"],
            "ip": "10.177.31.176",
            "cidr": "10.177.31.176/24",
            "auto_detected": True,
        }

    Logic:
      - If home_net contains the string "auto", derive from detected IP.
      - If interface is "auto" (or None/empty), auto-detect.
    """
    fallback_home_net = fallback_home_net or ["10.0.0.0/8"]

    result: dict = {
        "interface": fallback_interface,
        "home_net": None,
        "ip": None,
        "cidr": None,
        "auto_detected": False,
    }

    needs_interface_detect = (
        explicit_interface is None
        or explicit_interface == ""
        or explicit_interface.lower() == "auto"
    )

    needs_home_net_derive = (
        explicit_home_net is None
        or any(h.lower() == "auto" for h in explicit_home_net)
    )

    effective_interface = explicit_interface if not needs_interface_detect else None

    if needs_interface_detect or needs_home_net_derive:
        detected = detect_active_interface()
        if detected:
            effective_interface = detected
            result["auto_detected"] = True
        elif needs_interface_detect:
            logger.warning(
                f"Interface auto-detection failed, falling back to {fallback_interface}"
            )
            effective_interface = fallback_interface

    if effective_interface:
        result["interface"] = effective_interface
        net_info = detect_interface_network(effective_interface)
        if net_info:
            result["ip"] = net_info["ip"]
            result["cidr"] = net_info["cidr"]

    if needs_home_net_derive:
        if result["ip"]:
            derived = [f"{result['ip']}/32"]
            result["home_net"] = derived
            logger.info(f"Derived HOME_NET from interface IP: {derived}")
        else:
            logger.warning(
                f"Could not derive HOME_NET (no IP), falling back to {fallback_home_net}"
            )
            result["home_net"] = list(fallback_home_net)
    elif explicit_home_net is not None:
        result["home_net"] = [h for h in explicit_home_net if h.lower() != "auto"]
    elif not result["home_net"]:
        result["home_net"] = list(fallback_home_net)

    if result["auto_detected"]:
        logger.info(
            f"Auto-detected network: "
            f"interface={result['interface']}, "
            f"ip={result['ip'] or 'unknown'}, "
            f"home_net={result['home_net']}"
        )

    return result


def poll_network_change(
    previous: dict,
    current_interface: str,
    current_home_net: list[str],
) -> Optional[dict]:
    """Check if the network config has changed. Returns new config or None.

    Called periodically (e.g., every 60s) from the pipeline maintenance loop.
    Only checks the interface IP — if it changed, returns an updated config dict.
    """
    net_info = detect_interface_network(current_interface)
    if not net_info:
        return None

    old_ip = previous.get("ip")
    new_ip = net_info["ip"]
    if old_ip and new_ip and old_ip != new_ip:
        new_home_net = [f"{new_ip}/32"]
        updated = {
            "interface": current_interface,
            "ip": new_ip,
            "cidr": net_info["cidr"],
            "home_net": new_home_net,
            "auto_detected": True,
        }
        logger.warning(
            f"Network change detected: IP {old_ip} -> {new_ip}, "
            f"updating HOME_NET to {new_home_net}"
        )
        return updated

    return None
