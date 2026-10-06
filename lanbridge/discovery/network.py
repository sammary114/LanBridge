#!/usr/bin/env python3
"""LanBridge Network Interface & Subnet Auto-Adaptation (network.py).

Provides automated zero-configuration network discovery:
- Enumerates active IPv4 network interfaces (Wi-Fi, Ethernet, Virtual)
- Filters out loopback (127.x) and unconfigured APIPA link-local (169.254.x)
- Calculates subnets, CIDRs, and directed broadcast addresses
- Automatically determines primary outbound interface IP
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import logging
import socket
from typing import List, Optional

logger = logging.getLogger("lanbridge.discovery.network")


@dataclass
class NetworkInterfaceInfo:
    """Represents an active local network interface with IP and subnet details."""

    name: str
    ip: str
    netmask: str
    network: str  # e.g., "192.168.31.0/24"
    broadcast: str  # e.g., "192.168.31.255"

    @property
    def prefixlen(self) -> int:
        return int(self.network.split("/")[1]) if "/" in self.network else 24

    @property
    def is_loopback(self) -> bool:
        return ipaddress.ip_address(self.ip).is_loopback

    @property
    def is_link_local(self) -> bool:
        return ipaddress.ip_address(self.ip).is_link_local


def get_active_network_interfaces() -> List[NetworkInterfaceInfo]:
    """Discover all active non-loopback IPv4 interfaces and their subnet details."""
    interfaces: List[NetworkInterfaceInfo] = []

    # Method A: Try psutil for exact interface names, netmasks, and families
    try:
        import psutil

        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address:
                    try:
                        ip_obj = ipaddress.IPv4Address(a.address)
                        if not ip_obj.is_loopback and not ip_obj.is_link_local:
                            mask = a.netmask or "255.255.255.0"
                            iface_obj = ipaddress.IPv4Interface(f"{a.address}/{mask}")
                            interfaces.append(
                                NetworkInterfaceInfo(
                                    name=name,
                                    ip=a.address,
                                    netmask=mask,
                                    network=str(iface_obj.network),
                                    broadcast=str(iface_obj.network.broadcast_address),
                                )
                            )
                    except Exception as e:
                        logger.debug("Skipping interface %s (%s): %s", name, a.address, e)
        if interfaces:
            return interfaces
    except ImportError:
        logger.debug("psutil not available, falling back to standard socket discovery")

    # Method B: Fallback to socket hostname resolution
    try:
        hostname = socket.gethostname()
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        for idx, ip_str in enumerate(ip_list):
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
                if not ip_obj.is_loopback and not ip_obj.is_link_local:
                    mask = "255.255.255.0"
                    iface_obj = ipaddress.IPv4Interface(f"{ip_str}/{mask}")
                    interfaces.append(
                        NetworkInterfaceInfo(
                            name=f"eth{idx}",
                            ip=ip_str,
                            netmask=mask,
                            network=str(iface_obj.network),
                            broadcast=str(iface_obj.network.broadcast_address),
                        )
                    )
            except Exception as e:
                logger.debug("Skipping fallback IP %s: %s", ip_str, e)
    except Exception as e:
        logger.warning("Failed standard socket hostname resolution: %s", e)

    return interfaces


def get_default_broadcast_addresses() -> List[str]:
    """Get all directed broadcast addresses for active interfaces plus 255.255.255.255."""
    bcasts = set()
    for iface in get_active_network_interfaces():
        if iface.broadcast:
            bcasts.add(iface.broadcast)
    bcasts.add("255.255.255.255")
    return sorted(list(bcasts))


def get_primary_local_ip() -> str:
    """Determine the primary local IPv4 address used for outbound communication."""
    # Try routing lookup via dummy UDP connect (does not transmit packets)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("223.5.5.5", 80))
            candidate = s.getsockname()[0]
            if candidate and not candidate.startswith("127."):
                return candidate
    except Exception:
        pass

    # Fallback to the first discovered active interface
    active = get_active_network_interfaces()
    if active:
        return active[0].ip

    return "127.0.0.1"
