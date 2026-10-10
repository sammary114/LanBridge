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


def _probe_outbound_ip() -> Optional[str]:
    """Determine outbound IP by connecting a UDP socket without transmitting packets."""
    for target in (
        "223.5.5.5",
        "114.114.114.114",
        "8.8.8.8",
        "192.168.1.1",
        "192.168.0.1",
        "192.168.31.1",
        "10.0.0.1",
        "172.16.0.1",
    ):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((target, 80))
                candidate = s.getsockname()[0]
                if candidate and not candidate.startswith("127."):
                    return candidate
        except Exception:
            continue
    return None


def _discover_linux_android_interfaces() -> List[NetworkInterfaceInfo]:
    """Discover interfaces on Linux/Android using ip command, ifconfig, or /proc/net/route."""
    interfaces: List[NetworkInterfaceInfo] = []
    import os
    import re
    import shutil
    import subprocess

    # 1. Try 'ip -4 -o addr' (Standard on Linux & modern Android Termux)
    ip_bin = shutil.which("ip") or "/system/bin/ip"
    if ip_bin and (os.path.exists(ip_bin) or shutil.which("ip")):
        try:
            res = subprocess.run(
                [ip_bin, "-4", "-o", "addr"],
                capture_output=True,
                text=True,
                timeout=1.5,
            )
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    m = re.search(r"\d+:\s+([^\s]+)\s+inet\s+([0-9.]+)/(\d+)(?:\s+brd\s+([0-9.]+))?", line)
                    if m:
                        if_name = m.group(1)
                        ip_str = m.group(2)
                        prefix = int(m.group(3))
                        brd_str = m.group(4)
                        try:
                            ip_obj = ipaddress.IPv4Address(ip_str)
                            if not ip_obj.is_loopback and not ip_obj.is_link_local:
                                iface_obj = ipaddress.IPv4Interface(f"{ip_str}/{prefix}")
                                mask = str(iface_obj.netmask)
                                brd = brd_str if brd_str else str(iface_obj.network.broadcast_address)
                                interfaces.append(
                                    NetworkInterfaceInfo(
                                        name=if_name,
                                        ip=ip_str,
                                        netmask=mask,
                                        network=str(iface_obj.network),
                                        broadcast=brd,
                                    )
                                )
                        except Exception:
                            continue
                if interfaces:
                    return interfaces
        except Exception as e:
            logger.debug("Failed ip -4 -o addr discovery: %s", e)

    # 2. Try 'ifconfig' (Legacy Linux / Android)
    ifconfig_bin = shutil.which("ifconfig") or "/system/bin/ifconfig"
    if ifconfig_bin and (os.path.exists(ifconfig_bin) or shutil.which("ifconfig")):
        try:
            res = subprocess.run(
                [ifconfig_bin],
                capture_output=True,
                text=True,
                timeout=1.5,
            )
            if res.returncode == 0 and res.stdout:
                cur_if = "eth0"
                for line in res.stdout.splitlines():
                    if_m = re.match(r"^([a-zA-Z0-9_:-]+)\b", line)
                    if if_m and not line.startswith(" "):
                        cur_if = if_m.group(1).rstrip(":")
                    inet_m = re.search(r"inet (?:addr:)?([0-9.]+)", line)
                    mask_m = re.search(r"(?:netmask|Mask:)\s*([0-9.]+)", line)
                    brd_m = re.search(r"(?:broadcast|Bcast:)\s*([0-9.]+)", line)
                    if inet_m and mask_m:
                        ip_str = inet_m.group(1)
                        mask_str = mask_m.group(1)
                        try:
                            ip_obj = ipaddress.IPv4Address(ip_str)
                            if not ip_obj.is_loopback and not ip_obj.is_link_local:
                                iface_obj = ipaddress.IPv4Interface(f"{ip_str}/{mask_str}")
                                brd = brd_m.group(1) if brd_m else str(iface_obj.network.broadcast_address)
                                interfaces.append(
                                    NetworkInterfaceInfo(
                                        name=cur_if,
                                        ip=ip_str,
                                        netmask=mask_str,
                                        network=str(iface_obj.network),
                                        broadcast=brd,
                                    )
                                )
                        except Exception:
                            continue
                if interfaces:
                    return interfaces
        except Exception as e:
            logger.debug("Failed ifconfig discovery: %s", e)

    # 3. Try /proc/net/route
    if os.path.exists("/proc/net/route"):
        try:
            with open("/proc/net/route", "r") as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 8:
                    iface = parts[0]
                    dest_hex = parts[1]
                    mask_hex = parts[7]
                    if dest_hex != "00000000" and mask_hex != "00000000":
                        dest_ip = socket.inet_ntoa(bytes.fromhex(dest_hex)[::-1])
                        mask_ip = socket.inet_ntoa(bytes.fromhex(mask_hex)[::-1])
                        iface_ip = None
                        try:
                            import fcntl
                            import struct
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                                iface_ip = socket.inet_ntoa(
                                    fcntl.ioctl(
                                        s.fileno(),
                                        0x8915,  # SIOCGIFADDR
                                        struct.pack("256s", iface[:15].encode("utf-8")),
                                    )[20:24]
                                )
                        except Exception:
                            pass
                        if iface_ip and not iface_ip.startswith("127."):
                            iface_obj = ipaddress.IPv4Interface(f"{iface_ip}/{mask_ip}")
                            interfaces.append(
                                NetworkInterfaceInfo(
                                    name=iface,
                                    ip=iface_ip,
                                    netmask=mask_ip,
                                    network=str(iface_obj.network),
                                    broadcast=str(iface_obj.network.broadcast_address),
                                )
                            )
            if interfaces:
                return interfaces
        except Exception as e:
            logger.debug("Failed /proc/net/route discovery: %s", e)

    return interfaces


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
    except (ImportError, Exception):
        logger.debug("psutil not available, falling back to native discovery methods")

    # Method B: Native Linux / Android discovery (ip command, ifconfig, /proc/net/route)
    interfaces = _discover_linux_android_interfaces()
    if interfaces:
        return interfaces

    # Method C: Fallback to socket hostname resolution
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

    # Method D: Outbound route probing (especially effective on Android / Termux / Linux)
    if not interfaces:
        outbound = _probe_outbound_ip()
        if outbound:
            try:
                mask = "255.255.255.0"
                iface_obj = ipaddress.IPv4Interface(f"{outbound}/{mask}")
                interfaces.append(
                    NetworkInterfaceInfo(
                        name="wlan0",
                        ip=outbound,
                        netmask=mask,
                        network=str(iface_obj.network),
                        broadcast=str(iface_obj.network.broadcast_address),
                    )
                )
            except Exception as e:
                logger.debug("Skipping synthetic interface: %s", e)

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
    candidate = _probe_outbound_ip()
    if candidate:
        return candidate

    active = get_active_network_interfaces()
    if active:
        return active[0].ip

    return "127.0.0.1"
