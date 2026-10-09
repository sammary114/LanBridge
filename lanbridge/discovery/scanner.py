#!/usr/bin/env python3
"""LanBridge Multi-Subnet Active Discovery Scanner (scanner.py).

Provides asynchronous, concurrent scanning across arbitrary CIDR subnets (e.g. 192.168.1.0/24),
emitting UDP 9011 discovery packets and collecting responding NeiWangTong endpoints.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from typing import AsyncGenerator, Dict, List, Optional, Set, Tuple

from lanbridge.models import Contact
from lanbridge.protocol.discovery import (
    DEFAULT_GUID,
    DEFAULT_USER_ID,
    build_nwt_discovery_packet,
    parse_discovery_packet,
)

logger = logging.getLogger("lanbridge.scanner")


class SubnetScanner:
    """High-performance concurrent subnet scanner for Nwt instances."""

    def __init__(
        self,
        local_user_id: str = DEFAULT_USER_ID,
        discovery_port: int = 9011,
        listen_timeout: float = 2.0,
        rate_limit_delay: float = 0.002,
    ) -> None:
        self.local_user_id = local_user_id
        self.discovery_port = discovery_port
        self.listen_timeout = listen_timeout
        self.rate_limit_delay = rate_limit_delay

    @staticmethod
    def expand_subnets(cidrs: List[str]) -> List[str]:
        """Expand a list of CIDR strings or IP addresses into host IP strings."""
        hosts: List[str] = []
        for item in cidrs:
            item = item.strip()
            if not item:
                continue
            try:
                if "/" in item:
                    net = ipaddress.ip_network(item, strict=False)
                    for ip in net.hosts():
                        hosts.append(str(ip))
                else:
                    hosts.append(str(ipaddress.ip_address(item)))
            except ValueError as e:
                logger.warning("Invalid CIDR or IP skipped: %s (%s)", item, e)
        return hosts

    async def scan(
        self,
        targets: List[str],
        bind_ip: str = "0.0.0.0",
    ) -> List[Contact]:
        """Scan target CIDRs or IP list and return discovered Contacts."""
        discovered: Dict[str, Contact] = {}
        target_ips = self.expand_subnets(targets)
        if not target_ips:
            return []

        loop = asyncio.get_running_loop()

        # Dedicated UDP socket for scanning
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((bind_ip, 0))  # Bind to ephemeral port to avoid conflicts
        sock.setblocking(False)

        disc_pkt = build_nwt_discovery_packet(
            cmd=1,
            user_id=self.local_user_id,
            broadcast_ip="255.255.255.255",
            dynamic_port=53782,
            guid=DEFAULT_GUID,
        )

        send_done = asyncio.Event()

        async def listener():
            linger_end: Optional[float] = None
            while True:
                if send_done.is_set():
                    if linger_end is None:
                        linger_end = time.time() + self.listen_timeout
                    elif time.time() >= linger_end:
                        break
                try:
                    data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), timeout=0.05)
                    parsed = parse_discovery_packet(data)
                    if parsed and parsed.get("user_id") != self.local_user_id:
                        peer_ip, _ = addr
                        uid = parsed["user_id"]
                        if uid not in discovered:
                            c = Contact(
                                user_id=uid,
                                ip=peer_ip,
                                port=9012,
                                dynamic_port=parsed.get("dynamic_port", 53782),
                                guid=parsed.get("guid", b""),
                                version=parsed.get("version", "#3#4#4"),
                                last_seen=time.time(),
                            )
                            discovered[uid] = c
                            logger.info("[SCANNER] Discovered peer at %s (UID: %s)", peer_ip, uid)
                except asyncio.TimeoutError:
                    continue
                except (ConnectionResetError, BlockingIOError, OSError):
                    # Gracefully ignore Windows WSAECONNRESET (10054) caused by ICMP unreachables
                    continue
                except Exception as e:
                    logger.debug("[SCANNER] Listener exception: %s", e)
                    break

        async def sender():
            try:
                for idx, ip in enumerate(target_ips):
                    for attempt in range(5):
                        try:
                            sock.sendto(disc_pkt, (ip, self.discovery_port))
                            break
                        except (BlockingIOError, OSError):
                            await asyncio.sleep(0.005)
                    if (idx + 1) % 15 == 0:
                        delay = max(self.rate_limit_delay, 0.005)
                        await asyncio.sleep(delay)
            finally:
                send_done.set()

        listen_task = asyncio.create_task(listener())
        send_task = asyncio.create_task(sender())

        await send_task
        await listen_task

        sock.close()
        return list(discovered.values())
