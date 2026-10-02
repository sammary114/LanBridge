#!/usr/bin/env python3
"""LanBridge Asynchronous Client (client.py).

Provides a high-level asynchronous client for discovering, connecting, and chatting
with NeiWangTong (IMO 3.4.3055) clients over local networks.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import logging
import random
import socket
import struct
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .crypto import XTEACipher
from .enet import ENetCommandType, ENetProtocolSession
from .protocol import (
    OP_CHANGE_STATUS,
    OP_FLASH_SCREEN,
    OP_HANDSHAKE,
    OP_HEARTBEAT,
    OP_MSG_ACK,
    OP_QUIT,
    OP_READY,
    OP_SEND_MSG,
    OP_SEND_WRITING,
    build_change_status_xml,
    build_discovery_packet,
    build_flash_screen_xml,
    build_handshake_xml,
    build_msg_ack_xml,
    build_recall_xml,
    build_send_msg_xml,
    build_typing_xml,
    extract_chat_text,
    parse_discovery_packet,
)

logger = logging.getLogger("lanbridge")


@dataclass
class ClientConfig:
    bind_ip: str = "0.0.0.0"
    discovery_port: int = 9011
    data_port: int = 9012
    user_id: str = ""
    username: str = "LanBridge-Bot"
    hostname: str = "DESKTOP-LANBRIDGE"
    sign: str = "由 AstrBot 驱动的内网通 AI 助手"
    corp_id: str = ""
    auto_ack: bool = True
    auto_handshake: bool = True

    def __post_init__(self):
        if not self.user_id:
            # Generate deterministic or random 32-char hex string
            self.user_id = f"lanbridge{random.randint(10000000, 99999999)}{int(time.time()):08x}"[:32]


@dataclass
class PeerInfo:
    user_id: str
    username: str
    ip: str
    port: int = 9012
    hostname: str = ""
    org_id: str = ""
    last_seen: float = field(default_factory=time.time)


@dataclass
class LanBridgeMessage:
    msg_id: str
    sender_id: str
    sender_name: str
    text: str
    raw_xml: str
    timestamp: float
    peer: Optional[PeerInfo] = None


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_packet: Callable[[bytes, Tuple[str, int]], None]):
        self.on_packet = on_packet
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        self.on_packet(data, addr)

    def error_received(self, exc: Exception):
        logger.warning("UDP error received: %s", exc)


class LanBridgeClient:
    """High-level asynchronous LanBridge client for NeiWangTong (IMO 3.4.3055)."""

    def __init__(self, config: Optional[ClientConfig] = None):
        self.config = config or ClientConfig()
        self.cipher = XTEACipher()
        self.peers: Dict[str, PeerInfo] = {}  # user_id -> PeerInfo
        self.ip_to_peer: Dict[str, PeerInfo] = {}  # ip -> PeerInfo
        self.sessions: Dict[str, ENetProtocolSession] = {}  # ip:port -> session

        # Callbacks
        self.on_message: Optional[Callable[[LanBridgeMessage], Coroutine[Any, Any, None]]] = None
        self.on_shake: Optional[Callable[[str, PeerInfo], Coroutine[Any, Any, None]]] = None
        self.on_peer_online: Optional[Callable[[PeerInfo], Coroutine[Any, Any, None]]] = None
        self.on_peer_offline: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None

        self._transport_9011: Optional[asyncio.DatagramTransport] = None
        self._transport_9012: Optional[asyncio.DatagramTransport] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

    def get_session(self, ip: str, port: int = 9012) -> ENetProtocolSession:
        key = f"{ip}:{port}"
        if key not in self.sessions:
            self.sessions[key] = ENetProtocolSession()
        return self.sessions[key]

    async def start(self):
        """Start listening on UDP 9011 (discovery) and UDP 9012 (ENet)."""
        self._loop = asyncio.get_running_loop()
        self._running = True

        # Socket for 9011 (Discovery)
        sock_9011 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_9011.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_9011.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock_9011.bind((self.config.bind_ip, self.config.discovery_port))
        sock_9011.setblocking(False)

        # Socket for 9012 (ENet Data)
        sock_9012 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_9012.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_9012.bind((self.config.bind_ip, self.config.data_port))
        sock_9012.setblocking(False)

        self._transport_9011, _ = await self._loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self._handle_9011_packet), sock=sock_9011
        )
        self._transport_9012, _ = await self._loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self._handle_9012_packet), sock=sock_9012
        )

        logger.info(
            "LanBridgeClient started on %s (Discovery: %d, Data: %d)",
            self.config.bind_ip,
            self.config.discovery_port,
            self.config.data_port,
        )

        # Start periodic presence broadcast / heartbeat
        self._heartbeat_task = asyncio.create_task(self._periodic_loop())

    async def stop(self):
        """Stop client and close sockets."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self._transport_9011:
            self._transport_9011.close()
        if self._transport_9012:
            self._transport_9012.close()
        logger.info("LanBridgeClient stopped")

    def broadcast_discovery(self, target_ip: str = "255.255.255.255"):
        """Broadcast 304-byte discovery packet to announce presence."""
        pkt = build_discovery_packet(
            user_id=self.config.user_id,
            username=self.config.username,
            hostname=self.config.hostname,
            port=self.config.data_port,
            org_id=self.config.corp_id,
        )
        if self._transport_9011:
            try:
                self._transport_9011.sendto(pkt, (target_ip, self.config.discovery_port))
            except Exception as e:
                logger.debug("Broadcast discovery failed: %s", e)

    def _handle_9011_packet(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming 304-byte UDP 9011 discovery packets."""
        parsed = parse_discovery_packet(data)
        if not parsed:
            return

        sender_uid = parsed["user_id"]
        if sender_uid == self.config.user_id:
            return  # Ignore self-broadcast

        ip, _ = addr
        peer = PeerInfo(
            user_id=sender_uid,
            username=parsed["username"],
            ip=ip,
            port=parsed["port"] or 9012,
            hostname=parsed["hostname"],
            org_id=parsed["org_id"],
            last_seen=time.time(),
        )
        is_new = sender_uid not in self.peers
        self.peers[sender_uid] = peer
        self.ip_to_peer[ip] = peer

        logger.info("Discovered Nwt peer %s (%s) at %s:%d", peer.username, sender_uid, ip, peer.port)

        if is_new and self.on_peer_online:
            asyncio.create_task(self.on_peer_online(peer))

        # If auto_handshake enabled, send unicast discovery back and initiate handshake
        if self.config.auto_handshake:
            # 1. Unicast discovery response back to peer
            resp_pkt = build_discovery_packet(
                user_id=self.config.user_id,
                username=self.config.username,
                hostname=self.config.hostname,
                port=self.config.data_port,
                org_id=self.config.corp_id,
            )
            self._transport_9011.sendto(resp_pkt, (ip, self.config.discovery_port))

            # 2. Send Profile Handshake XML
            asyncio.create_task(self._send_profile_handshake(peer))

    async def _send_profile_handshake(self, peer: PeerInfo):
        """Send native <X_HANDSHARK> profile to light up in peer's contact list."""
        xml_bytes = build_handshake_xml(
            user_id=self.config.user_id,
            username=self.config.username,
            hostname=self.config.hostname,
            sign=self.config.sign,
            corp_id=self.config.corp_id,
        )
        encrypted_env = self.cipher.encrypt_envelope(OP_HANDSHAKE, xml_bytes)
        session = self.get_session(peer.ip, peer.port)
        if len(encrypted_env) > 1300:
            pkts = session.build_fragments(channel=0, payload=encrypted_env)
            for pkt in pkts:
                self._transport_9012.sendto(pkt, (peer.ip, peer.port))
                await asyncio.sleep(0.01)
        else:
            pkt = session.build_reliable(channel=0, payload=encrypted_env)
            self._transport_9012.sendto(pkt, (peer.ip, peer.port))

        # Follow up with online status
        await asyncio.sleep(0.05)
        status_xml = build_change_status_xml(status=1)
        status_env = self.cipher.encrypt_envelope(OP_CHANGE_STATUS, status_xml)
        status_pkt = session.build_reliable(channel=0, payload=status_env)
        self._transport_9012.sendto(status_pkt, (peer.ip, peer.port))

    def _handle_9012_packet(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP 9012 ENet packets."""
        ip, port = addr
        session = self.get_session(ip, port)
        commands = session.parse_packet(data)

        for cmd_type, channel, seq, payload in commands:
            # Automatic ACK response
            if self.config.auto_ack and cmd_type in (
                ENetCommandType.CONNECT,
                ENetCommandType.VERIFY_CONNECT,
                ENetCommandType.SEND_RELIABLE,
                ENetCommandType.SEND_FRAGMENT,
                ENetCommandType.PING,
            ):
                ack_pkt = session.build_ack(channel=channel, seq=seq)
                self._transport_9012.sendto(ack_pkt, (ip, port))

            # Handle Connect
            if cmd_type == ENetCommandType.CONNECT:
                # Reply VerifyConnect
                verify_pkt = session.build_reliable(channel=0xFF, payload=b"\x00" * 4)
                self._transport_9012.sendto(verify_pkt, (ip, port))

            # Handle Reliable / Fragment payload
            elif cmd_type in (ENetCommandType.SEND_RELIABLE, ENetCommandType.SEND_FRAGMENT):
                self._dispatch_envelope(payload, ip, port)

    def _dispatch_envelope(self, payload: bytes, ip: str, port: int):
        """Decrypt native envelope and dispatch Opcode."""
        if len(payload) < 6:
            return
        try:
            opcode, plain_bytes = self.cipher.decrypt_envelope(payload)
        except Exception as e:
            logger.debug("Failed to decrypt envelope from %s: %s", ip, e)
            return

        plain_text = plain_bytes.decode("gbk", errors="ignore")
        peer = self.ip_to_peer.get(ip)

        # 1. Handshake / Profile
        if opcode == OP_HANDSHAKE:
            logger.info("Received <X_HANDSHARK> from %s", ip)
            # Send back profile if we haven't yet
            if peer:
                asyncio.create_task(self._send_profile_handshake(peer))

        # 2. Text Message / Recall
        elif opcode == OP_SEND_MSG:
            extracted = extract_chat_text(plain_text)
            if extracted:
                msg_id, text, json_data = extracted
                msg_type = json_data.get("type", "0")

                # Send delivery ACK
                if msg_id:
                    ack_xml = build_msg_ack_xml(msg_id)
                    ack_env = self.cipher.encrypt_envelope(OP_SEND_MSG_ACK, ack_xml)
                    session = self.get_session(ip, port)
                    ack_pkt = session.build_reliable(channel=0, payload=ack_env)
                    self._transport_9012.sendto(ack_pkt, (ip, port))

                # Check if recall or normal text
                if msg_type == "6":
                    target_id = json_data.get("target_msg_id", "")
                    logger.info("Peer %s recalled message: %s", ip, target_id)
                elif msg_type == "0":
                    sender_id = peer.user_id if peer else ip
                    sender_name = peer.username if peer else ip
                    msg = LanBridgeMessage(
                        msg_id=msg_id,
                        sender_id=sender_id,
                        sender_name=sender_name,
                        text=text,
                        raw_xml=plain_text,
                        timestamp=time.time(),
                        peer=peer,
                    )
                    if self.on_message:
                        asyncio.create_task(self.on_message(msg))

        # 3. Window Shake
        elif opcode == OP_FLASH_SCREEN:
            sender_id = peer.user_id if peer else ip
            logger.info("Received Window Shake from %s", sender_id)
            if self.on_shake and peer:
                asyncio.create_task(self.on_shake(sender_id, peer))

        # 4. Quit / Offline
        elif opcode == OP_QUIT:
            sender_id = peer.user_id if peer else ip
            if sender_id in self.peers:
                del self.peers[sender_id]
            if ip in self.ip_to_peer:
                del self.ip_to_peer[ip]
            if self.on_peer_offline:
                asyncio.create_task(self.on_peer_offline(sender_id))

    async def send_text(self, target: str, text: str) -> str:
        """Send text message to peer (by IP address or user_id).

        Returns msg_id.
        """
        peer = self.peers.get(target) or self.ip_to_peer.get(target)
        target_ip = peer.ip if peer else target
        target_port = peer.port if peer else 9012

        xml_bytes, msg_id = build_send_msg_xml(text)
        encrypted_env = self.cipher.encrypt_envelope(OP_SEND_MSG, xml_bytes)
        session = self.get_session(target_ip, target_port)

        if len(encrypted_env) > 1300:
            pkts = session.build_fragments(channel=0, payload=encrypted_env)
            for pkt in pkts:
                self._transport_9012.sendto(pkt, (target_ip, target_port))
                await asyncio.sleep(0.01)
        else:
            pkt = session.build_reliable(channel=0, payload=encrypted_env)
            self._transport_9012.sendto(pkt, (target_ip, target_port))

        logger.info("Sent message [%s] to %s: %s", msg_id, target_ip, text[:50])
        return msg_id

    async def send_shake(self, target: str) -> bool:
        """Send window shake / flash screen to peer."""
        peer = self.peers.get(target) or self.ip_to_peer.get(target)
        target_ip = peer.ip if peer else target
        target_port = peer.port if peer else 9012

        xml_bytes = build_flash_screen_xml(shake_type=0)
        encrypted_env = self.cipher.encrypt_envelope(OP_FLASH_SCREEN, xml_bytes)
        session = self.get_session(target_ip, target_port)
        pkt = session.build_reliable(channel=0, payload=encrypted_env)
        self._transport_9012.sendto(pkt, (target_ip, target_port))
        logger.info("Sent Window Shake to %s", target_ip)
        return True

    async def recall_message(self, target: str, target_msg_id: str) -> str:
        """Recall a previously sent message."""
        peer = self.peers.get(target) or self.ip_to_peer.get(target)
        target_ip = peer.ip if peer else target
        target_port = peer.port if peer else 9012

        xml_bytes, recall_id = build_recall_xml(target_msg_id=target_msg_id)
        encrypted_env = self.cipher.encrypt_envelope(OP_SEND_MSG, xml_bytes)
        session = self.get_session(target_ip, target_port)
        pkt = session.build_reliable(channel=0, payload=encrypted_env)
        self._transport_9012.sendto(pkt, (target_ip, target_port))
        logger.info("Recalled message [%s] from %s", target_msg_id, target_ip)
        return recall_id

    async def _periodic_loop(self):
        """Periodically broadcast discovery presence and keepalives."""
        while self._running:
            try:
                self.broadcast_discovery()
            except Exception as e:
                logger.debug("Periodic broadcast error: %s", e)
            await asyncio.sleep(20)
