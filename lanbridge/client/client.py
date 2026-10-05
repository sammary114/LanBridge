#!/usr/bin/env python3
"""LanBridge High-Level Asynchronous Client (client.py).

Provides an event-driven, production-ready Python client for native Nwt interaction:
- Automatic UDP 9011 discovery & 7-stage handshake
- UDP 9012 text messaging with ACK delivery
- TCP CFolderTranEngine for high-resolution chat image transfer
- Extensible event callback decorators: @client.on_message, @client.on_contact_online, etc.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import socket
import struct
import time
from typing import Callable, Dict, List, Optional, Union

from lanbridge.models import ChatMessage, Contact, FileTask
from lanbridge.protocol import (
    DEFAULT_GROUP,
    DEFAULT_GUID,
    DEFAULT_NICKNAME,
    DEFAULT_USER_ID,
    DEFAULT_VERSION,
    ENetCommandType,
    ENetProtocolSession,
    XteaEngine,
    build_ack_response,
    build_folder_tran_chunk,
    build_folder_tran_response,
    build_handshake_reply,
    build_native_profile,
    build_nwt_discovery_packet,
    build_opcode_01,
    build_opcode_84,
    build_opcode_88_fragments,
    build_opcode_8a,
    build_x_flash_screen_envelope,
    build_x_heartbeat_envelope,
    build_x_ready_envelope,
    build_x_send_image_envelope,
    build_x_send_msg_ack_envelope,
    build_x_send_msg_envelope,
    extract_chat_message,
    extract_msg_id,
    parse_discovery_packet,
    parse_folder_tran_packet,
)

logger = logging.getLogger("lanbridge.client")


class LanBridgeClient:
    """Asynchronous client for NeiWangTong (Nwt 3.4.3055) compatibility."""

    def __init__(
        self,
        local_ip: str = "0.0.0.0",
        broadcast_ip: str = "172.31.127.255",
        user_id: str = DEFAULT_USER_ID,
        nickname: str = DEFAULT_NICKNAME,
        group: str = DEFAULT_GROUP,
        discovery_port: int = 9011,
        main_port: int = 9012,
        dynamic_port: int = 53782,
        tcp_file_port: int = 9013,
    ) -> None:
        self.local_ip = local_ip
        self.broadcast_ip = broadcast_ip
        self.user_id = user_id
        self.nickname = nickname
        self.group = group
        self.guid = DEFAULT_GUID
        self.discovery_port = discovery_port
        self.main_port = main_port
        self.dynamic_port = dynamic_port
        self.tcp_file_port = tcp_file_port

        self.xtea = XteaEngine()
        self.sessions: Dict[str, ENetProtocolSession] = {}
        self.contacts: Dict[str, Contact] = {}
        self.pending_images: Dict[str, bytes] = {}  # md5 -> bytes
        self.pending_tokens: Dict[int, str] = {}    # token -> md5

        # Event callbacks
        self._on_message_handlers: List[Callable[[ChatMessage], None]] = []
        self._on_contact_online_handlers: List[Callable[[Contact], None]] = []
        self._on_contact_offline_handlers: List[Callable[[Contact], None]] = []

        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._udp_9011_transport: Optional[asyncio.DatagramTransport] = None
        self._udp_9012_transport: Optional[asyncio.DatagramTransport] = None
        self._tcp_server: Optional[asyncio.Server] = None
        self._bg_tasks: List[asyncio.Task] = []

    def on_message(self, handler: Callable[[ChatMessage], None]) -> Callable[[ChatMessage], None]:
        """Register a callback for incoming chat messages."""
        self._on_message_handlers.append(handler)
        return handler

    def on_contact_online(self, handler: Callable[[Contact], None]) -> Callable[[Contact], None]:
        """Register a callback when a contact comes online."""
        self._on_contact_online_handlers.append(handler)
        return handler

    def on_contact_offline(self, handler: Callable[[Contact], None]) -> Callable[[Contact], None]:
        """Register a callback when a contact goes offline."""
        self._on_contact_offline_handlers.append(handler)
        return handler

    def get_session(self, peer_ip: str) -> ENetProtocolSession:
        """Get or initialize reliable ENet session for peer IP."""
        if peer_ip not in self.sessions:
            self.sessions[peer_ip] = ENetProtocolSession()
        return self.sessions[peer_ip]

    def emit_message(self, msg: ChatMessage) -> None:
        for handler in self._on_message_handlers:
            try:
                handler(msg)
            except Exception as e:
                logger.error("Error in on_message handler: %s", e)

    def emit_contact_online(self, contact: Contact) -> None:
        for handler in self._on_contact_online_handlers:
            try:
                handler(contact)
            except Exception as e:
                logger.error("Error in on_contact_online handler: %s", e)

    # -------------------------------------------------------------------------
    # Core Protocol Handlers
    # -------------------------------------------------------------------------

    def handle_discovery_packet(self, data: bytes, addr: Tuple[str, int]) -> Optional[bytes]:
        """Process UDP 9011 discovery packets."""
        parsed = parse_discovery_packet(data)
        if not parsed:
            return None

        peer_ip, _ = addr
        peer_uid = parsed["user_id"]
        dyn_port = parsed["dynamic_port"] or self.dynamic_port

        if peer_uid == self.user_id:
            return None  # Ignore self-broadcast

        is_new = peer_uid not in self.contacts
        contact = self.contacts.setdefault(peer_uid, Contact(user_id=peer_uid))
        contact.ip = peer_ip
        contact.port = self.main_port
        contact.dynamic_port = dyn_port
        contact.guid = parsed["guid"]
        contact.version = parsed["version"]
        contact.status = 0
        contact.last_seen = time.time()

        if is_new:
            logger.info("Discovered new contact: UID=%s, IP=%s, DynPort=%d", peer_uid, peer_ip, dyn_port)
            self.emit_contact_online(contact)

        # Reply with DiscoveryReply (cmd 2)
        if parsed["cmd"] == 1:
            reply = build_nwt_discovery_packet(
                cmd=2,
                user_id=self.user_id,
                broadcast_ip=self.broadcast_ip,
                dynamic_port=self.dynamic_port,
                guid=self.guid,
            )
            return reply
        return None

    def handle_main_udp_packet(self, data: bytes, addr: Tuple[str, int]) -> List[bytes]:
        """Process UDP 9012 reliable packets and return reply packets if any."""
        replies: List[bytes] = []
        if len(data) < 8:
            return replies

        peer_ip, peer_port = addr
        session = self.get_session(peer_ip)

        hdr_type = data[0]
        opcode = data[4]
        seq = int.from_bytes(data[2:4], "big")

        # 1. Opcode 0x82 Connect Request from peer
        if opcode == 0x82:
            reply_83 = build_handshake_reply(data)
            replies.append(reply_83)
            return replies

        # 2. Opcode 0x83 Verify Connect / Reply
        if opcode == 0x83:
            sync_01 = build_opcode_01(data[2:4])
            replies.append(sync_01)
            profile_env = build_native_profile(
                nick=self.nickname,
                user_id=self.user_id,
                tcp_file_port=self.tcp_file_port,
            )
            frags = build_opcode_88_fragments(profile_env)
            replies.extend(frags)
            return replies

        # 3. Opcode 0x85 Heartbeat Ping
        if opcode == 0x85:
            ack = build_ack_response(data)
            if ack:
                replies.append(ack)
            return replies

        # 4. Opcode 0x86 Single Frame (Ready, Envelope, Typing)
        if opcode == 0x86:
            ack = build_ack_response(data)
            if ack:
                replies.append(ack)

            if len(data) >= 16:
                tot_len = int.from_bytes(data[8:10], "big")
                enc_data = data[16 : 16 + tot_len]
                if len(enc_data) >= 8:
                    try:
                        inner_op, plaintext = self.xtea.parse_envelope(enc_data)
                        self._process_inner_envelope(inner_op, plaintext, peer_ip, replies)
                    except Exception as e:
                        logger.debug("Failed to decrypt 0x86 payload: %s", e)
            return replies

        # 5. Opcode 0x88 Multi-fragment Message
        if opcode == 0x88 and len(data) >= 28:
            ack = build_ack_response(data)
            if ack:
                replies.append(ack)

            base_sub_id = int.from_bytes(data[8:10], "big")
            chunk_len = int.from_bytes(data[10:12], "big")
            tot_frags = int.from_bytes(data[12:16], "big")
            frag_idx = int.from_bytes(data[16:20], "big")
            tot_len = int.from_bytes(data[20:24], "big")
            frag_payload = data[28 : 28 + chunk_len]

            if base_sub_id not in session.assemblers:
                session.assemblers[base_sub_id] = session.assemblers.get(
                    base_sub_id, None
                ) or session.assemblers.setdefault(
                    base_sub_id,
                    type(
                        "Assembler",
                        (),
                        {"parts": {}, "count": tot_frags, "total_len": tot_len},
                    )(),
                )
            asm = session.assemblers[base_sub_id]
            asm.parts[frag_idx] = frag_payload

            if len(asm.parts) == asm.count:
                full_payload = b"".join(asm.parts[i] for i in range(asm.count))
                del session.assemblers[base_sub_id]
                try:
                    inner_op, plaintext = self.xtea.parse_envelope(full_payload)
                    self._process_inner_envelope(inner_op, plaintext, peer_ip, replies)
                except Exception as e:
                    logger.debug("Failed to decrypt 0x88 reassembled payload: %s", e)
            return replies

        # Fallback ACK for any other request
        ack = build_ack_response(data)
        if ack:
            replies.append(ack)
        return replies

    def _process_inner_envelope(
        self,
        opcode: int,
        plaintext: bytes,
        peer_ip: str,
        replies: List[bytes],
    ) -> None:
        """Handle decrypted XML/JSON payloads."""
        xml_str = plaintext.decode("gbk", errors="replace")
        logger.debug("Received envelope Opcode=0x%04X: %s", opcode, xml_str[:120])

        # Opcode 1004 (0x03EC): X_SEND_MSG
        if opcode == 0x03EC:
            msg_id = extract_msg_id(xml_str)
            ack_env = build_x_send_msg_ack_envelope(msg_id)
            frags = build_opcode_88_fragments(ack_env)
            replies.extend(frags)

            text = extract_chat_message(xml_str)
            sender_uid = "unknown"
            for uid, c in self.contacts.items():
                if c.ip == peer_ip:
                    sender_uid = uid
                    break

            # Check for inline image
            import re
            img_match = re.search(r'(\d+)\|([0-9a-fA-F]{32})', xml_str)
            is_image = False
            token = None
            img_md5 = None
            if img_match:
                is_image = True
                token = int(img_match.group(1))
                img_md5 = img_match.group(2).lower()

            msg_obj = ChatMessage(
                msg_id=msg_id,
                sender_id=sender_uid,
                recipient_id=self.user_id,
                text=text,
                timestamp=time.time(),
                is_image=is_image,
                image_token=token,
                image_md5=img_md5,
                raw_xml=xml_str,
            )
            self.emit_message(msg_obj)

        # Opcode 1000 (0x03E8): X_HANDSHARK
        elif opcode == 0x03E8:
            ready_env = build_x_ready_envelope(self.user_id)
            replies.extend(build_opcode_88_fragments(ready_env))

    # -------------------------------------------------------------------------
    # Asynchronous Network Loop
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        """Start all background networking listeners."""
        self._loop = asyncio.get_running_loop()
        self._running = True

        # 1. Start UDP 9011 Discovery Server
        class DiscoveryProtocol(asyncio.DatagramProtocol):
            def __init__(self, client: LanBridgeClient):
                self.client = client
                self.transport: Optional[asyncio.DatagramTransport] = None

            def connection_made(self, transport: asyncio.DatagramTransport):
                self.transport = transport

            def datagram_received(self, data: bytes, addr: Tuple[str, int]):
                reply = self.client.handle_discovery_packet(data, addr)
                if reply and self.transport:
                    self.transport.sendto(reply, addr)

        # 2. Start UDP 9012 Main Channel Server
        class MainProtocol(asyncio.DatagramProtocol):
            def __init__(self, client: LanBridgeClient):
                self.client = client
                self.transport: Optional[asyncio.DatagramTransport] = None

            def connection_made(self, transport: asyncio.DatagramTransport):
                self.transport = transport

            def datagram_received(self, data: bytes, addr: Tuple[str, int]):
                replies = self.client.handle_main_udp_packet(data, addr)
                if replies and self.transport:
                    for pkt in replies:
                        self.transport.sendto(pkt, addr)

        sock_9011 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_9011.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_9011.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock_9011.bind((self.local_ip, self.discovery_port))
        t1, _ = await self._loop.create_datagram_endpoint(lambda: DiscoveryProtocol(self), sock=sock_9011)
        self._udp_9011_transport = t1

        sock_9012 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_9012.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_9012.bind((self.local_ip, self.main_port))
        t2, _ = await self._loop.create_datagram_endpoint(lambda: MainProtocol(self), sock=sock_9012)
        self._udp_9012_transport = t2

        # 3. Start TCP Mini-File / FolderTran Server
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp_client,
            self.local_ip,
            self.tcp_file_port,
        )

        logger.info(
            "LanBridgeClient started: UDP 9011/9012 & TCP %d on %s",
            self.tcp_file_port,
            self.local_ip,
        )

    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming TCP connections for CFolderTranEngine / CLanFileTran image downloads."""
        peer = writer.get_extra_info("peername")
        logger.debug("[TCP] Client connected: %s", peer)

        try:
            req_buf = bytearray()
            while len(req_buf) < 12:
                chunk = await reader.read(500)
                if not chunk:
                    break
                req_buf.extend(chunk)

            if len(req_buf) >= 12:
                pkt = parse_folder_tran_packet(bytes(req_buf))
                if pkt and pkt.get("cmd") == 1:
                    req_token = pkt.get("token", 0)
                    req_md5 = pkt.get("md5")
                    if not req_md5 and req_token in self.pending_tokens:
                        req_md5 = self.pending_tokens[req_token]
                    elif not req_md5 and len(self.pending_images) == 1:
                        req_md5 = next(iter(self.pending_images.keys()))

                    if req_md5 and req_md5 in self.pending_images:
                        img_data = self.pending_images[req_md5]
                        file_size = len(img_data)

                        # Send Command 2 (108B)
                        rsp_2 = build_folder_tran_response(file_size, token=req_token)
                        writer.write(rsp_2)
                        await writer.drain()

                        # Read Command 3 (108B)
                        cmd3_buf = bytearray()
                        while len(cmd3_buf) < 108:
                            chunk = await reader.read(108 - len(cmd3_buf))
                            if not chunk:
                                break
                            cmd3_buf.extend(chunk)

                        # Stream Command 4 Chunks
                        chunk_size = 16384
                        offset = 0
                        while offset < file_size:
                            piece = img_data[offset : offset + chunk_size]
                            chunk_pkt = build_folder_tran_chunk(file_size, offset, piece, token=req_token)
                            writer.write(chunk_pkt)
                            await writer.drain()
                            offset += len(piece)
                            await asyncio.sleep(0.005)
                        logger.info("[TCP] Image stream completed: MD5=%s (%d bytes)", req_md5, file_size)
        except Exception as e:
            logger.error("[TCP] Error serving stream: %s", e)
        finally:
            writer.close()
            await writer.wait_closed()

    async def broadcast_presence(self) -> None:
        """Send a UDP 9011 presence broadcast to announce online status."""
        pkt = build_nwt_discovery_packet(
            cmd=1,
            user_id=self.user_id,
            broadcast_ip=self.broadcast_ip,
            dynamic_port=self.dynamic_port,
            guid=self.guid,
        )
        if self._udp_9011_transport:
            self._udp_9011_transport.sendto(pkt, (self.broadcast_ip, self.discovery_port))
            logger.info("Sent discovery broadcast to %s:%d", self.broadcast_ip, self.discovery_port)

    async def send_message(self, target_ip: str, text: str) -> None:
        """Send a text message to a specific IP endpoint."""
        env = build_x_send_msg_envelope(text)
        frags = build_opcode_88_fragments(env)
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (target_ip, self.main_port))
            logger.info("Sent message to %s: '%s'", target_ip, text[:30])

    async def send_image(
        self,
        target_ip: str,
        image_data: bytes,
        caption: str = "",
    ) -> str:
        """Send an inline image to a target IP, managing token and CFolderTranEngine server."""
        img_md5 = hashlib.md5(image_data).hexdigest().lower()
        self.pending_images[img_md5] = image_data
        token = random.randint(10000, 30000)
        self.pending_tokens[token] = img_md5

        env = build_x_send_image_envelope(img_md5, token=token, caption=caption)
        frags = build_opcode_88_fragments(env)
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (target_ip, self.main_port))
            logger.info("Sent image notice to %s: MD5=%s, Token=%d", target_ip, img_md5, token)
        return img_md5

    async def shake_window(self, target_ip: str) -> None:
        """Send a window shake notice to target IP."""
        env = build_x_flash_screen_envelope()
        frags = build_opcode_88_fragments(env)
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (target_ip, self.main_port))
            logger.info("Sent window shake to %s", target_ip)

    async def stop(self) -> None:
        """Shut down the client and release network resources."""
        self._running = False
        if self._udp_9011_transport:
            self._udp_9011_transport.close()
        if self._udp_9012_transport:
            self._udp_9012_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        logger.info("LanBridgeClient stopped.")
