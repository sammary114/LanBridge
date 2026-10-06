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
import ipaddress
import logging
import os
import random
import socket
import struct
import time
from typing import Callable, Dict, List, Optional, Tuple, Union

from lanbridge.discovery import (
    SubnetScanner,
    get_active_network_interfaces,
    get_default_broadcast_addresses,
    get_primary_local_ip,
)
from lanbridge.models import ChatMessage, Contact, FileTask, GroupSharedFile
from lanbridge.protocol import (
    DEFAULT_GROUP,
    DEFAULT_GUID,
    DEFAULT_NICKNAME,
    DEFAULT_USER_ID,
    DEFAULT_VERSION,
    ENetCommandType,
    ENetProtocolSession,
    Opcode,
    ShareOpcode,
    XteaEngine,
    build_ack_response,
    build_folder_tran_chunk,
    build_folder_tran_response,
    build_handshake_reply,
    build_minifile_chunk,
    build_minifile_response,
    build_native_profile,
    build_nwt_discovery_packet,
    build_opcode_01,
    build_opcode_84,
    build_opcode_88_fragments,
    build_opcode_8a,
    build_x_flash_screen_envelope,
    build_x_heartbeat_envelope,
    build_x_qgroup_delete_share_envelope,
    build_x_qgroup_req_info_envelope,
    build_x_qgroup_req_info_rsp_envelope,
    build_x_qgroup_send_msg_envelope,
    build_x_qgroup_share_file_envelope,
    build_x_ready_envelope,
    build_x_send_image_envelope,
    build_x_send_msg_ack_envelope,
    build_x_send_msg_envelope,
    build_x_share_check_pwd_rsp_envelope,
    build_x_share_download_file_envelope,
    build_x_share_download_file_rsp_envelope,
    build_x_share_get_remote_root_rsp_envelope,
    build_x_share_get_remote_rsp_envelope,
    extract_chat_message,
    extract_msg_id,
    extract_qgroup_id,
    parse_discovery_packet,
    parse_folder_tran_packet,
    parse_minifile_packet,
    parse_share_xml,
)


logger = logging.getLogger("lanbridge.client")


class LanBridgeClient:
    """Asynchronous client for NeiWangTong (Nwt 3.4.3055) compatibility."""

    def __init__(
        self,
        local_ip: Optional[str] = None,
        broadcast_ip: Optional[Union[str, List[str]]] = None,
        user_id: str = DEFAULT_USER_ID,
        nickname: str = DEFAULT_NICKNAME,
        group: str = DEFAULT_GROUP,
        discovery_port: int = 9011,
        main_port: int = 9012,
        dynamic_port: int = 53782,
        tcp_file_port: int = 9013,
        share_port: int = 2442,
        share_dir: str = "./shared_files",
        enable_shadow_keeper: bool = True,
        cache_ttl_days: float = 7.0,
        max_cache_size_bytes: int = 10 * 1024 * 1024 * 1024,
        tiered_ttl_enabled: bool = True,
        shadow_max_filesize: int = 100 * 1024 * 1024,
        auto_scan_on_start: bool = True,
    ) -> None:
        if not local_ip or local_ip == "0.0.0.0":
            primary_ip = get_primary_local_ip()
            self.local_ip = primary_ip if primary_ip else "0.0.0.0"
            self.bind_ip = "0.0.0.0"
        else:
            self.local_ip = local_ip
            self.bind_ip = local_ip

        if broadcast_ip is None:
            self.broadcast_ips = get_default_broadcast_addresses()
            self.broadcast_ip = self.broadcast_ips[0] if self.broadcast_ips else "255.255.255.255"
        elif isinstance(broadcast_ip, list):
            self.broadcast_ips = broadcast_ip
            self.broadcast_ip = broadcast_ip[0] if broadcast_ip else "255.255.255.255"
        else:
            self.broadcast_ips = [broadcast_ip]
            self.broadcast_ip = broadcast_ip

        self.auto_scan_on_start = auto_scan_on_start
        self.user_id = user_id
        self.nickname = nickname
        self.group = group
        self.guid = DEFAULT_GUID
        self.discovery_port = discovery_port
        self.main_port = main_port
        self.dynamic_port = dynamic_port
        self.tcp_file_port = tcp_file_port
        self.share_port = share_port
        self.share_dir = os.path.abspath(share_dir)
        os.makedirs(self.share_dir, exist_ok=True)
        self.enable_shadow_keeper = enable_shadow_keeper
        self.cache_ttl_days = cache_ttl_days
        self.max_cache_size_bytes = max_cache_size_bytes
        self.tiered_ttl_enabled = tiered_ttl_enabled
        self.shadow_max_filesize = shadow_max_filesize

        self.xtea = XteaEngine()
        self.sessions: Dict[str, ENetProtocolSession] = {}
        self.contacts: Dict[str, Contact] = {}
        self.pending_images: Dict[str, bytes] = {}  # md5 -> bytes
        self.pending_tokens: Dict[int, str] = {}    # token -> md5
        self.group_shared_files: Dict[str, Dict[str, GroupSharedFile]] = {}  # qgroup_id -> {md5: GroupSharedFile}
        self.local_shared_files: Dict[str, GroupSharedFile] = {}  # md5 -> GroupSharedFile

        # Event callbacks
        self._on_message_handlers: List[Callable[[ChatMessage], None]] = []
        self._on_group_message_handlers: List[Callable[[ChatMessage], None]] = []
        self._on_contact_online_handlers: List[Callable[[Contact], None]] = []
        self._on_contact_offline_handlers: List[Callable[[Contact], None]] = []
        self._on_group_file_shared_handlers: List[Callable[[GroupSharedFile], None]] = []

        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._udp_9011_transport: Optional[asyncio.DatagramTransport] = None
        self._udp_9012_transport: Optional[asyncio.DatagramTransport] = None
        self._tcp_server: Optional[asyncio.Server] = None
        self._tcp_share_server: Optional[asyncio.Server] = None
        self._bg_tasks: List[asyncio.Task] = []

    def on_message(self, handler: Callable[[ChatMessage], None]) -> Callable[[ChatMessage], None]:
        """Register a callback for incoming chat messages."""
        self._on_message_handlers.append(handler)
        return handler

    def on_group_message(self, handler: Callable[[ChatMessage], None]) -> Callable[[ChatMessage], None]:
        """Register a callback for incoming group chat messages."""
        self._on_group_message_handlers.append(handler)
        return handler

    def on_contact_online(self, handler: Callable[[Contact], None]) -> Callable[[Contact], None]:
        """Register a callback when a contact comes online."""
        self._on_contact_online_handlers.append(handler)
        return handler

    def on_contact_offline(self, handler: Callable[[Contact], None]) -> Callable[[Contact], None]:
        """Register a callback when a contact goes offline."""
        self._on_contact_offline_handlers.append(handler)
        return handler

    def on_group_file_shared(self, handler: Callable[[GroupSharedFile], None]) -> Callable[[GroupSharedFile], None]:
        """Register a callback when a file is actively shared in a group."""
        self._on_group_file_shared_handlers.append(handler)
        return handler

    def emit_group_file_shared(self, shared_file: GroupSharedFile) -> None:
        for handler in self._on_group_file_shared_handlers:
            try:
                handler(shared_file)
            except Exception as e:
                logger.error("Error in on_group_file_shared handler: %s", e)


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

    def emit_group_message(self, msg: ChatMessage) -> None:
        for handler in self._on_group_message_handlers:
            try:
                handler(msg)
            except Exception as e:
                logger.error("Error in on_group_message handler: %s", e)

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
            if self._loop and self._loop.is_running():
                t = asyncio.create_task(self._proactive_connect(peer_ip))
                self._bg_tasks.append(t)

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

        # Opcode 3011 (0x0BC3): X_QGROUP_SEND_MSG (Group Chat Message)
        elif opcode == Opcode.X_QGROUP_SEND_MSG or "<X_QGROUP_SEND_MSG" in xml_str:
            msg_id = extract_msg_id(xml_str)
            text = extract_chat_message(xml_str)
            qgroup_id = extract_qgroup_id(xml_str) or "0"
            sender_uid = "unknown"
            for uid, c in self.contacts.items():
                if c.ip == peer_ip:
                    sender_uid = uid
                    break

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
                qgroup_id=qgroup_id,
            )
            self.emit_group_message(msg_obj)

        # Opcode 3005 (0x0BBD): X_QGROUP_REQ_INFO
        elif opcode == Opcode.X_QGROUP_REQ_INFO or "<X_QGROUP_REQ_INFO" in xml_str:
            qgroup_id = extract_qgroup_id(xml_str) or "0"
            rsp_env = build_x_qgroup_req_info_rsp_envelope(qgroup_id=qgroup_id, ret=0)
            replies.extend(build_opcode_88_fragments(rsp_env))

        # Group File Share Announcement (X_QGROUP_SHARE_FILE)
        elif opcode == ShareOpcode.X_QGROUP_SHARE_FILE or "<X_QGROUP_SHARE_FILE" in xml_str:
            share_dict = parse_share_xml(xml_str)
            qgroup_id = share_dict.get("qgroup_id", "0")
            file_name = share_dict.get("file_name", "unnamed.dat")
            file_size = int(share_dict.get("file_size", "0"))
            file_md5 = share_dict.get("file_md5", "").lower()
            uploader_id = share_dict.get("uploader_id", "unknown")
            uploader_name = share_dict.get("uploader_name", "Unknown")
            tcp_port = int(share_dict.get("tcp_port", "2442"))
            pwd_protect = share_dict.get("pwd_protect", "0") == "1"

            if file_md5:
                gsf = GroupSharedFile(
                    file_id=file_md5,
                    qgroup_id=qgroup_id,
                    filename=file_name,
                    filesize=file_size,
                    file_md5=file_md5,
                    uploader_id=uploader_id,
                    uploader_name=uploader_name,
                    uploader_ip=peer_ip,
                    share_port=tcp_port,
                    created_time=time.time(),
                    pwd_protect=pwd_protect,
                )
                self.group_shared_files.setdefault(qgroup_id, {})[file_md5] = gsf
                self.emit_group_file_shared(gsf)

                # Shadow keeper background pre-caching
                if self.enable_shadow_keeper and not gsf.is_cached and gsf.filesize <= self.shadow_max_filesize:
                    if self._loop and self._loop.is_running():
                        t = asyncio.create_task(self._shadow_cache_task(gsf))
                        self._bg_tasks.append(t)

        # Group File Revocation (X_QGROUP_DELETE_SHARE)
        elif opcode == ShareOpcode.X_QGROUP_DELETE_SHARE or "<X_QGROUP_DELETE_SHARE" in xml_str:
            del_dict = parse_share_xml(xml_str)
            qgroup_id = del_dict.get("qgroup_id", "0")
            file_md5 = del_dict.get("file_md5", "").lower()
            if qgroup_id in self.group_shared_files and file_md5 in self.group_shared_files[qgroup_id]:
                del self.group_shared_files[qgroup_id][file_md5]
            if file_md5 in self.local_shared_files:
                local_file = self.local_shared_files.pop(file_md5)
                if local_file.local_path and os.path.exists(local_file.local_path):
                    try:
                        os.remove(local_file.local_path)
                    except Exception as e:
                        logger.warning("Failed removing deleted shared file %s: %s", local_file.local_path, e)


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
        sock_9011.bind((self.bind_ip, self.discovery_port))
        t1, _ = await self._loop.create_datagram_endpoint(lambda: DiscoveryProtocol(self), sock=sock_9011)
        self._udp_9011_transport = t1

        sock_9012 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_9012.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_9012.bind((self.bind_ip, self.main_port))
        t2, _ = await self._loop.create_datagram_endpoint(lambda: MainProtocol(self), sock=sock_9012)
        self._udp_9012_transport = t2

        # 3. Start TCP Mini-File / FolderTran Server
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp_client,
            self.bind_ip,
            self.tcp_file_port,
        )

        # 4. Start TCP 2442 File Share Server
        try:
            self._tcp_share_server = await asyncio.start_server(
                self._handle_tcp_share_client,
                self.bind_ip,
                self.share_port,
            )
            logger.info("TCP Share Server listening on %s:%d", self.bind_ip, self.share_port)
        except Exception as e:
            logger.warning("Could not bind TCP share port %d: %s", self.share_port, e)

        logger.info(
            "LanBridgeClient started: UDP 9011/9012 & TCP %d (Mini-File), TCP %d (Share) on %s",
            self.tcp_file_port,
            self.share_port,
            self.bind_ip,
        )

        # 5. Proactive zero-touch auto scan task
        if self.auto_scan_on_start and self.bind_ip != "127.0.0.1":
            scan_task = asyncio.create_task(self._auto_subnet_scan_task())
            self._bg_tasks.append(scan_task)


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

    async def _handle_tcp_share_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming TCP 2442 connections (X_SHARE_* XML requests & CLanFileTran downloads)."""
        peer = writer.get_extra_info("peername")
        logger.debug("[TCP 2442] Share client connected: %s", peer)

        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not chunk:
                return
            req_buf = bytearray(chunk)

            # Check if this is an XTEA envelope (Opcode 0x0401..0x0420)
            # In Nwt XTEA envelope: [tot_len (4B), opcode (4B), ciphertext...]
            is_xtea = False
            if len(req_buf) >= 8:
                tot_len, op = struct.unpack(">2I", req_buf[:8])
                if 0x0400 <= op <= 0x0420:
                    is_xtea = True

            if is_xtea:
                tot_len, op = struct.unpack(">2I", req_buf[:8])
                while len(req_buf) < tot_len:
                    more = await asyncio.wait_for(reader.read(tot_len - len(req_buf)), timeout=5.0)
                    if not more:
                        break
                    req_buf.extend(more)

                opcode, plaintext = self.xtea.parse_envelope(bytes(req_buf))
                xml_str = plaintext.decode("gbk", errors="replace")
                parsed = parse_share_xml(xml_str)
                req_id = int(parsed.get("req_id", 1))
                logger.debug("[TCP 2442] XTEA envelope Opcode=0x%04x: %s", opcode, xml_str[:120])

                if opcode == ShareOpcode.X_SHARE_GET_REMOTE_ROOT:
                    catalogs = [
                        {"id": "1", "name": "群共享空间", "lastm": int(time.time()), "createt": int(time.time()), "valid": True}
                    ]
                    rsp = build_x_share_get_remote_root_rsp_envelope(catalogs, req_id=req_id)
                    writer.write(rsp)
                    await writer.drain()

                elif opcode == ShareOpcode.X_SHARE_GET_REMOTE:
                    files = []
                    for gsf in self.local_shared_files.values():
                        files.append({
                            "id": gsf.file_id,
                            "name": gsf.filename,
                            "size": gsf.filesize,
                            "md5": gsf.file_md5,
                            "lastm": int(gsf.created_time),
                        })
                    rsp = build_x_share_get_remote_rsp_envelope(files, req_id=req_id)
                    writer.write(rsp)
                    await writer.drain()

                elif opcode == ShareOpcode.X_SHARE_CHECK_PWD:
                    rsp = build_x_share_check_pwd_rsp_envelope(err=0, req_id=req_id)
                    writer.write(rsp)
                    await writer.drain()

                elif opcode == ShareOpcode.X_SHARE_DOWNLOAD_FILE:
                    target_fid = (parsed.get("file_id") or "").lower()
                    target_file = self.local_shared_files.get(target_fid)
                    if not target_file:
                        for f in self.local_shared_files.values():
                            if f.filename == parsed.get("file_path"):
                                target_file = f
                                break
                    if target_file:
                        rsp = build_x_share_download_file_rsp_envelope(target_file.filesize, target_file.file_md5, err=0, req_id=req_id)
                    else:
                        rsp = build_x_share_download_file_rsp_envelope(0, "", err=1, req_id=req_id)
                    writer.write(rsp)
                    await writer.drain()

            else:
                # Binary CLanFileTran Command 1 packet (344 bytes)
                total_len = struct.unpack(">I", req_buf[:4])[0] if len(req_buf) >= 4 else 344
                while len(req_buf) < total_len:
                    more = await asyncio.wait_for(reader.read(total_len - len(req_buf)), timeout=5.0)
                    if not more:
                        break
                    req_buf.extend(more)

                pkt = parse_minifile_packet(bytes(req_buf))
                if pkt and pkt.get("cmd") == 1:
                    req_md5 = pkt.get("md5")
                    if not req_md5 and len(self.local_shared_files) == 1:
                        req_md5 = next(iter(self.local_shared_files.keys()))

                    target_file = self.local_shared_files.get(req_md5) if req_md5 else None
                    if target_file and target_file.local_path and os.path.isfile(target_file.local_path):
                        file_path = target_file.local_path
                        file_size = os.path.getsize(file_path)

                        # Send Command 2 (356B response)
                        rsp_2 = build_minifile_response(target_file.file_md5, file_size, status=0)
                        writer.write(rsp_2)
                        await writer.drain()

                        # Stream Command 3 Chunks (16KB)
                        chunk_size = 16384
                        offset = 0
                        with open(file_path, "rb") as f:
                            while offset < file_size:
                                piece = f.read(chunk_size)
                                if not piece:
                                    break
                                chunk_pkt = build_minifile_chunk(file_size, offset, piece)
                                writer.write(chunk_pkt)
                                await writer.drain()
                                offset += len(piece)
                                await asyncio.sleep(0.001)

                        target_file.last_accessed = time.time()
                        logger.info("[TCP 2442] Streamed shared file completed: MD5=%s (%d bytes)", req_md5, file_size)
                    else:
                        rsp_2 = build_minifile_response(req_md5 or "0" * 32, 0, status=1)
                        writer.write(rsp_2)
                        await writer.drain()

        except Exception as e:
            logger.error("[TCP 2442] Error handling share client: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def get_cache_ttl_for_file(self, filesize: int) -> float:
        """Calculate cache retention TTL in seconds based on file size tiered policy."""
        if not self.tiered_ttl_enabled:
            return self.cache_ttl_days * 86400.0

        # Tiered retention policy:
        # < 10 MB: 14 days (1209600s)
        # 10 MB ~ 100 MB: 7 days (604800s)
        # > 100 MB: 2 days (48 hours, 172800s)
        if filesize < 10 * 1024 * 1024:
            return 14 * 86400.0
        elif filesize <= 100 * 1024 * 1024:
            return 7 * 86400.0
        else:
            return 2 * 86400.0

    def clean_expired_cache(self, current_time: Optional[float] = None) -> List[str]:
        """Evict expired cached files based on tiered TTL and LRU disk quota."""
        now = current_time if current_time is not None else time.time()
        purged_md5s: List[str] = []

        # 1. TTL-based expiration
        for md5, gsf in list(self.local_shared_files.items()):
            ttl = self.get_cache_ttl_for_file(gsf.filesize)
            if gsf.is_expired(ttl, now):
                if gsf.local_path and os.path.exists(gsf.local_path):
                    try:
                        os.remove(gsf.local_path)
                    except Exception as e:
                        logger.warning("Failed to delete expired cache file %s: %s", gsf.local_path, e)
                gsf.is_cached = False
                self.local_shared_files.pop(md5, None)
                purged_md5s.append(md5)
                logger.info("[CacheCleaner] Expired file evicted: %s (MD5=%s)", gsf.filename, md5)

        # 2. Disk Quota & LRU Eviction
        cached_files = [f for f in self.local_shared_files.values() if f.is_cached and not f.is_pinned]
        total_size = sum(f.filesize for f in cached_files)

        if total_size > self.max_cache_size_bytes:
            # Sort by last_accessed ascending (LRU)
            cached_files.sort(key=lambda x: x.last_accessed)
            target_size = int(self.max_cache_size_bytes * 0.70)
            for gsf in cached_files:
                if total_size <= target_size:
                    break
                if gsf.local_path and os.path.exists(gsf.local_path):
                    try:
                        os.remove(gsf.local_path)
                    except Exception as e:
                        logger.warning("Failed to remove LRU file %s: %s", gsf.local_path, e)
                gsf.is_cached = False
                total_size -= gsf.filesize
                self.local_shared_files.pop(gsf.file_md5, None)
                purged_md5s.append(gsf.file_md5)
                logger.info("[CacheCleaner] LRU evicted file: %s (MD5=%s)", gsf.filename, gsf.file_md5)

        return purged_md5s

    async def share_file_to_group(
        self,
        qgroup_id: str,
        file_path: str,
        target_ip: Optional[str] = None,
    ) -> GroupSharedFile:
        """Actively share a local file to a group, publishing X_QGROUP_SHARE_FILE."""
        abs_path = os.path.abspath(file_path)
        if not os.path.isfile(abs_path):
            raise FileNotFoundError(f"File not found: {abs_path}")

        filesize = os.path.getsize(abs_path)
        with open(abs_path, "rb") as f:
            file_md5 = hashlib.md5(f.read()).hexdigest().lower()

        filename = os.path.basename(abs_path)
        now = time.time()

        gsf = GroupSharedFile(
            file_id=file_md5,
            qgroup_id=qgroup_id,
            filename=filename,
            filesize=filesize,
            file_md5=file_md5,
            uploader_id=self.user_id,
            uploader_name=self.nickname,
            uploader_ip=self.local_ip,
            share_port=self.share_port,
            created_time=now,
            local_path=abs_path,
            is_cached=True,
            last_accessed=now,
            is_pinned=True,  # Shared by this user, protected against LRU
        )

        self.local_shared_files[file_md5] = gsf
        self.group_shared_files.setdefault(qgroup_id, {})[file_md5] = gsf

        # Broadcast or send X_QGROUP_SHARE_FILE envelope
        env = build_x_qgroup_share_file_envelope(
            qgroup_id=qgroup_id,
            file_name=filename,
            file_size=filesize,
            file_md5=file_md5,
            uploader_id=self.user_id,
            uploader_name=self.nickname,
            tcp_port=self.share_port,
            timestamp=int(now),
        )
        frags = build_opcode_88_fragments(env)
        dest_ip = target_ip if target_ip else self.broadcast_ip
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (dest_ip, self.main_port))
            logger.info(
                "Shared file '%s' to group %s (MD5=%s, Size=%d bytes) -> %s",
                filename,
                qgroup_id,
                file_md5,
                filesize,
                dest_ip,
            )

        return gsf

    async def delete_group_shared_file(
        self,
        qgroup_id: str,
        file_md5: str,
        target_ip: Optional[str] = None,
    ) -> None:
        """Revoke a shared group file and broadcast X_QGROUP_DELETE_SHARE."""
        file_md5 = file_md5.lower()
        if qgroup_id in self.group_shared_files:
            self.group_shared_files[qgroup_id].pop(file_md5, None)
        self.local_shared_files.pop(file_md5, None)

        env = build_x_qgroup_delete_share_envelope(
            qgroup_id=qgroup_id,
            file_md5=file_md5,
            uploader_id=self.user_id,
        )
        frags = build_opcode_88_fragments(env)
        dest_ip = target_ip if target_ip else self.broadcast_ip
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (dest_ip, self.main_port))
            logger.info("Sent delete share notice for %s in group %s -> %s", file_md5, qgroup_id, dest_ip)

    async def download_shared_file(
        self,
        shared_file: GroupSharedFile,
        target_dir: Optional[str] = None,
        failover_candidates: Optional[List[Union[str, Tuple[str, int]]]] = None,
        failover_ips: Optional[List[Union[str, Tuple[str, int]]]] = None,
    ) -> str:
        """Download a shared file via TCP 2442 with automatic Shadow Keeper Failover."""
        if target_dir is None:
            target_dir = self.share_dir
        os.makedirs(target_dir, exist_ok=True)

        safe_filename = os.path.basename(shared_file.filename)
        if not safe_filename or safe_filename in (".", ".."):
            safe_filename = f"file_{shared_file.file_md5[:8]}.dat"
        dest_path = os.path.join(target_dir, safe_filename)

        candidates: List[Tuple[str, int]] = []
        if shared_file.uploader_ip:
            candidates.append((shared_file.uploader_ip, shared_file.share_port or 2442))

        f_list = failover_candidates or failover_ips or []
        for item in f_list:
            if isinstance(item, tuple):
                ep = (item[0], item[1])
            else:
                ep = (item, shared_file.share_port or 2442)
            if ep not in candidates:
                candidates.append(ep)

        for contact in self.contacts.values():
            if contact.ip:
                ep = (contact.ip, 2442)
                if ep not in candidates:
                    candidates.append(ep)

        success = False
        last_error: Optional[Exception] = None

        for host, port in candidates:
            temp_path = dest_path + f".tmp_{int(time.time())}"
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=3.0,
                )
            except Exception as e:
                logger.debug("Failed connecting to %s:%d for file %s: %s", host, port, shared_file.filename, e)
                last_error = e
                continue

            try:
                # 1. Send Command 1 Request (344 bytes)
                req_pkt = bytearray(344)
                struct.pack_into(">I", req_pkt, 0, 344)
                struct.pack_into(">I", req_pkt, 4, 1)
                struct.pack_into(">I", req_pkt, 8, 1)  # Command 1: Download Request
                md5_b = shared_file.file_md5.encode("ascii")
                req_pkt[0x70 : 0x70 + len(md5_b)] = md5_b
                sig = f"|{shared_file.file_md5}".encode("ascii")
                req_pkt[0x90 : 0x90 + len(sig)] = sig

                writer.write(bytes(req_pkt))
                await writer.drain()

                # 2. Read Command 2 Response (356 bytes)
                rsp2_buf = bytearray()
                while len(rsp2_buf) < 356:
                    chunk = await asyncio.wait_for(reader.read(356 - len(rsp2_buf)), timeout=5.0)
                    if not chunk:
                        break
                    rsp2_buf.extend(chunk)

                if len(rsp2_buf) < 356:
                    raise IOError("Incomplete Command 2 response from server")

                rsp_pkt = parse_minifile_packet(bytes(rsp2_buf))
                if not rsp_pkt or rsp_pkt.get("cmd") != 2:
                    raise IOError("Invalid response packet (expected Cmd 2)")
                if rsp_pkt.get("status") != 0:
                    raise IOError(f"Server rejected file download, status={rsp_pkt.get('status')}")

                file_size = rsp_pkt.get("file_size", shared_file.filesize)

                # 3. Read Command 3 Data Chunks
                hasher = hashlib.md5()
                recv_size = 0
                with open(temp_path, "wb") as f_out:
                    while recv_size < file_size:
                        header_buf = bytearray()
                        while len(header_buf) < 0x98:
                            ch = await asyncio.wait_for(reader.read(0x98 - len(header_buf)), timeout=5.0)
                            if not ch:
                                break
                            header_buf.extend(ch)
                        if len(header_buf) < 0x98:
                            break

                        cmd3_meta = parse_minifile_packet(bytes(header_buf))
                        if not cmd3_meta or cmd3_meta.get("cmd") != 3:
                            break

                        chunk_len = cmd3_meta.get("chunk_len", 0)
                        data_buf = bytearray()
                        while len(data_buf) < chunk_len:
                            ch = await asyncio.wait_for(reader.read(chunk_len - len(data_buf)), timeout=5.0)
                            if not ch:
                                break
                            data_buf.extend(ch)
                        if len(data_buf) < chunk_len:
                            break

                        f_out.write(data_buf)
                        hasher.update(data_buf)
                        recv_size += len(data_buf)

                if recv_size == file_size:
                    calc_md5 = hasher.hexdigest().lower()
                    if calc_md5 == shared_file.file_md5.lower():
                        if os.path.exists(dest_path):
                            try:
                                os.remove(dest_path)
                            except Exception:
                                pass
                        os.replace(temp_path, dest_path)
                        shared_file.local_path = dest_path
                        shared_file.is_cached = True
                        shared_file.last_accessed = time.time()
                        self.local_shared_files[shared_file.file_md5] = shared_file
                        success = True
                        logger.info(
                            "Downloaded shared file '%s' from %s:%d successfully (%d bytes, MD5=%s)",
                            shared_file.filename,
                            host,
                            port,
                            file_size,
                            calc_md5,
                        )
                        break
                    else:
                        raise ValueError(f"MD5 mismatch: expected {shared_file.file_md5}, got {calc_md5}")
                else:
                    raise IOError(f"Incomplete download: {recv_size}/{file_size} bytes")

            except Exception as e:
                logger.warning("Download failed from %s:%d: %s", host, port, e)
                last_error = e
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        if not success:
            raise RuntimeError(
                f"Failed to download shared file '{shared_file.filename}' from any candidate: {last_error}"
            )
        return dest_path

    async def _shadow_cache_task(self, shared_file: GroupSharedFile) -> None:
        """Background task for Shadow Keeper: pre-cache group shared files."""
        try:
            logger.info(
                "[ShadowKeeper] Pre-caching file '%s' (MD5=%s, Size=%d bytes) from %s:%d",
                shared_file.filename,
                shared_file.file_md5,
                shared_file.filesize,
                shared_file.uploader_ip,
                shared_file.share_port,
            )
            await self.download_shared_file(shared_file)
            logger.info("[ShadowKeeper] Pre-cached file successfully: %s", shared_file.filename)
        except Exception as e:
            logger.debug("[ShadowKeeper] Background cache skipped or failed for %s: %s", shared_file.filename, e)

    async def broadcast_presence(self) -> None:
        """Send UDP 9011 presence broadcasts to all configured broadcast destinations."""
        if not self._udp_9011_transport:
            return
        for b_ip in self.broadcast_ips:
            pkt = build_nwt_discovery_packet(
                cmd=1,
                user_id=self.user_id,
                broadcast_ip=b_ip,
                dynamic_port=self.dynamic_port,
                guid=self.guid,
            )
            try:
                self._udp_9011_transport.sendto(pkt, (b_ip, self.discovery_port))
                logger.info("Sent discovery broadcast to %s:%d", b_ip, self.discovery_port)
            except Exception as e:
                logger.warning("Failed sending discovery broadcast to %s: %s", b_ip, e)

    async def _proactive_connect(self, peer_ip: str) -> None:
        """Initiate proactive ENet connection (Opcode 0x82) to peer."""
        session = self.get_session(peer_ip)
        connect_pkt = session.build_connect(b"\x01\x02\x03\x04")
        if self._udp_9012_transport:
            try:
                self._udp_9012_transport.sendto(connect_pkt, (peer_ip, self.main_port))
                logger.debug("Sent proactive ENet connect to %s:%d", peer_ip, self.main_port)
            except Exception as e:
                logger.debug("Failed sending proactive connect to %s: %s", peer_ip, e)

    async def _auto_subnet_scan_task(self) -> None:
        """Asynchronously scan local subnets on startup to discover Nwt instances."""
        try:
            await asyncio.sleep(0.1)
            await self.broadcast_presence()

            interfaces = get_active_network_interfaces()
            targets: List[str] = []
            for iface in interfaces:
                try:
                    net24 = ipaddress.ip_network(f"{iface.ip}/24", strict=False)
                    targets.append(str(net24))
                except Exception as e:
                    logger.debug("Failed computing /24 for interface %s: %s", iface.name, e)

            if targets:
                logger.info("Initiating auto subnet scan across: %s", targets)
                scanner = SubnetScanner(
                    local_user_id=self.user_id,
                    discovery_port=self.discovery_port,
                    listen_timeout=1.0,
                    rate_limit_delay=0.001,
                )
                discovered = await scanner.scan(targets, bind_ip="0.0.0.0")
                for contact in discovered:
                    if contact.user_id not in self.contacts and contact.user_id != self.user_id:
                        self.contacts[contact.user_id] = contact
                        self.emit_contact_online(contact)
                        logger.info("Auto-scan discovered peer: UID=%s, IP=%s", contact.user_id, contact.ip)
                        await self._proactive_connect(contact.ip)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("Error during auto subnet scan: %s", e)

    async def send_message(self, target_ip: str, text: str) -> None:
        """Send a text message to a specific IP endpoint."""
        env = build_x_send_msg_envelope(text)
        frags = build_opcode_88_fragments(env)
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (target_ip, self.main_port))
            logger.info("Sent message to %s: '%s'", target_ip, text[:30])

    async def send_group_message(
        self,
        qgroup_id: str,
        text: str,
        target_ip: Optional[str] = None,
    ) -> None:
        """Send a text message to a specific QGroup.
        
        If target_ip is provided, sends to that peer; otherwise broadcasts to all contacts
        and configured broadcast addresses.
        """
        env = build_x_qgroup_send_msg_envelope(qgroup_id=qgroup_id, text=text)
        frags = build_opcode_88_fragments(env)
        if not self._udp_9012_transport:
            return

        destinations = set()
        if target_ip:
            destinations.add(target_ip)
        else:
            for c in self.contacts.values():
                if c.ip:
                    destinations.add(c.ip)
            for b_ip in self.broadcast_ips:
                destinations.add(b_ip)

        for dest in destinations:
            for frag in frags:
                try:
                    self._udp_9012_transport.sendto(frag, (dest, self.main_port))
                except Exception as e:
                    logger.debug("Failed sending group msg frag to %s: %s", dest, e)
        logger.info("Sent group msg to %s (len=%d) -> %d destinations", qgroup_id, len(text), len(destinations))

    async def sync_group_info(self, qgroup_id: str, target_ip: str) -> None:
        """Request QGroup metadata and member directory via Opcode 3005."""
        env = build_x_qgroup_req_info_envelope(qgroup_id=qgroup_id)
        frags = build_opcode_88_fragments(env)
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (target_ip, self.main_port))
            logger.info("Sent X_QGROUP_REQ_INFO for group %s -> %s", qgroup_id, target_ip)

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
        for task in self._bg_tasks:
            if not task.done():
                task.cancel()
        if self._udp_9011_transport:
            self._udp_9011_transport.close()
        if self._udp_9012_transport:
            self._udp_9012_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        if self._tcp_share_server:
            self._tcp_share_server.close()
            await self._tcp_share_server.wait_closed()
        logger.info("LanBridgeClient stopped.")
