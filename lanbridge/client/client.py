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
import uuid
from typing import Callable, Dict, List, Optional, Tuple, Union

from lanbridge.adapter import NativeNwtAdapter
from lanbridge.discovery import (
    SubnetScanner,
    get_active_network_interfaces,
    get_default_broadcast_addresses,
    get_primary_local_ip,
)
from lanbridge.models import (
    ChatMessage,
    Contact,
    FileTask,
    GroupSharedFile,
    QGroup,
    RecallNotice,
    ShakeNotice,
    TypingNotice,
)
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
    build_ipmsg_presence,
    build_opcode_01,
    build_opcode_84,
    build_opcode_88_fragments,
    build_opcode_8a,
    build_stage4_node_announcement,
    build_x_ready_frame,
    build_x_change_sign_envelope,
    build_x_change_status_envelope,
    build_x_flash_screen_envelope,
    build_x_heartbeat_envelope,
    build_x_qgroup_delete_share_envelope,
    build_x_qgroup_dismiss_envelope,
    build_x_qgroup_exit_envelope,
    build_x_qgroup_invite_envelope,
    build_x_qgroup_invite_rsp_envelope,
    build_x_qgroup_kick_envelope,
    build_x_qgroup_other_invite_envelope,
    build_x_qgroup_push_info_envelope,
    build_x_qgroup_push_user_envelope,
    build_x_qgroup_req_info_envelope,
    build_x_qgroup_req_info_rsp_envelope,
    build_x_qgroup_req_user_envelope,
    build_x_qgroup_req_user_rsp_envelope,
    build_x_qgroup_send_msg_envelope,
    build_x_qgroup_share_file_envelope,
    build_x_ready_envelope,
    build_x_recall_msg_envelope,
    build_x_send_image_envelope,
    build_x_send_msg_ack_envelope,
    build_x_send_msg_envelope,
    build_x_send_writting_envelope,
    build_x_share_check_pwd_rsp_envelope,
    build_x_share_download_file_envelope,
    build_x_share_download_file_rsp_envelope,
    build_x_share_get_remote_root_rsp_envelope,
    build_x_share_get_remote_rsp_envelope,
    extract_chat_message,
    extract_msg_id,
    extract_qgroup_id,
    extract_recall_info,
    parse_discovery_packet,
    parse_folder_tran_packet,
    parse_minifile_packet,
    parse_qgroup_xml,
    parse_share_xml,
)


logger = logging.getLogger("lanbridge.client")


def get_or_create_device_id() -> str:
    """Retrieve or generate a persistent 32-hex device ID for this node.

    Checks ~/.lanbridge/device_id. If missing or invalid, generates a new
    random 32-char hexadecimal string (via uuid4) and persists it.
    """
    cfg_dir = os.path.expanduser(os.path.join("~", ".lanbridge"))
    id_file = os.path.join(cfg_dir, "device_id")
    try:
        if os.path.isfile(id_file):
            with open(id_file, "r", encoding="ascii") as f:
                val = f.read().strip()
                if len(val) == 32 and all(c in "0123456789abcdefABCDEF" for c in val):
                    return val.lower()
    except Exception:
        pass

    new_id = uuid.uuid4().hex.lower()
    try:
        os.makedirs(cfg_dir, exist_ok=True)
        with open(id_file, "w", encoding="ascii") as f:
            f.write(new_id)
    except Exception:
        pass
    return new_id


class LanBridgeClient:
    """Asynchronous client for NeiWangTong (Nwt 3.4.3055) compatibility."""

    def __init__(
        self,
        local_ip: Optional[str] = None,
        broadcast_ip: Optional[Union[str, List[str]]] = None,
        user_id: Optional[str] = None,
        nickname: str = DEFAULT_NICKNAME,
        group: str = DEFAULT_GROUP,
        corp_id: str = "296becfde55172409ef2b81908044747",
        signature: str = "LanBridge Native Online",
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
        self.user_id = user_id if user_id else get_or_create_device_id()
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
        self.qgroups: Dict[str, QGroup] = {}         # qgroup_id -> QGroup
        self.group_shared_files: Dict[str, Dict[str, GroupSharedFile]] = {}  # qgroup_id -> {md5: GroupSharedFile}
        self.local_shared_files: Dict[str, GroupSharedFile] = {}  # md5 -> GroupSharedFile
        self.status: int = 0
        self.signature: str = signature
        self.corp_id: str = corp_id
        self._native_subnets: List[str] = []
        self.native_adapter: Optional[NativeNwtAdapter] = None
        if NativeNwtAdapter.is_installed():
            self.native_adapter = NativeNwtAdapter()
            try:
                self._native_subnets = self.native_adapter.read_network_config().get("subnets", [])
            except Exception:
                pass

        # Event callbacks
        self._on_message_handlers: List[Callable[[ChatMessage], None]] = []
        self._on_group_message_handlers: List[Callable[[ChatMessage], None]] = []
        self._on_contact_online_handlers: List[Callable[[Contact], None]] = []
        self._on_contact_offline_handlers: List[Callable[[Contact], None]] = []
        self._on_group_file_shared_handlers: List[Callable[[GroupSharedFile], None]] = []
        self._on_qgroup_invite_handlers: List[Callable[[QGroup], None]] = []
        self._on_qgroup_member_change_handlers: List[Callable[[QGroup], None]] = []
        self._on_qgroup_dismiss_handlers: List[Callable[[str], None]] = []
        self._on_typing_handlers: List[Callable[[TypingNotice], None]] = []
        self._on_message_recall_handlers: List[Callable[[RecallNotice], None]] = []
        self._on_shake_handlers: List[Callable[[ShakeNotice], None]] = []

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

    def on_qgroup_invite(self, handler: Callable[[QGroup], None]) -> Callable[[QGroup], None]:
        """Register a callback when invited to a discussion group / QGroup."""
        self._on_qgroup_invite_handlers.append(handler)
        return handler

    def on_qgroup_member_change(self, handler: Callable[[QGroup], None]) -> Callable[[QGroup], None]:
        """Register a callback when a QGroup's members or profile change."""
        self._on_qgroup_member_change_handlers.append(handler)
        return handler

    def on_qgroup_dismiss(self, handler: Callable[[str], None]) -> Callable[[str], None]:
        """Register a callback when a QGroup is dismissed or user kicked."""
        self._on_qgroup_dismiss_handlers.append(handler)
        return handler

    def on_typing(self, handler: Callable[[TypingNotice], None]) -> Callable[[TypingNotice], None]:
        """Register a callback when a contact is typing."""
        self._on_typing_handlers.append(handler)
        return handler

    def on_message_recall(self, handler: Callable[[RecallNotice], None]) -> Callable[[RecallNotice], None]:
        """Register a callback when a message is recalled."""
        self._on_message_recall_handlers.append(handler)
        return handler

    def on_shake(self, handler: Callable[[ShakeNotice], None]) -> Callable[[ShakeNotice], None]:
        """Register a callback when receiving a window shake notice."""
        self._on_shake_handlers.append(handler)
        return handler

    def emit_group_file_shared(self, shared_file: GroupSharedFile) -> None:
        for handler in self._on_group_file_shared_handlers:
            try:
                handler(shared_file)
            except Exception as e:
                logger.error("Error in on_group_file_shared handler: %s", e)

    def emit_qgroup_invite(self, qg: QGroup) -> None:
        for handler in self._on_qgroup_invite_handlers:
            try:
                handler(qg)
            except Exception as e:
                logger.error("Error in on_qgroup_invite handler: %s", e)

    def emit_qgroup_member_change(self, qg: QGroup) -> None:
        for handler in self._on_qgroup_member_change_handlers:
            try:
                handler(qg)
            except Exception as e:
                logger.error("Error in on_qgroup_member_change handler: %s", e)

    def emit_qgroup_dismiss(self, qgroup_id: str) -> None:
        for handler in self._on_qgroup_dismiss_handlers:
            try:
                handler(qgroup_id)
            except Exception as e:
                logger.error("Error in on_qgroup_dismiss handler: %s", e)

    def emit_typing(self, tn: TypingNotice) -> None:
        for handler in self._on_typing_handlers:
            try:
                handler(tn)
            except Exception as e:
                logger.error("Error in on_typing handler: %s", e)

    def emit_message_recall(self, rn: RecallNotice) -> None:
        for handler in self._on_message_recall_handlers:
            try:
                handler(rn)
            except Exception as e:
                logger.error("Error in on_message_recall handler: %s", e)

    def emit_shake(self, sn: ShakeNotice) -> None:
        for handler in self._on_shake_handlers:
            try:
                handler(sn)
            except Exception as e:
                logger.error("Error in on_shake handler: %s", e)


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

    def _resolve_nickname_from_groups(self, user_id: str) -> Optional[str]:
        """Look up known nickname for a user ID from loaded QGroups."""
        for qg in self.qgroups.values():
            if user_id in qg.members:
                nick = qg.members[user_id]
                if nick and nick != user_id:
                    return nick
        return None

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

        if contact.nickname in ("Unknown", "", None):
            known_nick = self._resolve_nickname_from_groups(peer_uid)
            if known_nick:
                contact.nickname = known_nick

        if is_new:
            logger.info("Discovered new contact: UID=%s (%s), IP=%s, DynPort=%d", peer_uid, contact.nickname, peer_ip, dyn_port)
            self.emit_contact_online(contact)
            if self._loop and self._loop.is_running() and self._udp_9012_transport:
                t = asyncio.create_task(self._proactive_connect(peer_ip))
                self._bg_tasks.append(t)
        else:
            session = self.get_session(peer_ip)
            if not session.connected and self._loop and self._loop.is_running() and self._udp_9012_transport:
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

        h_val = int.from_bytes(data[:2], "big")
        has_sent_time = bool(h_val & 0x8000)
        cmd_offset = 4 if has_sent_time else 2

        if len(data) < cmd_offset + 4:
            return replies

        if has_sent_time:
            remote_sent_time = int.from_bytes(data[2:4], "big")
            session.last_remote_sent_time = remote_sent_time

        if session.peer_id == 0 and (h_val & 0x0FFF) != 0x0FFF:
            session.peer_id = h_val & 0x0FFF
            session.session_id = (h_val >> 12) & 3

        ack_hdr_val = ((session.session_id & 3) << 12) | (session.peer_id & 0x0FFF)
        opcode = data[cmd_offset]

        # 1. Opcode 0x82 Connect Request from peer
        if opcode == 0x82:
            if len(data) >= cmd_offset + 8:
                out_peer, in_sess, out_sess = struct.unpack(">HBB", data[cmd_offset + 4 : cmd_offset + 8])
                session.peer_id = out_peer
                session.session_id = in_sess
            reply_83 = build_handshake_reply(data)
            replies.append(reply_83)
            return replies

        # 2. Opcode 0x83 Verify Connect / Reply
        if opcode == 0x83:
            if len(data) >= cmd_offset + 8:
                out_peer, in_sess, out_sess = struct.unpack(">HBB", data[cmd_offset + 4 : cmd_offset + 8])
                session.peer_id = out_peer
                session.session_id = in_sess
                session.connected = True

            header_flag = session.get_header_flag()

            # Step 4: Frame 11 (ACK + PING)
            my_time = session.local_sent_time = (session.local_sent_time + 10) & 0xFFFF
            cmd_ack = struct.pack(">BBHHH", 0x01, 0xFF, 0x0001, 0x0001, session.last_remote_sent_time)
            cmd_ping = struct.pack(">BBH", 0x85, 0xFF, 0x0002)
            frame11 = struct.pack(">HH", header_flag, my_time) + cmd_ack + cmd_ping
            replies.append(frame11)

            # Step 6: Frame 17 (304B Node Discovery Announcement with cmd=4)
            my_time = session.local_sent_time = (session.local_sent_time + 10) & 0xFFFF
            frame17 = build_stage4_node_announcement(
                user_id=self.user_id,
                dynamic_port=self.dynamic_port,
                header_flag=header_flag,
                seq=my_time,
                my_seq=1,
            )
            replies.append(frame17)

            # Step 8: Stage 5 Profile Fragments (Opcode 0x88)
            profile_env = build_native_profile(
                nick=self.nickname,
                user_id=self.user_id,
                corp_id=self.corp_id,
                status=self.status,
                sign=self.signature,
                group=self.group,
                tcp_file_port=self.tcp_file_port,
            )
            my_time = session.local_sent_time = (session.local_sent_time + 10) & 0xFFFF
            frags = build_opcode_88_fragments(
                profile_env,
                seq=my_time,
                header_flag=header_flag,
            )
            session.local_sent_time = (session.local_sent_time + len(frags)) & 0xFFFF
            replies.extend(frags)
            return replies

        # 3. Opcode 0x85 Heartbeat Ping
        if opcode == 0x85:
            ack = build_ack_response(data, header_flag=ack_hdr_val)
            if ack:
                replies.append(ack)
            for c in self.contacts.values():
                if c.ip == peer_ip:
                    c.last_seen = time.time()
                    if c.status != 0:
                        c.status = 0
                        self.emit_contact_online(c)
                    break
            return replies

        # 4. Opcode 0x86 Single Frame (Ready, Envelope, Typing)
        if opcode == 0x86:
            ack = build_ack_response(data, header_flag=ack_hdr_val)
            if ack:
                replies.append(ack)

            for c in self.contacts.values():
                if c.ip == peer_ip:
                    c.last_seen = time.time()
                    if c.status != 0:
                        c.status = 0
                        self.emit_contact_online(c)
                    break

            payload_start = cmd_offset + 4
            if len(data) >= payload_start + 2:
                d_len = int.from_bytes(data[payload_start : payload_start + 2], "big")
                enc_data = data[payload_start + 2 : payload_start + 2 + d_len]
                if len(enc_data) < 8 or (len(enc_data) >= 4 and int.from_bytes(enc_data[:4], "big") != d_len):
                    if len(data) >= 16:
                        enc_data = data[16 : 16 + d_len]
                if len(enc_data) >= 8:
                    try:
                        inner_op, plaintext = self.xtea.parse_envelope(enc_data)
                        self._process_inner_envelope(inner_op, plaintext, peer_ip, replies)
                    except Exception as e:
                        logger.debug("Failed to decrypt 0x86 payload: %s", e)
            return replies

        # 5. Opcode 0x88 Multi-fragment Message
        if opcode == 0x88 and len(data) >= cmd_offset + 24:
            ack = build_ack_response(data, header_flag=ack_hdr_val)
            if ack:
                replies.append(ack)

            for c in self.contacts.values():
                if c.ip == peer_ip:
                    c.last_seen = time.time()
                    if c.status != 0:
                        c.status = 0
                        self.emit_contact_online(c)
                    break

            frag_info_offset = cmd_offset + 4
            base_sub_id = int.from_bytes(data[frag_info_offset : frag_info_offset + 2], "big")
            chunk_len = int.from_bytes(data[frag_info_offset + 2 : frag_info_offset + 4], "big")
            tot_frags = int.from_bytes(data[frag_info_offset + 4 : frag_info_offset + 8], "big")
            frag_idx = int.from_bytes(data[frag_info_offset + 8 : frag_info_offset + 12], "big")
            tot_len = int.from_bytes(data[frag_info_offset + 12 : frag_info_offset + 16], "big")
            frag_payload = data[frag_info_offset + 20 : frag_info_offset + 20 + chunk_len]

            if base_sub_id not in session.assemblers:
                session.assemblers[base_sub_id] = type(
                    "Assembler",
                    (),
                    {"parts": {}, "count": tot_frags, "total_len": tot_len},
                )()
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

        # 6. Opcode 0x8a (HandshakeFinal / BandwidthLimit)
        if opcode == 0x8A:
            ack = build_ack_response(data, header_flag=ack_hdr_val)
            if ack:
                replies.append(ack)
            return replies

        # Fallback ACK for any other request
        ack = build_ack_response(data, header_flag=ack_hdr_val)
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
        try:
            xml_str = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            xml_str = plaintext.decode("gbk", errors="replace")
        logger.debug("Received envelope Opcode=0x%04X: %s", opcode, xml_str[:120])

        session = self.get_session(peer_ip)
        header_flag = session.get_header_flag()

        # Opcode 1004 (0x03EC): X_SEND_MSG
        if opcode == 0x03EC or ("<X_SEND_MSG " in xml_str or "<X_SEND_MSG>" in xml_str):
            msg_id = extract_msg_id(xml_str)
            ack_env = build_x_send_msg_ack_envelope(msg_id)
            frags = build_opcode_88_fragments(ack_env, header_flag=header_flag)
            replies.extend(frags)

            sender_uid = "unknown"
            for uid, c in self.contacts.items():
                if c.ip == peer_ip:
                    sender_uid = uid
                    break

            # Check for message recall
            recall_info = extract_recall_info(xml_str)
            if recall_info:
                rn = RecallNotice(
                    sender_id=sender_uid,
                    target_uuid=recall_info["target_uuid"],
                    target_msg_id=recall_info["target_msg_id"],
                    timestamp=time.time(),
                )
                self.emit_message_recall(rn)
                return

            text = extract_chat_message(xml_str)
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
        elif opcode == 0x03E8 or "<X_HANDSHARK" in xml_str:
            ready_env = build_x_ready_envelope(self.user_id)
            replies.extend(build_opcode_88_fragments(ready_env, header_flag=header_flag))

            # Send our profile back if needed so peer has our contact record
            profile_env = build_native_profile(
                nick=self.nickname,
                user_id=self.user_id,
                corp_id=self.corp_id,
                status=self.status,
                sign=self.signature,
                group=self.group,
                tcp_file_port=self.tcp_file_port,
            )
            replies.extend(build_opcode_88_fragments(profile_env, header_flag=header_flag))

            # Parse sender's nickname and mark online
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(xml_str)
                info_elem = root.find("INFO")
                if info_elem is not None:
                    p_name = info_elem.findtext("NAME")
                    for c in self.contacts.values():
                        if c.ip == peer_ip:
                            if p_name:
                                c.nickname = p_name
                            c.status = 0
                            c.last_seen = time.time()
                            self.emit_contact_online(c)
                            break
            except Exception:
                pass

        # Opcode 1018 (0x03FA): X_READY
        elif opcode == Opcode.X_READY or "<X_READY" in xml_str:
            for c in self.contacts.values():
                if c.ip == peer_ip:
                    c.status = 0
                    c.last_seen = time.time()
                    self.emit_contact_online(c)
                    break

        # Opcode 1008 (0x03F0): X_SEND_WRITTING (Typing State)
        elif opcode == Opcode.X_SEND_WRITTING or "<X_SEND_WRITTING" in xml_str:
            parsed = parse_qgroup_xml(xml_str)
            param = parsed.get("param", "1")
            is_typing = (param == "1")
            sender_uid = "unknown"
            for uid, c in self.contacts.items():
                if c.ip == peer_ip:
                    sender_uid = uid
                    break
            tn = TypingNotice(
                sender_id=sender_uid,
                peer_ip=peer_ip,
                is_typing=is_typing,
                timestamp=time.time(),
            )
            self.emit_typing(tn)

        # Opcode 1007 (0x03EF): X_SEND_FLASH_SCREEN (Window Shake)
        elif opcode == Opcode.X_SEND_FLASH_SCREEN or "<X_SEND_FLASH_SCREEN" in xml_str:
            sender_uid = "unknown"
            for uid, c in self.contacts.items():
                if c.ip == peer_ip:
                    sender_uid = uid
                    break
            sn = ShakeNotice(
                sender_id=sender_uid,
                peer_ip=peer_ip,
                timestamp=time.time(),
            )
            logger.info("Received window shake from %s (%s)", peer_ip, sender_uid)
            self.emit_shake(sn)

        # Opcode 1001 (0x03E9): X_CHANGE_STATUS
        elif opcode == Opcode.X_CHANGE_STATUS or "<X_CHANGE_STATUS" in xml_str:
            parsed = parse_qgroup_xml(xml_str)
            st = int(parsed.get("status", "0"))
            for c in self.contacts.values():
                if c.ip == peer_ip:
                    c.status = st
                    break

        # Opcode 1002 (0x03EA): X_CHANGE_SIGN
        elif opcode == Opcode.X_CHANGE_SIGN or "<X_CHANGE_SIGN" in xml_str:
            parsed = parse_qgroup_xml(xml_str)
            sign = parsed.get("sign", "")
            for c in self.contacts.values():
                if c.ip == peer_ip:
                    c.group_name = sign or c.group_name
                    break

        # Opcode 3011 (0x0BC3): X_QGROUP_SEND_MSG (Group Chat Message)
        elif opcode == Opcode.X_QGROUP_SEND_MSG or "<X_QGROUP_SEND_MSG" in xml_str:
            qgroup_id = extract_qgroup_id(xml_str) or "0"
            sender_uid = "unknown"
            for uid, c in self.contacts.items():
                if c.ip == peer_ip:
                    sender_uid = uid
                    break

            # Check for group message recall
            recall_info = extract_recall_info(xml_str)
            if recall_info:
                rn = RecallNotice(
                    sender_id=sender_uid,
                    target_uuid=recall_info["target_uuid"],
                    target_msg_id=recall_info["target_msg_id"],
                    timestamp=time.time(),
                    qgroup_id=qgroup_id,
                )
                self.emit_message_recall(rn)
                return

            msg_id = extract_msg_id(xml_str)
            text = extract_chat_message(xml_str)
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

        # Opcode 3001 (0x0BB9): X_QGROUP_INVITE_RSP
        elif opcode == Opcode.X_QGROUP_INVITE_RSP or "<X_QGROUP_INVITE_RSP" in xml_str:
            info = parse_qgroup_xml(xml_str)
            qgroup_id = info.get("qgroup_id", "")
            user_name = info.get("user_name", "")
            action = int(info.get("action", "1"))
            sender_uid = "unknown"
            for uid, c in self.contacts.items():
                if c.ip == peer_ip:
                    sender_uid = uid
                    break
            if action == 1 and qgroup_id in self.qgroups:
                self.qgroups[qgroup_id].members[sender_uid] = user_name or sender_uid
                self.emit_qgroup_member_change(self.qgroups[qgroup_id])

        # Opcode 3000 (0x0BB8): X_QGROUP_INVITE
        elif opcode == Opcode.X_QGROUP_INVITE or ("<X_QGROUP_INVITE " in xml_str or "<X_QGROUP_INVITE>" in xml_str):
            info = parse_qgroup_xml(xml_str)
            qgroup_id = info.get("qgroup_id", "")
            if qgroup_id:
                sender_uid = "unknown"
                for uid, c in self.contacts.items():
                    if c.ip == peer_ip:
                        sender_uid = uid
                        break
                qg = self.qgroups.setdefault(qgroup_id, QGroup(qgroup_id=qgroup_id))
                qg.name = info.get("qgroup_name", qg.name)
                qg.master_id = info.get("qgroup_master", qg.master_id)
                qg.intro = info.get("qgroup_intr", qg.intro)
                qg.announcement = info.get("qgroup_ann", qg.announcement)
                if "qgroup_info_ver" in info:
                    try:
                        qg.version = int(info["qgroup_info_ver"])
                    except ValueError:
                        pass
                if sender_uid and sender_uid != "unknown":
                    qg.members[sender_uid] = sender_uid
                qg.members[self.user_id] = self.nickname
                self.emit_qgroup_invite(qg)

        # Opcode 3002 (0x0BBA): X_QGROUP_PUSH_INFO
        elif opcode == Opcode.X_QGROUP_PUSH_INFO or "<X_QGROUP_PUSH_INFO" in xml_str:
            info = parse_qgroup_xml(xml_str)
            qgroup_id = info.get("qgroup_id", "")
            if qgroup_id in self.qgroups:
                qg = self.qgroups[qgroup_id]
                if "qgroup_name" in info:
                    qg.name = info["qgroup_name"]
                if "qgroup_ann" in info:
                    qg.announcement = info["qgroup_ann"]
                if "qgroup_intr" in info:
                    qg.intro = info["qgroup_intr"]
                if "qgroup_info_ver" in info:
                    try:
                        qg.version = int(info["qgroup_info_ver"])
                    except ValueError:
                        pass
                self.emit_qgroup_member_change(qg)

        # Opcode 3003 (0x0BBB): X_QGROUP_PUSH_USER
        elif opcode == Opcode.X_QGROUP_PUSH_USER or "<X_QGROUP_PUSH_USER" in xml_str:
            info = parse_qgroup_xml(xml_str)
            qgroup_id = info.get("qgroup_id", "")
            if qgroup_id in self.qgroups:
                self.emit_qgroup_member_change(self.qgroups[qgroup_id])

        # Opcode 3005 (0x0BBD): X_QGROUP_REQ_INFO
        elif opcode == Opcode.X_QGROUP_REQ_INFO or ("<X_QGROUP_REQ_INFO " in xml_str or "<X_QGROUP_REQ_INFO>" in xml_str):
            qgroup_id = extract_qgroup_id(xml_str) or "0"
            rsp_env = build_x_qgroup_req_info_rsp_envelope(qgroup_id=qgroup_id, ret=0)
            replies.extend(build_opcode_88_fragments(rsp_env))

        # Opcode 3006 (0x0BBE): X_QGROUP_REQ_USER
        elif opcode == Opcode.X_QGROUP_REQ_USER or ("<X_QGROUP_REQ_USER " in xml_str or "<X_QGROUP_REQ_USER>" in xml_str):
            info = parse_qgroup_xml(xml_str)
            qgroup_id = info.get("qgroup_id", "")
            rsp_env = build_x_qgroup_req_user_rsp_envelope(qgroup_id=qgroup_id, name=self.nickname, ret=0)
            replies.extend(build_opcode_88_fragments(rsp_env))

        # Opcode 3008 (0x0BC0): X_QGROUP_DISMISS
        elif opcode == Opcode.X_QGROUP_DISMISS or "<X_QGROUP_DISMISS" in xml_str:
            info = parse_qgroup_xml(xml_str)
            qgroup_id = info.get("qgroup_id", "")
            if qgroup_id:
                self.qgroups.pop(qgroup_id, None)
                self.emit_qgroup_dismiss(qgroup_id)

        # Opcode 3009 (0x0BC1): X_QGROUP_EXIT
        elif opcode == Opcode.X_QGROUP_EXIT or "<X_QGROUP_EXIT" in xml_str:
            info = parse_qgroup_xml(xml_str)
            qgroup_id = info.get("qgroup_id", "")
            sender_uid = "unknown"
            for uid, c in self.contacts.items():
                if c.ip == peer_ip:
                    sender_uid = uid
                    break
            if qgroup_id in self.qgroups:
                self.qgroups[qgroup_id].members.pop(sender_uid, None)
                self.emit_qgroup_member_change(self.qgroups[qgroup_id])

        # Opcode 3010 (0x0BC2): X_QGROUP_KICK
        elif opcode == Opcode.X_QGROUP_KICK or "<X_QGROUP_KICK" in xml_str:
            info = parse_qgroup_xml(xml_str)
            qgroup_id = info.get("qgroup_id", "")
            if qgroup_id in self.qgroups:
                self.qgroups.pop(qgroup_id, None)
                self.emit_qgroup_dismiss(qgroup_id)

        # Opcode 3012 (0x0BC4): X_QGROUP_OTHER_INVITE
        elif opcode == Opcode.X_QGROUP_OTHER_INVITE or "<X_QGROUP_OTHER_INVITE" in xml_str:
            info = parse_qgroup_xml(xml_str)
            qgroup_id = info.get("qgroup_id", "")
            user_id = info.get("id", "")
            if qgroup_id in self.qgroups and user_id:
                self.qgroups[qgroup_id].members[user_id] = user_id
                self.emit_qgroup_member_change(self.qgroups[qgroup_id])

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

        try:
            sock_9011 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_9011.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_9011.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock_9011.bind((self.bind_ip, self.discovery_port))
            t1, _ = await self._loop.create_datagram_endpoint(lambda: DiscoveryProtocol(self), sock=sock_9011)
            self._udp_9011_transport = t1
        except Exception as e:
            logger.warning("Could not bind UDP discovery port %d: %s", self.discovery_port, e)

        try:
            sock_9012 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_9012.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_9012.bind((self.bind_ip, self.main_port))
            t2, _ = await self._loop.create_datagram_endpoint(lambda: MainProtocol(self), sock=sock_9012)
            self._udp_9012_transport = t2
        except Exception as e:
            logger.warning("Could not bind UDP main port %d: %s", self.main_port, e)

        # 3. Start TCP Mini-File / FolderTran Server
        try:
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp_client,
                self.bind_ip,
                self.tcp_file_port,
            )
        except Exception as e:
            logger.warning("Could not bind TCP file port %d: %s", self.tcp_file_port, e)

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

        # 6. Periodic heartbeat ping and discovery presence loop
        hb_task = asyncio.create_task(self._heartbeat_loop())
        self._bg_tasks.append(hb_task)


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

                    if req_md5 and req_md5 not in self.pending_images and self.native_adapter:
                        cached = self.native_adapter.get_picture_by_md5(req_md5)
                        if cached:
                            self.pending_images[req_md5] = cached

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
        """Send UDP 9011 presence broadcasts and UDP 2425 IPMSG broadcasts to all destinations."""
        if self._udp_9011_transport:
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

        # UDP 2425 IPMSG presence broadcast
        try:
            ipmsg_pkt = build_ipmsg_presence(
                nick=self.nickname,
                group=self.group,
                user_id=self.user_id,
                use_shiyeline_prefix=True,
            )
            sock2425 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock2425.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for b_ip in self.broadcast_ips:
                try:
                    sock2425.sendto(ipmsg_pkt, (b_ip, 2425))
                except Exception:
                    pass
            sock2425.close()
        except Exception as e:
            logger.debug("Failed sending IPMSG broadcast: %s", e)

    async def _proactive_connect(self, peer_ip: str) -> None:
        """Initiate proactive ENet connection (Opcode 0x82) and unicast discovery to peer."""
        session = self.get_session(peer_ip)
        connect_pkt = session.build_connect(b"\x01\x02\x03\x04")
        if self._udp_9012_transport:
            try:
                self._udp_9012_transport.sendto(connect_pkt, (peer_ip, self.main_port))
                logger.debug("Sent proactive ENet connect to %s:%d", peer_ip, self.main_port)
            except Exception as e:
                logger.debug("Failed sending proactive connect to %s: %s", peer_ip, e)

        # Unicast UDP 9011 discovery packet (cmd=1) directly to peer_ip:9011
        if self._udp_9011_transport:
            disc_pkt = build_nwt_discovery_packet(
                cmd=1,
                user_id=self.user_id,
                broadcast_ip=peer_ip,
                dynamic_port=self.dynamic_port,
                guid=self.guid,
            )
            try:
                self._udp_9011_transport.sendto(disc_pkt, (peer_ip, self.discovery_port))
            except Exception:
                pass

        # Unicast UDP 2425 IPMSG packet directly to peer_ip:2425
        try:
            ipmsg_pkt = build_ipmsg_presence(
                nick=self.nickname,
                group=self.group,
                user_id=self.user_id,
                use_shiyeline_prefix=True,
            )
            sock2425 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock2425.sendto(ipmsg_pkt, (peer_ip, 2425))
            sock2425.close()
        except Exception:
            pass

    async def _heartbeat_loop(self) -> None:
        """Periodically send ENet Ping / Heartbeat and refresh discovery presence."""
        step = 0
        while self._running:
            try:
                await asyncio.sleep(10.0)
                if not self._running:
                    break
                step += 1

                # 1. Send ENet Opcode 0x85 Ping to all active peers
                if self._udp_9012_transport:
                    for peer_ip, session in list(self.sessions.items()):
                        if session.connected or session.peer_id > 0:
                            session.ping_counter = getattr(session, "ping_counter", 1) + 1
                            ping_pkt = session.build_ping(session.ping_counter)
                            try:
                                self._udp_9012_transport.sendto(ping_pkt, (peer_ip, self.main_port))
                            except Exception as e:
                                logger.debug("Failed sending ping to %s: %s", peer_ip, e)

                # 2. Check for offline contacts (last_seen > 90 seconds)
                now = time.time()
                for contact in list(self.contacts.values()):
                    if contact.status == 0 and (now - contact.last_seen > 90.0):
                        contact.status = 1
                        self.emit_contact_offline(contact)
                        logger.info("Contact marked offline (timeout): UID=%s (%s)", contact.user_id, contact.nickname)

                # 3. Refresh presence broadcast every 30 seconds (every 3 steps)
                if step % 3 == 0:
                    await self.broadcast_presence()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Error in heartbeat loop: %s", e)

    async def scan_subnets(self, targets: Optional[List[str]] = None) -> List[Contact]:
        """Actively scan local/cross subnets to discover online peers and update contacts directory."""
        if targets is None:
            targets = []
            interfaces = get_active_network_interfaces()
            for iface in interfaces:
                try:
                    net24 = ipaddress.ip_network(f"{iface.ip}/24", strict=False)
                    targets.append(str(net24))
                except Exception as e:
                    logger.debug("Failed computing /24 for interface %s: %s", iface.name, e)

            for s in self._native_subnets:
                if s not in targets:
                    targets.append(s)

        if not targets:
            return []

        logger.info("Initiating active subnet scan across: %s", targets)
        scanner = SubnetScanner(
            local_user_id=self.user_id,
            discovery_port=self.discovery_port,
            listen_timeout=1.2,
            rate_limit_delay=0.002,
        )
        discovered = await scanner.scan(targets, bind_ip="0.0.0.0")

        for contact in discovered:
            if contact.user_id == self.user_id:
                continue

            # Populate nickname from known discussion groups if unknown
            if contact.nickname in ("Unknown", "", None):
                known_nick = self._resolve_nickname_from_groups(contact.user_id)
                if known_nick:
                    contact.nickname = known_nick

            existing = self.contacts.get(contact.user_id)
            if existing:
                existing.ip = contact.ip
                existing.port = contact.port
                existing.dynamic_port = contact.dynamic_port
                existing.status = 0
                existing.last_seen = time.time()
                if existing.nickname in ("Unknown", "", None) and contact.nickname not in ("Unknown", "", None):
                    existing.nickname = contact.nickname
                contact = existing
            else:
                self.contacts[contact.user_id] = contact
                self.emit_contact_online(contact)

            logger.info("Subnet scan peer online: UID=%s (%s), IP=%s", contact.user_id, contact.nickname, contact.ip)
            if self._loop and self._loop.is_running() and self._udp_9012_transport:
                asyncio.create_task(self._proactive_connect(contact.ip))

        return discovered

    async def _auto_subnet_scan_task(self) -> None:
        """Asynchronously scan local subnets on startup to discover Nwt instances."""
        try:
            await asyncio.sleep(0.1)
            await self.broadcast_presence()
            await self.scan_subnets()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("Error during auto subnet scan: %s", e)

    async def send_message(self, target_ip: str, text: str) -> None:
        """Send a text message to a specific IP endpoint."""
        session = self.get_session(target_ip)
        header_flag = session.get_header_flag()
        env = build_x_send_msg_envelope(text)
        frags = build_opcode_88_fragments(env, header_flag=header_flag)
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
            session = self.get_session(dest)
            frags = build_opcode_88_fragments(env, header_flag=session.get_header_flag())
            for frag in frags:
                try:
                    self._udp_9012_transport.sendto(frag, (dest, self.main_port))
                except Exception as e:
                    logger.debug("Failed sending group msg frag to %s: %s", dest, e)
        logger.info("Sent group msg to %s (len=%d) -> %d destinations", qgroup_id, len(text), len(destinations))

    async def sync_group_info(self, qgroup_id: str, target_ip: str) -> None:
        """Request QGroup metadata and member directory via Opcode 3005."""
        session = self.get_session(target_ip)
        env = build_x_qgroup_req_info_envelope(qgroup_id=qgroup_id)
        frags = build_opcode_88_fragments(env, header_flag=session.get_header_flag())
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
        if self.native_adapter:
            try:
                self.native_adapter.save_picture(img_md5, image_data)
            except Exception as e:
                logger.debug("Failed saving image to native cache: %s", e)
        token = random.randint(10000, 30000)
        self.pending_tokens[token] = img_md5

        session = self.get_session(target_ip)
        env = build_x_send_image_envelope(img_md5, token=token, caption=caption)
        frags = build_opcode_88_fragments(env, header_flag=session.get_header_flag())
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (target_ip, self.main_port))
            logger.info("Sent image notice to %s: MD5=%s, Token=%d", target_ip, img_md5, token)
        return img_md5

    async def shake_window(self, target_ip: str) -> None:
        """Send a window shake notice to target IP."""
        session = self.get_session(target_ip)
        env = build_x_flash_screen_envelope()
        frags = build_opcode_88_fragments(env, header_flag=session.get_header_flag())
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (target_ip, self.main_port))
            logger.info("Sent window shake to %s", target_ip)

    def create_qgroup(
        self,
        name: str,
        intro: str = "",
        announcement: str = "",
        member_ids: Optional[List[str]] = None,
    ) -> QGroup:
        """Create a new local QGroup discussion group."""
        qgroup_id = uuid.uuid4().hex
        qg = QGroup(
            qgroup_id=qgroup_id,
            name=name,
            master_id=self.user_id,
            intro=intro,
            announcement=announcement,
            members={self.user_id: self.nickname},
            created_time=time.time(),
        )
        self.qgroups[qgroup_id] = qg
        return qg

    async def invite_to_qgroup(
        self,
        qgroup_id: str,
        member_ids: List[str],
    ) -> None:
        """Send X_QGROUP_INVITE to specified member IDs."""
        qg = self.qgroups.get(qgroup_id)
        if not qg:
            raise KeyError(f"Group {qgroup_id} not found")

        env = build_x_qgroup_invite_envelope(
            qgroup_id=qgroup_id,
            name=qg.name,
            master_id=qg.master_id or self.user_id,
            intro=qg.intro,
            announcement=qg.announcement,
            version=qg.version,
        )
        frags = build_opcode_88_fragments(env)

        if not self._udp_9012_transport:
            return

        for mid in member_ids:
            contact = self.contacts.get(mid)
            if contact and contact.ip:
                for frag in frags:
                    try:
                        self._udp_9012_transport.sendto(frag, (contact.ip, self.main_port))
                    except Exception as e:
                        logger.debug("Failed sending group invite to %s: %s", contact.ip, e)

    async def respond_qgroup_invite(
        self,
        qgroup_id: str,
        target_ip: str,
        accept: bool = True,
    ) -> None:
        """Send X_QGROUP_INVITE_RSP accepting or rejecting an invitation."""
        env = build_x_qgroup_invite_rsp_envelope(
            qgroup_id=qgroup_id,
            user_name=self.nickname,
            action=1 if accept else 0,
        )
        frags = build_opcode_88_fragments(env)
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (target_ip, self.main_port))

    async def update_qgroup_info(
        self,
        qgroup_id: str,
        name: Optional[str] = None,
        announcement: Optional[str] = None,
        intro: Optional[str] = None,
    ) -> None:
        """Update group metadata and broadcast X_QGROUP_PUSH_INFO to members."""
        qg = self.qgroups.get(qgroup_id)
        if not qg:
            raise KeyError(f"Group {qgroup_id} not found")
        if name is not None:
            qg.name = name
        if announcement is not None:
            qg.announcement = announcement
        if intro is not None:
            qg.intro = intro
        qg.version += 1

        env = build_x_qgroup_push_info_envelope(
            qgroup_id=qgroup_id,
            name=qg.name,
            master_id=qg.master_id,
            intro=qg.intro,
            announcement=qg.announcement,
            version=qg.version,
        )
        frags = build_opcode_88_fragments(env)
        if not self._udp_9012_transport:
            return

        destinations = set()
        for mid in qg.members:
            if mid in self.contacts and self.contacts[mid].ip:
                destinations.add(self.contacts[mid].ip)
        for b_ip in self.broadcast_ips:
            destinations.add(b_ip)

        for dest in destinations:
            for frag in frags:
                try:
                    self._udp_9012_transport.sendto(frag, (dest, self.main_port))
                except Exception as e:
                    logger.debug("Failed sending qgroup info push to %s: %s", dest, e)

    async def kick_qgroup_member(
        self,
        qgroup_id: str,
        member_id: str,
    ) -> None:
        """Kick a member from a group via X_QGROUP_KICK."""
        qg = self.qgroups.get(qgroup_id)
        if not qg:
            raise KeyError(f"Group {qgroup_id} not found")
        qg.members.pop(member_id, None)

        env = build_x_qgroup_kick_envelope(qgroup_id=qgroup_id)
        frags = build_opcode_88_fragments(env)
        contact = self.contacts.get(member_id)
        if contact and contact.ip and self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (contact.ip, self.main_port))

    async def exit_qgroup(self, qgroup_id: str) -> None:
        """Leave a group via X_QGROUP_EXIT."""
        qg = self.qgroups.pop(qgroup_id, None)
        env = build_x_qgroup_exit_envelope(qgroup_id=qgroup_id)
        frags = build_opcode_88_fragments(env)
        if not self._udp_9012_transport:
            return
        destinations = set()
        if qg:
            for mid in qg.members:
                if mid in self.contacts and self.contacts[mid].ip:
                    destinations.add(self.contacts[mid].ip)
        for b_ip in self.broadcast_ips:
            destinations.add(b_ip)
        for dest in destinations:
            for frag in frags:
                try:
                    self._udp_9012_transport.sendto(frag, (dest, self.main_port))
                except Exception:
                    pass

    async def dismiss_qgroup(self, qgroup_id: str) -> None:
        """Dismiss/disband a group via X_QGROUP_DISMISS."""
        qg = self.qgroups.pop(qgroup_id, None)
        env = build_x_qgroup_dismiss_envelope(qgroup_id=qgroup_id)
        frags = build_opcode_88_fragments(env)
        if not self._udp_9012_transport:
            return
        destinations = set()
        if qg:
            for mid in qg.members:
                if mid in self.contacts and self.contacts[mid].ip:
                    destinations.add(self.contacts[mid].ip)
        for b_ip in self.broadcast_ips:
            destinations.add(b_ip)
        for dest in destinations:
            for frag in frags:
                try:
                    self._udp_9012_transport.sendto(frag, (dest, self.main_port))
                except Exception:
                    pass

    async def send_typing_state(self, peer_ip: str, typing: bool = True) -> None:
        """Send typing status notice (X_SEND_WRITTING) to peer IP."""
        session = self.get_session(peer_ip)
        env = build_x_send_writting_envelope(typing=typing)
        frags = build_opcode_88_fragments(env, header_flag=session.get_header_flag())
        if self._udp_9012_transport:
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (peer_ip, self.main_port))

    async def recall_message(
        self,
        target_ip: str,
        target_msg_id: int,
        target_uuid: str = "",
        qgroup_id: Optional[str] = None,
    ) -> None:
        """Send message recall notice to peer IP or group."""
        env = build_x_recall_msg_envelope(
            target_msg_id=target_msg_id,
            target_uuid=target_uuid,
            qgroup_id=qgroup_id,
        )
        if not self._udp_9012_transport:
            return
        if qgroup_id and not target_ip:
            destinations = set()
            for c in self.contacts.values():
                if c.ip:
                    destinations.add(c.ip)
            for b_ip in self.broadcast_ips:
                destinations.add(b_ip)
            for dest in destinations:
                session = self.get_session(dest)
                frags = build_opcode_88_fragments(env, header_flag=session.get_header_flag())
                for frag in frags:
                    try:
                        self._udp_9012_transport.sendto(frag, (dest, self.main_port))
                    except Exception:
                        pass
        else:
            session = self.get_session(target_ip)
            frags = build_opcode_88_fragments(env, header_flag=session.get_header_flag())
            for frag in frags:
                self._udp_9012_transport.sendto(frag, (target_ip, self.main_port))

    async def set_status(self, status: int) -> None:
        """Change online status and broadcast to contacts."""
        self.status = status
        env = build_x_change_status_envelope(status=status)
        frags = build_opcode_88_fragments(env)
        if not self._udp_9012_transport:
            return
        destinations = set(c.ip for c in self.contacts.values() if c.ip)
        for b_ip in self.broadcast_ips:
            destinations.add(b_ip)
        for dest in destinations:
            for frag in frags:
                try:
                    self._udp_9012_transport.sendto(frag, (dest, self.main_port))
                except Exception:
                    pass

    async def set_signature(self, signature: str) -> None:
        """Change personal signature and broadcast to contacts."""
        self.signature = signature
        env = build_x_change_sign_envelope(signature=signature)
        frags = build_opcode_88_fragments(env)
        if not self._udp_9012_transport:
            return
        destinations = set(c.ip for c in self.contacts.values() if c.ip)
        for b_ip in self.broadcast_ips:
            destinations.add(b_ip)
        for dest in destinations:
            for frag in frags:
                try:
                    self._udp_9012_transport.sendto(frag, (dest, self.main_port))
                except Exception:
                    pass


    def import_from_native(
        self,
        nwt_dir: Optional[str] = None,
        sync_subnets: bool = True,
        sync_groups: bool = True,
        sync_shares: bool = True,
        apply_identity: bool = False,
    ) -> dict:
        """Import configuration, groups, and shares from native Nwt installation.

        Args:
            nwt_dir: Optional custom path to Nwt data directory.
            sync_subnets: Whether to add native configured subnets to scanner targets.
            sync_groups: Whether to import native QGroup discussion groups and members.
            sync_shares: Whether to import native shared files.
            apply_identity: Whether to adopt native account UID, nickname, and signature.

        Returns:
            A summary dictionary detailing the imported assets.
        """
        adapter = NativeNwtAdapter(nwt_dir) if nwt_dir else (self.native_adapter or NativeNwtAdapter())
        self.native_adapter = adapter

        summary = {
            "installed": adapter.is_installed(adapter.nwt_dir),
            "nwt_dir": adapter.nwt_dir,
            "account": None,
            "user_name": None,
            "signature": None,
            "subnets": [],
            "groups_imported": 0,
            "shares_imported": 0,
        }

        if not summary["installed"]:
            return summary

        # 1. Identity & preferences
        account_uid = adapter.read_account()
        user_opts = adapter.read_user_options()
        summary["account"] = account_uid
        summary["user_name"] = user_opts.get("user_name")
        summary["signature"] = user_opts.get("signature")

        if user_opts.get("corp_id"):
            self.corp_id = user_opts["corp_id"]

        if apply_identity:
            if account_uid:
                self.user_id = account_uid
            if user_opts.get("user_name"):
                self.nickname = user_opts["user_name"]
            if user_opts.get("signature"):
                self.signature = user_opts["signature"]

        # 2. Subnets
        if sync_subnets:
            net_cfg = adapter.read_network_config()
            new_subnets = net_cfg.get("subnets", [])
            summary["subnets"] = new_subnets
            for s in new_subnets:
                if s not in self._native_subnets:
                    self._native_subnets.append(s)

        # 3. Discussion Groups
        if sync_groups:
            qgs = adapter.read_qgroups()
            summary["groups_imported"] = len(qgs)
            for gid, qg in qgs.items():
                if gid not in self.qgroups:
                    self.qgroups[gid] = qg
                else:
                    self.qgroups[gid].members.update(qg.members)
            for contact in self.contacts.values():
                if contact.nickname in ("Unknown", "", None):
                    nick = self._resolve_nickname_from_groups(contact.user_id)
                    if nick:
                        contact.nickname = nick

        # 4. Shares
        if sync_shares:
            shares = adapter.read_shared_files()
            summary["shares_imported"] = len(shares)
            for sid, gsf in shares.items():
                self.local_shared_files[sid] = gsf
                self.group_shared_files.setdefault(gsf.qgroup_id, {})[sid] = gsf

        logger.info(
            "Imported native Nwt data: %d groups, %d shares, %d subnets (identity=%s)",
            summary["groups_imported"],
            summary["shares_imported"],
            len(summary["subnets"]),
            "applied" if apply_identity else "preserved",
        )
        return summary


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
