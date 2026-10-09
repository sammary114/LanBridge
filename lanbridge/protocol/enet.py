#!/usr/bin/env python3
"""LanBridge ENet Protocol Engine (enet.py).

Implements reliable UDP framing, sequence control, fragmentation, and session handling
based on ENet protocol reverse-engineered from ShiYeLine.exe 3.4.3055.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


class ENetCommandType:
    NONE = 0
    ACKNOWLEDGE = 1
    CONNECT = 2
    VERIFY_CONNECT = 3
    DISCONNECT = 4
    PING = 5
    SEND_RELIABLE = 6
    SEND_UNRELIABLE = 7
    SEND_FRAGMENT = 8
    SEND_UNSEQUENCED = 9
    BANDWIDTH_LIMIT = 10
    THROTTLE_CONFIGURE = 11


FLAG_ACKNOWLEDGE = 0x80
FLAG_SENT_TIME = 0x8000
FLAG_COMPRESSED = 0x4000


@dataclass
class ENetFragmentAssembler:
    """Reassembles fragmented messages across multi-packet sequences."""

    count: int
    total_length: int
    parts: Dict[int, bytes] = field(default_factory=dict)

    def add_fragment(self, num: int, data: bytes) -> bool:
        self.parts[num] = data
        return len(self.parts) == self.count

    def get_payload(self) -> bytes:
        return b"".join(self.parts[i] for i in range(self.count))


class ENetProtocolSession:
    """Manages an active reliable UDP connection with an Nwt peer."""

    def __init__(self, outgoing_peer_id: int = 0) -> None:
        self.outgoing_peer_id = outgoing_peer_id
        self.peer_id: int = 0
        self.session_id: int = 0
        self.connected: bool = False
        self.local_sent_time: int = 0x1000
        self.last_remote_sent_time: int = 0
        self.outgoing_seq: int = 1
        self.assemblers: Dict[int, ENetFragmentAssembler] = {}

    def get_header(self, has_sent_time: bool = True) -> bytes:
        self.local_sent_time = (self.local_sent_time + 10) & 0xFFFF
        if has_sent_time:
            hdr_val = FLAG_SENT_TIME | ((self.session_id & 3) << 12) | (self.peer_id & 0x0FFF)
            return struct.pack(">HH", hdr_val, self.local_sent_time)
        else:
            hdr_val = ((self.session_id & 3) << 12) | (self.peer_id & 0x0FFF)
            return struct.pack(">H", hdr_val)

    def build_connect(self, connect_id: bytes) -> bytes:
        self.local_sent_time = (self.local_sent_time + 10) & 0xFFFF
        hdr = struct.pack(">HH", 0x8FFF, self.local_sent_time)
        body = (
            b"\x82\xff\x00\x01\x00\x00\x00\x00\x00\x00\x05\x78\x00\x01\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x88\x00\x00\x00\x02\x00\x00\x00\x02"
            + connect_id[:4]
            + b"\x00\x00\x00\x00"
        )
        return hdr + body

    def build_ack_and_ping(self, verify_seq: int, verify_sent_time: int) -> bytes:
        hdr = self.get_header(has_sent_time=True)
        ack = struct.pack(">BBHHH", ENetCommandType.ACKNOWLEDGE, 0xFF, 1, verify_seq, verify_sent_time)
        ping = struct.pack(">BBH", ENetCommandType.PING | FLAG_ACKNOWLEDGE, 0xFF, 2)
        return hdr + ack + ping

    def build_reliable(self, channel: int, payload: bytes) -> bytes:
        hdr = self.get_header(has_sent_time=True)
        cmd = struct.pack(">BBHH", ENetCommandType.SEND_RELIABLE | FLAG_ACKNOWLEDGE, channel, self.outgoing_seq, len(payload))
        self.outgoing_seq = (self.outgoing_seq + 1) & 0xFFFF
        return hdr + cmd + payload

    def build_fragments(self, channel: int, payload: bytes, max_chunk: int = 1372) -> List[bytes]:
        """Split a large payload into standard ENet SendFragment packets."""
        total_len = len(payload)
        chunks = [payload[i : i + max_chunk] for i in range(0, total_len, max_chunk)]
        frag_count = len(chunks)
        start_seq = self.outgoing_seq
        packets = []
        hdr = self.get_header(has_sent_time=True)

        for i, chunk in enumerate(chunks):
            offset = i * max_chunk
            cmd = struct.pack(">BBH", ENetCommandType.SEND_FRAGMENT | FLAG_ACKNOWLEDGE, channel, self.outgoing_seq)
            frag_hdr = struct.pack(">HHIIII", start_seq, len(chunk), frag_count, i, total_len, offset)
            packets.append(hdr + cmd + frag_hdr + chunk)
            self.outgoing_seq = (self.outgoing_seq + 1) & 0xFFFF

        return packets

    def build_ack(self, channel: int, seq: int) -> bytes:
        hdr = self.get_header(has_sent_time=False)
        ack = struct.pack(">BBHHH", ENetCommandType.ACKNOWLEDGE, channel, seq, seq, self.last_remote_sent_time)
        return hdr + ack

    def build_ping(self, counter: int = 1) -> bytes:
        """Build 8-byte Opcode 0x85 Heartbeat Ping frame."""
        hdr = self.get_header(has_sent_time=True)
        cmd = struct.pack(">BBH", ENetCommandType.PING | FLAG_ACKNOWLEDGE, 0xFF, counter)
        return hdr + cmd

    def get_header_flag(self) -> int:
        """Return the 16-bit ENet header flag combining session_id and peer_id."""
        return FLAG_SENT_TIME | ((self.session_id & 3) << 12) | (self.peer_id & 0x0FFF)
