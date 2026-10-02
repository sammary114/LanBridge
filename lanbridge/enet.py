#!/usr/bin/env python3
"""LanBridge ENet Protocol Engine (enet.py).

Implements reliable UDP framing, sequence control, fragmentation, and session handling
based on ENet protocol reverse-engineered from ShiYeLine.exe 3.4.3055.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
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

        for i, chunk in enumerate(chunks):
            offset = i * max_chunk
            hdr = self.get_header(has_sent_time=True)
            cmd = struct.pack(">BBH", ENetCommandType.SEND_FRAGMENT | FLAG_ACKNOWLEDGE, channel, self.outgoing_seq)
            frag_hdr = struct.pack(">HHIIII", start_seq, len(chunk), frag_count, i, total_len, offset)
            packets.append(hdr + cmd + frag_hdr + chunk)
            self.outgoing_seq = (self.outgoing_seq + 1) & 0xFFFF

        return packets

    def build_ack(self, channel: int, seq: int) -> bytes:
        hdr = self.get_header(has_sent_time=False)
        ack = struct.pack(">BBHHH", ENetCommandType.ACKNOWLEDGE, channel, seq, seq, self.last_remote_sent_time)
        return hdr + ack

    def parse_packet(self, data: bytes) -> List[Tuple[int, int, int, bytes]]:
        """Parse raw incoming UDP packet into list of (cmd_type, channel, seq, payload)."""
        if len(data) < 2:
            return []

        hdr_val = struct.unpack_from(">H", data, 0)[0]
        has_sent_time = bool(hdr_val & FLAG_SENT_TIME)
        offset = 4 if has_sent_time else 2

        if has_sent_time and len(data) >= 4:
            self.last_remote_sent_time = struct.unpack_from(">H", data, 2)[0]

        commands = []
        while offset < len(data):
            if offset + 4 > len(data):
                break
            cmd_byte, channel, seq = struct.unpack_from(">BBH", data, offset)
            cmd_type = cmd_byte & 0x0F
            cmd_hdr_len = 4

            if cmd_type == ENetCommandType.ACKNOWLEDGE:
                if offset + cmd_hdr_len + 4 <= len(data):
                    ack_seq, sent_time = struct.unpack_from(">HH", data, offset + cmd_hdr_len)
                    commands.append((cmd_type, channel, seq, struct.pack(">HH", ack_seq, sent_time)))
                    offset += cmd_hdr_len + 4
                else:
                    break

            elif cmd_type == ENetCommandType.CONNECT:
                # Connect payload is 44 bytes
                payload = data[offset + cmd_hdr_len : offset + cmd_hdr_len + 44]
                commands.append((cmd_type, channel, seq, payload))
                offset += cmd_hdr_len + 44

            elif cmd_type == ENetCommandType.VERIFY_CONNECT:
                # VerifyConnect payload is 40 bytes
                payload = data[offset + cmd_hdr_len : offset + cmd_hdr_len + 40]
                commands.append((cmd_type, channel, seq, payload))
                offset += cmd_hdr_len + 40

            elif cmd_type == ENetCommandType.SEND_RELIABLE:
                if offset + cmd_hdr_len + 2 <= len(data):
                    data_len = struct.unpack_from(">H", data, offset + cmd_hdr_len)[0]
                    payload = data[offset + cmd_hdr_len + 2 : offset + cmd_hdr_len + 2 + data_len]
                    commands.append((cmd_type, channel, seq, payload))
                    offset += cmd_hdr_len + 2 + data_len
                else:
                    break

            elif cmd_type == ENetCommandType.SEND_FRAGMENT:
                if offset + cmd_hdr_len + 20 <= len(data):
                    start_seq, data_len, count, num, total_len, frag_offset = struct.unpack_from(
                        ">HHIIII", data, offset + cmd_hdr_len
                    )
                    frag_data = data[offset + cmd_hdr_len + 20 : offset + cmd_hdr_len + 20 + data_len]
                    # Assemble fragment
                    if start_seq not in self.assemblers:
                        self.assemblers[start_seq] = ENetFragmentAssembler(count=count, total_length=total_len)
                    assembler = self.assemblers[start_seq]
                    is_complete = assembler.add_fragment(num, frag_data)
                    if is_complete:
                        full_payload = assembler.get_payload()
                        del self.assemblers[start_seq]
                        commands.append((cmd_type, channel, start_seq, full_payload))
                    offset += cmd_hdr_len + 20 + data_len
                else:
                    break

            elif cmd_type == ENetCommandType.PING:
                commands.append((cmd_type, channel, seq, b""))
                offset += cmd_hdr_len

            else:
                # Unhandled command
                break

        return commands
