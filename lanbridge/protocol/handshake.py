#!/usr/bin/env python3
"""LanBridge Handshake & Framing Engine (handshake.py).

Implements authentic raw packet builders for the 7-stage handshake on UDP 9012 / dynamic port:
- Opcode 0x82 / 0x83 (Stage 2/3 Handshake Reply)
- Opcode 0x01 (Stage 4 Sync)
- Opcode 0x84 (Stage 4 Auxiliary Sync)
- Opcode 0x8A (Stage 7 Finalize)
- Opcode 0x88 (Multi-fragment message framing)
- Opcode 0x85 / 0x86 / Multi-ACK builders
"""

from __future__ import annotations

import struct
from typing import List, Optional


def build_handshake_reply(
    req_packet: bytes,
    my_seq: int = 0xf7c6,
    header_flag: Optional[int] = None,
) -> bytes:
    """Build 48-byte Opcode 0x83 HandshakeReply responding to Opcode 0x82."""
    if len(req_packet) >= 48:
        payload_echo = req_packet[14:48]
    else:
        payload_echo = b"\x00" * 34

    if header_flag is None:
        req_h_val = int.from_bytes(req_packet[:2], "big")
        cmd_offset = 4 if (req_h_val & 0x8000) else 2
        if len(req_packet) >= cmd_offset + 8:
            out_peer, in_sess, out_sess = struct.unpack(">HBB", req_packet[cmd_offset + 4 : cmd_offset + 8])
            sess = out_sess if out_sess > 0 else (in_sess if in_sess > 0 else 1)
            header_flag = 0x8000 | ((sess & 3) << 12) | (out_peer & 0x0FFF)
        else:
            header_flag = 0x9000

    return (
        header_flag.to_bytes(2, "big")
        + my_seq.to_bytes(2, "big")
        + b"\x83\xff\x00\x01\x00\x00\x01\x01\x00\x00"
        + payload_echo
    )


def build_opcode_01(echo_seq: bytes, seq: int = 0xf7c6, header_flag: int = 0x9000) -> bytes:
    """Build 16-byte Opcode 0x01 channel synchronization packet echoing remote sequence."""
    return (
        header_flag.to_bytes(2, "big")
        + seq.to_bytes(2, "big")
        + b"\x01\xff\x00\x01\x00\x01"
        + echo_seq[:2]
        + b"\x85\xff\x00\x02"
    )


def build_stage4_node_announcement(
    user_id: str,
    dynamic_port: int = 53782,
    header_flag: int = 0x9000,
    seq: int = 0xf82b,
    my_seq: int = 1,
) -> bytes:
    """Build Frame 17 (Opcode 0x86 SEND_RELIABLE carrying 304B Node Discovery Announcement with cmd=4)."""
    from lanbridge.protocol.discovery import build_nwt_discovery_packet
    hdr = struct.pack(">HH", header_flag, seq)
    cmd = struct.pack(">BBHH", 0x86, 0x00, my_seq, 304)
    disc = build_nwt_discovery_packet(cmd=4, user_id=user_id, dynamic_port=dynamic_port)
    return hdr + cmd + disc


def build_x_ready_frame(
    user_id: str,
    header_flag: int = 0x9000,
    seq: int = 0xf830,
    my_seq: int = 4,
) -> bytes:
    """Build Opcode 0x86 SEND_RELIABLE carrying X_READY envelope."""
    from lanbridge.protocol.messages import build_x_ready_envelope
    ready_env = build_x_ready_envelope(user_id)
    hdr = struct.pack(">HH", header_flag, seq)
    cmd = struct.pack(">BBHH", 0x86, 0x00, my_seq, len(ready_env))
    return hdr + cmd + ready_env


def build_opcode_84(seq: int = 0xf8f4) -> bytes:
    """Build 12-byte Opcode 0x84 auxiliary channel synchronization packet."""
    return b"\x90\x00" + seq.to_bytes(2, "big") + b"\x84\xff\x00\x02\x00\x00\x00\x00"


def build_opcode_8a(seq: int = 0xfa87, header_flag: int = 0x9000) -> bytes:
    """Build 16-byte Opcode 0x8a HandshakeFinal packet."""
    return header_flag.to_bytes(2, "big") + seq.to_bytes(2, "big") + b"\x8a\xff\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00"


def build_opcode_88_fragments(
    payload: bytes,
    seq: int = 0xf88f,
    base_sub_id: int = 2,
    max_frag_size: int = 1372,
    header_flag: int = 0x9000,
) -> List[bytes]:
    """Split a message payload into Opcode 0x88 UDP fragments (28B header each)."""
    total_len = len(payload)
    chunks = [payload[i : i + max_frag_size] for i in range(0, total_len, max_frag_size)]
    total_frags = len(chunks)
    frags: List[bytes] = []
    offset = 0

    for idx, chunk in enumerate(chunks):
        sub_id = base_sub_id + idx
        hdr = bytearray(28)
        hdr[0:2] = header_flag.to_bytes(2, "big")
        hdr[2:4] = (seq + idx).to_bytes(2, "big")
        hdr[4:6] = b"\x88\x00"
        hdr[6:8] = sub_id.to_bytes(2, "big")
        hdr[8:10] = base_sub_id.to_bytes(2, "big")
        hdr[10:12] = len(chunk).to_bytes(2, "big")
        hdr[12:16] = total_frags.to_bytes(4, "big")
        hdr[16:20] = idx.to_bytes(4, "big")
        hdr[20:24] = total_len.to_bytes(4, "big")
        hdr[24:28] = offset.to_bytes(4, "big")
        frags.append(bytes(hdr) + chunk)
        offset += len(chunk)

    return frags


def build_multi_ack_response(seq_bytes: bytes, sub_id_0: bytes = b"\x00\x01", sub_id_1: bytes = b"\x00\x02") -> bytes:
    """Construct an 18-byte MultiACK acknowledging two fragments of an Opcode 0x88 message."""
    return (
        b"\x10\x00\x01\x00"
        + sub_id_0
        + sub_id_0
        + seq_bytes
        + b"\x01\x00"
        + sub_id_1
        + sub_id_1
        + seq_bytes
    )


def build_ack_response(req_packet: bytes, header_flag: Optional[int] = None) -> Optional[bytes]:
    """Construct an appropriate 10-byte ACK for a given Nwt request packet."""
    if len(req_packet) < 8:
        return None

    hdr0 = req_packet[0]
    if (hdr0 & 0x80) == 0:
        return None

    hdr_bytes = header_flag.to_bytes(2, "big") if header_flag is not None else b"\x00\x00"
    seq_id = req_packet[2:4]
    opcode = req_packet[4]

    if opcode == 0x85:
        # Heartbeat / Ping (8B) -> 10B ACK
        counter = req_packet[6:8]
        return hdr_bytes + b"\x01\xff" + counter + counter + seq_id

    elif opcode == 0x86:
        # Single frame data (44B / 78B / 80B / 115B / 314B)
        chan = req_packet[6:8] if len(req_packet) >= 8 else b"\x00\x01"
        return hdr_bytes + b"\x01\x00" + chan + chan + seq_id

    elif opcode == 0x88:
        # Fragmented message single ACK
        sub_id = req_packet[6:8] if len(req_packet) >= 8 else b"\x00\x01"
        return hdr_bytes + b"\x01\x00" + sub_id + sub_id + seq_id

    elif opcode in (0x82, 0x83, 0x84, 0x8A, 0x01):
        chan = req_packet[6:8] if len(req_packet) >= 8 else b"\x00\x01"
        return hdr_bytes + b"\x01\xff" + chan + chan + seq_id

    return None
