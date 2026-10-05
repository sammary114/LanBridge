#!/usr/bin/env python3
"""LanBridge Discovery Protocol (discovery.py).

Implements:
1. Native Nwt UDP 9011 discovery packets (304 bytes fixed).
2. Encapsulated discovery frames (Opcode 0x86, 314 bytes).
3. IPMSG (UDP 2425) compatibility presence broadcasts and filtering.
"""

from __future__ import annotations

import socket
import struct
from typing import Optional, Dict, Any

NWT_MAGIC_DISCOVERY = bytes.fromhex("5fc1d8ec")
DEFAULT_VERSION = b"#3#4#4"
DEFAULT_USER_ID = "2158b475dfcfdd43989482c4dcf0337b"
DEFAULT_GUID = bytes.fromhex("92f64910243444458df4dc184a44ba7c")
DEFAULT_NICKNAME = "LanBridge-Bot"
DEFAULT_GROUP = "内网通联系人"


def build_nwt_discovery_packet(
    cmd: int = 1,
    user_id: str = DEFAULT_USER_ID,
    broadcast_ip: str = "172.31.127.255",
    dynamic_port: int = 53782,
    guid: bytes = DEFAULT_GUID,
    version: bytes = DEFAULT_VERSION,
    magic: bytes = NWT_MAGIC_DISCOVERY,
) -> bytes:
    """Build a fixed 304-byte Nwt UDP 9011 discovery packet.

    cmd: 1 = DiscoveryBroadcast, 2 = DiscoveryReply, 4 = DiscoveryHandshake.
    """
    buf = bytearray(304)

    # 0x00 ~ 0x03: Total length = 304 (0x00000130)
    buf[0:4] = (304).to_bytes(4, "big")

    # 0x04 ~ 0x07: Command code
    buf[4:8] = cmd.to_bytes(4, "big")

    # 0x08 ~ 0x0B: Sub-command / sequence
    buf[8:12] = (1).to_bytes(4, "big")

    # 0x0C ~ 0x0F: Protocol Magic
    buf[12:16] = magic[:4]

    # 0x10 ~ 0x13: Reserved (0x00000000)
    buf[16:20] = b"\x00\x00\x00\x00"

    # 0x14 ~ 0x17: Directed subnet broadcast IP
    try:
        buf[20:24] = socket.inet_aton(broadcast_ip)
    except OSError:
        buf[20:24] = b"\xac\x1f\x7f\xff"

    # 0x18 ~ 0x1D: Version string (#3#4#4)
    ver_bytes = version[:6].ljust(6, b"\x00")
    buf[24:30] = ver_bytes

    # 0x1E ~ 0x3D: 32-character hexadecimal User ID
    uid_bytes = user_id.encode("ascii", errors="replace")[:32].ljust(32, b"\x00")
    buf[30:62] = uid_bytes

    # 0x3E ~ 0x5F: Reserved zeros (34 bytes)
    buf[62:96] = b"\x00" * 34

    # 0x60 ~ 0x6F: 16-byte Instance GUID
    buf[96:112] = guid[:16].ljust(16, b"\x00")

    # 0x70 ~ 0x9F: Reserved zeros (48 bytes)
    buf[112:160] = b"\x00" * 48

    # 0xA0 ~ 0xA3: Timeout threshold (500ms)
    buf[160:164] = (500).to_bytes(4, "big")

    # 0xA4 ~ 0xA7: Dynamic helper port info (00 + port_hi + port_lo + 00)
    buf[164] = 0x00
    buf[165:167] = dynamic_port.to_bytes(2, "big")
    buf[167] = 0x00

    # 0xA8 ~ 0x12F: Tail padding zeros (136 bytes)
    buf[168:304] = b"\x00" * 136

    assert len(buf) == 304, f"Packet length must be 304, got {len(buf)}"
    return bytes(buf)


# Alias for clean API naming
build_discovery_packet = build_nwt_discovery_packet


def parse_discovery_packet(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse a 304-byte Nwt UDP 9011 discovery packet."""
    if len(data) < 168:
        return None
    total_len = int.from_bytes(data[0:4], "big")
    if total_len != 304:
        return None

    cmd = int.from_bytes(data[4:8], "big")
    seq = int.from_bytes(data[8:12], "big")
    magic = data[12:16]
    broadcast_ip = socket.inet_ntoa(data[20:24])
    version = data[24:30].rstrip(b"\x00").decode("ascii", errors="ignore")
    user_id = data[30:62].rstrip(b"\x00").decode("ascii", errors="ignore")
    guid = data[96:112]
    dynamic_port = int.from_bytes(data[165:167], "big")

    return {
        "cmd": cmd,
        "seq": seq,
        "magic": magic,
        "broadcast_ip": broadcast_ip,
        "version": version,
        "user_id": user_id,
        "guid": guid,
        "dynamic_port": dynamic_port,
    }


def build_encapsulated_discovery(
    user_id: str = DEFAULT_USER_ID,
    broadcast_ip: str = "172.31.127.255",
    dynamic_port: int = 53782,
    seq: int = 0xf82b,
) -> bytes:
    """Build 314-byte Opcode 0x86 frame carrying 304B discovery frame with Cmd 4."""
    raw_disc = build_nwt_discovery_packet(
        cmd=4,
        user_id=user_id,
        broadcast_ip=broadcast_ip,
        dynamic_port=dynamic_port,
    )
    hdr = b"\x90\x00" + seq.to_bytes(2, "big") + b"\x86\x00\x00\x01\x01\x30\x00\x00\x01\x30"
    return hdr + raw_disc[4:]


def is_ipmsg_shiyeline(data: bytes) -> bool:
    """Check if an IPMSG packet carries @shiyeline signature (native Nwt suppression)."""
    return data.startswith(b"1@shiyeline:")


def build_ipmsg_presence(
    packet_no: int = 1001,
    user: str = "LanBridge",
    host: str = "HOST-BOT",
    nick: str = DEFAULT_NICKNAME,
    group: str = DEFAULT_GROUP,
    user_id: str = DEFAULT_USER_ID,
    use_shiyeline_prefix: bool = True,
) -> bytes:
    """Build a UDP 2425 IPMSG presence packet."""
    prefix = "1@shiyeline" if use_shiyeline_prefix else "1"
    if use_shiyeline_prefix:
        text = f"{prefix}:{packet_no}:{user}:{host}:1:{nick}\x00{group}\x00{user_id}\x00"
    else:
        text = f"{prefix}:{packet_no}:{user}:{host}:1:{nick}\x00{group}\x00"
    return text.encode("gbk", errors="replace")


def build_ipmsg_packet(
    command: int = 1,
    packet_no: int = 1001,
    user: str = "LanBridge",
    host: str = "HOST-BOT",
    nick: str = DEFAULT_NICKNAME,
    group: str = DEFAULT_GROUP,
    user_id: str = DEFAULT_USER_ID,
    use_shiyeline_prefix: bool = False,
) -> bytes:
    """Build a UDP 2425 IPMSG packet."""
    prefix = "1@shiyeline" if use_shiyeline_prefix else "1"
    if use_shiyeline_prefix:
        text = f"{prefix}:{packet_no}:{user}:{host}:{command}:{nick}\x00{group}\x00{user_id}\x00"
    else:
        text = f"{prefix}:{packet_no}:{user}:{host}:{command}:{nick}\x00{group}\x00"
    return text.encode("gbk", errors="replace")


def build_ipmsg_send_msg(
    message: str,
    packet_no: int = 1002,
    user: str = "LanBridge",
    host: str = "HOST-BOT",
    need_check: bool = True,
) -> bytes:
    """Build a UDP 2425 IPMSG text message packet (command 32)."""
    command = 32 | (0x100 if need_check else 0)
    text = f"1:{packet_no}:{user}:{host}:{command}:{message}\x00"
    return text.encode("gbk", errors="replace")


def build_ipmsg_recv_ack(
    packet_no_ack: str,
    packet_no: int = 1003,
    user: str = "LanBridge",
    host: str = "HOST-BOT",
) -> bytes:
    """Build a UDP 2425 IPMSG message delivery receipt ACK (command 33)."""
    text = f"1:{packet_no}:{user}:{host}:33:{packet_no_ack}\x00"
    return text.encode("gbk", errors="replace")
