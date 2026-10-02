#!/usr/bin/env python3
"""LanBridge Protocol Envelopes and Formats (protocol.py).

Contains Opcode definitions, XML envelope builders/parsers, and UDP 9011 discovery
packet serialization reverse-engineered from ShiYeLine.exe.
"""

import json
import random
import re
import struct
import time
from typing import Any, Dict, Optional, Tuple
import xml.etree.ElementTree as ET

# Native XML Signal Opcodes (ShiYeLine.exe PE VA 0x00401000)
OP_HANDSHAKE: int = 0x03E8  # 1000: <X_HANDSHARK> Profile exchange
OP_CHANGE_STATUS: int = 0x03E9  # 1001: <X_CHANGE_STATUS> Status change
OP_SEND_MSG: int = 0x03EC  # 1004: <X_SEND_MSG> Text message / Recall
OP_SEND_MSG_ACK: int = 0x03ED  # 1005: <X_SEND_MSG_ACK> Delivery confirmation
OP_MSG_ACK: int = OP_SEND_MSG_ACK
OP_SEND_RECEIPT: int = 0x03EE  # 1006: <X_SEND_RECEIPT> Read receipt
OP_FLASH_SCREEN: int = 0x03EF  # 1007: <X_SEND_FLASH_SCREEN> Window shake
OP_SEND_WRITING: int = 0x03F0  # 1008: <X_SEND_WRITTING> Typing indicator
OP_OPERATE_SEND_FILE: int = 0x03F2  # 1010: <X_OPERATE_SEND_FILE> Cancel sending
OP_OPERATE_RECV_FILE: int = 0x03F3  # 1011: <X_OPERATE_RECV_FILE> Accept/Reject file
OP_PROGRESS_RECV_FILE: int = 0x03F4  # 1012: <X_PROGRESS_RECV_FILE> File transfer progress
OP_HEARTBEAT: int = 0x03F8  # 1016: <X_HEARTBEAT> Keepalive
OP_QUIT: int = 0x03F9  # 1017: <X_QUIT> Offline notification
OP_READY: int = 0x03FA  # 1018: <X_READY> Handshake complete

# Discovery Magic
DISCOVERY_PACKET_LEN: int = 304


def build_discovery_packet(
    user_id: str,
    username: str = "LanBridge-Bot",
    hostname: str = "DESKTOP-LANBRIDGE",
    port: int = 9012,
    org_id: str = "",
) -> bytes:
    """Build the authentic 304-byte NeiWangTong UDP 9011 discovery packet."""
    buf = bytearray(DISCOVERY_PACKET_LEN)
    # Magic Header (4 bytes)
    buf[0:4] = b"\x01\x00\x00\x00"

    # User ID: 32 bytes ASCII hex string
    uid_bytes = user_id.encode("ascii")[:32]
    buf[4 : 4 + len(uid_bytes)] = uid_bytes

    # Org / Corp ID: 32 bytes
    if org_id:
        org_bytes = org_id.encode("ascii")[:32]
        buf[40 : 40 + len(org_bytes)] = org_bytes

    # Username / Nickname (offset 76, max 32 bytes, GBK)
    uname_bytes = username.encode("gbk")[:32]
    buf[76 : 76 + len(uname_bytes)] = uname_bytes

    # Hostname (offset 112, max 32 bytes, ASCII)
    host_bytes = hostname.encode("ascii")[:32]
    buf[112 : 112 + len(host_bytes)] = host_bytes

    # Listen Port (offset 148, uint16 little endian)
    struct.pack_into("<H", buf, 148, port)

    # Flags / Version
    struct.pack_into("<I", buf, 152, 3055)
    return bytes(buf)


def parse_discovery_packet(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse a 304-byte UDP 9011 discovery packet."""
    if len(data) < 156:
        return None
    try:
        user_id = data[4:36].rstrip(b"\x00").decode("ascii", errors="ignore")
        org_id = data[40:72].rstrip(b"\x00").decode("ascii", errors="ignore")
        username = data[76:108].rstrip(b"\x00").decode("gbk", errors="ignore")
        hostname = data[112:144].rstrip(b"\x00").decode("ascii", errors="ignore")
        port = struct.unpack_from("<H", data, 148)[0]
        return {
            "user_id": user_id,
            "org_id": org_id,
            "username": username,
            "hostname": hostname,
            "port": port,
        }
    except Exception:
        return None


def build_handshake_xml(
    user_id: str,
    username: str = "LanBridge-Bot",
    hostname: str = "DESKTOP-LANBRIDGE",
    sign: str = "LanBridge AI Assistant",
    corp_id: str = "LanBridgeCorp",
) -> bytes:
    """Build <X_HANDSHARK docver="1"> profile XML payload in GBK encoding."""
    xml_str = (
        '<?xml version="1.0" encoding="gb2312"?>\r\n'
        '<X_HANDSHARK docver="1">\r\n'
        f"\t<USER_ID>{user_id}</USER_ID>\r\n"
        f"\t<USER_NAME>{username}</USER_NAME>\r\n"
        f"\t<SIGN>{sign}</SIGN>\r\n"
        f"\t<DEPT>AI-Platform</DEPT>\r\n"
        f"\t<HOST_NAME>{hostname}</HOST_NAME>\r\n"
        "\t<HEAD_IMG>1</HEAD_IMG>\r\n"
        f"\t<CORP_ID>{corp_id}</CORP_ID>\r\n"
        "\t<VERSION>3.4.3055</VERSION>\r\n"
        "\t<STATUS>1</STATUS>\r\n"
        "</X_HANDSHARK>\r\n"
    )
    return xml_str.encode("gbk")


def build_change_status_xml(status: int = 1) -> bytes:
    """Build <X_CHANGE_STATUS docver="1"> XML payload (1=Online, 2=Away, 3=Busy, 4=Offline)."""
    xml_str = (
        '<?xml version="1.0" encoding="gb2312"?>\r\n'
        '<X_CHANGE_STATUS docver="1">\r\n'
        f"\t<STATUS>{status}</STATUS>\r\n"
        "</X_CHANGE_STATUS>\r\n"
    )
    return xml_str.encode("gbk")


def build_send_msg_xml(
    content: str,
    msg_id: Optional[str] = None,
    font_name: str = "Microsoft YaHei",
    font_size: int = 10,
    color: int = 0,
) -> Tuple[bytes, str]:
    """Build <X_SEND_MSG docver="1"> XML payload containing rich JSON body.

    Returns:
        (xml_bytes, msg_id)
    """
    if not msg_id:
        msg_id = f"{int(time.time() * 1000):013d}_{random.randint(1000, 9999)}"

    # Escaping for XML CDATA/body
    safe_content = (
        content.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )

    json_body = {
        "type": "0",  # 0: Text message
        "c": safe_content,
        "f": font_name,
        "s": font_size,
        "cl": color,
        "b": 0,
        "i": 0,
        "u": 0,
    }
    json_str = json.dumps(json_body, ensure_ascii=False)

    xml_str = (
        '<?xml version="1.0" encoding="gb2312"?>\r\n'
        '<X_SEND_MSG docver="1">\r\n'
        f"\t<MSG_ID>{msg_id}</MSG_ID>\r\n"
        f"\t<BODY>{json_str}</BODY>\r\n"
        f"\t<TIME>{int(time.time())}</TIME>\r\n"
        "</X_SEND_MSG>\r\n"
    )
    return xml_str.encode("gbk"), msg_id


def build_msg_ack_xml(msg_id: str, ack_id: int = 1) -> bytes:
    """Build <X_SEND_MSG_ACK docver="1"> XML confirmation."""
    xml_str = (
        '<?xml version="1.0" encoding="gb2312"?>\r\n'
        '<X_SEND_MSG_ACK docver="1">\r\n'
        f"\t<MSG_ID>{msg_id}</MSG_ID>\r\n"
        f"\t<ID>{ack_id}</ID>\r\n"
        "</X_SEND_MSG_ACK>\r\n"
    )
    return xml_str.encode("gbk")


def build_flash_screen_xml(shake_type: int = 0) -> bytes:
    """Build <X_SEND_FLASH_SCREEN docver="1"> window shake XML."""
    xml_str = (
        '<?xml version="1.0" encoding="gb2312"?>\r\n'
        '<X_SEND_FLASH_SCREEN docver="1">\r\n'
        f"\t<TYPE>{shake_type}</TYPE>\r\n"
        "</X_SEND_FLASH_SCREEN>\r\n"
    )
    return xml_str.encode("gbk")


def build_typing_xml(state: int = 1) -> bytes:
    """Build <X_SEND_WRITTING docver="1"> typing indicator XML."""
    xml_str = (
        '<?xml version="1.0" encoding="gb2312"?>\r\n'
        '<X_SEND_WRITTING docver="1">\r\n'
        f"\t<STATE>{state}</STATE>\r\n"
        "</X_SEND_WRITTING>\r\n"
    )
    return xml_str.encode("gbk")


def build_recall_xml(target_msg_id: str, target_uuid: str = "") -> Tuple[bytes, str]:
    """Build message recall XML (Opcode 0x03EC with type=6)."""
    recall_msg_id = f"{int(time.time() * 1000):013d}_{random.randint(1000, 9999)}"
    json_body = {
        "type": "6",  # 6: Message/file recall
        "t": "recall",
        "target_msg_id": target_msg_id,
        "target_id": target_uuid,
    }
    json_str = json.dumps(json_body, ensure_ascii=False)
    xml_str = (
        '<?xml version="1.0" encoding="gb2312"?>\r\n'
        '<X_SEND_MSG docver="1">\r\n'
        f"\t<MSG_ID>{recall_msg_id}</MSG_ID>\r\n"
        f"\t<BODY>{json_str}</BODY>\r\n"
        f"\t<TIME>{int(time.time())}</TIME>\r\n"
        "</X_SEND_MSG>\r\n"
    )
    return xml_str.encode("gbk"), recall_msg_id


def extract_chat_text(xml_text: str) -> Optional[Tuple[str, str, Dict[str, Any]]]:
    """Extract (msg_id, plain_text, json_dict) from a received <X_SEND_MSG> XML payload."""
    try:
        # Find MSG_ID
        msg_id_match = re.search(r"<MSG_ID>([^<]+)</MSG_ID>", xml_text)
        msg_id = msg_id_match.group(1).strip() if msg_id_match else ""

        # Find BODY
        body_match = re.search(r"<BODY>(.*?)</BODY>", xml_text, re.DOTALL)
        if not body_match:
            return None
        body_str = body_match.group(1).strip()
        data = json.loads(body_str)
        text = data.get("c", "")
        # Unescape XML entities
        text = (
            text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", '"')
            .replace("&apos;", "'")
            .replace("&amp;", "&")
        )
        return msg_id, text, data
    except Exception:
        return None
