#!/usr/bin/env python3
"""LanBridge Minimal Active Network Verification Tool (net-tester).

Simulates a compliant LanBridge endpoint against a running Nwt (ShiYeLine)
client (e.g. inside Windows Sandbox) to verify contact discovery, UI presentation,
bidirectional text messaging, and heartbeat keepalive.

Supports two operational modes:
- native (default): Pure Nwt native protocol on UDP 9011, 9012, and dynamic auxiliary port,
  producing native green badge contacts in the "内网通联系人" group and native 9012 chat.
- ipmsg: Legacy Feige/IPMSG compatibility layer on UDP 2425.
"""

from __future__ import annotations

import argparse
import logging
import os
import random
import select
import socket
import struct
import sys
import time
from typing import List, Optional, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from crypto_engine import XteaEngine

import sys
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("net-tester")
xtea_engine = XteaEngine()

# Standard protocol constants
NWT_MAGIC_DISCOVERY = bytes.fromhex("5fc1d8ec")
DEFAULT_VERSION = b"#3#4#4"
DEFAULT_USER_ID = "2158b475dfcfdd43989482c4dcf0337b"
DEFAULT_GUID = bytes.fromhex("92f64910243444458df4dc184a44ba7c")
DEFAULT_NICKNAME = "LanBridge-Bot"
DEFAULT_GROUP = "内网通联系人"
DEFAULT_INITIAL_MSG = "你好！我是 LanBridge 原生接入机器人，已成功上线！"

# Handshake template frames captured from authentic communication
TEMPLATE_0X84_12B = bytes.fromhex("9000f8f484ff000200000000")
TEMPLATE_PROBE_115B = bytes.fromhex(
    "9000fa2286000004006900000069000003fa5f4d1ebae1485eae3a643fa23c20e0ae"
    "4c11d92ae5fe42e59db59141f328fe32f992262cbb29622113601840778904a6e5b4"
    "e29e03005ec81a661d35a6f91339d6c5cffb09199b8acc80e00390340d623fb29841"
    "cb633983d16595a797e793713e"
)
TEMPLATE_FINAL_16B = bytes.fromhex("9000fa878aff00030000000000000000")
TEMPLATE_DATA_44B = bytes.fromhex(
    "9000fdac86000005002200000022000003f8d529c5439de045c9d3dc11866769e1fe"
    "dfa896e8e704a5532f3e"
)


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
    uid_bytes = user_id.encode("ascii", errors="replace")[:32].ljust(32, b"0")
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
    """Build a UDP 2425 IPMSG compatibility broadcast packet."""
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


def build_handshake_reply(req_packet: bytes, my_seq: int = 0xf7c6) -> bytes:
    """Build 48-byte Opcode 0x83 HandshakeReply responding to Opcode 0x82."""
    if len(req_packet) >= 48:
        payload_echo = req_packet[14:48]
    else:
        payload_echo = b"\x00" * 34
    return (
        b"\x90\x00"
        + my_seq.to_bytes(2, "big")
        + b"\x83\xff\x00\x01\x00\x00\x01\x01\x00\x00"
        + payload_echo
    )


def build_opcode_01(echo_seq: bytes, seq: int = 0xf7c6) -> bytes:
    """Build 16-byte Opcode 0x01 channel synchronization packet echoing remote sequence."""
    return (
        b"\x90\x00"
        + seq.to_bytes(2, "big")
        + b"\x01\xff\x00\x01\x00\x01"
        + echo_seq[:2]
        + b"\x85\xff\x00\x02"
    )


def build_opcode_84(seq: int = 0xf8f4) -> bytes:
    """Build 12-byte Opcode 0x84 auxiliary channel synchronization packet."""
    return b"\x90\x00" + seq.to_bytes(2, "big") + b"\x84\xff\x00\x02\x00\x00\x00\x00"


def build_opcode_8a(seq: int = 0xfa87) -> bytes:
    """Build 16-byte Opcode 0x8a HandshakeFinal packet."""
    return b"\x90\x00" + seq.to_bytes(2, "big") + b"\x8a\xff\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00"


def build_native_profile(
    nick: str = DEFAULT_NICKNAME,
    user_id: str = DEFAULT_USER_ID,
    corp_id: str = "296becfde55172409ef2b81908044747",
    status: int = 0,
    sign: str = "LanBridge Native Online",
    group: str = "Default",
    tcp_file_port: int = 9013,
) -> bytes:
    """Build authentic encrypted X_HANDSHARK profile envelope."""
    xml = (
        '<X_HANDSHARK docver="1">'
        '<FEATURE><MAJOR>3</MAJOR><MINOR>4</MINOR><BUILD>3055</BUILD><APP>1</APP><MSG>2:1</MSG>'
        '<FILE_TRAN>1</FILE_TRAN><FOLDER_TRAN>2:1</FOLDER_TRAN><REMOTE_ASSISTANCE>1</REMOTE_ASSISTANCE>'
        '<FILE_SHARE>1</FILE_SHARE><QGROUP>2:1</QGROUP><QGROUP_MSG>2:1</QGROUP_MSG>'
        '<QGROUP_FILE></QGROUP_FILE><QGROUP_FOLDER></QGROUP_FOLDER>'
        '<OFFLINE_MSG>1</OFFLINE_MSG><OFFLINE_FILE>1</OFFLINE_FILE><LAN_UPDATE>1</LAN_UPDATE><HIDE_RECORD>1</HIDE_RECORD>'
        '</FEATURE>'
        '<INFO>'
        f'<CORP_ID>{corp_id}</CORP_ID>'
        '<CORP_TIME>1494217112</CORP_TIME>'
        f'<NAME>{nick}</NAME>'
        f'<GROUP>{group}</GROUP>'
        '<CORPORATION></CORPORATION><DEPARTMENT></DEPARTMENT><SEX>0</SEX>'
        '<POST></POST><TEL></TEL><MOBILE></MOBILE><EMAIL></EMAIL>'
        f'<SIGN>{sign}</SIGN>'
        '<SYS_FACE>0</SYS_FACE><USER_FACE id="0"></USER_FACE>'
        f'<STATUS>{status}</STATUS>'
        '<ACTIVE_SEND>1</ACTIVE_SEND><ONLINE_POPUP>0</ONLINE_POPUP><HIDE_IP>0</HIDE_IP>'
        '<COLOR_NAME>0</COLOR_NAME><SORT_NAME>0</SORT_NAME><DECORATE_NAME>0</DECORATE_NAME>'
        '</INFO>'
        '<NET>'
        f'<FILE_TRAN_TCP_PORT>{tcp_file_port}</FILE_TRAN_TCP_PORT><FILE_TRAN_ENET_PORT>0</FILE_TRAN_ENET_PORT>'
        f'<FOLDER_TRAN_TCP_PORT>{tcp_file_port + 1}</FOLDER_TRAN_TCP_PORT><FOLDER_TRAN_ENET_PORT>0</FOLDER_TRAN_ENET_PORT>'
        f'<FILE_TRAN_TCP_REVERSE_PORT>{tcp_file_port + 2}</FILE_TRAN_TCP_REVERSE_PORT><FILE_TRAN_ENET_REVERSE_PORT>0</FILE_TRAN_ENET_REVERSE_PORT>'
        f'<FOLDER_TRAN_TCP_REVERSE_PORT>{tcp_file_port + 3}</FOLDER_TRAN_TCP_REVERSE_PORT><FOLDER_TRAN_ENET_REVERSE_PORT>0</FOLDER_TRAN_ENET_REVERSE_PORT>'
        f'<LAN_UPDATE_HTTP_PORT>{tcp_file_port + 4}</LAN_UPDATE_HTTP_PORT>'
        '</NET>'
        '</X_HANDSHARK>'
    )
    return xtea_engine.build_envelope(0x03E8, xml)


def build_x_ready_envelope(user_id: str = DEFAULT_USER_ID) -> bytes:
    """Build authentic encrypted X_READY (Opcode 1018 / 0x03fa) envelope."""
    xml = f'<X_READY docver="1"><USER_ID>{user_id}</USER_ID><PARAM>0</PARAM></X_READY>'
    return xtea_engine.build_envelope(0x03FA, xml)


def build_x_heartbeat_envelope() -> bytes:
    """Build authentic encrypted X_HEARTBEAT (Opcode 1016 / 0x03f8) envelope."""
    xml = '<X_HEARTBEAT docver="1" />'
    return xtea_engine.build_envelope(0x03F8, xml)


def build_x_send_msg_envelope(
    message: str,
    msg_id: int = 1,
    timestamp: Optional[int] = None,
    use_emoticons: bool = True,
) -> bytes:
    """Build authentic encrypted X_SEND_MSG (Opcode 1004 / 0x03ec) envelope."""
    import json, uuid
    if timestamp is None:
        timestamp = int(time.time())

    if use_emoticons:
        try:
            from lanbridge.emoticons import emoji_to_nwt_dt
            dt = emoji_to_nwt_dt(message)
        except Exception:
            dt = [{"txt": {"t": "normal", "v": message}}]
    else:
        dt = [{"txt": {"t": "normal", "v": message}}]

    msg_json = json.dumps(
        {
            "app": "shiyeline",
            "dt": dt,
            "ft": {
                "b": "0",
                "c": "0x000000",
                "i": "0",
                "n": "微软雅黑",
                "s": "9",
                "u": "0",
            },
            "id": uuid.uuid4().hex,
            "type": "0",
            "ver": "6.0",
        },
        ensure_ascii=False,
        indent=3,
        separators=(",", " : "),
    )
    # XML entity escaping matching authentic Nwt ShiYeLine payload
    escaped_msg = msg_json.replace('"', '&quot;').replace(' ', '&nbsp;') + "\n"
    xml = (
        f'<X_SEND_MSG docver="1"><MSG_ID>{msg_id}</MSG_ID><RECEIPT>0</RECEIPT>'
        f'<MSG>{escaped_msg}</MSG>'
        f'<MSG_TIME>{timestamp}</MSG_TIME><OFFLINE>0</OFFLINE><HIDE_RECORD>0</HIDE_RECORD></X_SEND_MSG>'
    )
    return xtea_engine.build_envelope(0x03EC, xml, encoding="utf-8")


def extract_chat_message(dec_xml: str) -> str:
    """Extract plain text message from decrypted X_SEND_MSG XML payload."""
    import json
    try:
        start_msg = dec_xml.find("<MSG>")
        end_msg = dec_xml.find("</MSG>")
        if start_msg != -1 and end_msg != -1:
            content_str = dec_xml[start_msg + 5 : end_msg].strip()
            # Unescape XML/HTML entities
            unescaped = (
                content_str.replace("&quot;", '"')
                .replace("&nbsp;", " ")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
            )
            m_json = json.loads(unescaped)
            logger.info("[RAW JSON BODY]: %s", unescaped)
            if "dt" in m_json and isinstance(m_json["dt"], list):
                try:
                    from lanbridge.emoticons import nwt_dt_to_emoji_text
                    return nwt_dt_to_emoji_text(m_json["dt"])
                except Exception:
                    pass
                if len(m_json["dt"]) > 0 and "txt" in m_json["dt"][0]:
                    return m_json["dt"][0]["txt"]["v"]
    except Exception:
        pass
    return dec_xml


def extract_msg_id(dec_xml: str) -> int:
    """Extract MSG_ID integer from decrypted X_SEND_MSG XML payload."""
    try:
        start = dec_xml.find("<MSG_ID>")
        end = dec_xml.find("</MSG_ID>")
        if start != -1 and end != -1:
            return int(dec_xml[start + 8 : end].strip())
    except Exception:
        pass
    return 1


def build_x_send_msg_ack_envelope(msg_id: int) -> bytes:
    """Build authentic encrypted X_SEND_MSG_ACK (Opcode 1005 / 0x03ed) envelope."""
    xml = f'<X_SEND_MSG_ACK docver="1"><MSG_ID>{msg_id}</MSG_ID></X_SEND_MSG_ACK>'
    return xtea_engine.build_envelope(0x03ED, xml)


def build_x_flash_screen_envelope(shake_type: int = 0) -> bytes:
    """Build authentic encrypted X_SEND_FLASH_SCREEN (Opcode 1007 / 0x03ef) envelope."""
    xml = f'<X_SEND_FLASH_SCREEN docver="1"><TYPE>{shake_type}</TYPE></X_SEND_FLASH_SCREEN>'
    return xtea_engine.build_envelope(0x03EF, xml)


def build_x_operate_recv_file_envelope(task_id: int, op: int = 1) -> bytes:
    """Build authentic encrypted X_OPERATE_RECV_FILE (Opcode 1011 / 0x03f3) envelope.
    
    OP: 1 = Accept/Start download, 2 = Reject/Cancel
    """
    xml = f'<X_OPERATE_RECV_FILE docver="1"><TASK_ID>{task_id}</TASK_ID><OP>{op}</OP></X_OPERATE_RECV_FILE>'
    return xtea_engine.build_envelope(0x03F3, xml)


def build_x_operate_send_file_envelope(task_id: int, op: int = 1) -> bytes:
    """Build authentic encrypted X_OPERATE_SEND_FILE (Opcode 1010 / 0x03f2) envelope.
    
    OP: 1 = Cancel send
    """
    xml = f'<X_OPERATE_SEND_FILE docver="1"><TASK_ID>{task_id}</TASK_ID><OP>{op}</OP></X_OPERATE_SEND_FILE>'
    return xtea_engine.build_envelope(0x03F2, xml)


def build_x_progress_recv_file_envelope(
    task_id: int,
    total_size: int,
    recvd_size: int,
    speed: str = "1.0MB/s",
) -> bytes:
    """Build authentic encrypted X_PROGRESS_RECV_FILE (Opcode 1012 / 0x03f4) envelope."""
    xml = (
        f'<X_PROGRESS_RECV_FILE docver="1">'
        f'<TASK_ID>{task_id}</TASK_ID>'
        f'<TOTAL_SIZE>{total_size}</TOTAL_SIZE>'
        f'<RECVD_SIZE>{recvd_size}</RECVD_SIZE>'
        f'<SPEED>{speed}</SPEED>'
        f'</X_PROGRESS_RECV_FILE>'
    )
    return xtea_engine.build_envelope(0x03F4, xml)


def build_x_recall_msg_envelope(
    target_msg_id: int,
    target_uuid: str,
    msg_id: int = 1,
    timestamp: Optional[int] = None,
) -> bytes:
    """Build authentic encrypted message recall envelope (Opcode 1004 / 0x03ec, type 6)."""
    import json, uuid
    if timestamp is None:
        timestamp = int(time.time())
    msg_json = json.dumps(
        {
            "app": "shiyeline",
            "dt": [
                {
                    "txt": {
                        "t": "recall",
                        "target_id": target_uuid,
                        "target_msg_id": target_msg_id,
                        "v": "",
                    }
                }
            ],
            "ft": {
                "b": "0",
                "c": "0x000000",
                "i": "0",
                "n": "微软雅黑",
                "s": "9",
                "u": "0",
            },
            "id": uuid.uuid4().hex,
            "type": "6",
            "ver": "6.0",
        },
        ensure_ascii=False,
        indent=3,
        separators=(",", " : "),
    )
    escaped_msg = msg_json.replace('"', '&quot;').replace(' ', '&nbsp;') + "\n"
    xml = (
        f'<X_SEND_MSG docver="1"><MSG_ID>{msg_id}</MSG_ID><RECEIPT>0</RECEIPT>'
        f'<MSG>{escaped_msg}</MSG>'
        f'<MSG_TIME>{timestamp}</MSG_TIME><OFFLINE>0</OFFLINE><HIDE_RECORD>0</HIDE_RECORD></X_SEND_MSG>'
    )
    return xtea_engine.build_envelope(0x03EC, xml, encoding="utf-8")


def build_x_send_image_envelope(
    img_md5: str,
    token: int = 1001,
    caption: str = "",
    msg_id: int = 1,
    img_type: str = "feihu",
    timestamp: Optional[int] = None,
) -> bytes:
    """Build authentic encrypted X_SEND_MSG (Opcode 1004 / 0x03ec) envelope containing an inline image."""
    import json, uuid
    if timestamp is None:
        timestamp = int(time.time())

    val = f"{token}|{img_md5}" if img_type == "feihu" else img_md5
    dt = [{"img": {"t": img_type, "v": val}}]
    if caption:
        dt.append({"txt": {"t": "normal", "v": caption}})

    msg_json = json.dumps(
        {
            "app": "shiyeline",
            "dt": dt,
            "ft": {
                "b": "0",
                "c": "0x000000",
                "i": "0",
                "n": "微软雅黑",
                "s": "9",
                "u": "0",
            },
            "id": uuid.uuid4().hex,
            "type": "0",
            "ver": "6.0",
        },
        ensure_ascii=False,
        indent=3,
        separators=(",", " : "),
    )
    escaped_msg = msg_json.replace('"', '&quot;').replace(' ', '&nbsp;') + "\n"
    xml = (
        f'<X_SEND_MSG docver="1"><MSG_ID>{msg_id}</MSG_ID><RECEIPT>0</RECEIPT>'
        f'<MSG>{escaped_msg}</MSG>'
        f'<MSG_TIME>{timestamp}</MSG_TIME><OFFLINE>0</OFFLINE><HIDE_RECORD>0</HIDE_RECORD></X_SEND_MSG>'
    )
    return xtea_engine.build_envelope(0x03EC, xml, encoding="utf-8")


def build_x_send_file_envelope(
    filename: str,
    size: int,
    task_id: int = 1,
    file_id: int = 1,
    last_modify: Optional[int] = None,
) -> bytes:
    """Build authentic encrypted X_SEND_FILE (Opcode 1009 / 0x03f1) envelope."""
    if last_modify is None:
        last_modify = int(time.time())
    xml = (
        f'<X_SEND_FILE docver="1">'
        f'<TASK_ID>{task_id}</TASK_ID>'
        f'<FILE_ID>{file_id}</FILE_ID>'
        f'<NAME>{filename}</NAME>'
        f'<PWD></PWD>'
        f'<SIZE>{size}</SIZE>'
        f'<LAST_MODIFY>{last_modify}</LAST_MODIFY>'
        f'<OFFLINE>0</OFFLINE>'
        f'</X_SEND_FILE>'
    )
    return xtea_engine.build_envelope(0x03F1, xml, encoding="gbk")



def build_x_send_msg(
    message: str,
    msg_id: int = 10001,
    timestamp: Optional[int] = None,
) -> bytes:
    """Build native Nwt X_SEND_MSG (Opcode 1004 / 0x3ec) XML payload envelope."""
    if timestamp is None:
        timestamp = int(time.time())
    xml_str = (
        f"<X_SEND_MSG><MSG_ID>{msg_id}</MSG_ID>"
        f"<RECEIPT>1</RECEIPT>"
        f"<MSG>{message}</MSG>"
        f"<MSG_TIME>{timestamp}</MSG_TIME>"
        f"<OFFLINE>0</OFFLINE>"
        f"<HIDE_RECORD>0</HIDE_RECORD></X_SEND_MSG>"
    )
    xml_bytes = xml_str.encode("gbk", errors="replace")
    total_len = len(xml_bytes) + 8
    hdr = total_len.to_bytes(4, "big") + (0x03EC).to_bytes(4, "big")
    return hdr + xml_bytes


def build_x_input_state(seq: int = 0xea51) -> bytes:
    """Build 78-byte Opcode 0x86 TypingIndicator (X_OPERATE_SEND_INPUT_STATE) frame."""
    return bytes.fromhex(
        "8000"
        + f"{seq:04x}"
        + "8600004b004400000044000003f0"
        + "69e9b754d98ba0614f259a85071268d63a643fa23c20e0aeef113e4e5542c944"
        + "94fcc7296c1147cdfaea94d196b187848682d9471761869f494e473e"
    )


def build_x_msg_ack(seq: int = 0xb5c3) -> bytes:
    """Build 80-byte Opcode 0x86 message delivery receipt (X_SEND_MSG_ACK) frame."""
    return bytes.fromhex(
        "8000"
        + f"{seq:04x}"
        + "86000051004600000046000003ed"
        + "69e9b754d98ba061b0e81ef94b110d9a426afbd748cd5e93af5708318a5fcccf"
        + "59f1180d456b7fc3c86dbb00d372b1816c41dd6bdac3f9c0475f41434b3e"
    )


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


def build_opcode_88_fragments(
    payload: bytes,
    seq: int = 0xf88f,
    base_sub_id: int = 2,
    max_frag_size: int = 1372,
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
        hdr[0:2] = b"\x90\x00"
        hdr[2:4] = seq.to_bytes(2, "big")
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


def build_ack_response(req_packet: bytes) -> Optional[bytes]:
    """Construct an appropriate 10-byte ACK for a given Nwt request packet."""
    if len(req_packet) < 8:
        return None

    hdr0 = req_packet[0]
    if (hdr0 & 0x80) == 0:
        return None

    seq_id = req_packet[2:4]
    opcode = req_packet[4]

    if opcode == 0x85:
        # Heartbeat / Ping (8B) -> 10B ACK
        counter = req_packet[6:8]
        return b"\x00\x00\x01\xff" + counter + counter + seq_id

    elif opcode == 0x86:
        # Single frame data (44B / 78B / 80B / 115B / 314B)
        chan = req_packet[6:8] if len(req_packet) >= 8 else b"\x00\x01"
        return b"\x00\x00\x01\x00" + chan + chan + seq_id

    elif opcode == 0x88:
        # Fragmented message single ACK
        sub_id = req_packet[6:8] if len(req_packet) >= 8 else b"\x00\x01"
        return b"\x00\x00\x01\x00" + sub_id + sub_id + seq_id

    elif opcode in (0x82, 0x83, 0x84, 0x8A, 0x01):
        chan = req_packet[6:8] if len(req_packet) >= 8 else b"\x00\x01"
        return b"\x00\x00\x01\xff" + chan + chan + seq_id

    return None


def build_minifile_response(md5_hex: str, file_size: int, status: int = 0) -> bytes:
    """Build authentic 356-byte Mini-File / Image download response packet (Command 2)."""
    buf = bytearray(356)
    struct.pack_into(">I", buf, 0, 356)
    struct.pack_into(">I", buf, 4, 1)
    struct.pack_into(">I", buf, 8, 2)  # Command 2: Response
    struct.pack_into(">I", buf, 0x70, status)  # Status: 0 = OK
    md5_b = md5_hex.encode("ascii")
    buf[0x74:0x74 + len(md5_b)] = md5_b
    struct.pack_into(">Q", buf, 0x94, file_size)  # 64-bit big-endian file size
    return bytes(buf)


def build_minifile_chunk(file_size: int, offset: int, chunk_data: bytes) -> bytes:
    """Build authentic Mini-File / Image data chunk packet (Command 3)."""
    chunk_len = len(chunk_data)
    total_len = chunk_len + 0x98
    buf = bytearray(total_len)
    struct.pack_into(">I", buf, 0, total_len)
    struct.pack_into(">I", buf, 4, 1)
    struct.pack_into(">I", buf, 8, 3)  # Command 3: Data Chunk
    struct.pack_into(">Q", buf, 0x70, file_size)  # 64-bit file size
    struct.pack_into(">Q", buf, 0x78, offset)  # 64-bit chunk offset
    struct.pack_into(">I", buf, 0x80, chunk_len)  # 32-bit chunk length
    buf[0x98:0x98 + chunk_len] = chunk_data
    return bytes(buf)


def build_folder_tran_response(file_size: int, token: int = 0, offset: int = 0, chunk_size: int = 16384) -> bytes:
    """Build authentic 108-byte CFolderTranEngine response packet (Command 2).

    Used by Nwt native chat inline image and folder/file transfer engines.
    Header layout (BE):
      0x00: total_len (108)
      0x04: proto_type (1)
      0x08: cmd (2)
      0x34: token (64-bit)
      0x3c: file_size (64-bit)
      0x44: chunk_size (64-bit)
    """
    buf = bytearray(108)
    struct.pack_into(">I", buf, 0, 108)  # total_len
    struct.pack_into(">I", buf, 4, 1)    # proto_type = 1
    struct.pack_into(">I", buf, 8, 2)    # cmd = 2 (Response)
    struct.pack_into(">Q", buf, 0x34, token)      # 64-bit token BE
    struct.pack_into(">Q", buf, 0x3c, file_size)  # 64-bit file size BE
    struct.pack_into(">Q", buf, 0x44, chunk_size) # 64-bit chunk size BE
    return bytes(buf)


def build_folder_tran_chunk(file_size: int, offset: int, chunk_data: bytes, token: int = 0) -> bytes:
    """Build authentic CFolderTranEngine data chunk packet (Command 4).

    Header length is exactly 100 bytes (0x64), followed by raw chunk payload.
    Header layout (BE):
      0x00: total_len (chunk_len + 100)
      0x04: proto_type (1)
      0x08: cmd (4)
      0x34: token (64-bit)
      0x3c: file_size (64-bit)
      0x44: offset (64-bit)
      0x4c: chunk_len (32-bit)
      0x64: raw payload
    """
    chunk_len = len(chunk_data)
    total_len = chunk_len + 100
    buf = bytearray(total_len)
    struct.pack_into(">I", buf, 0, total_len)     # total_len
    struct.pack_into(">I", buf, 4, 1)             # proto_type = 1
    struct.pack_into(">I", buf, 8, 4)             # cmd = 4 (Data Chunk)
    struct.pack_into(">Q", buf, 0x34, token)      # 64-bit token BE
    struct.pack_into(">Q", buf, 0x3c, file_size)  # 64-bit file size BE
    struct.pack_into(">Q", buf, 0x44, offset)     # 64-bit offset BE
    struct.pack_into(">I", buf, 0x4c, chunk_len)  # 32-bit chunk len BE
    buf[0x64 : 0x64 + chunk_len] = chunk_data
    return bytes(buf)


def parse_folder_tran_packet(data: bytes) -> Optional[dict]:
    """Parse incoming CFolderTranEngine packet (Command 1, 2, 3, or 4)."""
    if len(data) < 12:
        return None
    total_len = struct.unpack(">I", data[:4])[0]
    p_type = struct.unpack(">I", data[4:8])[0]
    p_cmd = struct.unpack(">I", data[8:12])[0]
    res = {"total_len": total_len, "type": p_type, "cmd": p_cmd}
    if p_cmd == 1 and len(data) >= 12:
        # Command 1: Download Request
        # 1. Check for binary token at offset 0x34
        if len(data) >= 0x3C:
            tok = struct.unpack(">Q", data[0x34:0x3c])[0]
            if tok != 0:
                res["token"] = tok
        # 2. Check for ASCII JSON / text format
        import re
        m = re.search(rb'(\d+)\|([0-9a-fA-F]{32})', data)
        if m:
            res["token"] = int(m.group(1))
            res["md5"] = m.group(2).decode("ascii").lower()
        else:
            m_v = re.search(rb'"v"\s*:\s*"([0-9a-fA-F]{32})"', data)
            if m_v:
                res["md5"] = m_v.group(1).decode("ascii").lower()
    elif p_cmd == 2 and len(data) >= 0x4C:
        # Command 2: Download Response
        res["token"] = struct.unpack(">Q", data[0x34:0x3c])[0]
        res["file_size"] = struct.unpack(">Q", data[0x3c:0x44])[0]
        res["chunk_size"] = struct.unpack(">Q", data[0x44:0x4c])[0]
    elif p_cmd == 3 and len(data) >= 0x44:
        # Command 3: Chunk Request from receiver
        res["token"] = struct.unpack(">Q", data[0x34:0x3c])[0]
        res["offset"] = struct.unpack(">Q", data[0x3c:0x44])[0]
        if len(data) >= 0x4C:
            res["chunk_len"] = struct.unpack(">Q", data[0x44:0x4c])[0]
    elif p_cmd == 4 and len(data) >= 0x64:
        # Command 4: Data Chunk
        res["token"] = struct.unpack(">Q", data[0x34:0x3c])[0]
        res["file_size"] = struct.unpack(">Q", data[0x3c:0x44])[0]
        res["offset"] = struct.unpack(">Q", data[0x44:0x4c])[0]
        chunk_len_32 = struct.unpack(">I", data[0x4c:0x50])[0]
        res["chunk_len"] = chunk_len_32
        res["chunk_data"] = data[0x64 : 0x64 + chunk_len_32]
    return res


def parse_minifile_packet(data: bytes) -> Optional[dict]:
    """Parse incoming Mini-File packet header and extract command and metadata."""
    if len(data) < 12:
        return None
    total_len = struct.unpack(">I", data[:4])[0]
    p_type = struct.unpack(">I", data[4:8])[0]
    p_cmd = struct.unpack(">I", data[8:12])[0]
    res = {"total_len": total_len, "type": p_type, "cmd": p_cmd}
    if p_cmd == 1 and len(data) >= 12:
        # Command 1: Download Request
        import re
        m = re.search(rb'\|([0-9a-fA-F]{32})', data)
        if m:
            res["md5"] = m.group(1).decode("ascii").lower()
        else:
            m_v = re.search(rb'"v"\s*:\s*"([0-9a-fA-F]{32})"', data)
            if m_v:
                res["md5"] = m_v.group(1).decode("ascii").lower()
            elif len(data) >= 0x90:
                raw_md5 = data[0x70:0x90].decode("ascii", errors="ignore").strip("\x00")
                if len(raw_md5) == 32 and all(c in "0123456789abcdefABCDEF" for c in raw_md5):
                    res["md5"] = raw_md5.lower()
    elif p_cmd == 2 and len(data) >= 356:
        # Command 2: Download Response
        res["status"] = struct.unpack(">I", data[0x70:0x74])[0]
        res["md5"] = data[0x74:0x94].decode("ascii", errors="ignore").strip("\x00")
        res["file_size"] = struct.unpack(">Q", data[0x94:0x9C])[0]
    elif p_cmd == 3 and len(data) >= 0x98:
        # Command 3: Data Chunk
        res["file_size"] = struct.unpack(">Q", data[0x70:0x78])[0]
        res["offset"] = struct.unpack(">Q", data[0x78:0x80])[0]
        res["chunk_len"] = struct.unpack(">I", data[0x80:0x84])[0]
        res["chunk_data"] = data[0x98:0x98 + res["chunk_len"]]
    return res


def check_and_save_image(raw_bytes: bytes, output_dir: Optional[str] = None) -> Optional[str]:
    """Detect image magic (PNG, JPG, GIF, BMP) in raw TCP payload and save to disk."""
    import uuid
    if output_dir is None:
        output_dir = os.path.join(PROJECT_ROOT, "captures", "images")
    os.makedirs(output_dir, exist_ok=True)

    png_magic = b"\x89PNG\r\n\x1a\n"
    jpg_magic = b"\xff\xd8\xff"
    gif_magic = b"GIF8"
    bmp_magic = b"BM"

    ext = None
    offset = -1
    for magic, extension in [(png_magic, "png"), (jpg_magic, "jpg"), (gif_magic, "gif"), (bmp_magic, "bmp")]:
        pos = raw_bytes.find(magic)
        if pos != -1:
            ext = extension
            offset = pos
            break

    if ext and offset != -1:
        img_data = raw_bytes[offset:]
        filename = f"captured_{int(time.time())}_{uuid.uuid4().hex[:6]}.{ext}"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "wb") as f:
            f.write(img_data)
        return filepath
    return None


class LanBridgeTester:
    """Active network endpoint simulator for Nwt protocol validation."""

    def __init__(
        self,
        sandbox_ip: str = "172.31.122.7",
        local_ip: str = "0.0.0.0",
        broadcast_ip: str = "172.31.127.255",
        user_id: str = DEFAULT_USER_ID,
        nick: str = DEFAULT_NICKNAME,
        group: str = DEFAULT_GROUP,
        dynamic_port: int = 53782,
        initial_msg: Optional[str] = None,
        image_path: Optional[str] = None,
        image_caption: str = "",
        file_to_send: Optional[str] = None,
        mode: str = "native",
    ) -> None:
        self.sandbox_ip = sandbox_ip
        self.local_ip = local_ip
        self.broadcast_ip = broadcast_ip
        self.user_id = user_id
        self.nick = nick
        self.group = group
        self.dynamic_port = dynamic_port
        self.initial_msg = initial_msg
        self.image_path = image_path
        self.image_caption = image_caption
        self.file_to_send = file_to_send
        self.mode = mode.lower().strip()

        self.image_sent = False
        self.file_sent = False
        self.pending_images: dict[str, bytes] = {}
        self.pending_tokens: dict[int, str] = {}
        self.pending_files: dict[int, dict] = {}
        self.peer_file_port: Optional[int] = None
        self.peer_reverse_port: Optional[int] = None



        self.sock_9011: Optional[socket.socket] = None
        self.sock_9012: Optional[socket.socket] = None
        self.sock_dyn: Optional[socket.socket] = None
        self.sock_2425: Optional[socket.socket] = None

        self.running = False
        self.packet_count_rx = 0
        self.packet_count_tx = 0
        self.heartbeat_ack_count = 0
        self.ipmsg_ack_count = 0
        self.sandbox_dyn_port: Optional[int] = None

        # ENet Protocol State
        self.out_peer: int = 0
        self.in_sess: int = 0
        self.out_sess: int = 0
        self.my_time: int = random.randint(0x2000, 0xD000)
        self.remote_time: int = 0
        self.my_seq: int = 1
        self.handshake_completed = False
        self.initial_msg_sent = False
        self.handshake_9012_started = False
        self.header_flag: int = 0x9000
        self.last_heartbeat_time = 0.0

        # Fragment reassembler: start_seq -> {'parts': {num: bytes}, 'count': int, 'total': int}
        self.frag_assembler: dict[int, dict] = {}
        self.processed_msg_ids: set[int] = set()

        # TCP P2P Image/File Transfer Servers (9013: Normal, 9015: Reverse, 13603: Sandbox Alt)
        self.tcp_listeners: dict[int, socket.socket] = {}
        self.tcp_clients: List[socket.socket] = []
        self.tcp_connecting: set[socket.socket] = set()
        self.tcp_buffers: dict[socket.socket, bytearray] = {}
        self.minifile_served: set[str] = set()

    def send_minifile_stream(
        self,
        sock: socket.socket,
        md5_hex: str,
        token: int = 0,
        is_folder_tran: bool = True,
    ) -> bool:
        """Stream an image file to a connected TCP socket.

        Supports:
        - CFolderTranEngine (Default for native chat images, Cmd 1 500B -> Cmd 2 108B -> Cmd 3 108B -> Cmd 4 data).
        - CLanFileTran (Legacy/alternative, Cmd 1 344B -> Cmd 2 356B -> Cmd 3 data).
        """
        img_data = self.pending_images.get(md5_hex)
        if not img_data:
            logger.warning("[TCP:STREAM] Image MD5 %s not found in pending_images!", md5_hex)
            return False

        file_size = len(img_data)
        engine_name = "CFolderTranEngine" if is_folder_tran else "CLanFileTran"
        logger.info("=" * 65)
        logger.info(
            "[TCP:STREAM] >>> STARTING MINI-FILE STREAM: MD5=%s, Size=%dB, Token=%d, Engine=%s",
            md5_hex, file_size, token, engine_name
        )
        logger.info("=" * 65)
        try:
            # Set socket to blocking mode for reliable transmission
            sock.setblocking(True)
            sock.settimeout(5.0)

            if is_folder_tran:
                # 1. Send Command 2 (CFolderTranEngine Response, 108 bytes with token)
                rsp = build_folder_tran_response(file_size=file_size, token=token, chunk_size=16384)
                sock.sendall(rsp)
                logger.info("[TCP:STREAM] >>> Sent CFolderTranEngine Command 2 (108B, token=%d, size=%d)", token, file_size)

                # 2. Wait for Command 3 (108 bytes Chunk Request from Sandbox)
                leftover = bytes(self.tcp_buffers.get(sock, bytearray()))
                if sock in self.tcp_buffers:
                    self.tcp_buffers[sock].clear()

                cmd3_buf = bytearray(leftover)
                while len(cmd3_buf) < 108:
                    try:
                        part = sock.recv(108 - len(cmd3_buf))
                        if not part:
                            break
                        cmd3_buf.extend(part)
                    except socket.timeout:
                        break

                start_offset = 0
                if len(cmd3_buf) >= 12:
                    cmd3_pkt = parse_folder_tran_packet(bytes(cmd3_buf))
                    if cmd3_pkt and cmd3_pkt.get("cmd") == 3:
                        start_offset = cmd3_pkt.get("offset", 0)
                        cli_token = cmd3_pkt.get("token", 0)
                        if cli_token:
                            token = cli_token
                        logger.info(
                            "[TCP:STREAM] <<< Received Command 3 from client: token=%d, offset=%d",
                            token, start_offset
                        )
                    else:
                        logger.warning("[TCP:STREAM] Received unexpected packet instead of Command 3: %s", cmd3_buf[:12].hex())
                else:
                    logger.warning("[TCP:STREAM] Did not receive complete Command 3, proceeding from offset 0")

                # 3. Stream Command 4 (Data Chunks, 16384 bytes each)
                chunk_size = 16384
                offset = start_offset
                chunk_idx = 1
                while offset < file_size:
                    piece = img_data[offset : offset + chunk_size]
                    chunk_pkt = build_folder_tran_chunk(file_size=file_size, offset=offset, chunk_data=piece, token=token)
                    sock.sendall(chunk_pkt)
                    logger.debug(
                        "[TCP:STREAM] >>> Sent Command 4 Chunk #%d (token=%d, offset=%d, len=%dB, total_pkt=%dB)",
                        chunk_idx, token, offset, len(piece), len(chunk_pkt)
                    )
                    offset += len(piece)
                    chunk_idx += 1
                    time.sleep(0.005)

            else:
                # CLanFileTran mode
                rsp = build_minifile_response(md5_hex.lower(), file_size, status=0)
                sock.sendall(rsp)
                logger.info("[TCP:STREAM] >>> Sent CLanFileTran Command 2 (356B)")

                chunk_size = 16384
                offset = 0
                chunk_idx = 1
                while offset < file_size:
                    piece = img_data[offset : offset + chunk_size]
                    chunk_pkt = build_minifile_chunk(file_size, offset, piece)
                    sock.sendall(chunk_pkt)
                    logger.debug(
                        "[TCP:STREAM] >>> Sent Chunk #%d (offset=%d, len=%dB, total_pkt=%dB)",
                        chunk_idx, offset, len(piece), len(chunk_pkt)
                    )
                    offset += len(piece)
                    chunk_idx += 1
                    time.sleep(0.005)

            logger.info("*" * 65)
            logger.info("[TCP:STREAM] >>> ALL CHUNKS SENT SUCCESSFULLY! (%d bytes total)", file_size)
            logger.info("*" * 65)
            self.minifile_served.add(md5_hex.lower())
            return True
        except Exception as e:
            logger.error("[TCP:STREAM] Stream error: %s", e)
            return False
        finally:
            try:
                sock.setblocking(False)
            except Exception:
                pass

    def init_sockets(self) -> None:
        """Create and bind UDP sockets (9011, 9012, dynamic, 2425) and TCP listeners (9013-9016, 13603)."""
        def make_udp_socket(port: int) -> socket.socket:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setblocking(False)
            try:
                s.bind((self.local_ip, port))
                logger.info("Bound UDP socket on %s:%d", self.local_ip, port)
            except OSError as e:
                logger.warning("Could not bind UDP %d on %s: %s", port, self.local_ip, e)
            return s

        self.sock_9011 = make_udp_socket(9011)
        self.sock_9012 = make_udp_socket(9012)
        self.sock_dyn = make_udp_socket(self.dynamic_port)
        self.sock_2425 = make_udp_socket(2425)

        # TCP listeners on 9013 (File), 9014 (Folder), 9015 (Reverse File), 9016 (Reverse Folder), 13603 (Sandbox Alt)
        for port in (9013, 9014, 9015, 9016, 13603):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setblocking(False)
                s.bind((self.local_ip, port))
                s.listen(5)
                self.tcp_listeners[port] = s
                desc = "Normal" if port == 9013 else ("Reverse File" if port == 9015 else f"Port {port}")
                logger.info("Bound TCP server on %s:%d (%s)", self.local_ip, port, desc)
            except OSError as e:
                logger.warning("Could not bind TCP %d on %s: %s", port, self.local_ip, e)

    def close_sockets(self) -> None:
        """Close all sockets."""
        for s in (self.sock_9011, self.sock_9012, self.sock_dyn, self.sock_2425):
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        for s in self.tcp_listeners.values():
            try:
                s.close()
            except Exception:
                pass
        self.tcp_listeners.clear()
        for c in self.tcp_clients:
            try:
                c.close()
            except Exception:
                pass
        self.tcp_clients.clear()
        self.tcp_buffers.clear()


    def send_discovery_broadcast(self) -> None:
        """Send 304B Nwt discovery frame to Sandbox unicast and subnet broadcast."""
        pkt = build_nwt_discovery_packet(
            cmd=1,
            user_id=self.user_id,
            broadcast_ip=self.broadcast_ip,
            dynamic_port=self.dynamic_port,
        )
        reply_pkt = build_nwt_discovery_packet(
            cmd=2,
            user_id=self.user_id,
            broadcast_ip=self.broadcast_ip,
            dynamic_port=self.dynamic_port,
        )
        if self.sock_9011:
            self.sock_9011.sendto(pkt, (self.sandbox_ip, 9011))
            self.sock_9011.sendto(reply_pkt, (self.sandbox_ip, 9011))
            self.packet_count_tx += 2
            try:
                self.sock_9011.sendto(pkt, (self.broadcast_ip, 9011))
                self.packet_count_tx += 1
            except OSError:
                pass
            logger.info("Sent 304B Nwt discovery (Broadcast & Reply) to %s:9011 and %s:9011", self.sandbox_ip, self.broadcast_ip)

    def send_ipmsg_online(self) -> None:
        """Send IPMSG BR_ENTRY online announcement to UDP 2425."""
        use_prefix = (self.mode == "native")
        pkt = build_ipmsg_packet(
            command=1,
            user="LanBridge",
            host="HOST-BOT",
            nick=self.nick,
            group=self.group,
            user_id=self.user_id,
            use_shiyeline_prefix=use_prefix,
        )
        sock = self.sock_2425 or self.sock_9011
        if sock:
            sock.sendto(pkt, (self.sandbox_ip, 2425))
            self.packet_count_tx += 1
            try:
                sock.sendto(pkt, (self.broadcast_ip, 2425))
                self.packet_count_tx += 1
            except OSError:
                pass

    def send_handshake_init(self) -> None:
        """Send ENet 0x82 CONNECT packet to initiate Stage 1 native handshake."""
        cid = random.randbytes(4)
        self.my_time = random.randint(0x2000, 0xD000)
        pkt_82 = (
            b"\x8f\xff"
            + struct.pack(">H", self.my_time)
            + b"\x82\xff\x00\x01\x00\x00\x00\x00\x00\x00\x05\x78\x00\x01\x00\x00\x00\x00\x00\x01"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x88\x00\x00\x00\x02\x00\x00\x00\x02"
            + cid
            + b"\x00\x00\x00\x00"
        )
        if self.sock_9012:
            self.sock_9012.sendto(pkt_82, (self.sandbox_ip, 9012))
            self.packet_count_tx += 1
            self.handshake_9012_started = True
            logger.info("[TX:9012] Sent ENet Connect 0x82 (cid=%s) to %s:9012", cid.hex(), self.sandbox_ip)

    def send_native_envelope(self, env: bytes, target_ip: Optional[str] = None) -> None:
        """Send an encrypted envelope over UDP 9012 via ENet (0x86 or 0x88 fragments)."""
        dst_ip = target_ip or self.sandbox_ip
        if not self.sock_9012:
            return

        tot_len = len(env)
        self.my_time = (self.my_time + 1) & 0xFFFF
        if tot_len <= 1372:
            hdr = struct.pack(">HH", self.header_flag, self.my_time)
            cmd = struct.pack(">BBHH", 0x86, 0x00, self.my_seq, tot_len)
            self.my_seq = (self.my_seq + 1) & 0xFFFF
            self.sock_9012.sendto(hdr + cmd + env, (dst_ip, 9012))
            self.packet_count_tx += 1
        else:
            chunks = [env[i : i + 1372] for i in range(0, tot_len, 1372)]
            start_seq = self.my_seq
            for idx, chk in enumerate(chunks):
                self.my_time = (self.my_time + 1) & 0xFFFF
                hdr = struct.pack(">HH", self.header_flag, self.my_time)
                cmd = struct.pack(">BBH", 0x88, 0x00, self.my_seq)
                frag_hdr = struct.pack(">HHIIII", start_seq, len(chk), len(chunks), idx, tot_len, idx * 1372)
                self.sock_9012.sendto(hdr + cmd + frag_hdr + chk, (dst_ip, 9012))
                self.packet_count_tx += 1
                self.my_seq = (self.my_seq + 1) & 0xFFFF

    def send_native_chat_message(self, message: str, target_ip: Optional[str] = None) -> None:
        """Send a native Nwt text message over UDP 9012 via XTEA-encrypted X_SEND_MSG."""
        env = build_x_send_msg_envelope(message)
        self.send_native_envelope(env, target_ip)
        logger.info("=" * 65)
        logger.info("[CHAT:9012] >>> SENT NATIVE CHAT MESSAGE: \"%s\"", message)
        logger.info("=" * 65)

    def send_native_image_message(
        self,
        image_path: str,
        caption: str = "",
        target_ip: Optional[str] = None,
        img_type: str = "feihu",
    ) -> None:
        """Send an inline image message over UDP 9012."""
        import hashlib
        with open(image_path, "rb") as f:
            img_data = f.read()
        img_md5 = hashlib.md5(img_data).hexdigest()
        self.pending_images[img_md5] = img_data

        token = random.randint(10000, 30000)
        self.pending_tokens[token] = img_md5
        env = build_x_send_image_envelope(
            img_md5=img_md5,
            token=token,
            caption=caption,
            img_type=img_type,
        )
        self.send_native_envelope(env, target_ip)
        logger.info("=" * 65)
        logger.info("[IMAGE:9012] >>> SENT INLINE IMAGE MESSAGE: MD5=%s (token=%d, size=%dB)", img_md5, token, len(img_data))
        if caption:
            logger.info("[IMAGE:9012] >>> CAPTION: \"%s\"", caption)
        logger.info("=" * 65)

    def send_native_file_transfer(
        self,
        file_path: str,
        task_id: int = 1,
        target_ip: Optional[str] = None,
    ) -> None:
        """Send an authentic X_SEND_FILE file transfer proposal."""
        filename = os.path.basename(file_path)
        size = os.path.getsize(file_path)
        last_mod = int(os.path.getmtime(file_path))
        self.pending_files[task_id] = {
            "path": file_path,
            "filename": filename,
            "size": size,
            "offset": 0,
        }
        env = build_x_send_file_envelope(
            filename=filename,
            size=size,
            task_id=task_id,
            file_id=task_id,
            last_modify=last_mod,
        )
        self.send_native_envelope(env, target_ip)
        logger.info("=" * 65)
        logger.info("[FILE:9012] >>> SENT FILE TRANSFER PROPOSAL: %s (%dB, task_id=%d)", filename, size, task_id)
        logger.info("=" * 65)


    def send_text_message(self, message: str, target_ip: Optional[str] = None) -> None:
        """Send a text message in accordance with operational mode."""
        if self.mode == "native":
            self.send_native_chat_message(message, target_ip)
        else:
            dst_ip = target_ip or self.sandbox_ip
            pkt = build_ipmsg_send_msg(message=message, user="LanBridge", host="HOST-BOT")
            sock = self.sock_2425 or self.sock_9011
            if sock:
                sock.sendto(pkt, (dst_ip, 2425))
                self.packet_count_tx += 1
                logger.info("[TX:2425] >>> Sent IPMSG text message to %s:2425: \"%s\"", dst_ip, message)

    def send_stage5_profile(self, target_ip: str, target_port: int = 9012) -> None:
        """Send dynamic Host profile fragments (Opcode 0x88) to create native contact."""
        profile_env = build_native_profile(nick=self.nick, user_id=self.user_id, group=self.group)
        tot_len = len(profile_env)
        chunks = [profile_env[i : i + 1372] for i in range(0, tot_len, 1372)]
        start_seq = self.my_seq

        for idx, chk in enumerate(chunks):
            self.my_time = (self.my_time + 1) & 0xFFFF
            hdr = struct.pack(">HH", self.header_flag, self.my_time)
            cmd = struct.pack(">BBH", 0x88, 0x00, self.my_seq)
            frag_hdr = struct.pack(">HHIIII", start_seq, len(chk), len(chunks), idx, tot_len, idx * 1372)
            if self.sock_9012:
                self.sock_9012.sendto(hdr + cmd + frag_hdr + chk, (target_ip, target_port))
                self.packet_count_tx += 1
                logger.info("[TX:9012] Sent Profile Fragment %d/%d (%dB) seq=%d", idx + 1, len(chunks), len(chk), self.my_seq)
            self.my_seq = (self.my_seq + 1) & 0xFFFF

    def handle_incoming_packet(self, sock: socket.socket, local_port: int) -> None:
        """Receive and process a packet on the given socket."""
        try:
            data, addr = sock.recvfrom(4096)
        except (BlockingIOError, OSError):
            return

        self.packet_count_rx += 1
        src_ip, src_port = addr

        # Ignore self-loopback
        if src_ip in ("127.0.0.1", "172.31.112.1") and src_port in (9011, 9012, self.dynamic_port, 2425):
            return

        # ------------------------------------------------------------------
        # 1. Handle UDP 2425 IPMSG Packets
        # ------------------------------------------------------------------
        if local_port == 2425 or (src_port == 2425 and b":" in data[:20]):
            text = data.decode("gbk", errors="replace")
            parts = text.split(":", 5)
            if len(parts) >= 5:
                raw_cmd = int(parts[4]) if parts[4].isdigit() else 0
                cmd_code = raw_cmd & 0xFF
                extra = parts[5].split("\x00") if len(parts) > 5 else []
                sender_nick = extra[0] if extra else parts[2]
                if cmd_code == 3:  # IPMSG_ANSENTRY
                    self.ipmsg_ack_count += 1
                    logger.info("[RX:2425] Sandbox IPMSG ACK from %s (%s)", src_ip, sender_nick)
                elif cmd_code == 32:  # IPMSG_SENDMSG
                    msg_body = parts[5].rstrip("\x00") if len(parts) > 5 else ""
                    rx_pkt_no = parts[1]
                    logger.info("=" * 65)
                    logger.info("[CHAT:2425] <<< RECEIVED IPMSG MESSAGE FROM [%s]: %s", sender_nick, msg_body)
                    logger.info("=" * 65)
                    ack_pkt = build_ipmsg_recv_ack(packet_no_ack=rx_pkt_no)
                    sock.sendto(ack_pkt, addr)
                    self.packet_count_tx += 1
            return

        # ------------------------------------------------------------------
        # 2. Handle UDP 9011 Discovery Packets
        # ------------------------------------------------------------------
        if local_port == 9011 and len(data) == 304 and data[:4] == b"\x00\x00\x01\x30":
            cmd = int.from_bytes(data[4:8], "big")
            sender_uid = data[30:62].decode("ascii", errors="replace").strip("\x00")
            if data[165:167] != b"\x00\x00":
                self.sandbox_dyn_port = int.from_bytes(data[165:167], "big")

            logger.info(
                "[RX:9011] Discovery frame from %s:%d | cmd=%d (%s) | uid=%s | dyn_port=%s",
                src_ip,
                src_port,
                cmd,
                "Broadcast" if cmd == 1 else "Reply",
                sender_uid[:8],
                self.sandbox_dyn_port,
            )

            if cmd == 1:
                reply = build_nwt_discovery_packet(
                    cmd=2,
                    user_id=self.user_id,
                    broadcast_ip=self.broadcast_ip,
                    dynamic_port=self.dynamic_port,
                )
                sock.sendto(reply, (src_ip, 9011))
                self.packet_count_tx += 1

            if not self.handshake_9012_started:
                self.send_handshake_init()
            return

        # ------------------------------------------------------------------
        # 3. Handle UDP 9012 Native Binary Protocol Packets
        # ------------------------------------------------------------------
        if local_port == 9012 and len(data) >= 8:
            h_val, = struct.unpack(">H", data[:2])
            has_sent_time = bool(h_val & 0x8000)
            offset = 4 if has_sent_time else 2
            r_time = struct.unpack(">H", data[2:4])[0] if has_sent_time else 0

            # Check if this is initial 0x83 VERIFY_CONNECT
            if data[4] == 0x83:
                flag_peer, sb_sent_time = struct.unpack(">HH", data[:4])
                cmd, ch, seq = struct.unpack(">BBH", data[4:8])
                self.out_peer, self.in_sess, self.out_sess = struct.unpack(">HBB", data[8:12])
                logger.info("[RX:9012] HandshakeReply (0x83) from %s:%d | outPeer=%d inSess=%d", src_ip, src_port, self.out_peer, self.in_sess)

                # Formulate Frame 11 (header = 0x8000 | (in_sess << 12) | out_peer)
                self.header_flag = 0x8000 | ((self.in_sess & 3) << 12) | (self.out_peer & 0x0FFF)
                self.my_time = (self.my_time + 0x66) & 0xFFFF
                hdr = struct.pack(">HH", self.header_flag, self.my_time)
                cmd_ack = struct.pack(">BBHHH", 0x01, 0xFF, 0x0001, 0x0001, sb_sent_time)
                cmd_ping = struct.pack(">BBH", 0x85, 0xFF, 0x0002)
                sock.sendto(hdr + cmd_ack + cmd_ping, addr)
                self.packet_count_tx += 1
                logger.info("[TX:9012] Sent Frame 11 (header=0x%04x) to %s:9012", self.header_flag, src_ip)

                # Send Frame 17 (304B Node Announcement with cmd=4)
                self.my_time = (self.my_time + 0x65) & 0xFFFF
                hdr17 = struct.pack(">HH", self.header_flag, self.my_time)
                cmd17 = struct.pack(">BBHH", 0x86, 0x00, 0x0001, 304)
                disc_directed = bytearray(build_nwt_discovery_packet(cmd=4, user_id=self.user_id, dynamic_port=self.dynamic_port))
                sock.sendto(hdr17 + cmd17 + disc_directed, addr)
                self.packet_count_tx += 1
                logger.info("[TX:9012] Sent Frame 17 (304B Node Announcement) to %s:9012", src_ip)

                # Send Stage 5 Profile Fragments
                self.my_seq = 2
                self.send_stage5_profile(src_ip, 9012)
                return

            acks_to_send: List[Tuple[int, int]] = []

            while offset < len(data):
                c_byte, c_chan, c_seq = struct.unpack(">BBH", data[offset : offset + 4])
                c_type = c_byte & 0x0F
                offset += 4

                if c_type == 1:  # ACK
                    rx_seq, rx_time = struct.unpack(">HH", data[offset : offset + 4])
                    offset += 4
                    logger.debug("[RX:9012] ACK for chan=%d seq=%d", c_chan, rx_seq)

                elif c_type == 8:  # SEND_FRAGMENT
                    s_seq, d_len, f_cnt, f_num, tot_l, f_off = struct.unpack(">HHIIII", data[offset : offset + 20])
                    f_data = data[offset + 20 : offset + 20 + d_len]
                    offset += 20 + d_len
                    acks_to_send.append((c_chan, c_seq))

                    if s_seq not in self.frag_assembler:
                        self.frag_assembler[s_seq] = {"parts": {}, "count": f_cnt, "total": tot_l}
                    self.frag_assembler[s_seq]["parts"][f_num] = f_data

                    if len(self.frag_assembler[s_seq]["parts"]) == f_cnt:
                        full_p = b"".join(self.frag_assembler[s_seq]["parts"][i] for i in range(f_cnt))
                        if len(full_p) >= 8:
                            tot_len, op = struct.unpack(">2I", full_p[:8])
                            raw_dec = xtea_engine.decrypt(full_p[8:])
                            try:
                                dec_xml = raw_dec.decode("utf-8")
                            except UnicodeDecodeError:
                                dec_xml = raw_dec.decode("gbk", errors="ignore")

                            if op == 0x03E8:
                                logger.info("[RX:9012] Received Sandbox Profile (X_HANDSHARK): %s", dec_xml)
                                import re
                                m_f = re.search(r"<FILE_TRAN_TCP_PORT>(\d+)</FILE_TRAN_TCP_PORT>", dec_xml)
                                if m_f:
                                    self.peer_file_port = int(m_f.group(1))
                                m_r = re.search(r"<FILE_TRAN_TCP_REVERSE_PORT>(\d+)</FILE_TRAN_TCP_REVERSE_PORT>", dec_xml)
                                if m_r:
                                    self.peer_reverse_port = int(m_r.group(1))
                                logger.info("[PROFILE:NET] Peer ports: FILE=%s, REVERSE=%s", self.peer_file_port, self.peer_reverse_port)
                                if self.peer_file_port and self.peer_file_port not in self.tcp_listeners:
                                    try:
                                        s_dyn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                        s_dyn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                        s_dyn.setblocking(False)
                                        s_dyn.bind((self.local_ip, self.peer_file_port))
                                        s_dyn.listen(5)
                                        self.tcp_listeners[self.peer_file_port] = s_dyn
                                        logger.info("Bound dynamic TCP server on %s:%d to match peer FILE_TRAN_TCP_PORT", self.local_ip, self.peer_file_port)
                                    except Exception as ex:
                                        logger.warning("Could not bind dynamic TCP %d: %s", self.peer_file_port, ex)

                            elif op == 0x03EC:
                                msg_id = extract_msg_id(dec_xml)
                                # Send SendMsgAck (0x03ed) echoing peer's exact MSG_ID
                                ack_env = build_x_send_msg_ack_envelope(msg_id)
                                self.my_time = (self.my_time + 1) & 0xFFFF
                                h_ack = struct.pack(">HH", self.header_flag, self.my_time)
                                cmd_ack = struct.pack(">BBHH", 0x86, 0x00, self.my_seq, len(ack_env))
                                self.my_seq = (self.my_seq + 1) & 0xFFFF
                                sock.sendto(h_ack + cmd_ack + ack_env, addr)
                                self.packet_count_tx += 1

                                if msg_id not in self.processed_msg_ids:
                                    self.processed_msg_ids.add(msg_id)
                                    msg_text = extract_chat_message(dec_xml)
                                    logger.info("=" * 65)
                                    logger.info("[CHAT:9012] <<< RECEIVED NATIVE CHAT MESSAGE (id=%d): %s", msg_id, msg_text)
                                    logger.info("=" * 65)

                                    # Auto-reply once per new message
                                    auto_reply = f"LanBridge Bot 收到: {msg_text}"
                                    self.send_native_chat_message(auto_reply, target_ip=src_ip)

                            else:
                                logger.info("[RX:9012-FRAG] Received Opcode 0x%04X (%d): %s", op, op, dec_xml)

                elif c_type == 6:  # SEND_RELIABLE
                    d_len, = struct.unpack(">H", data[offset : offset + 2])
                    p_data = data[offset + 2 : offset + 2 + d_len]
                    offset += 2 + d_len
                    acks_to_send.append((c_chan, c_seq))

                    if len(p_data) >= 8:
                        tot_len, op = struct.unpack(">2I", p_data[:8])
                        raw_dec = xtea_engine.decrypt(p_data[8:])
                        try:
                            dec_xml = raw_dec.decode("utf-8")
                        except UnicodeDecodeError:
                            dec_xml = raw_dec.decode("gbk", errors="ignore")

                        if op == 0x03FA:  # X_READY
                            logger.info("[RX:9012] Received Sandbox X_READY! Sending Host X_READY...")
                            ready_env = build_x_ready_envelope(self.user_id)
                            self.my_time = (self.my_time + 1) & 0xFFFF
                            hdr = struct.pack(">HH", self.header_flag, self.my_time)
                            cmd_r = struct.pack(">BBHH", 0x86, 0x00, self.my_seq, len(ready_env))
                            self.my_seq = (self.my_seq + 1) & 0xFFFF
                            sock.sendto(hdr + cmd_r + ready_env, addr)
                            self.packet_count_tx += 1
                            self.handshake_completed = True
                            logger.info("*** NATIVE HANDSHAKE COMPLETED SUCCESSFULLY! Contact is now ONLINE in '内网通联系人' ***")

                            if self.initial_msg and not self.initial_msg_sent:
                                time.sleep(0.2)
                                self.send_native_chat_message(self.initial_msg)
                                self.initial_msg_sent = True

                            if self.image_path and not self.image_sent:
                                time.sleep(0.5)
                                self.send_native_image_message(self.image_path, caption=self.image_caption)
                                self.image_sent = True

                            if self.file_to_send and not self.file_sent:
                                time.sleep(0.5)
                                self.send_native_file_transfer(self.file_to_send)
                                self.file_sent = True

                        elif op == 0x03F8:  # X_HEARTBEAT
                            logger.debug("[RX:9012] Received peer X_HEARTBEAT")

                        elif op == 0x03EC:  # X_SEND_MSG
                            msg_id = extract_msg_id(dec_xml)
                            # Send SendMsgAck (0x03ed) echoing peer's exact MSG_ID
                            ack_env = build_x_send_msg_ack_envelope(msg_id)
                            self.my_time = (self.my_time + 1) & 0xFFFF
                            h_ack = struct.pack(">HH", self.header_flag, self.my_time)
                            cmd_ack = struct.pack(">BBHH", 0x86, 0x00, self.my_seq, len(ack_env))
                            self.my_seq = (self.my_seq + 1) & 0xFFFF
                            sock.sendto(h_ack + cmd_ack + ack_env, addr)
                            self.packet_count_tx += 1

                            if msg_id not in self.processed_msg_ids:
                                self.processed_msg_ids.add(msg_id)
                                msg_text = extract_chat_message(dec_xml)
                                logger.info("=" * 65)
                                logger.info("[CHAT:9012] <<< RECEIVED NATIVE CHAT MESSAGE (id=%d): %s", msg_id, msg_text)
                                logger.info("=" * 65)

                                # Auto-reply once per new message
                                if '"recall"' in dec_xml or '&quot;recall&quot;' in dec_xml or '"type": "6"' in dec_xml:
                                    logger.info("[RECALL:9012] <<< PEER RECALLED A MESSAGE OR FILE (对方撤回了消息/文件)!")
                                else:
                                    auto_reply = f"LanBridge Bot 收到: {msg_text}"
                                    self.send_native_chat_message(auto_reply, target_ip=src_ip)

                        elif op == 0x03EF:  # X_SEND_FLASH_SCREEN
                            logger.info("=" * 65)
                            logger.info("[ACTION:9012] <<< RECEIVED WINDOW SHAKE / FLASH SCREEN (收到对端窗口抖动)!")
                            logger.info("=" * 65)
                            auto_reply = "LanBridge Bot 收到窗口抖动！"
                            self.send_native_chat_message(auto_reply, target_ip=src_ip)

                        elif op == 0x03F3:  # X_OPERATE_RECV_FILE
                            logger.info("[FILE:9012] Peer performed file receive operation: %s", dec_xml)
                            if "<OP>1</OP>" in dec_xml or "<OP>1 </OP>" in dec_xml:
                                logger.info("*" * 65)
                                logger.info("[FILE:ACCEPTED] REMOTE USER ACCEPTED FILE TRANSFER!")
                                logger.info("*" * 65)
                                for p in (self.peer_file_port, self.peer_reverse_port):
                                    if p:
                                        try:
                                            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                            c.setblocking(False)
                                            err = c.connect_ex((self.sandbox_ip, p))
                                            self.tcp_clients.append(c)
                                            self.tcp_buffers[c] = bytearray()
                                            logger.info("[TCP:FILE_RECV] Connecting to Sandbox %s:%d (code=%d)", self.sandbox_ip, p, err)
                                        except Exception as ex:
                                            logger.warning("[TCP:FILE_RECV] Connect error %s:%d: %s", self.sandbox_ip, p, ex)

                        elif op == 0x03F2:  # X_OPERATE_SEND_FILE
                            logger.info("[FILE:9012] Peer performed file send operation: %s", dec_xml)

                        elif op == 0x03F4:  # X_PROGRESS_RECV_FILE
                            logger.debug("[FILE:9012] Peer file progress sync: %s", dec_xml)

                        elif op == 0x03FB:  # X_REVERSE_FILE_REQ
                            logger.info("[FILE:9012] <<< RECEIVED X_REVERSE_FILE_REQ (Peer requests reverse transfer): %s", dec_xml)
                            for p in (self.peer_reverse_port, self.peer_file_port):
                                if p:
                                    try:
                                        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                        c.setblocking(False)
                                        err = c.connect_ex((self.sandbox_ip, p))
                                        self.tcp_clients.append(c)
                                        self.tcp_buffers[c] = bytearray()
                                        logger.info("[TCP:OUTBOUND] Connecting to Sandbox reverse port %s:%d (code=%d)", self.sandbox_ip, p, err)
                                    except Exception as ex:
                                        logger.warning("[TCP:OUTBOUND] Connect error %s:%d: %s", self.sandbox_ip, p, ex)


                        elif op == 0x03FE:  # X_OFFLINE_SEND_COMPLETED
                            logger.info("[MSG:9012] Peer completed offline message flushing: %s", dec_xml)

                        elif op == 0x03ED:  # X_SEND_MSG_ACK
                            logger.debug("[MSG:9012] Received X_SEND_MSG_ACK receipt: %s", dec_xml)

                        else:
                            logger.info("[RX:9012] Received unknown Opcode 0x%04X (%d): %s", op, op, dec_xml)



                elif c_type == 10:  # BANDWIDTH_LIMIT
                    offset += 8
                    acks_to_send.append((c_chan, c_seq))

                elif c_type == 5:  # PING
                    acks_to_send.append((c_chan, c_seq))
                    self.heartbeat_ack_count += 1

                else:
                    break

            # Send batched ACKs
            if acks_to_send:
                ack_hdr = struct.pack(">H", 0x1000 | (self.out_peer & 0x0FFF))
                ack_cmds = bytearray()
                for chan, sq in acks_to_send:
                    ack_cmds.extend(struct.pack(">BBHHH", 0x01, chan, sq, sq, r_time))
                sock.sendto(ack_hdr + ack_cmds, addr)
                self.packet_count_tx += 1

    def run(self, duration_seconds: Optional[float] = None) -> None:
        """Run the main event loop sending discovery, handshaking, and maintaining session."""
        self.init_sockets()
        self.running = True
        logger.info("=" * 65)
        logger.info("  LanBridge Active Network Verification Tester (M4 Native)")
        logger.info("  Operational Mode:   %s", self.mode.upper())
        logger.info("  Target Sandbox IP:  %s", self.sandbox_ip)
        logger.info("  Virtual Contact:    %s (Group: %s)", self.nick, self.group)
        logger.info("  Virtual User ID:    %s...", self.user_id[:8])
        logger.info("  Dynamic UDP Port:   %d", self.dynamic_port)
        logger.info("  Press Ctrl+C to terminate cleanly.")
        logger.info("=" * 65)

        # Initial discovery & presence broadcast
        self.send_discovery_broadcast()
        self.send_ipmsg_online()
        if self.mode == "native":
            self.send_handshake_init()
        elif self.mode == "ipmsg" and self.initial_msg:
            time.sleep(0.1)
            self.send_text_message(self.initial_msg)

        last_bcast_time = time.time()
        self.last_heartbeat_time = time.time()
        bcast_interval = 5.0
        heartbeat_interval = 2.5
        start_time = time.time()

        try:
            while self.running:
                now = time.time()
                if duration_seconds and (now - start_time) >= duration_seconds:
                    logger.info("Target duration (%.1fs) reached, exiting.", duration_seconds)
                    break

                if now - last_bcast_time >= bcast_interval:
                    self.send_discovery_broadcast()
                    last_bcast_time = now

                # Send periodic Heartbeat once connected
                if self.handshake_completed and (now - self.last_heartbeat_time >= heartbeat_interval):
                    self.last_heartbeat_time = now
                    if self.sock_9012:
                        self.my_time = (self.my_time + 10) & 0xFFFF
                        hdr = struct.pack(">HH", self.header_flag, self.my_time)
                        env_hb = build_x_heartbeat_envelope()
                        cmd_hb = struct.pack(">BBHH", 0x86, 0x00, self.my_seq, len(env_hb))
                        self.my_seq = (self.my_seq + 1) & 0xFFFF
                        self.sock_9012.sendto(hdr + cmd_hb + env_hb, (self.sandbox_ip, 9012))
                        self.packet_count_tx += 1
                        logger.debug("[TX:9012] Sent X_HEARTBEAT keepalive")

                socks = [s for s in (self.sock_9011, self.sock_9012, self.sock_dyn, self.sock_2425) if s]
                socks.extend(self.tcp_listeners.values())
                socks.extend(self.tcp_clients)

                readable, _, _ = select.select(socks, [], [], 0.05)
                for s in readable:
                    if s in self.tcp_listeners.values():
                        l_port = [p for p, sock in self.tcp_listeners.items() if sock == s][0]
                        try:
                            conn, caddr = s.accept()
                            conn.setblocking(False)
                            self.tcp_clients.append(conn)
                            self.tcp_buffers[conn] = bytearray()
                            logger.info("[TCP:%d] Inbound connection established from %s", l_port, caddr)
                        except Exception as e:
                            logger.warning("[TCP:%d] Accept error: %s", l_port, e)
                    elif s in self.tcp_clients:
                        peer_desc = "unknown"
                        try:
                            peer_desc = str(s.getpeername())
                        except Exception:
                            pass
                        try:
                            chunk = s.recv(8192)
                            if not chunk:
                                logger.info("[TCP:%s] Remote closed connection", peer_desc)
                                self.tcp_clients.remove(s)
                                s.close()
                                if s in self.tcp_buffers:
                                    del self.tcp_buffers[s]
                                continue
                            self.tcp_buffers[s].extend(chunk)
                            logger.info("[TCP:%s] Full Chunk Hex (%d bytes):\n%s", peer_desc, len(chunk), chunk.hex())
                            try:
                                logger.info("[TCP:%s] Chunk ASCII: %s", peer_desc, chunk.decode("latin1", errors="replace"))
                            except Exception:
                                pass
                            # Check for Mini-File / Image protocol command 1 (Download Request)
                            minifile_pkt = parse_folder_tran_packet(bytes(self.tcp_buffers[s])) or parse_minifile_packet(bytes(self.tcp_buffers[s]))
                            if minifile_pkt and minifile_pkt.get("cmd") == 1:
                                req_token = minifile_pkt.get("token", 0)
                                req_md5 = minifile_pkt.get("md5")
                                if not req_md5 and req_token in self.pending_tokens:
                                    req_md5 = self.pending_tokens[req_token]
                                elif not req_md5 and len(self.pending_images) == 1:
                                    req_md5 = next(iter(self.pending_images.keys()))

                                if req_md5:
                                    req_md5 = req_md5.lower()
                                    req_len = minifile_pkt["total_len"]
                                    is_folder_tran = (req_len == 500 or req_len >= 400)
                                    engine_name = "CFolderTranEngine" if is_folder_tran else "CLanFileTran"
                                    logger.info("=" * 65)
                                    logger.info(
                                        "[TCP:MINIFILE] <<< RECEIVED DOWNLOAD REQUEST (CMD 1) FOR MD5: %s (token=%d, total_len=%d, engine=%s)",
                                        req_md5, req_token, req_len, engine_name
                                    )
                                    logger.info("=" * 65)
                                    del self.tcp_buffers[s][:req_len]
                                    if self.send_minifile_stream(s, req_md5, token=req_token, is_folder_tran=is_folder_tran):
                                        logger.info("[TCP:MINIFILE] Image stream completed for MD5 %s", req_md5)
                                    else:
                                        logger.warning("[TCP:MINIFILE] Failed to stream image for MD5 %s", req_md5)

                            saved_img = check_and_save_image(bytes(self.tcp_buffers[s]))
                            if saved_img:
                                logger.info("*" * 65)
                                logger.info("[IMAGE:SUCCESS] EXTRACTED & SAVED IMAGE TO: %s (%d bytes)", saved_img, os.path.getsize(saved_img))
                                logger.info("*" * 65)
                        except Exception as e:
                            logger.warning("[TCP:9013] Read error: %s", e)
                            self.tcp_clients.remove(s)
                            s.close()
                            if s in self.tcp_buffers:
                                del self.tcp_buffers[s]
                    else:
                        port = (
                            9011
                            if s == self.sock_9011
                            else (
                                9012
                                if s == self.sock_9012
                                else (self.dynamic_port if s == self.sock_dyn else 2425)
                            )
                        )
                        self.handle_incoming_packet(s, port)

        except KeyboardInterrupt:
            logger.info("Interrupted by user.")
        finally:
            self.running = False
            self.close_sockets()
            logger.info(
                "Tester stopped. Summary: RX=%d, TX=%d, Heartbeat ACKs=%d, IPMSG ACKs=%d",
                self.packet_count_rx,
                self.packet_count_tx,
                self.heartbeat_ack_count,
                self.ipmsg_ack_count,
            )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="LanBridge Active Network Verification Tester (M4)")
    parser.add_argument("--sandbox-ip", default="172.31.121.133", help="Sandbox target IP address (default: 172.31.121.133)")
    parser.add_argument("--mode", choices=["native", "ipmsg"], default="native", help="Operational mode (default: native)")
    parser.add_argument("--nick", default=DEFAULT_NICKNAME, help="Display nickname (default: LanBridge-Bot)")
    parser.add_argument("--group", default=DEFAULT_GROUP, help="Display contact group (default: 内网通联系人)")
    parser.add_argument("--msg", default=None, help="Optional text message to send on startup")
    parser.add_argument("--image", default=None, help="Optional image file path to send on connection")
    parser.add_argument("--caption", default="", help="Optional text caption for the sent image")
    parser.add_argument("--file", default=None, help="Optional file path to send via P2P file transfer")
    parser.add_argument("--greeting", action="store_true", help="Send default Chinese greeting on connection")
    parser.add_argument("--duration", type=float, default=None, help="Run duration in seconds (default: unlimited)")
    parser.add_argument("--bcast-ip", default="172.31.127.255", help="Subnet broadcast IP (default: 172.31.127.255)")
    args = parser.parse_args()

    initial_msg = args.msg
    if args.greeting or initial_msg in ("default", "greeting", "1"):
        initial_msg = DEFAULT_INITIAL_MSG

    tester = LanBridgeTester(
        sandbox_ip=args.sandbox_ip,
        broadcast_ip=args.bcast_ip,
        nick=args.nick,
        group=args.group,
        initial_msg=initial_msg,
        image_path=args.image,
        image_caption=args.caption,
        file_to_send=args.file,
        mode=args.mode,
    )
    tester.run(duration_seconds=args.duration)



if __name__ == "__main__":
    main()
