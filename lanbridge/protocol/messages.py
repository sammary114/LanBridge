#!/usr/bin/env python3
"""LanBridge High-Level Message & Envelope Engine (messages.py).

Implements authentic XML/JSON envelopes for native Nwt chat, profiles, and state machines:
- Opcode 1000 (0x03E8): X_HANDSHARK (User Profile / Capability Exchange)
- Opcode 1004 (0x03EC): X_SEND_MSG (Text, Emoji, Inline Image, Message Recall)
- Opcode 1005 (0x03ED): X_SEND_MSG_ACK (Message Delivery Receipt)
- Opcode 1007 (0x03EF): X_SEND_FLASH_SCREEN (Window Shake)
- Opcode 1009 (0x03F1): X_SEND_FILE (File Transfer Offer)
- Opcode 1010 (0x03F2): X_OPERATE_SEND_FILE (Cancel Sender Task)
- Opcode 1011 (0x03F3): X_OPERATE_RECV_FILE (Accept / Reject Receiver Task)
- Opcode 1012 (0x03F4): X_PROGRESS_RECV_FILE (File Download Progress)
- Opcode 1016 (0x03F8): X_HEARTBEAT (Session Keepalive)
- Opcode 1018 (0x03FA): X_READY (Session Ready / Finalize)
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Optional, Union

from lanbridge.protocol.crypto import XteaEngine

logger = logging.getLogger("lanbridge.messages")
_xtea = XteaEngine()

DEFAULT_USER_ID = "2158b475dfcfdd43989482c4dcf0337b"
DEFAULT_NICKNAME = "LanBridge-Bot"
DEFAULT_GROUP = "内网通联系人"


class Opcode:
    X_HANDSHARK = 0x03E8           # 1000
    X_SEND_MSG = 0x03EC            # 1004
    X_SEND_MSG_ACK = 0x03ED        # 1005
    X_SEND_FLASH_SCREEN = 0x03EF   # 1007
    X_INPUT_STATE = 0x03F0         # 1008
    X_SEND_FILE = 0x03F1           # 1009
    X_OPERATE_SEND_FILE = 0x03F2   # 1010
    X_OPERATE_RECV_FILE = 0x03F3   # 1011
    X_PROGRESS_RECV_FILE = 0x03F4  # 1012
    X_HEARTBEAT = 0x03F8           # 1016
    X_READY = 0x03FA               # 1018


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
    return _xtea.build_envelope(Opcode.X_HANDSHARK, xml)


def build_x_ready_envelope(user_id: str = DEFAULT_USER_ID) -> bytes:
    """Build authentic encrypted X_READY (Opcode 1018 / 0x03fa) envelope."""
    xml = f'<X_READY docver="1"><USER_ID>{user_id}</USER_ID><PARAM>0</PARAM></X_READY>'
    return _xtea.build_envelope(Opcode.X_READY, xml)


def build_x_heartbeat_envelope() -> bytes:
    """Build authentic encrypted X_HEARTBEAT (Opcode 1016 / 0x03f8) envelope."""
    xml = '<X_HEARTBEAT docver="1" />'
    return _xtea.build_envelope(Opcode.X_HEARTBEAT, xml)


def build_x_send_msg_envelope(
    message: str,
    msg_id: int = 1,
    timestamp: Optional[int] = None,
    use_emoticons: bool = True,
) -> bytes:
    """Build authentic encrypted X_SEND_MSG (Opcode 1004 / 0x03ec) envelope."""
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
    escaped_msg = msg_json.replace('"', '&quot;').replace(' ', '&nbsp;') + "\n"
    xml = (
        f'<X_SEND_MSG docver="1"><MSG_ID>{msg_id}</MSG_ID><RECEIPT>0</RECEIPT>'
        f'<MSG>{escaped_msg}</MSG>'
        f'<MSG_TIME>{timestamp}</MSG_TIME><OFFLINE>0</OFFLINE><HIDE_RECORD>0</HIDE_RECORD></X_SEND_MSG>'
    )
    return _xtea.build_envelope(Opcode.X_SEND_MSG, xml, encoding="utf-8")


def extract_chat_message(dec_xml: str) -> str:
    """Extract plain text message from decrypted X_SEND_MSG XML payload."""
    try:
        start_msg = dec_xml.find("<MSG>")
        end_msg = dec_xml.find("</MSG>")
        if start_msg != -1 and end_msg != -1:
            content_str = dec_xml[start_msg + 5 : end_msg].strip()
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
    return _xtea.build_envelope(Opcode.X_SEND_MSG_ACK, xml)


def build_x_flash_screen_envelope(shake_type: int = 0) -> bytes:
    """Build authentic encrypted X_SEND_FLASH_SCREEN (Opcode 1007 / 0x03ef) envelope."""
    xml = f'<X_SEND_FLASH_SCREEN docver="1"><TYPE>{shake_type}</TYPE></X_SEND_FLASH_SCREEN>'
    return _xtea.build_envelope(Opcode.X_SEND_FLASH_SCREEN, xml)


def build_x_operate_recv_file_envelope(task_id: int, op: int = 1) -> bytes:
    """Build authentic encrypted X_OPERATE_RECV_FILE (Opcode 1011 / 0x03f3) envelope."""
    xml = f'<X_OPERATE_RECV_FILE docver="1"><TASK_ID>{task_id}</TASK_ID><OP>{op}</OP></X_OPERATE_RECV_FILE>'
    return _xtea.build_envelope(Opcode.X_OPERATE_RECV_FILE, xml)


def build_x_operate_send_file_envelope(task_id: int, op: int = 1) -> bytes:
    """Build authentic encrypted X_OPERATE_SEND_FILE (Opcode 1010 / 0x03f2) envelope."""
    xml = f'<X_OPERATE_SEND_FILE docver="1"><TASK_ID>{task_id}</TASK_ID><OP>{op}</OP></X_OPERATE_SEND_FILE>'
    return _xtea.build_envelope(Opcode.X_OPERATE_SEND_FILE, xml)


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
    return _xtea.build_envelope(Opcode.X_PROGRESS_RECV_FILE, xml)


def build_x_recall_msg_envelope(
    target_msg_id: int,
    target_uuid: str,
    msg_id: int = 1,
    timestamp: Optional[int] = None,
) -> bytes:
    """Build authentic encrypted message recall envelope (Opcode 1004 / 0x03ec, type 6)."""
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
    return _xtea.build_envelope(Opcode.X_SEND_MSG, xml, encoding="utf-8")


def build_x_send_image_envelope(
    img_md5: str,
    token: int = 1001,
    caption: str = "",
    msg_id: int = 1,
    img_type: str = "feihu",
    timestamp: Optional[int] = None,
) -> bytes:
    """Build authentic encrypted X_SEND_MSG envelope containing an inline image."""
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
    return _xtea.build_envelope(Opcode.X_SEND_MSG, xml, encoding="utf-8")


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
    return _xtea.build_envelope(Opcode.X_SEND_FILE, xml, encoding="gbk")


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
