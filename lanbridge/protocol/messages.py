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
DEFAULT_GROUP = "未分组联系人"


class Opcode:
    # Basic / 1-on-1 Messages (1000 ~ 1025)
    X_HANDSHARK = 0x03E8           # 1000
    X_CHANGE_STATUS = 0x03E9       # 1001
    X_CHANGE_SIGN = 0x03EA         # 1002
    X_CHANGE_INFO = 0x03EB         # 1003
    X_SEND_MSG = 0x03EC            # 1004
    X_SEND_MSG_ACK = 0x03ED        # 1005
    X_SEND_RECEIPT = 0x03EE        # 1006
    X_SEND_FLASH_SCREEN = 0x03EF   # 1007
    X_SEND_WRITTING = 0x03F0       # 1008
    X_INPUT_STATE = 0x03F0         # 1008 (Alias)
    X_SEND_FILE = 0x03F1           # 1009
    X_OPERATE_SEND_FILE = 0x03F2   # 1010
    X_OPERATE_RECV_FILE = 0x03F3   # 1011
    X_PROGRESS_RECV_FILE = 0x03F4  # 1012
    X_SEND_FOLDER = 0x03F5         # 1013
    X_OPERATE_SEND_FOLDER = 0x03F6 # 1014
    X_OPERATE_RECV_FOLDER = 0x03F7 # 1015
    X_HEARTBEAT = 0x03F8           # 1016
    X_QUIT = 0x03F9                # 1017
    X_READY = 0x03FA               # 1018
    X_REVERSE_FILE_REQ = 0x03FB    # 1019
    X_REVERSE_FOLDER_REQ = 0x03FC  # 1020
    X_SHARE_SUBNET = 0x03FD        # 1021

    # QGroup Discussion / Group (3000 ~ 3012)
    X_QGROUP_INVITE = 0x0BB8       # 3000
    X_QGROUP_INVITE_RSP = 0x0BB9   # 3001
    X_QGROUP_PUSH_INFO = 0x0BBA    # 3002
    X_QGROUP_PUSH_USER = 0x0BBB    # 3003
    X_QGROUP_REQ_INFO_SYS = 0x0BBC # 3004
    X_QGROUP_REQ_INFO = 0x0BBD     # 3005
    X_QGROUP_REQ_INFO_RSP = 0x0BBE # 3006
    X_QGROUP_REQ_USER = 0x0BBE     # 3006 (Alias)
    X_QGROUP_REQ_USER_RSP = 0x0BBF # 3007
    X_QGROUP_DISMISS = 0x0BC0      # 3008
    X_QGROUP_EXIT = 0x0BC1         # 3009
    X_QGROUP_KICK = 0x0BC2         # 3010
    X_QGROUP_SEND_MSG = 0x0BC3     # 3011
    X_QGROUP_OTHER_INVITE = 0x0BC4 # 3012


def build_native_profile(
    nick: str = DEFAULT_NICKNAME,
    user_id: str = DEFAULT_USER_ID,
    corp_id: str = "296becfde55172409ef2b81908044747",
    status: int = 0,
    sign: str = "LanBridge Native Online",
    group: str = DEFAULT_GROUP,
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
        import re
        m = re.search(r"<MSG_ID[^>]*>\s*(\d+)\s*</MSG_ID>", dec_xml, re.IGNORECASE)
        if m:
            return int(m.group(1))
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


def build_x_qgroup_send_msg_envelope(
    qgroup_id: str,
    text: str,
    msg_id: Optional[int] = None,
    use_emoticons: bool = True,
) -> bytes:
    """Build authentic encrypted X_QGROUP_SEND_MSG (Opcode 3011 / 0x0BC3) envelope."""
    if msg_id is None:
        msg_id = int(time.time() * 1000)

    if use_emoticons:
        try:
            from lanbridge.emoticons import emoji_to_nwt_dt
            dt = emoji_to_nwt_dt(text)
        except Exception:
            dt = [{"txt": {"t": "normal", "v": text}}]
    else:
        dt = [{"txt": {"t": "normal", "v": text}}]

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
        f'<X_QGROUP_SEND_MSG docver="1">'
        f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
        f'<MSG_ID>{msg_id}</MSG_ID>'
        f'<MSG>{escaped_msg}</MSG>'
        f'<HIDE_RECORD>0</HIDE_RECORD>'
        f'</X_QGROUP_SEND_MSG>'
    )
    return _xtea.build_envelope(Opcode.X_QGROUP_SEND_MSG, xml, encoding="utf-8")


def build_x_qgroup_req_info_envelope(qgroup_id: str) -> bytes:
    """Build authentic encrypted X_QGROUP_REQ_INFO (Opcode 3005 / 0x0BBD) envelope."""
    xml = f'<X_QGROUP_REQ_INFO docver="1"><QGROUP_ID>{qgroup_id}</QGROUP_ID></X_QGROUP_REQ_INFO>'
    return _xtea.build_envelope(Opcode.X_QGROUP_REQ_INFO, xml, encoding="utf-8")


def build_x_qgroup_req_info_rsp_envelope(qgroup_id: str, ret: int = 0) -> bytes:
    """Build authentic encrypted X_QGROUP_REQ_INFO_RSP (Opcode 3006 / 0x0BBE) envelope."""
    xml = f'<X_QGROUP_REQ_INFO_RSP docver="1"><RET>{ret}</RET><QGROUP_ID>{qgroup_id}</QGROUP_ID></X_QGROUP_REQ_INFO_RSP>'
    return _xtea.build_envelope(Opcode.X_QGROUP_REQ_INFO_RSP, xml, encoding="utf-8")


def extract_qgroup_id(dec_xml: str) -> Optional[str]:
    """Extract QGROUP_ID from decrypted QGroup XML payload."""
    try:
        start = dec_xml.find("<QGROUP_ID>")
        end = dec_xml.find("</QGROUP_ID>")
        if start != -1 and end != -1:
            return dec_xml[start + 11 : end].strip()
    except Exception:
        pass
    return None


def build_x_qgroup_invite_envelope(
    qgroup_id: str,
    name: str,
    master_id: str,
    intro: str = "",
    announcement: str = "",
    version: int = 1,
) -> bytes:
    """Build authentic encrypted X_QGROUP_INVITE (Opcode 3000 / 0x0BB8) envelope."""
    xml = (
        f'<X_QGROUP_INVITE docver="1">'
        f'<INFO>'
        f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
        f'<QGROUP_NAME>{name}</QGROUP_NAME>'
        f'<QGROUP_MASTER>{master_id}</QGROUP_MASTER>'
        f'<QGROUP_INTR>{intro}</QGROUP_INTR>'
        f'<QGROUP_ANN>{announcement}</QGROUP_ANN>'
        f'<QGROUP_INFO_VER>{version}</QGROUP_INFO_VER>'
        f'</INFO>'
        f'</X_QGROUP_INVITE>'
    )
    return _xtea.build_envelope(Opcode.X_QGROUP_INVITE, xml, encoding="utf-8")


def build_x_qgroup_invite_rsp_envelope(
    qgroup_id: str,
    user_name: str,
    action: int = 1,
) -> bytes:
    """Build authentic encrypted X_QGROUP_INVITE_RSP (Opcode 3001 / 0x0BB9) envelope."""
    xml = (
        f'<X_QGROUP_INVITE_RSP docver="1">'
        f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
        f'<USER_NAME>{user_name}</USER_NAME>'
        f'<ACTION>{action}</ACTION>'
        f'</X_QGROUP_INVITE_RSP>'
    )
    return _xtea.build_envelope(Opcode.X_QGROUP_INVITE_RSP, xml, encoding="utf-8")


def build_x_qgroup_push_info_envelope(
    qgroup_id: str,
    name: str,
    master_id: str,
    intro: str = "",
    announcement: str = "",
    version: int = 1,
) -> bytes:
    """Build authentic encrypted X_QGROUP_PUSH_INFO (Opcode 3002 / 0x0BBA) envelope."""
    xml = (
        f'<X_QGROUP_PUSH_INFO docver="1">'
        f'<INFO>'
        f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
        f'<QGROUP_NAME>{name}</QGROUP_NAME>'
        f'<QGROUP_MASTER>{master_id}</QGROUP_MASTER>'
        f'<QGROUP_INTR>{intro}</QGROUP_INTR>'
        f'<QGROUP_ANN>{announcement}</QGROUP_ANN>'
        f'<QGROUP_INFO_VER>{version}</QGROUP_INFO_VER>'
        f'</INFO>'
        f'</X_QGROUP_PUSH_INFO>'
    )
    return _xtea.build_envelope(Opcode.X_QGROUP_PUSH_INFO, xml, encoding="utf-8")


def build_x_qgroup_push_user_envelope(
    qgroup_id: str,
    name: str,
    master_id: str,
    intro: str = "",
    announcement: str = "",
) -> bytes:
    """Build authentic encrypted X_QGROUP_PUSH_USER (Opcode 3003 / 0x0BBB) envelope."""
    xml = (
        f'<X_QGROUP_PUSH_USER docver="1">'
        f'<INFO>'
        f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
        f'<QGROUP_NAME>{name}</QGROUP_NAME>'
        f'<QGROUP_MASTER>{master_id}</QGROUP_MASTER>'
        f'<QGROUP_INTR>{intro}</QGROUP_INTR>'
        f'<QGROUP_ANN>{announcement}</QGROUP_ANN>'
        f'</INFO>'
        f'</X_QGROUP_PUSH_USER>'
    )
    return _xtea.build_envelope(Opcode.X_QGROUP_PUSH_USER, xml, encoding="utf-8")


def build_x_qgroup_req_user_envelope(qgroup_id: str) -> bytes:
    """Build authentic encrypted X_QGROUP_REQ_USER (Opcode 3006 / 0x0BBE) envelope."""
    xml = f'<X_QGROUP_REQ_USER docver="1"><QGROUP_ID>{qgroup_id}</QGROUP_ID></X_QGROUP_REQ_USER>'
    return _xtea.build_envelope(Opcode.X_QGROUP_REQ_USER, xml, encoding="utf-8")


def build_x_qgroup_req_user_rsp_envelope(qgroup_id: str, name: str = "", ret: int = 0) -> bytes:
    """Build authentic encrypted X_QGROUP_REQ_USER_RSP (Opcode 3007 / 0x0BBF) envelope."""
    xml = (
        f'<X_QGROUP_REQ_USER_RSP docver="1">'
        f'<RET>{ret}</RET>'
        f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
        f'<INFO><QGROUP_NAME>{name}</QGROUP_NAME></INFO>'
        f'</X_QGROUP_REQ_USER_RSP>'
    )
    return _xtea.build_envelope(Opcode.X_QGROUP_REQ_USER_RSP, xml, encoding="utf-8")


def build_x_qgroup_dismiss_envelope(qgroup_id: str) -> bytes:
    """Build authentic encrypted X_QGROUP_DISMISS (Opcode 3008 / 0x0BC0) envelope."""
    xml = f'<X_QGROUP_DISMISS docver="1"><QGROUP_ID>{qgroup_id}</QGROUP_ID></X_QGROUP_DISMISS>'
    return _xtea.build_envelope(Opcode.X_QGROUP_DISMISS, xml, encoding="utf-8")


def build_x_qgroup_exit_envelope(qgroup_id: str) -> bytes:
    """Build authentic encrypted X_QGROUP_EXIT (Opcode 3009 / 0x0BC1) envelope."""
    xml = f'<X_QGROUP_EXIT docver="1"><QGROUP_ID>{qgroup_id}</QGROUP_ID></X_QGROUP_EXIT>'
    return _xtea.build_envelope(Opcode.X_QGROUP_EXIT, xml, encoding="utf-8")


def build_x_qgroup_kick_envelope(qgroup_id: str) -> bytes:
    """Build authentic encrypted X_QGROUP_KICK (Opcode 3010 / 0x0BC2) envelope."""
    xml = f'<X_QGROUP_KICK docver="1"><QGROUP_ID>{qgroup_id}</QGROUP_ID></X_QGROUP_KICK>'
    return _xtea.build_envelope(Opcode.X_QGROUP_KICK, xml, encoding="utf-8")


def build_x_qgroup_other_invite_envelope(qgroup_id: str, user_id: str) -> bytes:
    """Build authentic encrypted X_QGROUP_OTHER_INVITE (Opcode 3012 / 0x0BC4) envelope."""
    xml = (
        f'<X_QGROUP_OTHER_INVITE docver="1">'
        f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
        f'<USER><ID>{user_id}</ID></USER>'
        f'</X_QGROUP_OTHER_INVITE>'
    )
    return _xtea.build_envelope(Opcode.X_QGROUP_OTHER_INVITE, xml, encoding="utf-8")


def build_x_send_writting_envelope(typing: bool = True) -> bytes:
    """Build authentic encrypted X_SEND_WRITTING (Opcode 1008 / 0x03F0) envelope."""
    param = 1 if typing else 0
    xml = f'<X_SEND_WRITTING docver="1"><PARAM>{param}</PARAM></X_SEND_WRITTING>'
    return _xtea.build_envelope(Opcode.X_SEND_WRITTING, xml, encoding="utf-8")


def build_x_change_status_envelope(status: int = 0) -> bytes:
    """Build authentic encrypted X_CHANGE_STATUS (Opcode 1001 / 0x03E9) envelope."""
    xml = f'<X_CHANGE_STATUS docver="1"><STATUS>{status}</STATUS></X_CHANGE_STATUS>'
    return _xtea.build_envelope(Opcode.X_CHANGE_STATUS, xml, encoding="utf-8")


def build_x_change_sign_envelope(signature: str = "") -> bytes:
    """Build authentic encrypted X_CHANGE_SIGN (Opcode 1002 / 0x03EA) envelope."""
    xml = f'<X_CHANGE_SIGN docver="1"><SIGN>{signature}</SIGN></X_CHANGE_SIGN>'
    return _xtea.build_envelope(Opcode.X_CHANGE_SIGN, xml, encoding="gbk")


def parse_qgroup_xml(dec_xml: str) -> dict:
    """Extract structured QGroup fields from decrypted XML payload."""
    res = {}
    for tag in (
        "QGROUP_ID",
        "QGROUP_NAME",
        "QGROUP_MASTER",
        "QGROUP_INTR",
        "QGROUP_ANN",
        "QGROUP_INFO_VER",
        "USER_NAME",
        "ACTION",
        "RET",
        "ID",
        "PARAM",
        "STATUS",
        "SIGN",
    ):
        s = dec_xml.find(f"<{tag}>")
        e = dec_xml.find(f"</{tag}>")
        if s != -1 and e != -1:
            res[tag.lower()] = dec_xml[s + len(tag) + 2 : e].strip()
    return res


def build_x_recall_msg_envelope(
    target_msg_id: int,
    target_uuid: str = "",
    qgroup_id: Optional[str] = None,
    timestamp: Optional[int] = None,
) -> bytes:
    """Build authentic encrypted recall message envelope (X_SEND_MSG or X_QGROUP_SEND_MSG)."""
    if timestamp is None:
        timestamp = int(time.time())
    if not target_uuid:
        target_uuid = uuid.uuid4().hex

    recall_json = json.dumps(
        {
            "app": "shiyeline",
            "dt": [
                {
                    "txt": {
                        "t": "recall",
                        "v": "",
                    }
                }
            ],
            "id": target_uuid,
            "target_id": target_uuid,
            "target_msg_id": target_msg_id,
            "type": "6",
            "ver": "6.0",
        },
        ensure_ascii=False,
        indent=3,
        separators=(",", " : "),
    )
    escaped_msg = recall_json.replace('"', '&quot;').replace(' ', '&nbsp;') + "\n"

    if qgroup_id:
        xml = (
            f'<X_QGROUP_SEND_MSG docver="1">'
            f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
            f'<MSG_ID>{target_msg_id}</MSG_ID>'
            f'<MSG>{escaped_msg}</MSG>'
            f'<HIDE_RECORD>0</HIDE_RECORD>'
            f'</X_QGROUP_SEND_MSG>'
        )
        return _xtea.build_envelope(Opcode.X_QGROUP_SEND_MSG, xml, encoding="utf-8")
    else:
        xml = (
            f'<X_SEND_MSG docver="1"><MSG_ID>{target_msg_id}</MSG_ID><RECEIPT>0</RECEIPT>'
            f'<MSG>{escaped_msg}</MSG>'
            f'<MSG_TIME>{timestamp}</MSG_TIME><OFFLINE>0</OFFLINE><HIDE_RECORD>0</HIDE_RECORD></X_SEND_MSG>'
        )
        return _xtea.build_envelope(Opcode.X_SEND_MSG, xml, encoding="utf-8")


def extract_recall_info(dec_xml: str) -> Optional[dict]:
    """Check if decrypted XML payload contains a message recall notice and parse it."""
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
            msg_type = str(m_json.get("type", ""))
            dt = m_json.get("dt", [])
            is_recall = (msg_type == "6")
            if not is_recall and isinstance(dt, list) and len(dt) > 0:
                if isinstance(dt[0], dict) and dt[0].get("txt", {}).get("t") == "recall":
                    is_recall = True
            if is_recall:
                target_id = m_json.get("target_id") or m_json.get("id") or ""
                target_msg_id = m_json.get("target_msg_id") or extract_msg_id(dec_xml)
                return {
                    "target_uuid": target_id,
                    "target_msg_id": int(target_msg_id) if target_msg_id else 0,
                }
    except Exception:
        pass
    return None



