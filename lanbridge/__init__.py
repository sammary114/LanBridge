"""LanBridge Protocol Core SDK.

Python client and protocol driver for NeiWangTong (IMO 3.4.3055).
"""

from .client import ClientConfig, LanBridgeClient, LanBridgeMessage, PeerInfo
from .crypto import DEFAULT_XTEA_KEY, XTEACipher
from .enet import ENetCommandType, ENetProtocolSession
from .protocol import (
    OP_CHANGE_STATUS,
    OP_FLASH_SCREEN,
    OP_HANDSHAKE,
    OP_HEARTBEAT,
    OP_MSG_ACK,
    OP_QUIT,
    OP_READY,
    OP_SEND_MSG,
    OP_SEND_WRITING,
    build_change_status_xml,
    build_discovery_packet,
    build_flash_screen_xml,
    build_handshake_xml,
    build_msg_ack_xml,
    build_recall_xml,
    build_send_msg_xml,
    build_typing_xml,
    extract_chat_text,
    parse_discovery_packet,
)

__all__ = [
    "LanBridgeClient",
    "ClientConfig",
    "LanBridgeMessage",
    "PeerInfo",
    "XTEACipher",
    "DEFAULT_XTEA_KEY",
    "ENetProtocolSession",
    "ENetCommandType",
    "build_discovery_packet",
    "parse_discovery_packet",
    "build_handshake_xml",
    "build_change_status_xml",
    "build_send_msg_xml",
    "build_msg_ack_xml",
    "build_flash_screen_xml",
    "build_typing_xml",
    "build_recall_xml",
    "extract_chat_text",
    "OP_HANDSHAKE",
    "OP_CHANGE_STATUS",
    "OP_SEND_MSG",
    "OP_SEND_MSG_ACK",
    "OP_FLASH_SCREEN",
    "OP_SEND_WRITING",
    "OP_HEARTBEAT",
    "OP_QUIT",
    "OP_READY",
]
