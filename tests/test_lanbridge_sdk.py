#!/usr/bin/env python3
"""Tests for LanBridge Core SDK (tests/test_lanbridge_sdk.py)."""

from __future__ import annotations

import os
import struct
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import lanbridge
from lanbridge import (
    LanBridgeClient,
    Contact,
    ChatMessage,
    XteaEngine,
    ENetProtocolSession,
    ENetCommandType,
    Opcode,
    build_nwt_discovery_packet,
    parse_discovery_packet,
    build_native_profile,
    build_x_send_msg_envelope,
    build_x_send_image_envelope,
    build_x_flash_screen_envelope,
    build_x_ready_envelope,
    extract_chat_message,
    build_folder_tran_response,
    build_folder_tran_chunk,
    parse_folder_tran_packet,
    build_minifile_response,
    build_minifile_chunk,
    parse_minifile_packet,
)


class TestLanBridgeSDK(unittest.TestCase):
    """Verify modularized LanBridge SDK components and APIs."""

    def test_version_and_exports(self) -> None:
        self.assertTrue(hasattr(lanbridge, "__version__"))
        self.assertEqual(lanbridge.__version__, "0.5.0")
        self.assertTrue(callable(LanBridgeClient))
        self.assertTrue(callable(XteaEngine))

    def test_xtea_roundtrip(self) -> None:
        xtea = XteaEngine()
        data = b"Hello, LanBridge Modular SDK!"
        enc = xtea.encrypt(data)
        self.assertNotEqual(data, enc)
        dec = xtea.decrypt(enc)
        self.assertEqual(data, dec)

    def test_xtea_envelope(self) -> None:
        xtea = XteaEngine()
        payload = "<X_TEST>12345</X_TEST>"
        env = xtea.build_envelope(Opcode.X_READY, payload)
        self.assertGreaterEqual(len(env), 8)
        op, plain = xtea.parse_envelope(env)
        self.assertEqual(op, Opcode.X_READY)
        self.assertEqual(plain.decode("utf-8"), payload)

    def test_enet_session_and_framing(self) -> None:
        session = ENetProtocolSession()
        conn_pkt = session.build_connect(b"\x12\x34\x56\x78")
        self.assertGreater(len(conn_pkt), 4)

        rel_pkt = session.build_reliable(channel=0, payload=b"test-payload")
        self.assertIn(b"test-payload", rel_pkt)

        # Fragmentation
        large_payload = b"A" * 3000
        frags = session.build_fragments(channel=0, payload=large_payload, max_chunk=1000)
        self.assertEqual(len(frags), 3)

    def test_discovery_packet_roundtrip(self) -> None:
        pkt = build_nwt_discovery_packet(
            cmd=1,
            user_id="test_user_id_12345678901234567",
            broadcast_ip="192.168.1.255",
            dynamic_port=54321,
        )
        self.assertEqual(len(pkt), 304)
        parsed = parse_discovery_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["cmd"], 1)
        self.assertEqual(parsed["user_id"], "test_user_id_12345678901234567")
        self.assertEqual(parsed["dynamic_port"], 54321)
        self.assertEqual(parsed["broadcast_ip"], "192.168.1.255")

    def test_messages_text_and_extract(self) -> None:
        env = build_x_send_msg_envelope(
            message="测试消息：你好 LanBridge SDK！",
            msg_id=1234,
            use_emoticons=False,
        )
        xtea = XteaEngine()
        op, plain = xtea.parse_envelope(env)
        self.assertEqual(op, Opcode.X_SEND_MSG)
        text = extract_chat_message(plain.decode("utf-8"))
        self.assertEqual(text, "测试消息：你好 LanBridge SDK！")

    def test_messages_inline_image(self) -> None:
        md5_test = "0123456789abcdef0123456789abcdef"
        env = build_x_send_image_envelope(img_md5=md5_test, token=9999, caption="风景照")
        xtea = XteaEngine()
        op, plain = xtea.parse_envelope(env)
        self.assertEqual(op, Opcode.X_SEND_MSG)
        xml = plain.decode("utf-8")
        self.assertIn("9999|0123456789abcdef0123456789abcdef", xml)

    def test_messages_flash_screen(self) -> None:
        env = build_x_flash_screen_envelope()
        xtea = XteaEngine()
        op, plain = xtea.parse_envelope(env)
        self.assertEqual(op, Opcode.X_SEND_FLASH_SCREEN)
        self.assertIn("<X_SEND_FLASH_SCREEN", plain.decode("utf-8"))

    def test_folder_tran_engine_roundtrip(self) -> None:
        file_size = 123456
        token = 7788
        # Command 2 (Response)
        rsp = build_folder_tran_response(file_size=file_size, token=token)
        self.assertEqual(len(rsp), 108)
        parsed_rsp = parse_folder_tran_packet(rsp)
        self.assertEqual(parsed_rsp["cmd"], 2)
        self.assertEqual(parsed_rsp["token"], token)
        self.assertEqual(parsed_rsp["file_size"], file_size)

        # Command 4 (Data Chunk)
        chunk = b"IMG_CHUNK_DATA_HERE"
        c4 = build_folder_tran_chunk(file_size=file_size, offset=1024, chunk_data=chunk, token=token)
        self.assertEqual(len(c4), len(chunk) + 100)
        parsed_c4 = parse_folder_tran_packet(c4)
        self.assertEqual(parsed_c4["cmd"], 4)
        self.assertEqual(parsed_c4["token"], token)
        self.assertEqual(parsed_c4["offset"], 1024)
        self.assertEqual(parsed_c4["chunk_len"], len(chunk))
        self.assertEqual(parsed_c4["chunk_data"], chunk)

    def test_client_event_dispatching(self) -> None:
        client = LanBridgeClient(user_id="bot_user_id_11111111111111111")
        received_msgs = []
        received_contacts = []

        @client.on_message
        def handle_msg(msg: ChatMessage) -> None:
            received_msgs.append(msg)

        @client.on_contact_online
        def handle_online(c: Contact) -> None:
            received_contacts.append(c)

        # Simulate discovery packet
        peer_pkt = build_nwt_discovery_packet(
            cmd=1,
            user_id="peer_user_id_22222222222222222",
            broadcast_ip="172.31.127.255",
            dynamic_port=53782,
        )
        reply = client.handle_discovery_packet(peer_pkt, ("172.31.120.125", 9011))
        self.assertIsNotNone(reply)
        self.assertEqual(len(received_contacts), 1)
        self.assertEqual(received_contacts[0].user_id, "peer_user_id_22222222222222222")
        self.assertEqual(received_contacts[0].ip, "172.31.120.125")

    def test_subnet_scanner_expansion(self) -> None:
        from lanbridge import SubnetScanner
        cidrs = ["192.168.1.0/30", "10.0.0.1"]
        hosts = SubnetScanner.expand_subnets(cidrs)
        self.assertIn("192.168.1.1", hosts)
        self.assertIn("192.168.1.2", hosts)
        self.assertIn("10.0.0.1", hosts)


if __name__ == "__main__":
    unittest.main()
