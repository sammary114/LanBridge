#!/usr/bin/env python3
"""Tests for LanBridge Protocol Core SDK (test_lanbridge_sdk.py)."""

import asyncio
import unittest

from lanbridge.client import ClientConfig, LanBridgeClient, LanBridgeMessage, PeerInfo
from lanbridge.crypto import DEFAULT_XTEA_KEY, XTEACipher
from lanbridge.enet import ENetCommandType, ENetProtocolSession
from lanbridge.protocol import (
    OP_CHANGE_STATUS,
    OP_FLASH_SCREEN,
    OP_HANDSHAKE,
    OP_MSG_ACK,
    OP_SEND_MSG,
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


class TestLanBridgeSDK(unittest.TestCase):
    """Unit tests for the standalone LanBridge SDK."""

    def setUp(self):
        self.cipher = XTEACipher()

    def test_xtea_basic_roundtrip(self):
        """Test XTEA block cipher encryption and decryption."""
        plain = b"LanBridge-Test-12345678"
        cipher = self.cipher.encrypt(plain)
        self.assertNotEqual(plain, cipher)
        decrypted = self.cipher.decrypt(cipher)
        self.assertEqual(decrypted[: len(plain)], plain)

    def test_xtea_arbitrary_length_padding(self):
        """Test XTEA zero-padding with unaligned byte lengths."""
        for length in (1, 7, 8, 9, 15, 16, 17, 100, 1024):
            data = b"A" * length
            enc = self.cipher.encrypt(data)
            self.assertEqual(len(enc) % 8, 0)
            dec = self.cipher.decrypt(enc)
            self.assertEqual(dec[:length], data)

    def test_xtea_envelope_packing(self):
        """Test packing and unpacking of 6-byte headed native envelopes."""
        test_xml = b"<X_TEST>Hello</X_TEST>"
        opcode = 0x03EC
        envelope = self.cipher.encrypt_envelope(opcode, test_xml)
        self.assertGreaterEqual(len(envelope), 6)

        dec_op, dec_data = self.cipher.decrypt_envelope(envelope)
        self.assertEqual(dec_op, opcode)
        self.assertEqual(dec_data, test_xml)

    def test_discovery_packet_roundtrip(self):
        """Test building and parsing of authentic 304-byte UDP 9011 discovery packets."""
        uid = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        uname = "测试机器人"
        host = "BOT-HOST-01"
        port = 9012
        org = "LanBridgeCorp"

        pkt = build_discovery_packet(user_id=uid, username=uname, hostname=host, port=port, org_id=org)
        self.assertEqual(len(pkt), 304)

        parsed = parse_discovery_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["user_id"], uid)
        self.assertEqual(parsed["username"], uname)
        self.assertEqual(parsed["hostname"], host)
        self.assertEqual(parsed["port"], port)
        self.assertEqual(parsed["org_id"], org)

    def test_handshake_xml(self):
        """Test native <X_HANDSHARK> profile XML generation."""
        xml_bytes = build_handshake_xml(user_id="test_uid", username="Bot", sign="I am bot")
        self.assertIn(b"<X_HANDSHARK docver=\"1\">", xml_bytes)
        self.assertIn(b"<USER_NAME>Bot</USER_NAME>", xml_bytes)
        self.assertIn(b"<SIGN>I am bot</SIGN>", xml_bytes)

    def test_send_msg_xml_and_extract(self):
        """Test chat message XML generation and entity extraction."""
        test_text = "你好！LanBridge & <测试> \"123\""
        xml_bytes, msg_id = build_send_msg_xml(test_text)
        self.assertIn(b"<X_SEND_MSG docver=\"1\">", xml_bytes)
        self.assertTrue(len(msg_id) > 10)

        xml_str = xml_bytes.decode("gbk")
        extracted = extract_chat_text(xml_str)
        self.assertIsNotNone(extracted)
        ext_id, ext_text, ext_json = extracted
        self.assertEqual(ext_id, msg_id)
        self.assertEqual(ext_text, test_text)
        self.assertEqual(ext_json.get("type"), "0")

    def test_recall_msg_xml(self):
        """Test message recall XML generation (type 6)."""
        target_msg = "1234567890_test"
        xml_bytes, recall_id = build_recall_xml(target_msg_id=target_msg, target_uuid="peer_uuid")
        xml_str = xml_bytes.decode("gbk")
        extracted = extract_chat_text(xml_str)
        self.assertIsNotNone(extracted)
        ext_id, _, ext_json = extracted
        self.assertEqual(ext_json.get("type"), "6")
        self.assertEqual(ext_json.get("target_msg_id"), target_msg)

    def test_flash_screen_xml(self):
        """Test window shake XML generation."""
        xml_bytes = build_flash_screen_xml(shake_type=0)
        self.assertIn(b"<X_SEND_FLASH_SCREEN docver=\"1\">", xml_bytes)
        self.assertIn(b"<TYPE>0</TYPE>", xml_bytes)

    def test_enet_session_reliable_and_ack(self):
        """Test ENet session reliable packet generation and ACK generation."""
        session = ENetProtocolSession()
        payload = b"TEST_PAYLOAD"
        reliable_pkt = session.build_reliable(channel=0, payload=payload)
        self.assertGreater(len(reliable_pkt), len(payload))

        ack_pkt = session.build_ack(channel=0, seq=1)
        self.assertGreaterEqual(len(ack_pkt), 7)

    def test_enet_session_fragmentation(self):
        """Test ENet session fragmentation and reassembly."""
        session = ENetProtocolSession()
        large_payload = b"X" * 3500  # Will be split into 3 fragments
        fragments = session.build_fragments(channel=0, payload=large_payload, max_chunk=1372)
        self.assertEqual(len(fragments), 3)

        # Parse and reassemble
        receiver_session = ENetProtocolSession()
        assembled_commands = []
        for frag in fragments:
            cmds = receiver_session.parse_packet(frag)
            assembled_commands.extend(cmds)

        # The last fragment completes the message
        self.assertEqual(len(assembled_commands), 1)
        cmd_type, channel, seq, payload = assembled_commands[0]
        self.assertEqual(cmd_type, ENetCommandType.SEND_FRAGMENT)
        self.assertEqual(payload, large_payload)

    def test_client_config(self):
        """Test client configuration defaults and auto UID."""
        cfg = ClientConfig()
        self.assertTrue(len(cfg.user_id) > 10)
        self.assertEqual(cfg.discovery_port, 9011)
        self.assertEqual(cfg.data_port, 9012)
        self.assertEqual(cfg.username, "LanBridge-Bot")


if __name__ == "__main__":
    unittest.main()
