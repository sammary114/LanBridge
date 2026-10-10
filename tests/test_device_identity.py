#!/usr/bin/env python3
"""Tests for device identity, persistent UID generation, IPMSG shiyeline suppression, and group config."""

import os
import shutil
import tempfile
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from lanbridge.client.client import LanBridgeClient, get_or_create_device_id
from lanbridge.protocol.discovery import build_ipmsg_presence
from lanbridge.protocol.messages import build_native_profile
from lanbridge.protocol import DEFAULT_GROUP
from lanbridge.__main__ import build_parser


class TestDeviceIdentityAndGrouping(unittest.IsolatedAsyncioTestCase):
    """Test device UID persistence, presence formatting and group naming."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_or_create_device_id_generates_and_persists(self):
        fake_cfg_dir = os.path.join(self.temp_dir, ".lanbridge")
        fake_id_file = os.path.join(fake_cfg_dir, "device_id")

        with patch("os.path.expanduser", return_value=fake_cfg_dir):
            uid1 = get_or_create_device_id()
            self.assertEqual(len(uid1), 32)
            self.assertTrue(all(c in "0123456789abcdef" for c in uid1))
            self.assertTrue(os.path.isfile(fake_id_file))

            # Second call should read existing file
            uid2 = get_or_create_device_id()
            self.assertEqual(uid1, uid2)

    def test_lanbridge_client_defaults(self):
        client = LanBridgeClient(auto_scan_on_start=False)
        self.assertEqual(len(client.user_id), 32)
        self.assertEqual(client.group, "未分组联系人")
        self.assertEqual(DEFAULT_GROUP, "未分组联系人")
        self.assertEqual(client.signature, "LanBridge Native Online")
        self.assertTrue(hasattr(client, "corp_id"))
        self.assertTrue(hasattr(client, "_native_subnets"))

    def test_lanbridge_client_custom_group_and_corp_id(self):
        custom_group = "产品研发部"
        custom_corp = "11223344556677889900aabbccddeeff"
        custom_uid = "0102030405060708090a0b0c0d0e0f10"
        client = LanBridgeClient(
            user_id=custom_uid,
            group=custom_group,
            corp_id=custom_corp,
            signature="Busy",
            auto_scan_on_start=False,
        )
        self.assertEqual(client.user_id, custom_uid)
        self.assertEqual(client.group, custom_group)
        self.assertEqual(client.corp_id, custom_corp)
        self.assertEqual(client.signature, "Busy")

    def test_ipmsg_presence_has_shiyeline_prefix_and_uid(self):
        pkt = build_ipmsg_presence(
            nick="Android-Phone",
            group="未分组联系人",
            user_id="1234567890abcdef1234567890abcdef",
            use_shiyeline_prefix=True,
        )
        self.assertTrue(pkt.startswith(b"1@shiyeline:"))
        text = pkt.decode("gbk", errors="ignore")
        self.assertIn("Android-Phone", text)
        self.assertIn("未分组联系人", text)
        self.assertIn("1234567890abcdef1234567890abcdef", text)

    async def test_broadcast_presence_uses_shiyeline_prefix(self):
        client = LanBridgeClient(
            user_id="abcdef0123456789abcdef0123456789",
            nickname="TestPhone",
            group="未分组联系人",
            broadcast_ip="127.0.0.1",
            auto_scan_on_start=False,
        )
        client._udp_9011_transport = MagicMock()

        real_socket = socket.socket
        mock_sock = MagicMock()

        def socket_side_effect(*args, **kwargs):
            if args and len(args) >= 2 and args[0] == socket.AF_INET and args[1] == socket.SOCK_DGRAM:
                return mock_sock
            return real_socket(*args, **kwargs)

        with patch("socket.socket", side_effect=socket_side_effect):
            await client.broadcast_presence()

            # Ensure sendto was called on 2425 port with 1@shiyeline:
            calls = mock_sock.sendto.call_args_list
            self.assertTrue(len(calls) > 0)
            sent_data, addr = calls[0][0]
            self.assertEqual(addr[1], 2425)
            self.assertTrue(sent_data.startswith(b"1@shiyeline:"))
            sent_text = sent_data.decode("gbk", errors="ignore")
            self.assertIn("abcdef0123456789abcdef0123456789", sent_text)
            self.assertIn("未分组联系人", sent_text)

    def test_build_native_profile_group_xml(self):
        # Default group
        profile_bytes = build_native_profile(nick="PhoneBot")
        from lanbridge.protocol.crypto import XteaEngine
        xtea = XteaEngine()
        op, xml = xtea.parse_envelope(profile_bytes)
        self.assertEqual(op, 0x03E8)
        self.assertIn("<GROUP>未分组联系人</GROUP>", xml.decode("utf-8"))

        # Custom group
        custom_bytes = build_native_profile(nick="PhoneBot", group="行政部门")
        op2, xml2 = xtea.parse_envelope(custom_bytes)
        self.assertEqual(op2, 0x03E8)
        self.assertIn("<GROUP>行政部门</GROUP>", xml2.decode("utf-8"))

    def test_cli_parser_options(self):
        parser = build_parser()
        args = parser.parse_args([
            "--group", "技术支持组",
            "--corp-id", "99887766554433221100aabbccddeeff",
            "--signature", "在线测试中",
        ])
        self.assertEqual(args.group, "技术支持组")
        self.assertEqual(args.corp_id, "99887766554433221100aabbccddeeff")
        self.assertEqual(args.signature, "在线测试中")

    def test_x_send_msg_replies_80byte_opcode_86_ack(self):
        client = LanBridgeClient(auto_scan_on_start=False)
        sess = client.get_session("192.168.1.50")
        sess.connected = True
        sess.peer_id = 0x0123
        sess.session_id = 0

        # Construct an authentic X_SEND_MSG packet
        from lanbridge.protocol.messages import build_x_send_msg_envelope
        from lanbridge.protocol.crypto import XteaEngine
        env = build_x_send_msg_envelope("test message", msg_id=1)
        # Wrap into 0x86 packet for simulation
        raw_pkt = sess.build_reliable(0, env)

        replies = client.handle_main_udp_packet(raw_pkt, ("192.168.1.50", 9012))
        # Expect 2 replies: 1 ENet ACK for 0x86, and 1 X_SEND_MSG_ACK (80 bytes, Opcode 0x86)
        self.assertTrue(len(replies) >= 2)
        ack_pkt = replies[-1]
        self.assertEqual(len(ack_pkt), 80)
        self.assertEqual(ack_pkt[4], 0x86)  # Opcode 0x86 (SendReliable)
        xtea = XteaEngine()
        op, dec = xtea.parse_envelope(ack_pkt[10:])
        self.assertEqual(op, 0x03ED)  # Opcode.X_SEND_MSG_ACK
        self.assertIn("<MSG_ID>1</MSG_ID>", dec.decode("utf-8"))

    async def test_send_message_dynamic_seq_and_msg_id(self):
        client = LanBridgeClient(auto_scan_on_start=False)
        sess = client.get_session("192.168.1.50")
        sess.connected = True
        sess.peer_id = 0x0123
        sess.session_id = 0

        client._udp_9012_transport = MagicMock()

        # Send first message
        await client.send_message("192.168.1.50", "msg 1")
        calls = client._udp_9012_transport.sendto.call_args_list
        self.assertTrue(len(calls) > 0)
        pkt1 = calls[0][0][0]
        sub_id1 = int.from_bytes(pkt1[6:8], "big")

        # Send second message
        await client.send_message("192.168.1.50", "msg 2")
        calls2 = client._udp_9012_transport.sendto.call_args_list
        pkt2 = calls2[-1][0][0]
        sub_id2 = int.from_bytes(pkt2[6:8], "big")

        # Verify outgoing_seq advanced and is not hardcoded
        self.assertGreater(sub_id2, sub_id1)

    def test_opcode_82_connect_session_and_peer_tracking(self):
        """Verify that receiving 0x82 Connect preserves out_peer and sets session_id=1 and connected=True."""
        client = LanBridgeClient(auto_scan_on_start=False)
        peer_ip = "192.168.31.225"

        # Construct authentic 0x82 Connect packet from PC with out_peer=3
        pkt_82 = (
            struct.pack(">HH", 0x8FFF, 0x1000)
            + b"\x82\xff\x00\x01\x00\x03\x00\x00\x00\x00\x05\x78\x00\x01\x00\x00\x00\x00\x00\x01"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x88\x00\x00\x00\x02\x00\x00\x00\x02"
            + b"\xa9\x05\x45\x2a\x00\x00\x00\x00"
        )
        replies = client.handle_main_udp_packet(pkt_82, (peer_ip, 9012))
        self.assertEqual(len(replies), 1)

        session = client.get_session(peer_ip)
        self.assertTrue(session.connected)
        self.assertEqual(session.peer_id, 3)
        self.assertEqual(session.session_id, 1)

        # Now simulate PC sending X_SEND_MSG (with h_val=0x9000 carrying receiver peer 0)
        from lanbridge.protocol.messages import build_x_send_msg_envelope
        from lanbridge.protocol.crypto import XteaEngine
        env = build_x_send_msg_envelope("hello from pc", msg_id=10086)
        # PC sends with header flag 0x9000 (session 1, receiver 0)
        fake_hdr = struct.pack(">HH", 0x9000, 0x2000)
        cmd = struct.pack(">BBHH", 0x86, 0x00, 1, len(env))
        data_pkt = fake_hdr + cmd + env

        data_replies = client.handle_main_udp_packet(data_pkt, (peer_ip, 9012))
        self.assertGreaterEqual(len(data_replies), 2)

        # Ensure session.peer_id was NOT overwritten to 0!
        self.assertEqual(session.peer_id, 3)
        self.assertEqual(session.session_id, 1)

        # Verify X_SEND_MSG_ACK response header has peer_id=3 and session_id=1 (0x9003)
        ack_pkt = data_replies[-1]
        ack_hdr = struct.unpack(">H", ack_pkt[:2])[0]
        self.assertEqual(ack_hdr, 0x8000 | (1 << 12) | 3)  # 0x9003

        xtea = XteaEngine()
        op, dec = xtea.parse_envelope(ack_pkt[10:])
        self.assertEqual(op, 0x03ED)
        self.assertIn("<MSG_ID>10086</MSG_ID>", dec.decode("utf-8"))

    def test_extract_msg_id_robust(self):
        """Verify robust msg_id extraction across various formats and attributes."""
        from lanbridge.protocol.messages import extract_msg_id
        self.assertEqual(extract_msg_id('<X_SEND_MSG docver="1"><MSG_ID>12345</MSG_ID></X_SEND_MSG>'), 12345)
        self.assertEqual(extract_msg_id('<X_SEND_MSG><MSG_ID docver="2">   9876543210   </MSG_ID></X_SEND_MSG>'), 9876543210)
        self.assertEqual(extract_msg_id('<invalid>xml</invalid>'), 1)


    def test_linux_android_interface_discovery_ip_output(self):
        """Verify _discover_linux_android_interfaces parses Linux/Android ip command output."""
        from lanbridge.discovery.network import _discover_linux_android_interfaces
        mock_output = (
            "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
            "2: wlan0    inet 192.168.31.150/24 brd 192.168.31.255 scope global wlan0\\       valid_lft forever preferred_lft forever\n"
        )
        with patch("shutil.which", return_value="/system/bin/ip"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=mock_output)
            ifaces = _discover_linux_android_interfaces()
            self.assertEqual(len(ifaces), 1)
            self.assertEqual(ifaces[0].name, "wlan0")
            self.assertEqual(ifaces[0].ip, "192.168.31.150")
            self.assertEqual(ifaces[0].netmask, "255.255.255.0")
            self.assertEqual(ifaces[0].broadcast, "192.168.31.255")
            self.assertEqual(ifaces[0].network, "192.168.31.0/24")

    def test_build_handshake_reply_dynamic_header_flag(self):
        """Verify build_handshake_reply dynamically reflects peer_id and session_id from 0x82 packet."""
        from lanbridge.protocol.handshake import build_handshake_reply
        pkt_82 = (
            struct.pack(">HH", 0x8FFF, 0x1000)
            + b"\x82\xff\x00\x01\x00\x05\x00\x00\x00\x00\x05\x78\x00\x01\x00\x00\x00\x00\x00\x01"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x88\x00\x00\x00\x02\x00\x00\x00\x02"
            + b"\xa9\x05\x45\x2a\x00\x00\x00\x00"
        )
        reply = build_handshake_reply(pkt_82)
        h_val = int.from_bytes(reply[:2], "big")
        # Should reflect peer_id=5 and session_id=1 -> 0x9005
        self.assertEqual(h_val, 0x8000 | (1 << 12) | 5)

    def test_cli_parser_scan_targets_and_local_ip(self):
        """Verify CLI parser handles --target, --scan-target and --local-ip."""
        parser = build_parser()
        args = parser.parse_args([
            "--target", "192.168.31.225",
            "--local-ip", "192.168.31.150",
        ])
        self.assertEqual(args.target, "192.168.31.225")
        self.assertEqual(args.local_ip, "192.168.31.150")

        # Verify client initialization accepts scan_targets
        client = LanBridgeClient(
            local_ip=args.local_ip,
            scan_targets=[args.target],
            auto_scan_on_start=False,
        )
        self.assertIn("192.168.31.225", client.scan_targets)
        self.assertIn("192.168.31.225", client.broadcast_ips)


if __name__ == "__main__":
    unittest.main()

