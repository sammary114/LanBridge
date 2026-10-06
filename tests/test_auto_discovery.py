#!/usr/bin/env python3
"""Tests for LanBridge Zero-Touch Autonomous Integration & Group Chat."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import unittest
from typing import List

from lanbridge.client import LanBridgeClient
from lanbridge.discovery import (
    NetworkInterfaceInfo,
    get_active_network_interfaces,
    get_default_broadcast_addresses,
    get_primary_local_ip,
)
from lanbridge.models import ChatMessage, Contact
from lanbridge.protocol import (
    Opcode,
    XteaEngine,
    build_opcode_88_fragments,
    build_x_qgroup_req_info_envelope,
    build_x_qgroup_req_info_rsp_envelope,
    build_x_qgroup_send_msg_envelope,
    extract_chat_message,
    extract_qgroup_id,
)


class TestAutoDiscoveryAndGroupChat(unittest.TestCase):
    """Test suite for autonomous discovery, network self-tuning, and group messaging."""

    def setUp(self) -> None:
        self.xtea = XteaEngine()

    def test_network_interface_detection(self) -> None:
        """Verify get_active_network_interfaces and broadcast calculation."""
        interfaces = get_active_network_interfaces()
        self.assertIsInstance(interfaces, list)

        for iface in interfaces:
            self.assertIsInstance(iface, NetworkInterfaceInfo)
            self.assertFalse(iface.is_loopback)
            self.assertFalse(iface.ip.startswith("127."))
            self.assertFalse(iface.ip.startswith("169.254."))
            # Verify valid IP address parsing
            ip_obj = ipaddress.ip_address(iface.ip)
            self.assertEqual(ip_obj.version, 4)

        broadcasts = get_default_broadcast_addresses()
        self.assertIsInstance(broadcasts, list)
        self.assertIn("255.255.255.255", broadcasts)

        primary_ip = get_primary_local_ip()
        self.assertIsInstance(primary_ip, str)
        self.assertNotEqual(primary_ip, "")

    def test_qgroup_send_msg_envelope(self) -> None:
        """Verify building and parsing X_QGROUP_SEND_MSG envelopes."""
        qgroup_id = "test_qgroup_9999"
        text = "Hello LanBridge Autonomous Group!"
        env = build_x_qgroup_send_msg_envelope(qgroup_id=qgroup_id, text=text, msg_id=12345678)
        self.assertGreater(len(env), 8)

        # Decrypt with XteaEngine
        op, plaintext = self.xtea.parse_envelope(env)
        self.assertEqual(op, Opcode.X_QGROUP_SEND_MSG)
        self.assertEqual(op, 0x0BC3)

        xml_str = plaintext.decode("utf-8")
        self.assertIn("<X_QGROUP_SEND_MSG", xml_str)
        self.assertIn(f"<QGROUP_ID>{qgroup_id}</QGROUP_ID>", xml_str)

        extracted_gid = extract_qgroup_id(xml_str)
        self.assertEqual(extracted_gid, qgroup_id)

        extracted_text = extract_chat_message(xml_str)
        self.assertEqual(extracted_text, text)

    def test_qgroup_req_info_and_rsp_envelopes(self) -> None:
        """Verify Opcode 3005 and 3006 group info request/response envelopes."""
        qgroup_id = "group_meta_001"

        req_env = build_x_qgroup_req_info_envelope(qgroup_id=qgroup_id)
        req_op, req_pt = self.xtea.parse_envelope(req_env)
        self.assertEqual(req_op, Opcode.X_QGROUP_REQ_INFO)
        self.assertEqual(req_op, 0x0BBD)
        self.assertIn(f"<QGROUP_ID>{qgroup_id}</QGROUP_ID>", req_pt.decode("utf-8"))

        rsp_env = build_x_qgroup_req_info_rsp_envelope(qgroup_id=qgroup_id, ret=0)
        rsp_op, rsp_pt = self.xtea.parse_envelope(rsp_env)
        self.assertEqual(rsp_op, Opcode.X_QGROUP_REQ_INFO_RSP)
        self.assertEqual(rsp_op, 0x0BBE)
        self.assertIn("<RET>0</RET>", rsp_pt.decode("utf-8"))
        self.assertIn(f"<QGROUP_ID>{qgroup_id}</QGROUP_ID>", rsp_pt.decode("utf-8"))

    def test_client_auto_configuration(self) -> None:
        """Verify LanBridgeClient self-detects local IP and broadcast destinations."""
        client = LanBridgeClient(auto_scan_on_start=False)
        self.assertIsNotNone(client.local_ip)
        self.assertNotEqual(client.local_ip, "")
        self.assertIsInstance(client.broadcast_ips, list)
        self.assertGreater(len(client.broadcast_ips), 0)
        self.assertIn("255.255.255.255", client.broadcast_ips)
        self.assertTrue(client.auto_scan_on_start is False)

    def test_client_group_message_dispatch(self) -> None:
        """Verify receiving and dispatching group messages via on_group_message."""
        client = LanBridgeClient(local_ip="127.0.0.1", auto_scan_on_start=False)
        client.contacts["peer_1"] = Contact(user_id="peer_1", ip="192.168.31.88")

        received_msgs: List[ChatMessage] = []

        @client.on_group_message
        def handle_group_msg(msg: ChatMessage) -> None:
            received_msgs.append(msg)

        qgroup_id = "group_dept_chat"
        text = "Hello teammates, autonomous sync online!"
        env = build_x_qgroup_send_msg_envelope(qgroup_id=qgroup_id, text=text, msg_id=987654321)
        op, plaintext = client.xtea.parse_envelope(env)

        replies: List[bytes] = []
        client._process_inner_envelope(op, plaintext, "192.168.31.88", replies)

        self.assertEqual(len(received_msgs), 1)
        msg = received_msgs[0]
        self.assertEqual(msg.qgroup_id, qgroup_id)
        self.assertEqual(msg.text, text)
        self.assertEqual(msg.sender_id, "peer_1")
        self.assertEqual(msg.msg_id, 987654321)

    def test_client_group_req_info_auto_reply(self) -> None:
        """Verify _process_inner_envelope automatically responds to X_QGROUP_REQ_INFO."""
        client = LanBridgeClient(local_ip="127.0.0.1", auto_scan_on_start=False)
        qgroup_id = "group_sync_test"
        req_env = build_x_qgroup_req_info_envelope(qgroup_id=qgroup_id)
        op, plaintext = client.xtea.parse_envelope(req_env)

        replies: List[bytes] = []
        client._process_inner_envelope(op, plaintext, "127.0.0.1", replies)

        self.assertGreater(len(replies), 0)
        # Reply is Opcode 0x88 fragments containing X_QGROUP_REQ_INFO_RSP
        session = client.get_session("127.0.0.1")
        for pkt in replies:
            client.handle_main_udp_packet(pkt, ("127.0.0.1", 9012))

    def test_client_proactive_connect_packet(self) -> None:
        """Verify _proactive_connect constructs an authentic Opcode 0x82 connect packet."""
        client = LanBridgeClient(local_ip="127.0.0.1", auto_scan_on_start=False)
        session = client.get_session("172.31.122.7")
        connect_pkt = session.build_connect(b"\x01\x02\x03\x04")

        self.assertGreaterEqual(len(connect_pkt), 44)
        self.assertEqual(connect_pkt[4], 0x82)  # Opcode 0x82 ENet Connect command


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestClientAsyncNetworking(unittest.IsolatedAsyncioTestCase):
    """Async tests for zero-touch networking and group sending."""

    async def test_async_group_send_and_presence(self) -> None:
        """Test broadcast_presence and send_group_message without error."""
        disc_port = get_free_udp_port()
        main_port = get_free_udp_port()
        tcp_port = get_free_port()
        share_port = get_free_port()

        client = LanBridgeClient(
            local_ip="127.0.0.1",
            broadcast_ip="127.0.0.1",
            discovery_port=disc_port,
            main_port=main_port,
            dynamic_port=53782,
            tcp_file_port=tcp_port,
            share_port=share_port,
            auto_scan_on_start=False,
        )
        await client.start()
        try:
            # Test broadcast_presence across all destinations
            await client.broadcast_presence()

            # Test send_group_message
            await client.send_group_message("test_grp_100", "Group broadcast message")

            # Test sync_group_info
            await client.sync_group_info("test_grp_100", "127.0.0.1")
        finally:
            await client.stop()


if __name__ == "__main__":
    unittest.main()
