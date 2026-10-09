#!/usr/bin/env python3
"""Tests for LanBridge Web Gateway REST API and WebSocket handling."""

import json
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from lanbridge.client import LanBridgeClient
from lanbridge.models import Contact, QGroup, ChatMessage
from lanbridge.web import create_app


class TestWebGateway(AioHTTPTestCase):
    """Test suite for WebGateway REST endpoints and WebSocket functionality."""

    async def get_application(self):
        self.client_node = LanBridgeClient(
            user_id="gateway_test_node_001",
            nickname="GatewayBot",
            discovery_port=19011,
            main_port=19012,
            auto_scan_on_start=False,
        )
        # Prepopulate dummy contact and group
        c = Contact(user_id="contact_bob", nickname="Bob", ip="127.0.0.1", port=9012)
        self.client_node.contacts["contact_bob"] = c

        g = QGroup(
            qgroup_id="group_test_001",
            name="研发一组",
            master_id="gateway_test_node_001",
            members={"gateway_test_node_001": "GatewayBot", "contact_bob": "Bob"},
        )
        self.client_node.qgroups["group_test_001"] = g

        return create_app(self.client_node)

    @unittest_run_loop
    async def test_get_index_html(self):
        """Test GET / returns HTML SPA page."""
        resp = await self.client.get("/")
        self.assertEqual(resp.status, 200)
        text = await resp.text()
        self.assertIn("<title>LanBridge - 内网通原生协议终端</title>", text)

    @unittest_run_loop
    async def test_get_status_api(self):
        """Test GET /api/status."""
        resp = await self.client.get("/api/status")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["user_id"], "gateway_test_node_001")
        self.assertEqual(data["nickname"], "GatewayBot")
        self.assertEqual(data["contacts_count"], 1)
        self.assertEqual(data["groups_count"], 1)

    @unittest_run_loop
    async def test_get_contacts_api(self):
        """Test GET /api/contacts."""
        resp = await self.client.get("/api/contacts")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["contacts"]), 1)
        self.assertEqual(data["contacts"][0]["nickname"], "Bob")

    @unittest_run_loop
    async def test_get_groups_api(self):
        """Test GET /api/groups."""
        resp = await self.client.get("/api/groups")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["groups"]), 1)
        self.assertEqual(data["groups"][0]["name"], "研发一组")
        self.assertIn("members_detail", data["groups"][0])
        self.assertEqual(len(data["groups"][0]["members_detail"]), 2)
        self_member = next(m for m in data["groups"][0]["members_detail"] if m["is_self"])
        self.assertEqual(self_member["status"], 0)
        self.assertEqual(self_member["nickname"], "GatewayBot")

    @unittest_run_loop
    async def test_post_create_group(self):
        """Test POST /api/group/create."""
        payload = {"name": "新部门", "intro": "部门简介", "announcement": "公告"}
        resp = await self.client.post("/api/group/create", json=payload)
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["ok"])
        self.assertIn("qgroup_id", data)
        self.assertIn(data["qgroup_id"], self.client_node.qgroups)
        self.assertEqual(self.client_node.qgroups[data["qgroup_id"]].name, "新部门")

    @unittest_run_loop
    async def test_post_status_and_signature(self):
        """Test POST /api/status."""
        payload = {"status": 1, "signature": "外出开会中"}
        resp = await self.client.post("/api/status", json=payload)
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.client_node.status, 1)
        self.assertEqual(self.client_node.signature, "外出开会中")

    @unittest_run_loop
    async def test_post_message_and_typing(self):
        """Test POST /api/message and POST /api/typing."""
        # Test missing params
        resp_bad = await self.client.post("/api/message", json={})
        self.assertEqual(resp_bad.status, 400)

        # Test valid typing state post
        resp_type = await self.client.post("/api/typing", json={"peer_ip": "127.0.0.1", "typing": True})
        self.assertEqual(resp_type.status, 200)

        # Test valid recall post
        resp_recall = await self.client.post("/api/recall", json={"target_ip": "127.0.0.1", "target_msg_id": 12345})
        self.assertEqual(resp_recall.status, 200)

    @unittest_run_loop
    async def test_websocket_connection_and_ping(self):
        """Test WebSocket connection and ping/pong."""
        ws = await self.client.ws_connect("/ws")
        await ws.send_json({"action": "ping"})
        msg = await ws.receive_json()
        self.assertEqual(msg.get("event"), "pong")
        await ws.close()

    @unittest_run_loop
    async def test_native_status_and_import(self):
        """Test GET /api/native/status and POST /api/native/import."""
        resp = await self.client.get("/api/native/status")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["ok"])

        resp_import = await self.client.post("/api/native/import", json={"sync_groups": True})
        self.assertEqual(resp_import.status, 200)
        import_data = await resp_import.json()
        self.assertTrue(import_data["ok"])

    @unittest_run_loop
    async def test_image_endpoint(self):
        """Test GET /api/images/{md5}."""
        dummy_md5 = "11223344556677889900aabbccddeeff"
        # Prepopulate dummy image
        self.client_node.pending_images[dummy_md5] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

        resp = await self.client.get(f"/api/images/{dummy_md5}")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content_type, "image/png")
        body = await resp.read()
        self.assertEqual(body, b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

        # Not found test
        resp_404 = await self.client.get("/api/images/00000000000000000000000000000000")
        self.assertEqual(resp_404.status, 404)

    @unittest_run_loop
    async def test_static_vue_js(self):
        """Test GET /static/vue.global.prod.js offline availability."""
        resp = await self.client.get("/static/vue.global.prod.js")
        self.assertEqual(resp.status, 200)
        text = await resp.text()
        self.assertIn("Vue", text)
        self.assertTrue(len(text) > 50000)

    @unittest_run_loop
    async def test_post_scan_endpoint(self):
        """Test POST /api/scan triggers scan_subnets and returns results."""
        resp = await self.client.post("/api/scan", json={"targets": ["127.0.0.1"]})
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["ok"])
        self.assertIn("count", data)
        self.assertIn("contacts", data)



if __name__ == "__main__":
    import unittest
    unittest.main()
