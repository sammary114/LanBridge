#!/usr/bin/env python3
"""Tests for AstrBot LanBridge Platform Adapter (test_astrbot_adapter.py)."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from adapter import LanBridgePlatformAdapter
from compat import MessageChain, Plain
from event import LanBridgePlatformEvent
from lanbridge.client import LanBridgeMessage, PeerInfo
from main import LanBridgePlugin


class TestAstrBotAdapter(unittest.IsolatedAsyncioTestCase):
    """Unit tests for the LanBridge AstrBot platform adapter."""

    async def asyncSetUp(self):
        self.queue = asyncio.Queue()
        self.config = {
            "bind_ip": "127.0.0.1",
            "bot_name": "TestAI",
            "bot_sign": "AI Assistant for NeiWangTong",
            "discovery_port": 19011,
            "data_port": 19012,
            "auto_shake_back": True,
        }
        self.adapter = LanBridgePlatformAdapter(
            platform_config=self.config,
            platform_settings={},
            event_queue=self.queue,
        )

    def test_adapter_metadata(self):
        """Verify adapter metadata."""
        meta = self.adapter.meta()
        self.assertEqual(meta.name, "lanbridge")
        self.assertIn("内网通", meta.description)

    async def test_convert_message(self):
        """Test converting LanBridgeMessage to AstrBotMessage."""
        msg = LanBridgeMessage(
            msg_id="123456789_001",
            sender_id="peer_user_123",
            sender_name="张三",
            text="你好，机器人！",
            raw_xml="<X_SEND_MSG>...</X_SEND_MSG>",
            timestamp=1234567890.0,
        )
        abm = await self.adapter.convert_message(msg)
        self.assertEqual(abm.message_str, "你好，机器人！")
        self.assertEqual(abm.session_id, "peer_user_123")
        self.assertEqual(abm.message_id, "123456789_001")
        self.assertEqual(abm.sender.user_id, "peer_user_123")
        self.assertEqual(abm.sender.nickname, "张三")
        self.assertEqual(len(abm.message), 1)
        self.assertIsInstance(abm.message[0], Plain)
        self.assertEqual(abm.message[0].text, "你好，机器人！")

    async def test_handle_msg_commits_event(self):
        """Test that handle_msg wraps message into event and puts on event_queue."""
        msg = LanBridgeMessage(
            msg_id="999_test",
            sender_id="uid_456",
            sender_name="李四",
            text="测试事件提交",
            raw_xml="<X_SEND_MSG></X_SEND_MSG>",
            timestamp=123456.0,
        )
        abm = await self.adapter.convert_message(msg)
        await self.adapter.handle_msg(abm)

        # Should be committed to queue
        self.assertFalse(self.queue.empty())
        event = await self.queue.get()
        self.assertIsInstance(event, LanBridgePlatformEvent)
        self.assertEqual(event.message_str, "测试事件提交")
        self.assertEqual(event.get_sender_id(), "uid_456")

    async def test_event_send_plain(self):
        """Test sending message chain with Plain text."""
        msg = LanBridgeMessage(
            msg_id="msg_001",
            sender_id="uid_reply",
            sender_name="王五",
            text="你好",
            raw_xml="",
            timestamp=100.0,
        )
        abm = await self.adapter.convert_message(msg)
        event = LanBridgePlatformEvent(
            message_str=abm.message_str,
            message_obj=abm,
            platform_meta=self.adapter.meta(),
            session_id=abm.session_id,
            client=self.adapter.client,
        )

        with patch.object(self.adapter.client, "send_text", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = "sent_msg_id"
            chain = MessageChain([Plain(text="回复：你好！")])
            await event.send(chain)
            mock_send.assert_called_once_with(target="uid_reply", text="回复：你好！")

    async def test_send_by_session(self):
        """Test proactive sending by session."""
        session = MagicMock()
        session.session_id = "target_peer_777"
        with patch.object(self.adapter.client, "send_text", new_callable=AsyncMock) as mock_send:
            chain = MessageChain([Plain(text="主动通知测试")])
            await self.adapter.send_by_session(session, chain)
            mock_send.assert_called_once_with(target="target_peer_777", text="主动通知测试")

    def test_plugin_init(self):
        """Test AstrBot Star plugin initialization."""
        plugin = LanBridgePlugin(context=None)
        self.assertIsNotNone(plugin.adapter_cls)


if __name__ == "__main__":
    unittest.main()
