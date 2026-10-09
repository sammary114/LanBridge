#!/usr/bin/env python3
"""Tests for AstrBot LanBridge Platform Adapter (test_astrbot_adapter.py)."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from adapter import LanBridgePlatformAdapter
from compat import Image, MessageChain, MessageType, Plain
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
            "image_port": 19013,
            "auto_shake_back": True,
            "auto_typing": True,
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
        self.assertEqual(abm.type, MessageType.FRIEND_MESSAGE)
        self.assertEqual(abm.message_str, "你好，机器人！")
        self.assertEqual(abm.session_id, "peer_user_123")
        self.assertEqual(abm.message_id, "123456789_001")
        self.assertEqual(abm.sender.user_id, "peer_user_123")
        self.assertEqual(abm.sender.nickname, "张三")
        self.assertEqual(len(abm.message), 1)
        self.assertIsInstance(abm.message[0], Plain)
        self.assertEqual(abm.message[0].text, "你好，机器人！")

    async def test_convert_group_message(self):
        """Test converting group LanBridgeMessage to AstrBot GROUP_MESSAGE."""
        msg = LanBridgeMessage(
            msg_id="group_msg_001",
            sender_id="user_in_group",
            sender_name="群友小王",
            text="大家下午好",
            raw_xml="<X_QGROUP_SEND_MSG></X_QGROUP_SEND_MSG>",
            timestamp=1234567890.0,
            qgroup_id="99999",
        )
        abm = await self.adapter.convert_message(msg)
        self.assertEqual(abm.type, MessageType.GROUP_MESSAGE)
        self.assertEqual(abm.group_id, "99999")
        self.assertEqual(abm.session_id, "qgroup_99999")
        self.assertEqual(abm.sender.user_id, "user_in_group")

    async def test_convert_image_message(self):
        """Test converting message containing an inline image."""
        msg = LanBridgeMessage(
            msg_id="img_msg_001",
            sender_id="user_pic",
            sender_name="摄影师",
            text="[图片]",
            raw_xml="",
            timestamp=1234567890.0,
            is_image=True,
            image_md5="0123456789abcdef0123456789abcdef",
        )
        abm = await self.adapter.convert_message(msg)
        self.assertEqual(len(abm.message), 2)
        self.assertIsInstance(abm.message[0], Plain)
        self.assertIsInstance(abm.message[1], Image)
        self.assertEqual(abm.message[1].file, "0123456789abcdef0123456789abcdef")

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

    async def test_event_send_image_1v1(self):
        """Test sending Image component in 1v1 chat via client.send_image."""
        msg = LanBridgeMessage(
            msg_id="msg_pic",
            sender_id="uid_pic_sender",
            sender_name="小李",
            text="发张图来看看",
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

        with patch.object(self.adapter.client, "send_image", new_callable=AsyncMock) as mock_send_img:
            mock_send_img.return_value = "fake_md5_hash"
            chain = MessageChain([Image(file="/tmp/test.png")])
            await event.send(chain)
            mock_send_img.assert_called_once_with(target="uid_pic_sender", image="/tmp/test.png")

    async def test_event_send_group_text_and_image(self):
        """Test sending Plain and Image components in group chat."""
        msg = LanBridgeMessage(
            msg_id="grp_msg_100",
            sender_id="uid_group_user",
            sender_name="群友小张",
            text="群聊消息",
            raw_xml="",
            timestamp=100.0,
            qgroup_id="group_888",
        )
        abm = await self.adapter.convert_message(msg)
        event = LanBridgePlatformEvent(
            message_str=abm.message_str,
            message_obj=abm,
            platform_meta=self.adapter.meta(),
            session_id=abm.session_id,
            client=self.adapter.client,
        )

        with patch.object(self.adapter.client, "send_group_text", new_callable=AsyncMock) as mock_grp_txt, \
             patch.object(self.adapter.client, "send_group_image", new_callable=AsyncMock) as mock_grp_img:
            chain = MessageChain([Plain(text="群文本回复"), Image(file="/tmp/group_pic.jpg")])
            await event.send(chain)
            mock_grp_txt.assert_called_once_with(qgroup_id="group_888", text="群文本回复")
            mock_grp_img.assert_called_once_with(qgroup_id="group_888", image="/tmp/group_pic.jpg")

    async def test_event_typing(self):
        """Test sending typing indicator from event."""
        msg = LanBridgeMessage(
            msg_id="msg_002",
            sender_id="uid_typing_target",
            sender_name="测试打字",
            text="你在吗",
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

        with patch.object(self.adapter.client, "send_typing", new_callable=AsyncMock) as mock_typing:
            mock_typing.return_value = True
            await event.typing(typing=True)
            mock_typing.assert_called_once_with(target="uid_typing_target", typing=True)

    async def test_change_status(self):
        """Test changing online status on adapter."""
        with patch.object(self.adapter.client, "change_status", new_callable=AsyncMock) as mock_status:
            await self.adapter.change_status(status=2)
            mock_status.assert_called_once_with(status=2)

    async def test_send_by_session(self):
        """Test proactive sending by session (private and group)."""
        # 1. 1v1 session
        session = MagicMock()
        session.session_id = "target_peer_777"
        session.group_id = None
        with patch.object(self.adapter.client, "send_text", new_callable=AsyncMock) as mock_send:
            chain = MessageChain([Plain(text="主动通知测试")])
            await self.adapter.send_by_session(session, chain)
            mock_send.assert_called_once_with(target="target_peer_777", text="主动通知测试")

        # 2. Group session
        session_group = MagicMock()
        session_group.session_id = "qgroup_12345"
        session_group.group_id = "12345"
        with patch.object(self.adapter.client, "send_group_text", new_callable=AsyncMock) as mock_grp_send, \
             patch.object(self.adapter.client, "send_group_image", new_callable=AsyncMock) as mock_grp_img:
            chain = MessageChain([Plain(text="群主动通知"), Image(file="pic.png")])
            await self.adapter.send_by_session(session_group, chain)
            mock_grp_send.assert_called_once_with(qgroup_id="12345", text="群主动通知")
            mock_grp_img.assert_called_once_with(qgroup_id="12345", image="pic.png")

    def test_plugin_init(self):
        """Test AstrBot Star plugin initialization."""
        plugin = LanBridgePlugin(context=None)
        self.assertIsNotNone(plugin.adapter_cls)


if __name__ == "__main__":
    unittest.main()
