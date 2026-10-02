#!/usr/bin/env python3
"""LanBridge Platform Adapter for AstrBot (adapter.py).

Implements the Platform adapter registering with AstrBot so that AstrBot can
act as a native NeiWangTong (IMO 3.4.3055) contact.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

try:
    from .compat import (
        AstrBotMessage,
        MessageChain,
        MessageMember,
        MessageSession,
        MessageType,
        Plain,
        Platform,
        PlatformMetadata,
        logger,
        register_platform_adapter,
    )
    from .event import LanBridgePlatformEvent
    from .lanbridge.client import ClientConfig, LanBridgeClient, LanBridgeMessage, PeerInfo
except (ImportError, ValueError):
    from compat import (
        AstrBotMessage,
        MessageChain,
        MessageMember,
        MessageSession,
        MessageType,
        Plain,
        Platform,
        PlatformMetadata,
        logger,
        register_platform_adapter,
    )
    from event import LanBridgePlatformEvent
    from lanbridge.client import ClientConfig, LanBridgeClient, LanBridgeMessage, PeerInfo


@register_platform_adapter(
    "lanbridge",
    "内网通 (LanBridge) 适配器",
    default_config_tmpl={
        "bind_ip": "0.0.0.0",
        "bot_name": "LanBridge-AI助手",
        "bot_sign": "由 AstrBot 大模型驱动的内网通 AI 助手",
        "corp_id": "",
        "discovery_port": 9011,
        "data_port": 9012,
        "auto_shake_back": False,
    },
)
class LanBridgePlatformAdapter(Platform):
    """AstrBot Platform adapter for NeiWangTong (LanBridge)."""

    def __init__(
        self,
        platform_config: dict,
        platform_settings: dict,
        event_queue: asyncio.Queue,
    ) -> None:
        super().__init__(event_queue)
        self.config = platform_config or {}
        self.settings = platform_settings or {}

        # Build client configuration
        client_cfg = ClientConfig(
            bind_ip=self.config.get("bind_ip", "0.0.0.0"),
            discovery_port=int(self.config.get("discovery_port", 9011)),
            data_port=int(self.config.get("data_port", 9012)),
            username=self.config.get("bot_name", "LanBridge-AI助手"),
            sign=self.config.get("bot_sign", "由 AstrBot 大模型驱动的内网通 AI 助手"),
            corp_id=self.config.get("corp_id", ""),
            auto_ack=True,
            auto_handshake=True,
        )
        self.client = LanBridgeClient(config=client_cfg)
        self._stop_event = asyncio.Event()

    def meta(self) -> PlatformMetadata:
        return PlatformMetadata(
            "lanbridge",
            "内网通 (LanBridge) 适配器",
        )

    async def run(self):
        """Main lifecycle runner for AstrBot adapter."""
        logger.info("Starting LanBridge platform adapter...")

        # Setup callbacks
        async def _on_client_message(msg: LanBridgeMessage):
            logger.info("Received NeiWangTong message from %s: %s", msg.sender_id, msg.text)
            abm = await self.convert_message(msg)
            await self.handle_msg(abm)

        async def _on_client_shake(sender_id: str, peer: PeerInfo):
            logger.info("Received Window Shake from %s", sender_id)
            if self.config.get("auto_shake_back", False):
                await self.client.send_shake(target=sender_id)

        self.client.on_message = _on_client_message
        self.client.on_shake = _on_client_shake

        # Start LanBridge client network loop
        await self.client.start()
        logger.info("LanBridge platform adapter is running!")

        # Keep running until cancelled
        try:
            await self._stop_event.wait()
        finally:
            await self.client.stop()
            logger.info("LanBridge platform adapter stopped.")

    async def convert_message(self, msg: LanBridgeMessage) -> AstrBotMessage:
        """Convert a LanBridge message into an AstrBotMessage object."""
        abm = AstrBotMessage()
        abm.type = MessageType.FRIEND_MESSAGE  # 1v1 private chat
        abm.message_str = msg.text
        abm.sender = MessageMember(
            user_id=msg.sender_id,
            nickname=msg.sender_name,
        )
        abm.message = [Plain(text=msg.text)]
        abm.raw_message = msg.raw_xml
        abm.self_id = self.client.config.user_id
        abm.session_id = msg.sender_id
        abm.message_id = msg.msg_id
        return abm

    async def handle_msg(self, message: AstrBotMessage):
        """Wrap and commit message event to AstrBot core event queue."""
        message_event = LanBridgePlatformEvent(
            message_str=message.message_str,
            message_obj=message,
            platform_meta=self.meta(),
            session_id=message.session_id,
            client=self.client,
        )
        self.commit_event(message_event)

    async def send_by_session(
        self, session: Any, message_chain: MessageChain
    ):
        """Send message proactively by AstrBot session."""
        target_id = getattr(session, "session_id", str(session))
        for comp in message_chain.chain:
            if isinstance(comp, Plain):
                await self.client.send_text(target=target_id, text=comp.text)
            else:
                text_val = getattr(comp, "text", str(comp))
                if text_val:
                    await self.client.send_text(target=target_id, text=text_val)

        if hasattr(super(), "send_by_session"):
            await super().send_by_session(session, message_chain)

    async def terminate(self):
        """Gracefully stop adapter."""
        self._stop_event.set()
