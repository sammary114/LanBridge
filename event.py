#!/usr/bin/env python3
"""LanBridge Platform Event for AstrBot (event.py).

Implements the AstrMessageEvent subclass for LanBridge / NeiWangTong.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

try:
    from .compat import AstrMessageEvent, Image, MessageChain, Plain, Record, logger
except (ImportError, ValueError):
    from compat import AstrMessageEvent, Image, MessageChain, Plain, Record, logger

if TYPE_CHECKING:
    try:
        from .lanbridge.client import LanBridgeClient
    except (ImportError, ValueError):
        from lanbridge.client import LanBridgeClient


class LanBridgePlatformEvent(AstrMessageEvent):
    """Event triggered by an incoming message from a NeiWangTong client."""

    def __init__(
        self,
        message_str: str,
        message_obj: Any,
        platform_meta: Any,
        session_id: str,
        client: LanBridgeClient,
    ):
        super().__init__(message_str, message_obj, platform_meta, session_id)
        self.client = client

    async def send(self, message: MessageChain):
        """Send a MessageChain reply back to the sender in NeiWangTong."""
        target_id = self.get_sender_id()
        for component in message.chain:
            if isinstance(component, Plain):
                await self.client.send_text(target=target_id, text=component.text)
            elif isinstance(component, Image):
                # When an image is received from LLM or plugin, resolve to file path
                img_path = await component.convert_to_file_path()
                logger.info("Sending image to %s: %s", target_id, img_path)
                # LanBridge file transfer or notification
                await self.client.send_text(target=target_id, text=f"[图片: {img_path}]")
            else:
                text_repr = getattr(component, "text", str(component))
                if text_repr:
                    await self.client.send_text(target=target_id, text=text_repr)

        await super().send(message)
