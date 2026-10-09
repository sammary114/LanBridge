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

    def get_group_id(self) -> Optional[str]:
        """Get group ID if message is from a QGroup."""
        return getattr(self.message_obj, "group_id", None)

    async def typing(self, typing: bool = True):
        """Send authentic typing indicator (Opcode 1008) to peer in 1v1 chat."""
        target_id = self.get_sender_id()
        if not self.get_group_id():
            try:
                await self.client.send_typing(target=target_id, typing=typing)
            except Exception as e:
                logger.debug("Failed sending typing indicator: %s", e)

    async def send(self, message: MessageChain):
        """Send a MessageChain reply back to the sender or group in NeiWangTong."""
        group_id = self.get_group_id()
        is_group = bool(group_id)
        target_id = self.get_sender_id()

        for component in message.chain:
            if isinstance(component, Plain):
                if is_group and group_id:
                    await self.client.send_group_text(qgroup_id=group_id, text=component.text)
                else:
                    await self.client.send_text(target=target_id, text=component.text)
            elif isinstance(component, Image):
                img_path = await component.convert_to_file_path()
                logger.info("Sending authentic CFolderTranEngine image to %s: %s", group_id if is_group else target_id, img_path)
                if is_group and group_id:
                    await self.client.send_group_image(qgroup_id=group_id, image=img_path)
                else:
                    await self.client.send_image(target=target_id, image=img_path)
            else:
                text_repr = getattr(component, "text", str(component))
                if text_repr:
                    if is_group and group_id:
                        await self.client.send_group_text(qgroup_id=group_id, text=text_repr)
                    else:
                        await self.client.send_text(target=target_id, text=text_repr)

        await super().send(message)
