#!/usr/bin/env python3
"""AstrBot Compatibility Layer (compat.py).

Provides unified imports for AstrBot API classes with clean fallback stubs
allowing the adapter and tests to run seamlessly in any Python environment.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional

try:
    from astrbot.api import logger
    from astrbot.api.event import AstrMessageEvent, MessageChain, filter
    from astrbot.api.message_components import Image, Plain, Record
    from astrbot.api.platform import (
        AstrBotMessage,
        MessageMember,
        MessageType,
        Platform,
        PlatformMetadata,
        register_platform_adapter,
    )
    from astrbot.api.star import Context, Star
    try:
        from astrbot.core.platform.astr_message_event import MessageSession
    except ImportError:
        try:
            from astrbot.core.platform.astr_message_event import MessageSesion as MessageSession
        except ImportError:
            MessageSession = None

    IS_ASTRBOT_INSTALLED = True

except ImportError:
    IS_ASTRBOT_INSTALLED = False

    logger = logging.getLogger("astrbot_plugin_lanbridge")

    class MessageType:
        GROUP_MESSAGE = 1
        FRIEND_MESSAGE = 2

    class Plain:
        def __init__(self, text: str):
            self.text = text

        def __repr__(self):
            return f"Plain({self.text!r})"

    class Image:
        def __init__(self, file: str = "", url: str = ""):
            self.file = file
            self.url = url

        async def convert_to_file_path(self) -> str:
            return self.file

    class Record:
        def __init__(self, file: str = ""):
            self.file = file

    class MessageChain:
        def __init__(self, chain: Optional[List[Any]] = None):
            self.chain = chain or []

    class MessageMember:
        def __init__(self, user_id: str, nickname: str):
            self.user_id = user_id
            self.nickname = nickname

    class AstrBotMessage:
        def __init__(self):
            self.type = MessageType.FRIEND_MESSAGE
            self.group_id = None
            self.message_str = ""
            self.sender = None
            self.message = []
            self.raw_message = None
            self.self_id = ""
            self.session_id = ""
            self.message_id = ""

    class PlatformMetadata:
        def __init__(self, name: str, description: str):
            self.name = name
            self.description = description

    class Platform:
        def __init__(self, event_queue: asyncio.Queue):
            self.event_queue = event_queue

        def commit_event(self, event: Any):
            if self.event_queue:
                self.event_queue.put_nowait(event)

        async def send_by_session(self, session: Any, message_chain: Any):
            pass

    class AstrMessageEvent:
        def __init__(self, message_str: str, message_obj: Any, platform_meta: Any, session_id: str):
            self.message_str = message_str
            self.message_obj = message_obj
            self.platform_meta = platform_meta
            self.session_id = session_id
            self._sender_id = getattr(message_obj.sender, "user_id", session_id) if hasattr(message_obj, "sender") else session_id

        def get_sender_id(self) -> str:
            return self._sender_id

        async def send(self, message: Any):
            pass

    class Context:
        pass

    class Star:
        def __init__(self, context: Any):
            self.context = context

    class _Filter:
        @staticmethod
        def command(name: str):
            def decorator(func: Callable):
                func._command_name = name
                return func
            return decorator

    filter = _Filter()

    def register_platform_adapter(name: str, desc: str, default_config_tmpl: Optional[dict] = None):
        def decorator(cls):
            cls._adapter_name = name
            cls._adapter_desc = desc
            cls._default_config_tmpl = default_config_tmpl or {}
            return cls
        return decorator

    MessageSession = None

__all__ = [
    "logger",
    "AstrMessageEvent",
    "MessageChain",
    "Plain",
    "Image",
    "Record",
    "AstrBotMessage",
    "MessageMember",
    "MessageType",
    "Platform",
    "PlatformMetadata",
    "Context",
    "Star",
    "filter",
    "register_platform_adapter",
    "MessageSession",
    "IS_ASTRBOT_INSTALLED",
]
