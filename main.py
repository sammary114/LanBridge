#!/usr/bin/env python3
"""LanBridge Plugin Entry for AstrBot (main.py).

AstrBot plugin entry point registering the LanBridge platform adapter and
providing management commands.
"""

from __future__ import annotations

import logging
from typing import Any

try:
    from .adapter import LanBridgePlatformAdapter
    from .compat import AstrMessageEvent, Context, Star, filter, logger
except (ImportError, ValueError):
    from adapter import LanBridgePlatformAdapter
    from compat import AstrMessageEvent, Context, Star, filter, logger


class LanBridgePlugin(Star):
    """AstrBot plugin providing the LanBridge (NeiWangTong) platform adapter."""

    def __init__(self, context: Context):
        super().__init__(context)
        # Reference adapter to ensure registration decorator runs
        self.adapter_cls = LanBridgePlatformAdapter
        logger.info("LanBridge platform adapter plugin loaded successfully!")

    @filter.command("lanbridge_info")
    async def lanbridge_info(self, event: AstrMessageEvent):
        """查看当前内网通 (LanBridge) 适配器状态与连接信息"""
        yield event.plain_result(
            "【LanBridge 适配器信息】\n"
            "- 支持平台: 内网通 / IMO (3.4.3055)\n"
            "- 传输协议: ENet 可靠 UDP (端口 9012)\n"
            "- 设备发现: 304B 二进制广播 (端口 9011)\n"
            "- 加密机制: 32 轮 XTEA 对称加密\n"
            "- 兼容协议: 飞鸽 / 飞秋 (UDP 2425)\n"
            "- 状态: 运行就绪"
        )

    async def terminate(self):
        """Plugin termination callback."""
        logger.info("LanBridge platform adapter plugin unloading...")
