#!/usr/bin/env python3
"""LanBridge CLanFileTran Protocol (file_tran.py).

Implements the single large file transmission protocol reverse-engineered from
ShiYeLine.exe (0x005a44b0 / 0x005aa5c0):
- Command 1: Download Request (344 bytes)
- Command 2: Download Response (356 bytes, carrying status, md5, 64-bit file_size)
- Command 3: Data Chunk (chunk_len + 152 bytes, carrying file_size, offset, chunk_len)
"""

from __future__ import annotations

import os
import re
import struct
import time
import uuid
from typing import Optional, Dict, Any


def build_minifile_response(md5_hex: str, file_size: int, status: int = 0) -> bytes:
    """Build authentic 356-byte Mini-File / File download response packet (Command 2)."""
    buf = bytearray(356)
    struct.pack_into(">I", buf, 0, 356)
    struct.pack_into(">I", buf, 4, 1)
    struct.pack_into(">I", buf, 8, 2)  # Command 2: Response
    struct.pack_into(">I", buf, 0x70, status)  # Status: 0 = OK
    md5_b = md5_hex.encode("ascii")
    buf[0x74 : 0x74 + len(md5_b)] = md5_b
    struct.pack_into(">Q", buf, 0x94, file_size)  # 64-bit big-endian file size
    return bytes(buf)


def build_minifile_chunk(file_size: int, offset: int, chunk_data: bytes) -> bytes:
    """Build authentic Mini-File / File data chunk packet (Command 3)."""
    chunk_len = len(chunk_data)
    total_len = chunk_len + 0x98
    buf = bytearray(total_len)
    struct.pack_into(">I", buf, 0, total_len)
    struct.pack_into(">I", buf, 4, 1)
    struct.pack_into(">I", buf, 8, 3)  # Command 3: Data Chunk
    struct.pack_into(">Q", buf, 0x70, file_size)  # 64-bit file size
    struct.pack_into(">Q", buf, 0x78, offset)  # 64-bit chunk offset
    struct.pack_into(">I", buf, 0x80, chunk_len)  # 32-bit chunk length
    buf[0x98 : 0x98 + chunk_len] = chunk_data
    return bytes(buf)


def parse_minifile_packet(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse incoming Mini-File packet header and extract command and metadata."""
    if len(data) < 12:
        return None
    total_len = struct.unpack(">I", data[:4])[0]
    p_type = struct.unpack(">I", data[4:8])[0]
    p_cmd = struct.unpack(">I", data[8:12])[0]
    res: Dict[str, Any] = {"total_len": total_len, "type": p_type, "cmd": p_cmd}

    if p_cmd == 1 and len(data) >= 12:
        # Command 1: Download Request
        m = re.search(rb'\|([0-9a-fA-F]{32})', data)
        if m:
            res["md5"] = m.group(1).decode("ascii").lower()
        else:
            m_v = re.search(rb'"v"\s*:\s*"([0-9a-fA-F]{32})"', data)
            if m_v:
                res["md5"] = m_v.group(1).decode("ascii").lower()
            elif len(data) >= 0x90:
                raw_md5 = data[0x70:0x90].decode("ascii", errors="ignore").strip("\x00")
                if len(raw_md5) == 32 and all(c in "0123456789abcdefABCDEF" for c in raw_md5):
                    res["md5"] = raw_md5.lower()

    elif p_cmd == 2 and len(data) >= 356:
        # Command 2: Download Response
        res["status"] = struct.unpack(">I", data[0x70:0x74])[0]
        res["md5"] = data[0x74:0x94].decode("ascii", errors="ignore").strip("\x00")
        res["file_size"] = struct.unpack(">Q", data[0x94:0x9C])[0]

    elif p_cmd == 3 and len(data) >= 0x98:
        # Command 3: Data Chunk
        res["file_size"] = struct.unpack(">Q", data[0x70:0x78])[0]
        res["offset"] = struct.unpack(">Q", data[0x78:0x80])[0]
        res["chunk_len"] = struct.unpack(">I", data[0x80:0x84])[0]
        res["chunk_data"] = data[0x98 : 0x98 + res["chunk_len"]]

    return res


def check_and_save_image(raw_bytes: bytes, output_dir: Optional[str] = None) -> Optional[str]:
    """Detect image magic (PNG, JPG, GIF, BMP) in raw TCP payload and save to disk."""
    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), "captures", "images")
    os.makedirs(output_dir, exist_ok=True)

    png_magic = b"\x89PNG\r\n\x1a\n"
    jpg_magic = b"\xff\xd8\xff"
    gif_magic = b"GIF8"
    bmp_magic = b"BM"

    ext = None
    offset = -1
    for magic, extension in [(png_magic, "png"), (jpg_magic, "jpg"), (gif_magic, "gif"), (bmp_magic, "bmp")]:
        pos = raw_bytes.find(magic)
        if pos != -1:
            ext = extension
            offset = pos
            break

    if ext and offset != -1:
        img_data = raw_bytes[offset:]
        filename = f"captured_{int(time.time())}_{uuid.uuid4().hex[:6]}.{ext}"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "wb") as f:
            f.write(img_data)
        return filepath
    return None
