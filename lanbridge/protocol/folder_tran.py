#!/usr/bin/env python3
"""LanBridge CFolderTranEngine Protocol (folder_tran.py).

Implements the dedicated folder and chat inline image transmission protocol reverse-engineered
from ShiYeLine.exe (0x00647050~0x00647b20):
- Command 1: Download Request (500 bytes, carrying token at 0x34)
- Command 2: Download Response (108 bytes, carrying token, file_size, chunk_size)
- Command 3: Chunk Request (108 bytes, carrying token, offset, chunk_len)
- Command 4: Data Chunk (chunk_len + 100 bytes, data starting at offset 0x64)
"""

from __future__ import annotations

import re
import struct
from typing import Optional, Dict, Any


def build_folder_tran_response(
    file_size: int,
    token: int = 0,
    offset: int = 0,
    chunk_size: int = 16384,
) -> bytes:
    """Build authentic 108-byte CFolderTranEngine response packet (Command 2).

    Used by Nwt native chat inline image and folder/file transfer engines.
    Header layout (BE):
      0x00: total_len (108)
      0x04: proto_type (1)
      0x08: cmd (2)
      0x34: token (64-bit)
      0x3c: file_size (64-bit)
      0x44: chunk_size (64-bit)
    """
    buf = bytearray(108)
    struct.pack_into(">I", buf, 0, 108)          # total_len
    struct.pack_into(">I", buf, 4, 1)            # proto_type = 1
    struct.pack_into(">I", buf, 8, 2)            # cmd = 2 (Response)
    struct.pack_into(">Q", buf, 0x34, token)      # 64-bit token BE
    struct.pack_into(">Q", buf, 0x3c, file_size)  # 64-bit file size BE
    struct.pack_into(">Q", buf, 0x44, chunk_size) # 64-bit chunk size BE
    return bytes(buf)


def build_folder_tran_chunk(
    file_size: int,
    offset: int,
    chunk_data: bytes,
    token: int = 0,
) -> bytes:
    """Build authentic CFolderTranEngine data chunk packet (Command 4).

    Header length is exactly 100 bytes (0x64), followed by raw chunk payload.
    Header layout (BE):
      0x00: total_len (chunk_len + 100)
      0x04: proto_type (1)
      0x08: cmd (4)
      0x34: token (64-bit)
      0x3c: file_size (64-bit)
      0x44: offset (64-bit)
      0x4c: chunk_len (32-bit)
      0x64: raw payload
    """
    chunk_len = len(chunk_data)
    total_len = chunk_len + 100
    buf = bytearray(total_len)
    struct.pack_into(">I", buf, 0, total_len)     # total_len
    struct.pack_into(">I", buf, 4, 1)             # proto_type = 1
    struct.pack_into(">I", buf, 8, 4)             # cmd = 4 (Data Chunk)
    struct.pack_into(">Q", buf, 0x34, token)      # 64-bit token BE
    struct.pack_into(">Q", buf, 0x3c, file_size)  # 64-bit file size BE
    struct.pack_into(">Q", buf, 0x44, offset)     # 64-bit offset BE
    struct.pack_into(">I", buf, 0x4c, chunk_len)  # 32-bit chunk len BE
    buf[0x64 : 0x64 + chunk_len] = chunk_data
    return bytes(buf)


def parse_folder_tran_packet(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse incoming CFolderTranEngine packet (Command 1, 2, 3, or 4)."""
    if len(data) < 12:
        return None
    total_len = struct.unpack(">I", data[:4])[0]
    p_type = struct.unpack(">I", data[4:8])[0]
    p_cmd = struct.unpack(">I", data[8:12])[0]
    res: Dict[str, Any] = {"total_len": total_len, "type": p_type, "cmd": p_cmd}

    if p_cmd == 1 and len(data) >= 12:
        # Command 1: Download Request
        if len(data) >= 0x3C:
            tok = struct.unpack(">Q", data[0x34:0x3c])[0]
            if tok != 0:
                res["token"] = tok
        m = re.search(rb'(\d+)\|([0-9a-fA-F]{32})', data)
        if m:
            res["token"] = int(m.group(1))
            res["md5"] = m.group(2).decode("ascii").lower()
        else:
            m_v = re.search(rb'"v"\s*:\s*"([0-9a-fA-F]{32})"', data)
            if m_v:
                res["md5"] = m_v.group(1).decode("ascii").lower()

    elif p_cmd == 2 and len(data) >= 0x4C:
        # Command 2: Download Response
        res["token"] = struct.unpack(">Q", data[0x34:0x3c])[0]
        res["file_size"] = struct.unpack(">Q", data[0x3c:0x44])[0]
        res["chunk_size"] = struct.unpack(">Q", data[0x44:0x4c])[0]

    elif p_cmd == 3 and len(data) >= 0x44:
        # Command 3: Chunk Request from receiver
        res["token"] = struct.unpack(">Q", data[0x34:0x3c])[0]
        res["offset"] = struct.unpack(">Q", data[0x3c:0x44])[0]
        if len(data) >= 0x4C:
            res["chunk_len"] = struct.unpack(">Q", data[0x44:0x4c])[0]

    elif p_cmd == 4 and len(data) >= 0x64:
        # Command 4: Data Chunk
        res["token"] = struct.unpack(">Q", data[0x34:0x3c])[0]
        res["file_size"] = struct.unpack(">Q", data[0x3c:0x44])[0]
        res["offset"] = struct.unpack(">Q", data[0x44:0x4c])[0]
        chunk_len_32 = struct.unpack(">I", data[0x4c:0x50])[0]
        res["chunk_len"] = chunk_len_32
        res["chunk_data"] = data[0x64 : 0x64 + chunk_len_32]

    return res
