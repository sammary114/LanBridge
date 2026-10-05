#!/usr/bin/env python3
"""Tests for LanBridge File Transfer Protocols (CLanFileTran & CFolderTranEngine)."""

from __future__ import annotations

import hashlib
import io
import os
import struct
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from lanbridge.protocol.file_tran import (
    build_minifile_response,
    build_minifile_chunk,
    parse_minifile_packet,
)
from lanbridge.protocol.folder_tran import (
    build_folder_tran_response,
    build_folder_tran_chunk,
    parse_folder_tran_packet,
)
from lanbridge.protocol.messages import (
    build_x_send_file_envelope,
    build_x_operate_recv_file_envelope,
    build_x_operate_send_file_envelope,
    build_x_progress_recv_file_envelope,
    Opcode,
)
from lanbridge.protocol.crypto import XteaEngine


class TestFileTranProtocol(unittest.TestCase):
    """Verify file transmission packets, envelopes, and chunking states."""

    def setUp(self) -> None:
        self.xtea = XteaEngine()

    def test_send_file_envelope(self) -> None:
        """Verify X_SEND_FILE envelope creation and decoding."""
        filename = "presentation.pdf"
        size = 10485760  # 10 MB
        task_id = 9527
        file_id = 1
        env = build_x_send_file_envelope(
            filename=filename,
            size=size,
            task_id=task_id,
            file_id=file_id,
            last_modify=1700000000,
        )
        self.assertGreater(len(env), 8)
        op, plain = self.xtea.parse_envelope(env)
        self.assertEqual(op, Opcode.X_SEND_FILE)
        xml = plain.decode("gbk")
        self.assertIn("<NAME>presentation.pdf</NAME>", xml)
        self.assertIn("<SIZE>10485760</SIZE>", xml)
        self.assertIn("<TASK_ID>9527</TASK_ID>", xml)

    def test_file_operation_envelopes(self) -> None:
        """Verify accept/reject/cancel and progress envelopes."""
        # 1. Accept file
        accept_env = build_x_operate_recv_file_envelope(task_id=9527, op=1)
        op, plain = self.xtea.parse_envelope(accept_env)
        self.assertEqual(op, Opcode.X_OPERATE_RECV_FILE)
        self.assertIn("<OP>1</OP>", plain.decode("gbk"))

        # 2. Progress notification
        prog_env = build_x_progress_recv_file_envelope(
            task_id=9527,
            total_size=10485760,
            recvd_size=5242880,
            speed="5.0MB/s",
        )
        op, plain = self.xtea.parse_envelope(prog_env)
        self.assertEqual(op, Opcode.X_PROGRESS_RECV_FILE)
        self.assertIn("<RECVD_SIZE>5242880</RECVD_SIZE>", plain.decode("gbk"))
        self.assertIn("<SPEED>5.0MB/s</SPEED>", plain.decode("gbk"))

    def test_clanfiletran_streaming_simulation(self) -> None:
        """Simulate a complete 3-chunk CLanFileTran streaming session."""
        sample_file_data = b"DATA_CHUNK_TEST_" * 2000  # 32,000 bytes
        file_size = len(sample_file_data)
        file_md5 = hashlib.md5(sample_file_data).hexdigest().lower()

        # 1. Receiver simulates sending Command 1 (344B)
        cmd1_buf = bytearray(344)
        struct.pack_into(">I", cmd1_buf, 0, 344)
        struct.pack_into(">I", cmd1_buf, 4, 1)
        struct.pack_into(">I", cmd1_buf, 8, 1)  # Cmd 1
        cmd1_buf[0x70 : 0x70 + 32] = file_md5.encode("ascii")
        parsed_cmd1 = parse_minifile_packet(bytes(cmd1_buf))
        self.assertEqual(parsed_cmd1["cmd"], 1)
        self.assertEqual(parsed_cmd1["md5"], file_md5)

        # 2. Sender replies with Command 2 (356B)
        cmd2 = build_minifile_response(md5_hex=file_md5, file_size=file_size, status=0)
        self.assertEqual(len(cmd2), 356)
        parsed_cmd2 = parse_minifile_packet(cmd2)
        self.assertEqual(parsed_cmd2["cmd"], 2)
        self.assertEqual(parsed_cmd2["status"], 0)
        self.assertEqual(parsed_cmd2["file_size"], file_size)
        self.assertEqual(parsed_cmd2["md5"], file_md5)

        # 3. Sender streams chunks via Command 3
        chunk_size = 16384
        offset = 0
        received_stream = bytearray()
        while offset < file_size:
            piece = sample_file_data[offset : offset + chunk_size]
            chunk_pkt = build_minifile_chunk(file_size=file_size, offset=offset, chunk_data=piece)
            parsed_chunk = parse_minifile_packet(chunk_pkt)
            self.assertEqual(parsed_chunk["cmd"], 3)
            self.assertEqual(parsed_chunk["offset"], offset)
            self.assertEqual(parsed_chunk["chunk_len"], len(piece))
            received_stream.extend(parsed_chunk["chunk_data"])
            offset += len(piece)

        # Verify receiver reconstruction and MD5 integrity
        self.assertEqual(bytes(received_stream), sample_file_data)
        self.assertEqual(hashlib.md5(received_stream).hexdigest().lower(), file_md5)


if __name__ == "__main__":
    unittest.main()
