#!/usr/bin/env python3
"""Tests for LanBridge Group File Sharing & Shadow Keeper Protocol (test_share_tran.py)."""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import sys
import tempfile
import time
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from lanbridge.models import Contact, GroupSharedFile
from lanbridge.protocol.crypto import XteaEngine
from lanbridge.protocol.share_tran import (
    ShareOpcode,
    build_x_qgroup_delete_share_envelope,
    build_x_qgroup_share_file_envelope,
    build_x_share_check_pwd_envelope,
    build_x_share_check_pwd_rsp_envelope,
    build_x_share_download_file_envelope,
    build_x_share_download_file_rsp_envelope,
    build_x_share_get_remote_envelope,
    build_x_share_get_remote_root_envelope,
    build_x_share_get_remote_root_rsp_envelope,
    build_x_share_get_remote_rsp_envelope,
    build_x_share_subnet_envelope,
    parse_share_xml,
)
from lanbridge.client import LanBridgeClient


class TestShareTranProtocol(unittest.TestCase):
    """Verify X_SHARE_* and X_QGROUP_* envelopes encoding, decoding, and models."""

    def setUp(self) -> None:
        self.xtea = XteaEngine()

    def test_share_subnet_envelope(self) -> None:
        """Verify X_SHARE_SUBNET announcement envelope."""
        env = build_x_share_subnet_envelope(subnets="172.31.112.0/20", req_id=101)
        self.assertGreater(len(env), 8)
        op, plain = self.xtea.parse_envelope(env)
        self.assertEqual(op, ShareOpcode.X_SHARE_SUBNET)
        parsed = parse_share_xml(plain.decode("gbk"))
        self.assertEqual(parsed.get("tag"), "X_SHARE_SUBNET")
        self.assertEqual(parsed.get("req_id"), "101")
        self.assertEqual(parsed.get("subnets"), "172.31.112.0/20")

    def test_share_catalog_root_envelopes(self) -> None:
        """Verify X_SHARE_GET_REMOTE_ROOT request and response envelopes."""
        # 1. Request
        req_env = build_x_share_get_remote_root_envelope(req_id=202)
        op, plain = self.xtea.parse_envelope(req_env)
        self.assertEqual(op, ShareOpcode.X_SHARE_GET_REMOTE_ROOT)
        parsed_req = parse_share_xml(plain.decode("gbk"))
        self.assertEqual(parsed_req.get("req_id"), "202")

        # 2. Response
        catalogs = [
            {"id": "1", "name": "设计规范", "lastm": 1700000001, "createt": 1700000000, "valid": True},
            {"id": "2", "name": "项目文档", "lastm": 1700000002, "createt": 1700000000, "valid": True},
        ]
        rsp_env = build_x_share_get_remote_root_rsp_envelope(catalogs, req_id=202)
        op_rsp, plain_rsp = self.xtea.parse_envelope(rsp_env)
        self.assertEqual(op_rsp, ShareOpcode.X_SHARE_GET_REMOTE_ROOT_RSP)
        parsed_rsp = parse_share_xml(plain_rsp.decode("gbk"))
        self.assertEqual(parsed_rsp.get("req_id"), "202")
        cat_items = parsed_rsp.get("catalogs", [])
        self.assertEqual(len(cat_items), 2)
        self.assertEqual(cat_items[0]["id"], "1")
        self.assertEqual(cat_items[0]["name"], "设计规范")
        self.assertEqual(cat_items[1]["name"], "项目文档")

    def test_share_file_list_envelopes(self) -> None:
        """Verify X_SHARE_GET_REMOTE request and response envelopes."""
        req_env = build_x_share_get_remote_envelope(catalog_id="1", req_id=303)
        op, plain = self.xtea.parse_envelope(req_env)
        self.assertEqual(op, ShareOpcode.X_SHARE_GET_REMOTE)

        files = [
            {"id": "f1", "name": "arch.pdf", "size": 10240, "md5": "abc12345678901234567890123456789", "lastm": 1700000000},
            {"id": "f2", "name": "demo.mp4", "size": 20480, "md5": "def12345678901234567890123456789", "lastm": 1700000005},
        ]
        rsp_env = build_x_share_get_remote_rsp_envelope(files, req_id=303)
        op_rsp, plain_rsp = self.xtea.parse_envelope(rsp_env)
        self.assertEqual(op_rsp, ShareOpcode.X_SHARE_GET_REMOTE_RSP)
        parsed_rsp = parse_share_xml(plain_rsp.decode("gbk"))
        self.assertEqual(parsed_rsp.get("req_id"), "303")
        file_items = parsed_rsp.get("items", [])
        self.assertEqual(len(file_items), 2)
        self.assertEqual(file_items[0]["name"], "arch.pdf")
        self.assertEqual(file_items[0]["size"], 10240)
        self.assertEqual(file_items[1]["name"], "demo.mp4")

    def test_share_pwd_and_download_file_envelopes(self) -> None:
        """Verify password check and file download negotiation envelopes."""
        # 1. Password check
        pwd_env = build_x_share_check_pwd_envelope(share_id="s1", pwd="secret_password", req_id=404)
        op, plain = self.xtea.parse_envelope(pwd_env)
        self.assertEqual(op, ShareOpcode.X_SHARE_CHECK_PWD)

        pwd_rsp = build_x_share_check_pwd_rsp_envelope(err=0, req_id=404)
        op, plain_rsp = self.xtea.parse_envelope(pwd_rsp)
        self.assertEqual(op, ShareOpcode.X_SHARE_CHECK_PWD_RSP)
        parsed_pwd = parse_share_xml(plain_rsp.decode("gbk"))
        self.assertEqual(parsed_pwd.get("err"), "0")

        # 2. Download file negotiation
        dl_env = build_x_share_download_file_envelope(share_id="s1", file_id="f1", file_path="arch.pdf")
        op, plain = self.xtea.parse_envelope(dl_env)
        self.assertEqual(op, ShareOpcode.X_SHARE_DOWNLOAD_FILE)

        dl_rsp = build_x_share_download_file_rsp_envelope(file_size=50000, file_md5="abc12345678901234567890123456789")
        op, plain = self.xtea.parse_envelope(dl_rsp)
        self.assertEqual(op, ShareOpcode.X_SHARE_DOWNLOAD_FILE_RSP)
        parsed_dl = parse_share_xml(plain.decode("gbk"))
        self.assertEqual(parsed_dl.get("size"), "50000")
        self.assertEqual(parsed_dl.get("md5"), "abc12345678901234567890123456789")

    def test_qgroup_share_and_delete_envelopes(self) -> None:
        """Verify X_QGROUP_SHARE_FILE and X_QGROUP_DELETE_SHARE envelopes."""
        md5_sample = "aabbccddeeff00112233445566778899"
        share_env = build_x_qgroup_share_file_envelope(
            qgroup_id="group_1001",
            file_name="project_spec.docx",
            file_size=1234567,
            file_md5=md5_sample,
            uploader_id="uploader_user_999",
            uploader_name="张三",
            tcp_port=2442,
            timestamp=1700000000,
        )
        op, plain = self.xtea.parse_envelope(share_env)
        self.assertEqual(op, ShareOpcode.X_QGROUP_SHARE_FILE)
        parsed = parse_share_xml(plain.decode("gbk"))
        self.assertEqual(parsed.get("qgroup_id"), "group_1001")
        self.assertEqual(parsed.get("file_name"), "project_spec.docx")
        self.assertEqual(parsed.get("file_size"), "1234567")
        self.assertEqual(parsed.get("file_md5"), md5_sample)
        self.assertEqual(parsed.get("uploader_name"), "张三")

        del_env = build_x_qgroup_delete_share_envelope(
            qgroup_id="group_1001",
            file_md5=md5_sample,
            uploader_id="uploader_user_999",
        )
        op_del, plain_del = self.xtea.parse_envelope(del_env)
        self.assertEqual(op_del, ShareOpcode.X_QGROUP_DELETE_SHARE)
        parsed_del = parse_share_xml(plain_del.decode("gbk"))
        self.assertEqual(parsed_del.get("qgroup_id"), "group_1001")
        self.assertEqual(parsed_del.get("file_md5"), md5_sample)

    def test_group_shared_file_model_expiration(self) -> None:
        """Verify GroupSharedFile expiration and pinned properties."""
        now = time.time()
        file_obj = GroupSharedFile(
            file_id="fid_1",
            qgroup_id="gid_1",
            filename="temp.log",
            filesize=1000,
            file_md5="0123456789abcdef0123456789abcdef",
            uploader_id="user_1",
            uploader_name="User",
            uploader_ip="127.0.0.1",
            created_time=now - 200,
            last_accessed=now - 150,
            is_pinned=False,
        )
        # TTL = 100s -> last accessed 150s ago -> expired
        self.assertTrue(file_obj.is_expired(100.0, current_time=now))
        # TTL = 300s -> not expired
        self.assertFalse(file_obj.is_expired(300.0, current_time=now))

        # Pinned files never expire
        file_obj.is_pinned = True
        self.assertFalse(file_obj.is_expired(50.0, current_time=now))


class TestClientShareLogic(unittest.TestCase):
    """Verify LanBridgeClient cache management, tiered TTL, and group share handling."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.client = LanBridgeClient(
            user_id="test_client_uid_111",
            nickname="TestClient",
            share_dir=self.temp_dir,
            cache_ttl_days=7.0,
            max_cache_size_bytes=2000,  # small quota for testing LRU
            tiered_ttl_enabled=True,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_tiered_ttl_policy(self) -> None:
        """Verify tiered TTL calculation for small, medium, and large files."""
        # < 10MB -> 14 days
        ttl_small = self.client.get_cache_ttl_for_file(5 * 1024 * 1024)
        self.assertEqual(ttl_small, 14 * 86400.0)

        # 10MB ~ 100MB -> 7 days
        ttl_med = self.client.get_cache_ttl_for_file(50 * 1024 * 1024)
        self.assertEqual(ttl_med, 7 * 86400.0)

        # > 100MB -> 2 days (48 hours)
        ttl_large = self.client.get_cache_ttl_for_file(150 * 1024 * 1024)
        self.assertEqual(ttl_large, 2 * 86400.0)

    def test_cache_ttl_expiration_cleaning(self) -> None:
        """Verify expired files are cleaned up from disk and cache dictionary."""
        file_path = os.path.join(self.temp_dir, "expired.dat")
        with open(file_path, "wb") as f:
            f.write(b"EXP_CONTENT" * 10)

        md5 = "exp12345678901234567890123456789"
        gsf = GroupSharedFile(
            file_id=md5,
            qgroup_id="g1",
            filename="expired.dat",
            filesize=os.path.getsize(file_path),
            file_md5=md5,
            uploader_id="u1",
            uploader_name="U1",
            uploader_ip="127.0.0.1",
            created_time=1000.0,
            last_accessed=1000.0,
            local_path=file_path,
            is_cached=True,
            is_pinned=False,
        )
        self.client.local_shared_files[md5] = gsf

        # Clean with simulated current time (1000 + 20 days)
        now_simulated = 1000.0 + (20 * 86400.0)
        purged = self.client.clean_expired_cache(current_time=now_simulated)
        self.assertIn(md5, purged)
        self.assertNotIn(md5, self.client.local_shared_files)
        self.assertFalse(os.path.exists(file_path))

    def test_cache_lru_quota_eviction(self) -> None:
        """Verify LRU eviction when total cached files exceed max_cache_size_bytes."""
        # Create 3 files of 800 bytes each (Total = 2400 > quota 2000)
        files = []
        for i in range(3):
            p = os.path.join(self.temp_dir, f"file_{i}.dat")
            with open(p, "wb") as f:
                f.write(b"A" * 800)
            md5 = f"{i}" * 32
            gsf = GroupSharedFile(
                file_id=md5,
                qgroup_id="g1",
                filename=f"file_{i}.dat",
                filesize=800,
                file_md5=md5,
                uploader_id="u1",
                uploader_name="U1",
                uploader_ip="127.0.0.1",
                created_time=1000.0 + i,
                last_accessed=1000.0 + i,  # file 0 is oldest accessed
                local_path=p,
                is_cached=True,
                is_pinned=False,
            )
            self.client.local_shared_files[md5] = gsf
            files.append(gsf)

        # Trigger cleaner (current_time=1005, within TTL, but triggers LRU quota)
        purged = self.client.clean_expired_cache(current_time=1005.0)
        # Oldest accessed file ('0'*32) must be evicted first
        self.assertIn("0" * 32, purged)
        self.assertFalse(os.path.exists(files[0].local_path))
        # Total cached size is now 1600 > 1400 (70% of 2000), so second file is also evicted
        self.assertIn("1" * 32, purged)
        # Newest file ('2'*32) must still remain
        self.assertIn("2" * 32, self.client.local_shared_files)
        self.assertTrue(os.path.exists(files[2].local_path))

    def test_process_inner_envelope_share_events(self) -> None:
        """Verify handling of incoming X_QGROUP_SHARE_FILE and revocation."""
        received_shares = []

        @self.client.on_group_file_shared
        def on_shared(f: GroupSharedFile) -> None:
            received_shares.append(f)

        sample_md5 = "11223344556677889900aabbccddeeff"
        share_xml = (
            f'<X_QGROUP_SHARE_FILE docver="1">'
            f'<QGROUP_ID>grp_888</QGROUP_ID>'
            f'<FILE_NAME>meeting_notes.txt</FILE_NAME>'
            f'<FILE_SIZE>2048</FILE_SIZE>'
            f'<FILE_MD5>{sample_md5}</FILE_MD5>'
            f'<UPLOADER_ID>uploader_user_777</UPLOADER_ID>'
            f'<UPLOADER_NAME>李四</UPLOADER_NAME>'
            f'<TCP_PORT>2442</TCP_PORT>'
            f'</X_QGROUP_SHARE_FILE>'
        )

        replies = []
        self.client._process_inner_envelope(
            opcode=ShareOpcode.X_QGROUP_SHARE_FILE,
            plaintext=share_xml.encode("gbk"),
            peer_ip="172.31.120.125",
            replies=replies,
        )

        self.assertEqual(len(received_shares), 1)
        shared_item = received_shares[0]
        self.assertEqual(shared_item.filename, "meeting_notes.txt")
        self.assertEqual(shared_item.qgroup_id, "grp_888")
        self.assertEqual(shared_item.file_md5, sample_md5)
        self.assertEqual(shared_item.uploader_ip, "172.31.120.125")
        self.assertIn(sample_md5, self.client.group_shared_files["grp_888"])

        # Revocation
        del_xml = (
            f'<X_QGROUP_DELETE_SHARE docver="1">'
            f'<QGROUP_ID>grp_888</QGROUP_ID>'
            f'<FILE_MD5>{sample_md5}</FILE_MD5>'
            f'<UPLOADER_ID>uploader_user_777</UPLOADER_ID>'
            f'</X_QGROUP_DELETE_SHARE>'
        )
        self.client._process_inner_envelope(
            opcode=ShareOpcode.X_QGROUP_DELETE_SHARE,
            plaintext=del_xml.encode("gbk"),
            peer_ip="172.31.120.125",
            replies=replies,
        )
        self.assertNotIn(sample_md5, self.client.group_shared_files["grp_888"])


class TestAsyncTCPShareTransfer(unittest.IsolatedAsyncioTestCase):
    """Verify asynchronous TCP 2442 file sharing, remote query, and shadow keeper failover."""

    async def asyncSetUp(self) -> None:
        self.temp_server_dir = tempfile.mkdtemp()
        self.temp_client_dir = tempfile.mkdtemp()

        # Generate a test payload file
        self.test_payload = b"LANBRIDGE_GROUP_SHARED_FILE_PAYLOAD_CHUNK_" * 1000  # ~42 KB
        self.test_md5 = hashlib.md5(self.test_payload).hexdigest().lower()
        self.test_file_path = os.path.join(self.temp_server_dir, "shared_document.pdf")
        with open(self.test_file_path, "wb") as f:
            f.write(self.test_payload)

        # Server client (Uploader / Hub)
        self.server_client = LanBridgeClient(
            local_ip="127.0.0.1",
            user_id="server_user_uid_111",
            nickname="ServerUploader",
            discovery_port=39011,
            main_port=39012,
            tcp_file_port=39013,
            share_port=32442,
            share_dir=self.temp_server_dir,
        )
        await self.server_client.start()

        # Actively share the document on server client
        await self.server_client.share_file_to_group(
            qgroup_id="group_test_001",
            file_path=self.test_file_path,
        )

        # Downloader client
        self.downloader = LanBridgeClient(
            local_ip="127.0.0.1",
            user_id="downloader_uid_222",
            nickname="DownloaderNode",
            discovery_port=39021,
            main_port=39022,
            tcp_file_port=39023,
            share_port=32443,
            share_dir=self.temp_client_dir,
        )
        await self.downloader.start()

    async def asyncTearDown(self) -> None:
        await self.server_client.stop()
        await self.downloader.stop()
        shutil.rmtree(self.temp_server_dir, ignore_errors=True)
        shutil.rmtree(self.temp_client_dir, ignore_errors=True)

    async def test_tcp_share_catalog_and_file_query(self) -> None:
        """Verify querying remote root catalog and file list over TCP 2442."""
        reader, writer = await asyncio.open_connection("127.0.0.1", 32442)

        # 1. Query remote root catalog
        req_root = build_x_share_get_remote_root_envelope(req_id=888)
        writer.write(req_root)
        await writer.drain()

        rsp_buf = bytearray()
        while len(rsp_buf) < 8:
            ch = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            rsp_buf.extend(ch)
        tot_len = int.from_bytes(rsp_buf[0:4], "big")
        while len(rsp_buf) < tot_len:
            ch = await asyncio.wait_for(reader.read(tot_len - len(rsp_buf)), timeout=3.0)
            rsp_buf.extend(ch)

        xtea = XteaEngine()
        op, plain = xtea.parse_envelope(bytes(rsp_buf))
        self.assertEqual(op, ShareOpcode.X_SHARE_GET_REMOTE_ROOT_RSP)
        parsed_root = parse_share_xml(plain.decode("gbk"))
        self.assertGreaterEqual(len(parsed_root.get("catalogs", [])), 1)

        writer.close()
        await writer.wait_closed()

    async def test_tcp_share_download_success(self) -> None:
        """Verify normal file download from uploader via TCP 2442 with MD5 validation."""
        shared_file = GroupSharedFile(
            file_id=self.test_md5,
            qgroup_id="group_test_001",
            filename="shared_document.pdf",
            filesize=len(self.test_payload),
            file_md5=self.test_md5,
            uploader_id="server_user_uid_111",
            uploader_name="ServerUploader",
            uploader_ip="127.0.0.1",
            share_port=32442,
        )

        dl_path = await self.downloader.download_shared_file(shared_file)
        self.assertTrue(os.path.isfile(dl_path))
        with open(dl_path, "rb") as f:
            downloaded_bytes = f.read()
        self.assertEqual(downloaded_bytes, self.test_payload)
        self.assertEqual(hashlib.md5(downloaded_bytes).hexdigest().lower(), self.test_md5)
        self.assertTrue(shared_file.is_cached)

    async def test_shadow_keeper_failover(self) -> None:
        """Verify automatic failover when original uploader is offline (Shadow Keeper)."""
        # Node A (original uploader) was on dead_port 39999 (offline / unreachable)
        # Node B (Shadow Keeper Hub) is running on 127.0.0.1:32442
        dead_port = 39999
        shared_file = GroupSharedFile(
            file_id=self.test_md5,
            qgroup_id="group_test_001",
            filename="shared_document.pdf",
            filesize=len(self.test_payload),
            file_md5=self.test_md5,
            uploader_id="offline_author_000",
            uploader_name="OfflineAuthor",
            uploader_ip="127.0.0.1",
            share_port=dead_port,  # Dead port: connection immediately refused
        )

        # Download with Shadow Keeper Hub (127.0.0.1:32442) provided in failover_candidates
        # Since uploader_ip:39999 is dead, it will gracefully failover to the Hub node!
        dl_path = await self.downloader.download_shared_file(
            shared_file=shared_file,
            failover_candidates=[("127.0.0.1", 32442)],
        )
        self.assertTrue(os.path.isfile(dl_path))
        with open(dl_path, "rb") as f:
            downloaded_bytes = f.read()
        self.assertEqual(downloaded_bytes, self.test_payload)
        self.assertEqual(hashlib.md5(downloaded_bytes).hexdigest().lower(), self.test_md5)


if __name__ == "__main__":
    unittest.main()
