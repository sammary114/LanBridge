#!/usr/bin/env python3
"""Tests for Native NeiWangTong Data Adapter (tests/test_nwt_adapter.py)."""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from lanbridge.adapter import NativeNwtAdapter
from lanbridge.client import LanBridgeClient


class TestNativeNwtAdapter(unittest.TestCase):
    """Verify safe, non-invasive extraction of native Nwt data."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="nwt_test_")

    def tearDown(self) -> None:
        if os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_is_installed_mock(self) -> None:
        # Empty dir should return False
        self.assertFalse(NativeNwtAdapter.is_installed(self.temp_dir))

        # Add data/acc
        acc_dir = os.path.join(self.temp_dir, "data")
        os.makedirs(acc_dir, exist_ok=True)
        acc_path = os.path.join(acc_dir, "acc")
        with open(acc_path, "w", encoding="utf-8") as f:
            f.write("2158b475dfcfdd43989482c4dcf0337b")

        self.assertTrue(NativeNwtAdapter.is_installed(self.temp_dir))

    def test_read_account(self) -> None:
        adapter = NativeNwtAdapter(self.temp_dir)
        self.assertIsNone(adapter.read_account())

        acc_dir = os.path.join(self.temp_dir, "data")
        os.makedirs(acc_dir, exist_ok=True)
        with open(os.path.join(acc_dir, "acc"), "w", encoding="utf-8") as f:
            f.write("2158b475dfcfdd43989482c4dcf0337b\n")

        self.assertEqual(adapter.read_account(), "2158b475dfcfdd43989482c4dcf0337b")

        # Invalid short account
        with open(os.path.join(acc_dir, "acc"), "w", encoding="utf-8") as f:
            f.write("short_uid")
        self.assertIsNone(adapter.read_account())

    def test_read_network_config(self) -> None:
        cfg_dir = os.path.join(self.temp_dir, "cache", "cfg")
        os.makedirs(cfg_dir, exist_ok=True)

        xml_content = """<?xml version="1.0" encoding="utf-8"?>
<NetworkConfig>
    <LanPort>9011</LanPort>
    <IpMsgPort>2425</IpMsgPort>
    <CorpNumber>CORP999</CorpNumber>
    <OtherSubnetIpList>
        <OtherSubnetIp>192.168.31</OtherSubnetIp>
        <OtherSubnetIp>10.0.0.1</OtherSubnetIp>
        <OtherSubnetIp>172.16.0.0/16</OtherSubnetIp>
    </OtherSubnetIpList>
</NetworkConfig>"""
        with open(os.path.join(cfg_dir, "Network.xml"), "w", encoding="utf-8") as f:
            f.write(xml_content)

        adapter = NativeNwtAdapter(self.temp_dir)
        net = adapter.read_network_config()

        self.assertEqual(net["lan_port"], 9011)
        self.assertEqual(net["ipmsg_port"], 2425)
        self.assertEqual(net["corp_number"], "CORP999")
        self.assertIn("192.168.31.0/24", net["subnets"])
        self.assertIn("10.0.0.1/24", net["subnets"])
        self.assertIn("172.16.0.0/16", net["subnets"])

    def test_read_user_options(self) -> None:
        cfg_dir = os.path.join(self.temp_dir, "cache", "cfg")
        os.makedirs(cfg_dir, exist_ok=True)

        xml_content = """<?xml version="1.0" encoding="utf-8"?>
<OptionConfig>
    <UserName>TestUser</UserName>
    <CorpId>CORP_ID_HEX_123</CorpId>
    <UserSign>Keep Moving Forward</UserSign>
    <LastVersion>3.4.3055</LastVersion>
    <OpenIpMsg>True</OpenIpMsg>
</OptionConfig>"""
        with open(os.path.join(cfg_dir, "Option.xml"), "w", encoding="utf-8") as f:
            f.write(xml_content)

        adapter = NativeNwtAdapter(self.temp_dir)
        opts = adapter.read_user_options()

        self.assertEqual(opts["user_name"], "TestUser")
        self.assertEqual(opts["corp_id"], "CORP_ID_HEX_123")
        self.assertEqual(opts["signature"], "Keep Moving Forward")
        self.assertEqual(opts["last_version"], "3.4.3055")
        self.assertTrue(opts["open_ipmsg"])

    def test_read_qgroups_sqlite(self) -> None:
        data_dir = os.path.join(self.temp_dir, "data")
        os.makedirs(data_dir, exist_ok=True)
        qrp_path = os.path.join(data_dir, "qrp")

        uid = "2158b475dfcfdd43989482c4dcf0337b"
        conn = sqlite3.connect(qrp_path)
        cur = conn.cursor()

        # Create QGroupInfo table
        cur.execute(f"""
            CREATE TABLE QGroupInfo_{uid} (
                QGroupId TEXT PRIMARY KEY,
                Name TEXT,
                Master TEXT,
                Intr TEXT,
                Ann TEXT,
                InfoVer INTEGER,
                CreateTime REAL
            )
        """)
        cur.execute(f"""
            CREATE TABLE QGroupUser_{uid} (
                QGroupId TEXT,
                UserId TEXT,
                UserName TEXT
            )
        """)

        cur.execute(
            f"INSERT INTO QGroupInfo_{uid} VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("2710", "架构攻坚群 🐂🐎", uid, "研发群组", "严禁灌水", 3, 1600000000.0),
        )
        cur.execute(
            f"INSERT INTO QGroupUser_{uid} VALUES (?, ?, ?)",
            ("2710", uid, "LH"),
        )
        cur.execute(
            f"INSERT INTO QGroupUser_{uid} VALUES (?, ?, ?)",
            ("2710", "peer_999", "张工"),
        )
        conn.commit()
        conn.close()

        adapter = NativeNwtAdapter(self.temp_dir)
        groups = adapter.read_qgroups()

        self.assertIn("2710", groups)
        qg = groups["2710"]
        self.assertEqual(qg.name, "架构攻坚群 🐂🐎")
        self.assertEqual(qg.master_id, uid)
        self.assertEqual(qg.version, 3)
        self.assertEqual(len(qg.members), 2)
        self.assertEqual(qg.members[uid], "LH")
        self.assertEqual(qg.members["peer_999"], "张工")

    def test_read_shared_files_sqlite(self) -> None:
        db_dir = os.path.join(self.temp_dir, "cache", "db")
        os.makedirs(db_dir, exist_ok=True)
        sd_path = os.path.join(db_dir, "sd")

        uid = "2158b475dfcfdd43989482c4dcf0337b"
        conn = sqlite3.connect(sd_path)
        cur = conn.cursor()
        cur.execute(f"""
            CREATE TABLE ShareData_{uid} (
                ShareId TEXT PRIMARY KEY,
                LocalPath TEXT,
                ShareSize INTEGER,
                SharePwd TEXT,
                ShareCreateTime REAL,
                ShareLastModify REAL
            )
        """)

        dummy_file = os.path.join(self.temp_dir, "test_file.xlsx")
        with open(dummy_file, "wb") as f:
            f.write(b"SAMPLE DATA FOR SHARE TEST")

        file_md5 = "e99a18c428cb38d5f260853678922e03"
        cur.execute(
            f"INSERT INTO ShareData_{uid} VALUES (?, ?, ?, ?, ?, ?)",
            (file_md5, dummy_file, len(b"SAMPLE DATA FOR SHARE TEST"), "", 1600000000.0, 1600000000.0),
        )
        conn.commit()
        conn.close()

        adapter = NativeNwtAdapter(self.temp_dir)
        shares = adapter.read_shared_files()

        self.assertIn(file_md5, shares)
        gsf = shares[file_md5]
        self.assertEqual(gsf.filename, "test_file.xlsx")
        self.assertEqual(gsf.filesize, len(b"SAMPLE DATA FOR SHARE TEST"))
        self.assertTrue(gsf.is_cached)

    def test_picture_cache(self) -> None:
        adapter = NativeNwtAdapter(self.temp_dir)
        pic_md5 = "aabbccddeeff00112233445566778899"
        pic_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 32

        # Verify not found initially
        self.assertIsNone(adapter.get_picture_by_md5(pic_md5))

        # Save picture
        saved_path = adapter.save_picture(pic_md5, pic_bytes)
        self.assertTrue(os.path.isfile(saved_path))

        # Get picture
        loaded = adapter.get_picture_by_md5(pic_md5)
        self.assertEqual(loaded, pic_bytes)

    def test_client_import_from_native(self) -> None:
        # Setup mock native directory with account, config, qgroups, and shares
        data_dir = os.path.join(self.temp_dir, "data")
        cfg_dir = os.path.join(self.temp_dir, "cache", "cfg")
        db_dir = os.path.join(self.temp_dir, "cache", "db")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(cfg_dir, exist_ok=True)
        os.makedirs(db_dir, exist_ok=True)

        uid = "2158b475dfcfdd43989482c4dcf0337b"
        with open(os.path.join(data_dir, "acc"), "w", encoding="utf-8") as f:
            f.write(uid)

        with open(os.path.join(cfg_dir, "Network.xml"), "w", encoding="utf-8") as f:
            f.write("<NetworkConfig><OtherSubnetIpList><OtherSubnetIp>192.168.100</OtherSubnetIp></OtherSubnetIpList></NetworkConfig>")

        with open(os.path.join(cfg_dir, "Option.xml"), "w", encoding="utf-8") as f:
            f.write("<OptionConfig><UserName>NativeUser</UserName><UserSign>My Signature</UserSign></OptionConfig>")

        conn = sqlite3.connect(os.path.join(data_dir, "qrp"))
        conn.execute(f"CREATE TABLE QGroupInfo_{uid} (QGroupId TEXT, Name TEXT, Master TEXT, Intr TEXT, Ann TEXT, InfoVer INTEGER, CreateTime REAL)")
        conn.execute(f"INSERT INTO QGroupInfo_{uid} VALUES ('g100', 'Group 100', '{uid}', '', '', 1, 0)")
        conn.commit()
        conn.close()

        client = LanBridgeClient(
            local_ip="127.0.0.1",
            nickname="TempBot",
            auto_scan_on_start=False,
        )

        res = client.import_from_native(
            nwt_dir=self.temp_dir,
            sync_subnets=True,
            sync_groups=True,
            sync_shares=True,
            apply_identity=True,
        )

        self.assertTrue(res["installed"])
        self.assertEqual(res["account"], uid)
        self.assertEqual(res["user_name"], "NativeUser")
        self.assertEqual(res["groups_imported"], 1)
        self.assertIn("192.168.100.0/24", res["subnets"])

        # Check client identity applied
        self.assertEqual(client.user_id, uid)
        self.assertEqual(client.nickname, "NativeUser")
        self.assertEqual(client.signature, "My Signature")

        # Check group imported
        self.assertIn("g100", client.qgroups)
        self.assertEqual(client.qgroups["g100"].name, "Group 100")

    def test_real_host_nwt_if_present(self) -> None:
        """Read-only test on actual C:\\Users\\Public\\Nwt if present on host machine."""
        default_dir = NativeNwtAdapter.DEFAULT_NWT_DIR
        if not NativeNwtAdapter.is_installed(default_dir):
            self.skipTest(f"Host Nwt directory not found at {default_dir}")

        adapter = NativeNwtAdapter(default_dir)
        uid = adapter.read_account()
        self.assertIsNotNone(uid)
        self.assertEqual(len(uid), 32)

        net_cfg = adapter.read_network_config()
        self.assertIsInstance(net_cfg["subnets"], list)

        opts = adapter.read_user_options()
        self.assertIsInstance(opts["user_name"], str)

        qgroups = adapter.read_qgroups()
        self.assertIsInstance(qgroups, dict)

        shares = adapter.read_shared_files()
        self.assertIsInstance(shares, dict)


if __name__ == "__main__":
    unittest.main()
