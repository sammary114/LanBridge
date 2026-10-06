"""LanBridge Native NeiWangTong Data Adapter (nwt_adapter.py).

Provides non-invasive, read-safe adaptation for native Nwt installation
and user storage in C:\\Users\\Public\\Nwt:
- Native UID and account identity from data/acc
- Subnet scan lists from cache/cfg/Network.xml
- User preferences, nickname, signature, and CorpId from cache/cfg/Option.xml
- Discussion group profiles and member maps from SQLite data/qrp
- Shared files catalog from SQLite cache/db/sd
- Fast image cache hit and retrieval from cache/pic
"""

from __future__ import annotations

import logging
import os
import sqlite3
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from lanbridge.models import GroupSharedFile, QGroup

logger = logging.getLogger("lanbridge.adapter")


class NativeNwtAdapter:
    """Extracts configuration, group directories, and file caches from native Nwt."""

    DEFAULT_NWT_DIR = r"C:\Users\Public\Nwt"

    def __init__(self, nwt_dir: Optional[str] = None):
        self.nwt_dir = os.path.abspath(nwt_dir if nwt_dir else self.DEFAULT_NWT_DIR)

    @classmethod
    def is_installed(cls, path: Optional[str] = None) -> bool:
        """Check if native NeiWangTong data directory structure exists."""
        target = os.path.abspath(path if path else cls.DEFAULT_NWT_DIR)
        acc_path = os.path.join(target, "data", "acc")
        net_path = os.path.join(target, "cache", "cfg", "Network.xml")
        return os.path.isfile(acc_path) or os.path.isfile(net_path)

    def read_account(self) -> Optional[str]:
        """Read 32-character native user ID from data/acc."""
        acc_path = os.path.join(self.nwt_dir, "data", "acc")
        if not os.path.isfile(acc_path):
            return None
        try:
            with open(acc_path, "r", encoding="utf-8", errors="ignore") as f:
                uid = f.read().strip()
            if len(uid) == 32:
                return uid
        except Exception as e:
            logger.debug("Failed reading native account: %s", e)
        return None

    def read_network_config(self) -> dict:
        """Parse cache/cfg/Network.xml for ports and other subnet IP targets."""
        res = {
            "lan_port": 9011,
            "ipmsg_port": 2425,
            "corp_number": "",
            "subnets": [],
        }
        net_path = os.path.join(self.nwt_dir, "cache", "cfg", "Network.xml")
        if not os.path.isfile(net_path):
            return res

        try:
            tree = ET.parse(net_path)
            root = tree.getroot()
            lp = root.findtext("LanPort")
            if lp and lp.isdigit():
                res["lan_port"] = int(lp)
            ip = root.findtext("IpMsgPort")
            if ip and ip.isdigit():
                res["ipmsg_port"] = int(ip)
            res["corp_number"] = root.findtext("CorpNumber") or ""

            raw_subnets: List[str] = []
            for elem in root.findall(".//OtherSubnetIp"):
                if elem.text and elem.text.strip():
                    raw = elem.text.strip()
                    parts = raw.split(".")
                    if len(parts) == 3:
                        raw_subnets.append(f"{raw}.0/24")
                    elif len(parts) == 4 and "/" not in raw:
                        raw_subnets.append(f"{raw}/24")
                    else:
                        raw_subnets.append(raw)
            res["subnets"] = raw_subnets
        except Exception as e:
            logger.warning("Failed parsing Network.xml: %s", e)
        return res

    def read_user_options(self) -> dict:
        """Parse cache/cfg/Option.xml for user nickname, CorpId, and preferences."""
        res = {
            "user_name": "LanBridge-Bot",
            "corp_id": "",
            "signature": "",
            "last_version": "3.4.3055",
            "open_ipmsg": True,
        }
        opt_path = os.path.join(self.nwt_dir, "cache", "cfg", "Option.xml")
        if not os.path.isfile(opt_path):
            return res

        try:
            tree = ET.parse(opt_path)
            root = tree.getroot()
            name = root.findtext("UserName")
            if name:
                res["user_name"] = name
            corp = root.findtext("CorpId")
            if corp:
                res["corp_id"] = corp
            sign = root.findtext("UserSign")
            if sign:
                res["signature"] = sign
            ver = root.findtext("LastVersion")
            if ver:
                res["last_version"] = ver
            ipmsg = root.findtext("OpenIpMsg")
            if ipmsg is not None:
                res["open_ipmsg"] = ipmsg.lower() == "true"
        except Exception as e:
            logger.warning("Failed parsing Option.xml: %s", e)
        return res

    def read_qgroups(self) -> Dict[str, QGroup]:
        """Read native discussion groups and members from data/qrp SQLite database."""
        groups: Dict[str, QGroup] = {}
        qrp_path = os.path.join(self.nwt_dir, "data", "qrp")
        if not os.path.isfile(qrp_path):
            return groups

        try:
            uri = f"file:{os.path.abspath(qrp_path)}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            cur = conn.cursor()

            # Find all QGroupInfo tables
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'QGroupInfo_%'")
            info_tables = [r[0] for r in cur.fetchall()]

            for info_tbl in info_tables:
                suffix = info_tbl[len("QGroupInfo_"):]
                user_tbl = f"QGroupUser_{suffix}"

                # Query group info
                cur.execute(f"SELECT QGroupId, Name, Master, Intr, Ann, InfoVer, CreateTime FROM {info_tbl}")
                for row in cur.fetchall():
                    gid, name, master, intr, ann, info_ver, create_time = row
                    if not gid:
                        continue
                    qg = QGroup(
                        qgroup_id=str(gid),
                        name=str(name or "未命名群组"),
                        master_id=str(master or ""),
                        intro=str(intr or ""),
                        announcement=str(ann or ""),
                        version=int(info_ver) if info_ver else 1,
                        created_time=float(create_time) if create_time else 0.0,
                    )
                    groups[str(gid)] = qg

                # Query members if user table exists
                cur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{user_tbl}'")
                if cur.fetchone():
                    cur.execute(f"SELECT QGroupId, UserId, UserName FROM {user_tbl}")
                    for gid, uid, uname in cur.fetchall():
                        gid_s = str(gid)
                        if gid_s in groups and uid:
                            groups[gid_s].members[str(uid)] = str(uname or uid)

            conn.close()
        except Exception as e:
            logger.warning("Failed reading native qrp database: %s", e)
        return groups

    def read_shared_files(self) -> Dict[str, GroupSharedFile]:
        """Read native shared files from cache/db/sd SQLite database."""
        shares: Dict[str, GroupSharedFile] = {}
        sd_path = os.path.join(self.nwt_dir, "cache", "db", "sd")
        if not os.path.isfile(sd_path):
            return shares

        my_uid = self.read_account() or "unknown"
        my_opt = self.read_user_options()
        my_name = my_opt.get("user_name", "LocalUser")

        try:
            uri = f"file:{os.path.abspath(sd_path)}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            cur = conn.cursor()

            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ShareData_%'")
            data_tables = [r[0] for r in cur.fetchall()]

            for tbl in data_tables:
                cur.execute(
                    f"SELECT ShareId, LocalPath, ShareSize, SharePwd, ShareCreateTime, ShareLastModify FROM {tbl}"
                )
                for sid, loc_path, size, pwd, c_time, m_time in cur.fetchall():
                    if not sid:
                        continue
                    file_md5 = str(sid).lower()
                    fname = os.path.basename(loc_path) if loc_path else f"file_{file_md5[:8]}.dat"
                    gsf = GroupSharedFile(
                        file_id=file_md5,
                        qgroup_id="0",
                        filename=fname,
                        filesize=int(size) if size else 0,
                        file_md5=file_md5,
                        uploader_id=my_uid,
                        uploader_name=my_name,
                        uploader_ip="127.0.0.1",
                        created_time=float(c_time) if c_time else 0.0,
                        pwd_protect=bool(pwd),
                        local_path=str(loc_path) if (loc_path and os.path.exists(loc_path)) else None,
                        is_cached=bool(loc_path and os.path.exists(loc_path)),
                        is_pinned=True,
                    )
                    shares[file_md5] = gsf

            conn.close()
        except Exception as e:
            logger.warning("Failed reading native sd database: %s", e)
        return shares

    def get_picture_by_md5(self, md5_hash: str) -> Optional[bytes]:
        """Fetch image bytes directly from native pic/ cache by MD5 hash."""
        pic_file = os.path.join(self.nwt_dir, "cache", "pic", md5_hash.lower())
        if os.path.isfile(pic_file):
            try:
                with open(pic_file, "rb") as f:
                    return f.read()
            except Exception as e:
                logger.debug("Failed reading native pic %s: %s", md5_hash, e)
        return None

    def save_picture(self, md5_hash: str, data: bytes) -> str:
        """Save received image into native pic/ directory."""
        pic_dir = os.path.join(self.nwt_dir, "cache", "pic")
        os.makedirs(pic_dir, exist_ok=True)
        dest_path = os.path.join(pic_dir, md5_hash.lower())
        try:
            with open(dest_path, "wb") as f:
                f.write(data)
        except Exception as e:
            logger.warning("Failed writing native picture cache %s: %s", dest_path, e)
        return dest_path

    def get_picture_cache_dir(self) -> str:
        """Return path to cache/pic/ directory."""
        return os.path.join(self.nwt_dir, "cache", "pic")

    def get_received_files_dir(self) -> str:
        """Return path to cache/recv/ directory."""
        return os.path.join(self.nwt_dir, "cache", "recv")
