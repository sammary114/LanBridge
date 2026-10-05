#!/usr/bin/env python3
"""LanBridge LAN File Sharing & Group Share Protocol (share_tran.py).

Implements the authentic LAN File Share & Group Shared File subsystem reverse-engineered
from ShiYeLine.exe (TCP 2442, AVCShare* and X_SHARE_* XML envelopes):
- X_SHARE_SUBNET: Subnet announcement of share services
- X_SHARE_GET_REMOTE_ROOT & RSP: Catalog browsing (<CATALOG_ITEM>)
- X_SHARE_GET_REMOTE & RSP: File listing (<ITEM>)
- X_SHARE_CHECK_PWD & RSP: Password verification
- X_SHARE_DOWNLOAD_FILE & RSP: File download negotiation
- X_QGROUP_SHARE_FILE & DELETE: Group active file share & revocation
"""

from __future__ import annotations

import logging
import re
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from lanbridge.protocol.crypto import XteaEngine

logger = logging.getLogger("lanbridge.share_tran")
_xtea = XteaEngine()


class ShareOpcode:
    X_SHARE_SUBNET = 0x0401
    X_SHARE_GET_REMOTE_ROOT = 0x0402
    X_SHARE_GET_REMOTE_ROOT_RSP = 0x0403
    X_SHARE_GET_REMOTE = 0x0404
    X_SHARE_GET_REMOTE_RSP = 0x0405
    X_SHARE_DOWNLOAD_FILE = 0x0406
    X_SHARE_DOWNLOAD_FILE_RSP = 0x0407
    X_SHARE_DOWNLOAD_FOLDER = 0x0408
    X_SHARE_DOWNLOAD_FOLDER_RSP = 0x0409
    X_SHARE_CHECK_PWD = 0x040A
    X_SHARE_CHECK_PWD_RSP = 0x040B
    X_QGROUP_SHARE_FILE = 0x0410
    X_QGROUP_DELETE_SHARE = 0x0411


def build_x_share_subnet_envelope(subnets: str = "", req_id: int = 1) -> bytes:
    """Build X_SHARE_SUBNET announcement envelope."""
    xml = (
        f'<X_SHARE_SUBNET docver="1">'
        f'<REQ_ID>{req_id}</REQ_ID>'
        f'<SUBNETS>{subnets}</SUBNETS>'
        f'</X_SHARE_SUBNET>'
    )
    return _xtea.build_envelope(ShareOpcode.X_SHARE_SUBNET, xml, encoding="gbk")


def build_x_share_get_remote_root_envelope(req_id: int = 1) -> bytes:
    """Build X_SHARE_GET_REMOTE_ROOT request envelope."""
    xml = (
        f'<X_SHARE_GET_REMOTE_ROOT docver="1">'
        f'<REQ_ID>{req_id}</REQ_ID>'
        f'</X_SHARE_GET_REMOTE_ROOT>'
    )
    return _xtea.build_envelope(ShareOpcode.X_SHARE_GET_REMOTE_ROOT, xml, encoding="gbk")


def build_x_share_get_remote_root_rsp_envelope(
    catalogs: List[Dict[str, Any]],
    req_id: int = 1,
    err: int = 0,
    end: int = 1,
) -> bytes:
    """Build authentic X_SHARE_GET_REMOTE_ROOT_RSP envelope.

    Matching ShiYeLine.exe:
      <X_SHARE_GET_REMOTE_ROOT_RSP docver="%u"><ERR>%u</ERR><END>%u</END><REQ_ID>%llu</REQ_ID>
      <CATALOG_ITEM><ITEM id="1">Docs</ITEM><LASTM>1700000000</LASTM><CREATET>1700000000</CREATET><VALID>1</VALID></CATALOG_ITEM>
      </X_SHARE_GET_REMOTE_ROOT_RSP>
    """
    items_xml = []
    for c in catalogs:
        cid = c.get("id", "0")
        name = c.get("name", "Default")
        lastm = c.get("lastm", int(time.time()))
        createt = c.get("createt", int(time.time()))
        valid = 1 if c.get("valid", True) else 0
        items_xml.append(
            f'<CATALOG_ITEM>'
            f'<ITEM id="{cid}">{name}</ITEM>'
            f'<LASTM>{lastm}</LASTM>'
            f'<CREATET>{createt}</CREATET>'
            f'<VALID>{valid}</VALID>'
            f'</CATALOG_ITEM>'
        )

    xml = (
        f'<X_SHARE_GET_REMOTE_ROOT_RSP docver="1">'
        f'<ERR>{err}</ERR>'
        f'<END>{end}</END>'
        f'<REQ_ID>{req_id}</REQ_ID>'
        f'{"".join(items_xml)}'
        f'</X_SHARE_GET_REMOTE_ROOT_RSP>'
    )
    return _xtea.build_envelope(ShareOpcode.X_SHARE_GET_REMOTE_ROOT_RSP, xml, encoding="gbk")


def build_x_share_get_remote_envelope(catalog_id: str, req_id: int = 1) -> bytes:
    """Build X_SHARE_GET_REMOTE request envelope."""
    xml = (
        f'<X_SHARE_GET_REMOTE docver="1">'
        f'<REQ_ID>{req_id}</REQ_ID>'
        f'<CATALOG_ID>{catalog_id}</CATALOG_ID>'
        f'</X_SHARE_GET_REMOTE>'
    )
    return _xtea.build_envelope(ShareOpcode.X_SHARE_GET_REMOTE, xml, encoding="gbk")


def build_x_share_get_remote_rsp_envelope(
    files: List[Dict[str, Any]],
    req_id: int = 1,
    err: int = 0,
    end: int = 1,
) -> bytes:
    """Build X_SHARE_GET_REMOTE_RSP file list envelope."""
    files_xml = []
    for f in files:
        fid = f.get("id", "0")
        name = f.get("name", "file.dat")
        size = f.get("size", 0)
        md5 = f.get("md5", "")
        lastm = f.get("lastm", int(time.time()))
        files_xml.append(
            f'<ITEM id="{fid}">'
            f'<NAME>{name}</NAME>'
            f'<SIZE>{size}</SIZE>'
            f'<MD5>{md5}</MD5>'
            f'<LASTM>{lastm}</LASTM>'
            f'</ITEM>'
        )

    xml = (
        f'<X_SHARE_GET_REMOTE_RSP docver="1">'
        f'<ERR>{err}</ERR>'
        f'<END>{end}</END>'
        f'<REQ_ID>{req_id}</REQ_ID>'
        f'{"".join(files_xml)}'
        f'</X_SHARE_GET_REMOTE_RSP>'
    )
    return _xtea.build_envelope(ShareOpcode.X_SHARE_GET_REMOTE_RSP, xml, encoding="gbk")


def build_x_share_check_pwd_envelope(share_id: str, pwd: str, req_id: int = 1) -> bytes:
    """Build X_SHARE_CHECK_PWD envelope."""
    xml = (
        f'<X_SHARE_CHECK_PWD docver="1">'
        f'<REQ_ID>{req_id}</REQ_ID>'
        f'<SHARE_ID>{share_id}</SHARE_ID>'
        f'<PWD>{pwd}</PWD>'
        f'</X_SHARE_CHECK_PWD>'
    )
    return _xtea.build_envelope(ShareOpcode.X_SHARE_CHECK_PWD, xml, encoding="gbk")


def build_x_share_check_pwd_rsp_envelope(err: int = 0, req_id: int = 1) -> bytes:
    """Build X_SHARE_CHECK_PWD_RSP envelope."""
    xml = (
        f'<X_SHARE_CHECK_PWD_RSP docver="1">'
        f'<ERR>{err}</ERR>'
        f'<REQ_ID>{req_id}</REQ_ID>'
        f'</X_SHARE_CHECK_PWD_RSP>'
    )
    return _xtea.build_envelope(ShareOpcode.X_SHARE_CHECK_PWD_RSP, xml, encoding="gbk")


def build_x_share_download_file_envelope(
    share_id: str,
    file_id: str,
    file_path: str = "",
    pwd: str = "",
    req_id: int = 1,
) -> bytes:
    """Build authentic X_SHARE_DOWNLOAD_FILE request envelope."""
    xml = (
        f'<X_SHARE_DOWNLOAD_FILE docver="1">'
        f'<REQ_ID>{req_id}</REQ_ID>'
        f'<SHARE_ID>{share_id}</SHARE_ID>'
        f'<FILE_ID>{file_id}</FILE_ID>'
        f'<FILE_PATH>{file_path}</FILE_PATH>'
        f'<SHARE_PWD>{pwd}</SHARE_PWD>'
        f'</X_SHARE_DOWNLOAD_FILE>'
    )
    return _xtea.build_envelope(ShareOpcode.X_SHARE_DOWNLOAD_FILE, xml, encoding="gbk")


def build_x_share_download_file_rsp_envelope(
    file_size: int,
    file_md5: str,
    err: int = 0,
    req_id: int = 1,
) -> bytes:
    """Build X_SHARE_DOWNLOAD_FILE_RSP response envelope."""
    xml = (
        f'<X_SHARE_DOWNLOAD_FILE_RSP docver="1">'
        f'<ERR>{err}</ERR>'
        f'<REQ_ID>{req_id}</REQ_ID>'
        f'<SIZE>{file_size}</SIZE>'
        f'<MD5>{file_md5}</MD5>'
        f'</X_SHARE_DOWNLOAD_FILE_RSP>'
    )
    return _xtea.build_envelope(ShareOpcode.X_SHARE_DOWNLOAD_FILE_RSP, xml, encoding="gbk")


def build_x_qgroup_share_file_envelope(
    qgroup_id: str,
    file_name: str,
    file_size: int,
    file_md5: str,
    uploader_id: str,
    uploader_name: str,
    task_id: int = 1,
    tcp_port: int = 2442,
    pwd_protect: int = 0,
    timestamp: Optional[int] = None,
) -> bytes:
    """Build X_QGROUP_SHARE_FILE active group share announcement envelope."""
    if timestamp is None:
        timestamp = int(time.time())
    xml = (
        f'<X_QGROUP_SHARE_FILE docver="1">'
        f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
        f'<TASK_ID>{task_id}</TASK_ID>'
        f'<FILE_NAME>{file_name}</FILE_NAME>'
        f'<FILE_SIZE>{file_size}</FILE_SIZE>'
        f'<FILE_MD5>{file_md5}</FILE_MD5>'
        f'<UPLOADER_ID>{uploader_id}</UPLOADER_ID>'
        f'<UPLOADER_NAME>{uploader_name}</UPLOADER_NAME>'
        f'<TCP_PORT>{tcp_port}</TCP_PORT>'
        f'<PWD_PROTECT>{pwd_protect}</PWD_PROTECT>'
        f'<TIME>{timestamp}</TIME>'
        f'</X_QGROUP_SHARE_FILE>'
    )
    return _xtea.build_envelope(ShareOpcode.X_QGROUP_SHARE_FILE, xml, encoding="gbk")


def build_x_qgroup_delete_share_envelope(
    qgroup_id: str,
    file_md5: str,
    uploader_id: str,
) -> bytes:
    """Build X_QGROUP_DELETE_SHARE group share revocation envelope."""
    xml = (
        f'<X_QGROUP_DELETE_SHARE docver="1">'
        f'<QGROUP_ID>{qgroup_id}</QGROUP_ID>'
        f'<FILE_MD5>{file_md5}</FILE_MD5>'
        f'<UPLOADER_ID>{uploader_id}</UPLOADER_ID>'
        f'</X_QGROUP_DELETE_SHARE>'
    )
    return _xtea.build_envelope(ShareOpcode.X_QGROUP_DELETE_SHARE, xml, encoding="gbk")


def parse_share_xml(xml_str: str) -> Dict[str, Any]:
    """Parse share subsystem XML strings into dictionary representation."""
    res: Dict[str, Any] = {}
    try:
        root = ET.fromstring(xml_str)
        res["tag"] = root.tag
        res["attrib"] = root.attrib
        for child in root:
            if child.tag == "CATALOG_ITEM":
                catalogs = res.setdefault("catalogs", [])
                item_elem = child.find("ITEM")
                c_info = {
                    "id": item_elem.attrib.get("id") if item_elem is not None else None,
                    "name": item_elem.text if item_elem is not None else "",
                    "lastm": int(child.findtext("LASTM", "0")),
                    "createt": int(child.findtext("CREATET", "0")),
                    "valid": child.findtext("VALID", "1") == "1",
                }
                catalogs.append(c_info)
            elif child.tag == "ITEM":
                items = res.setdefault("items", [])
                items.append({
                    "id": child.attrib.get("id"),
                    "name": child.findtext("NAME", ""),
                    "size": int(child.findtext("SIZE", "0")),
                    "md5": child.findtext("MD5", ""),
                    "lastm": int(child.findtext("LASTM", "0")),
                })
            else:
                res[child.tag.lower()] = child.text
    except Exception as e:
        logger.debug("Failed parsing share XML: %s", e)
    return res
