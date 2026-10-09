"""LanBridge Modern Web Client & Bot Gateway (app.py).

Provides full HTTP REST and WebSocket gateway endpoints:
- GET  /                     Single Page Application (SPA) Web UI
- GET  /ws                   Real-time WebSocket event bus
- GET  /api/status           Current node information and runtime metrics
- GET  /api/contacts         Discovered online contacts directory
- GET  /api/groups           Joined and created QGroups
- GET  /api/shared_files     Group shared files and cloud storage
- POST /api/message          Send 1-on-1 private chat message
- POST /api/group_message    Send group message
- POST /api/group/create     Create new discussion group
- POST /api/group/invite     Invite members to discussion group
- POST /api/typing           Broadcast typing indicator
- POST /api/recall           Recall sent message
- POST /api/status           Change online status and signature
- POST /api/share_file       Publish file to group share
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Set
from aiohttp import web, WSMsgType

from lanbridge.adapter import NativeNwtAdapter
from lanbridge.client import LanBridgeClient
from lanbridge.models import (
    ChatMessage,
    Contact,
    GroupSharedFile,
    QGroup,
    RecallNotice,
    TypingNotice,
)

logger = logging.getLogger("lanbridge.web")


class WebGateway:
    """Bridges LanBridgeClient events with HTTP REST endpoints and WebSockets."""

    def __init__(self, client: LanBridgeClient):
        self.client = client
        self.app = web.Application()
        self.websockets: Set[web.WebSocketResponse] = set()
        self._setup_routes()
        self._setup_client_listeners()

    def _setup_routes(self) -> None:
        self.app.router.add_get("/", self.handle_index)
        self.app.router.add_get("/ws", self.handle_ws)
        self.app.router.add_get("/api/status", self.handle_get_status)
        self.app.router.add_get("/api/contacts", self.handle_get_contacts)
        self.app.router.add_get("/api/groups", self.handle_get_groups)
        self.app.router.add_get("/api/shared_files", self.handle_get_shared_files)
        self.app.router.add_get("/api/native/status", self.handle_get_native_status)
        self.app.router.add_post("/api/native/import", self.handle_post_native_import)
        self.app.router.add_get("/api/images/{md5}", self.handle_get_image)
        self.app.router.add_post("/api/message", self.handle_post_message)
        self.app.router.add_post("/api/group_message", self.handle_post_group_message)
        self.app.router.add_post("/api/group/create", self.handle_post_create_group)
        self.app.router.add_post("/api/group/invite", self.handle_post_invite_group)
        self.app.router.add_post("/api/typing", self.handle_post_typing)
        self.app.router.add_post("/api/recall", self.handle_post_recall)
        self.app.router.add_post("/api/status", self.handle_post_status)
        self.app.router.add_post("/api/share_file", self.handle_post_share_file)
        self.app.router.add_post("/api/scan", self.handle_post_scan)

        static_dir = os.path.join(os.path.dirname(__file__), "static")
        if os.path.isdir(static_dir):
            self.app.router.add_static("/static/", static_dir)

    def _setup_client_listeners(self) -> None:
        self.client.on_message(self._on_message)
        self.client.on_group_message(self._on_group_message)
        self.client.on_contact_online(self._on_contact_online)
        self.client.on_typing(self._on_typing)
        self.client.on_message_recall(self._on_message_recall)
        self.client.on_qgroup_invite(self._on_qgroup_invite)
        self.client.on_qgroup_member_change(self._on_qgroup_member_change)
        self.client.on_qgroup_dismiss(self._on_qgroup_dismiss)
        self.client.on_group_file_shared(self._on_group_file_shared)

    async def broadcast_ws(self, event_type: str, data: dict) -> None:
        if not self.websockets:
            return
        payload = json.dumps({"event": event_type, "data": data})
        closed = []
        for ws in self.websockets:
            try:
                await ws.send_str(payload)
            except Exception:
                closed.append(ws)
        for ws in closed:
            self.websockets.discard(ws)

    def _on_message(self, msg: ChatMessage) -> None:
        asyncio.create_task(
            self.broadcast_ws(
                "message",
                {
                    "msg_id": msg.msg_id,
                    "sender_id": msg.sender_id,
                    "recipient_id": msg.recipient_id,
                    "text": msg.text,
                    "timestamp": msg.timestamp,
                    "is_image": msg.is_image,
                    "image_token": msg.image_token,
                    "image_md5": msg.image_md5,
                },
            )
        )

    def _on_group_message(self, msg: ChatMessage) -> None:
        asyncio.create_task(
            self.broadcast_ws(
                "group_message",
                {
                    "msg_id": msg.msg_id,
                    "qgroup_id": msg.qgroup_id,
                    "sender_id": msg.sender_id,
                    "text": msg.text,
                    "timestamp": msg.timestamp,
                    "is_image": msg.is_image,
                    "image_token": msg.image_token,
                    "image_md5": msg.image_md5,
                },
            )
        )

    def _on_contact_online(self, contact: Contact) -> None:
        asyncio.create_task(
            self.broadcast_ws(
                "contact_online",
                {
                    "user_id": contact.user_id,
                    "nickname": contact.nickname,
                    "ip": contact.ip,
                    "port": contact.port,
                    "status": contact.status,
                    "group_name": contact.group_name,
                },
            )
        )

    def _on_typing(self, tn: TypingNotice) -> None:
        asyncio.create_task(
            self.broadcast_ws(
                "typing",
                {
                    "sender_id": tn.sender_id,
                    "peer_ip": tn.peer_ip,
                    "is_typing": tn.is_typing,
                    "timestamp": tn.timestamp,
                },
            )
        )

    def _on_message_recall(self, rn: RecallNotice) -> None:
        asyncio.create_task(
            self.broadcast_ws(
                "recall",
                {
                    "sender_id": rn.sender_id,
                    "target_uuid": rn.target_uuid,
                    "target_msg_id": rn.target_msg_id,
                    "timestamp": rn.timestamp,
                    "qgroup_id": rn.qgroup_id,
                },
            )
        )

    def _on_qgroup_invite(self, qg: QGroup) -> None:
        asyncio.create_task(
            self.broadcast_ws(
                "group_invite",
                {
                    "qgroup_id": qg.qgroup_id,
                    "name": qg.name,
                    "master_id": qg.master_id,
                    "intro": qg.intro,
                    "announcement": qg.announcement,
                    "members": qg.members,
                },
            )
        )

    def _on_qgroup_member_change(self, qg: QGroup) -> None:
        asyncio.create_task(
            self.broadcast_ws(
                "group_member_change",
                {
                    "qgroup_id": qg.qgroup_id,
                    "name": qg.name,
                    "members": qg.members,
                    "announcement": qg.announcement,
                },
            )
        )

    def _on_qgroup_dismiss(self, qgroup_id: str) -> None:
        asyncio.create_task(
            self.broadcast_ws("group_dismiss", {"qgroup_id": qgroup_id})
        )

    def _on_group_file_shared(self, gsf: GroupSharedFile) -> None:
        asyncio.create_task(
            self.broadcast_ws(
                "group_file_shared",
                {
                    "file_id": gsf.file_id,
                    "qgroup_id": gsf.qgroup_id,
                    "filename": gsf.filename,
                    "filesize": gsf.filesize,
                    "file_md5": gsf.file_md5,
                    "uploader_name": gsf.uploader_name,
                    "uploader_ip": gsf.uploader_ip,
                },
            )
        )

    async def handle_index(self, request: web.Request) -> web.Response:
        html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                content = f.read()
            return web.Response(text=content, content_type="text/html")
        return web.Response(
            text="<!DOCTYPE html><html><head><title>LanBridge</title></head><body><h1>LanBridge Web Gateway</h1></body></html>",
            content_type="text/html",
        )

    async def handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.websockets.add(ws)
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        action = data.get("action")
                        if action == "ping":
                            await ws.send_json({"event": "pong"})
                        elif action == "send_message":
                            tip = data.get("target_ip")
                            txt = data.get("text", "")
                            if tip and txt:
                                await self.client.send_message(tip, txt)
                        elif action == "send_group_message":
                            gid = data.get("qgroup_id")
                            txt = data.get("text", "")
                            if gid and txt:
                                await self.client.send_group_message(gid, txt)
                    except Exception as e:
                        logger.warning("Error processing ws payload: %s", e)
                elif msg.type == WSMsgType.ERROR:
                    logger.debug("WS error: %s", ws.exception())
        finally:
            self.websockets.discard(ws)
        return ws

    async def handle_get_status(self, request: web.Request) -> web.Response:
        return web.json_response({
            "ok": True,
            "user_id": self.client.user_id,
            "nickname": self.client.nickname,
            "group": self.client.group,
            "status": self.client.status,
            "signature": self.client.signature,
            "local_ip": self.client.local_ip,
            "discovery_port": self.client.discovery_port,
            "main_port": self.client.main_port,
            "share_port": self.client.share_port,
            "contacts_count": len(self.client.contacts),
            "groups_count": len(self.client.qgroups),
        })

    async def handle_get_contacts(self, request: web.Request) -> web.Response:
        contacts_list = []
        for c in self.client.contacts.values():
            contacts_list.append({
                "user_id": c.user_id,
                "nickname": c.nickname,
                "ip": c.ip,
                "port": c.port,
                "dynamic_port": c.dynamic_port,
                "status": c.status,
                "group_name": c.group_name,
                "last_seen": c.last_seen,
            })
        return web.json_response({"ok": True, "contacts": contacts_list})

    async def handle_get_groups(self, request: web.Request) -> web.Response:
        groups_list = []
        for g in self.client.qgroups.values():
            members_detail = []
            for uid, nick in g.members.items():
                is_self = (uid == self.client.user_id)
                contact = self.client.contacts.get(uid)
                status = 0 if is_self else (contact.status if contact else 3)
                ip = self.client.local_ip if is_self else (contact.ip if contact else "")
                members_detail.append({
                    "user_id": uid,
                    "nickname": nick,
                    "status": status,
                    "is_self": is_self,
                    "is_master": (uid == g.master_id),
                    "ip": ip,
                })
            members_detail.sort(key=lambda m: (0 if m["status"] == 0 else 1, m["nickname"].lower()))

            groups_list.append({
                "qgroup_id": g.qgroup_id,
                "name": g.name,
                "master_id": g.master_id,
                "announcement": g.announcement,
                "intro": g.intro,
                "members": g.members,
                "members_detail": members_detail,
                "version": g.version,
            })
        return web.json_response({"ok": True, "groups": groups_list})

    async def handle_get_shared_files(self, request: web.Request) -> web.Response:
        qgroup_id = request.query.get("qgroup_id")
        files_list = []
        if qgroup_id:
            files_dict = self.client.group_shared_files.get(qgroup_id, {})
            for f in files_dict.values():
                files_list.append({
                    "file_id": f.file_id,
                    "qgroup_id": f.qgroup_id,
                    "filename": f.filename,
                    "filesize": f.filesize,
                    "file_md5": f.file_md5,
                    "uploader_name": f.uploader_name,
                    "uploader_ip": f.uploader_ip,
                    "is_cached": f.is_cached,
                })
        else:
            for gid, f_dict in self.client.group_shared_files.items():
                for f in f_dict.values():
                    files_list.append({
                        "file_id": f.file_id,
                        "qgroup_id": f.qgroup_id,
                        "filename": f.filename,
                        "filesize": f.filesize,
                        "file_md5": f.file_md5,
                        "uploader_name": f.uploader_name,
                        "uploader_ip": f.uploader_ip,
                        "is_cached": f.is_cached,
                    })
        return web.json_response({"ok": True, "files": files_list})

    async def handle_get_native_status(self, request: web.Request) -> web.Response:
        adapter = self.client.native_adapter
        if not adapter and NativeNwtAdapter.is_installed():
            adapter = NativeNwtAdapter()
            self.client.native_adapter = adapter

        installed = adapter.is_installed() if adapter else False
        nwt_dir = adapter.nwt_dir if adapter else None
        account = adapter.read_account() if adapter else None
        opts = adapter.read_user_options() if adapter else {}
        user_name = opts.get("user_name")
        signature = opts.get("signature")
        subnets = adapter.read_network_config().get("subnets", []) if adapter else []

        return web.json_response({
            "ok": True,
            "installed": installed,
            "nwt_dir": nwt_dir,
            "account": account,
            "user_name": user_name,
            "signature": signature,
            "subnets": subnets,
        })

    async def handle_post_native_import(self, request: web.Request) -> web.Response:
        data = {}
        if request.can_read_body:
            try:
                data = await request.json()
            except Exception:
                data = {}
        nwt_dir = data.get("nwt_dir")
        sync_subnets = data.get("sync_subnets", True)
        sync_groups = data.get("sync_groups", True)
        sync_shares = data.get("sync_shares", True)
        apply_identity = data.get("apply_identity", True)

        result = self.client.import_from_native(
            nwt_dir=nwt_dir,
            sync_subnets=sync_subnets,
            sync_groups=sync_groups,
            sync_shares=sync_shares,
            apply_identity=apply_identity,
        )
        return web.json_response({"ok": True, "result": result})

    async def handle_get_image(self, request: web.Request) -> web.Response:
        md5_hash = request.match_info.get("md5", "").lower()
        if not md5_hash:
            return web.Response(status=400, text="Missing md5")

        data = self.client.pending_images.get(md5_hash)
        if not data and self.client.native_adapter:
            data = self.client.native_adapter.get_picture_by_md5(md5_hash)
            if data:
                self.client.pending_images[md5_hash] = data

        if not data:
            return web.Response(status=404, text="Image not found")

        content_type = "image/jpeg"
        if data.startswith(b"\x89PNG"):
            content_type = "image/png"
        elif data.startswith(b"GIF"):
            content_type = "image/gif"
        elif data.startswith(b"BM"):
            content_type = "image/bmp"

        return web.Response(body=data, content_type=content_type)

    async def handle_post_message(self, request: web.Request) -> web.Response:
        data = await request.json()
        target_ip = data.get("target_ip")
        target_uid = data.get("target_uid")
        text = data.get("text", "")
        if not target_ip and target_uid:
            contact = self.client.contacts.get(target_uid)
            if contact:
                target_ip = contact.ip
        if not target_ip or not text:
            return web.json_response({"ok": False, "error": "Missing target_ip or text"}, status=400)
        await self.client.send_message(target_ip, text)
        return web.json_response({"ok": True})

    async def handle_post_group_message(self, request: web.Request) -> web.Response:
        data = await request.json()
        qgroup_id = data.get("qgroup_id")
        text = data.get("text", "")
        if not qgroup_id or not text:
            return web.json_response({"ok": False, "error": "Missing qgroup_id or text"}, status=400)
        await self.client.send_group_message(qgroup_id, text)
        return web.json_response({"ok": True})

    async def handle_post_create_group(self, request: web.Request) -> web.Response:
        data = await request.json()
        name = data.get("name", "未命名讨论组")
        intro = data.get("intro", "")
        announcement = data.get("announcement", "")
        member_ids = data.get("member_ids")
        qg = self.client.create_qgroup(name, intro, announcement, member_ids)
        if member_ids:
            await self.client.invite_to_qgroup(qg.qgroup_id, member_ids)
        return web.json_response({"ok": True, "qgroup_id": qg.qgroup_id})

    async def handle_post_invite_group(self, request: web.Request) -> web.Response:
        data = await request.json()
        qgroup_id = data.get("qgroup_id")
        member_ids = data.get("member_ids", [])
        if not qgroup_id or not member_ids:
            return web.json_response({"ok": False, "error": "Missing qgroup_id or member_ids"}, status=400)
        await self.client.invite_to_qgroup(qgroup_id, member_ids)
        return web.json_response({"ok": True})

    async def handle_post_typing(self, request: web.Request) -> web.Response:
        data = await request.json()
        peer_ip = data.get("peer_ip")
        typing = data.get("typing", True)
        if not peer_ip:
            return web.json_response({"ok": False, "error": "Missing peer_ip"}, status=400)
        await self.client.send_typing_state(peer_ip, typing)
        return web.json_response({"ok": True})

    async def handle_post_recall(self, request: web.Request) -> web.Response:
        data = await request.json()
        target_ip = data.get("target_ip", "")
        target_msg_id = int(data.get("target_msg_id", 0))
        target_uuid = data.get("target_uuid", "")
        qgroup_id = data.get("qgroup_id")
        if not target_msg_id:
            return web.json_response({"ok": False, "error": "Missing target_msg_id"}, status=400)
        await self.client.recall_message(target_ip, target_msg_id, target_uuid, qgroup_id)
        return web.json_response({"ok": True})

    async def handle_post_status(self, request: web.Request) -> web.Response:
        data = await request.json()
        if "status" in data:
            await self.client.set_status(int(data["status"]))
        if "signature" in data:
            await self.client.set_signature(str(data["signature"]))
        return web.json_response({"ok": True})

    async def handle_post_share_file(self, request: web.Request) -> web.Response:
        data = await request.json()
        qgroup_id = data.get("qgroup_id")
        file_path = data.get("file_path")
        if not qgroup_id or not file_path or not os.path.exists(file_path):
            return web.json_response({"ok": False, "error": "Invalid qgroup_id or file_path"}, status=400)
        gsf = await self.client.share_file_to_group(qgroup_id, file_path)
        return web.json_response({"ok": True, "file_md5": gsf.file_md5})

    async def handle_post_scan(self, request: web.Request) -> web.Response:
        data = {}
        if request.can_read_body:
            try:
                data = await request.json()
            except Exception:
                data = {}
        targets = data.get("targets") if isinstance(data, dict) else None
        discovered = await self.client.scan_subnets(targets)
        for c in discovered:
            self._on_contact_online(c)
        return web.json_response({
            "ok": True,
            "count": len(discovered),
            "contacts": [
                {
                    "user_id": c.user_id,
                    "nickname": c.nickname,
                    "ip": c.ip,
                    "port": c.port,
                    "status": c.status,
                }
                for c in discovered
            ],
        })


def create_app(client: LanBridgeClient) -> web.Application:
    """Create configured aiohttp web application bound to client."""
    gateway = WebGateway(client)
    return gateway.app


async def start_web_server(client: LanBridgeClient, host: str = "0.0.0.0", port: int = 8080) -> web.AppRunner:
    """Start background Web Gateway server."""
    gateway = WebGateway(client)
    runner = web.AppRunner(gateway.app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info("LanBridge Web Gateway running at http://%s:%d", host, port)
    return runner
