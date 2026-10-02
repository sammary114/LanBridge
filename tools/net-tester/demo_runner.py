#!/usr/bin/env python3
"""LanBridge Host-to-Sandbox Live Demo Runner (demo_runner.py).

Demonstrates full native interoperability from Host to Windows Sandbox:
1. Contact list handshake & lighting up 'LanBridge-Bot' in '内网通联系人'.
2. Sending a native greeting message.
3. Sending an authentic window shake (Flash Screen, Opcode 0x03EF).
4. Sending a test message and demonstrating native message recall (Opcode 0x03EC, type 4, retrieve).
5. Automatic echo loop for incoming messages from Sandbox.
"""

from __future__ import annotations

import json
import logging
import os
import random
import select
import socket
import struct
import sys
import time
import uuid
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from crypto_engine import XteaEngine
from tester import (
    DEFAULT_GUID,
    DEFAULT_USER_ID,
    DEFAULT_VERSION,
    NWT_MAGIC_DISCOVERY,
    build_handshake_reply,
    build_native_profile,
    build_nwt_discovery_packet,
    build_x_flash_screen_envelope,
    build_x_heartbeat_envelope,
    build_x_ready_envelope,
    build_x_send_msg_ack_envelope,
    extract_chat_message,
    extract_msg_id,
)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("LanBridge-Demo")
xtea_engine = XteaEngine()


def build_custom_send_msg(
    message: str,
    msg_id: int = 1,
    msg_uuid: Optional[str] = None,
) -> Tuple[bytes, str, str]:
    """Build X_SEND_MSG envelope and return (envelope_bytes, msg_uuid, raw_json_str)."""
    if not msg_uuid:
        msg_uuid = uuid.uuid4().hex
    timestamp = int(time.time())

    try:
        from lanbridge.emoticons import emoji_to_nwt_dt
        dt = emoji_to_nwt_dt(message)
    except Exception:
        dt = [{"txt": {"t": "normal", "v": message}}]

    msg_obj = {
        "app": "shiyeline",
        "dt": dt,
        "ft": {
            "b": "0",
            "c": "0x000000",
            "i": "0",
            "n": "微软雅黑",
            "s": "9",
            "u": "0",
        },
        "id": msg_uuid,
        "type": "0",
        "ver": "6.0",
    }
    raw_json_str = json.dumps(msg_obj, ensure_ascii=False, indent=3, separators=(",", " : ")) + "\n"
    escaped_msg = raw_json_str.replace('"', '&quot;').replace(' ', '&nbsp;')
    xml = (
        f'<X_SEND_MSG docver="1"><MSG_ID>{msg_id}</MSG_ID><RECEIPT>0</RECEIPT>'
        f'<MSG>{escaped_msg}</MSG>'
        f'<MSG_TIME>{timestamp}</MSG_TIME><OFFLINE>0</OFFLINE><HIDE_RECORD>0</HIDE_RECORD></X_SEND_MSG>'
    )
    env = xtea_engine.build_envelope(0x03EC, xml, encoding="utf-8")
    return env, msg_uuid, raw_json_str


def build_authentic_recall(
    target_uuid: str,
    target_raw_json: str,
    msg_id: int = 2,
) -> bytes:
    """Build authentic message recall envelope (Opcode 0x03EC, type 4, retrieve node)."""
    recall_uuid = uuid.uuid4().hex
    timestamp = int(time.time())

    recall_obj = {
        "app": "shiyeline",
        "dt": [
            {
                "txt": {
                    "t": "compatible",
                    "v": "对方请求撤回一条消息，当前版本不支持。请升级到最新版本。",
                }
            },
            {
                "retrieve": {
                    "m": target_raw_json,
                    "v": target_uuid,
                }
            },
        ],
        "ft": {
            "s": "10",
        },
        "id": recall_uuid,
        "type": "4",
        "ver": "6.0",
    }
    raw_json_str = json.dumps(recall_obj, ensure_ascii=False, indent=3, separators=(",", " : ")) + "\n"
    escaped_msg = raw_json_str.replace('"', '&quot;').replace(' ', '&nbsp;')
    xml = (
        f'<X_SEND_MSG docver="1"><MSG_ID>{msg_id}</MSG_ID><RECEIPT>0</RECEIPT>'
        f'<MSG>{escaped_msg}</MSG>'
        f'<MSG_TIME>{timestamp}</MSG_TIME><OFFLINE>0</OFFLINE><HIDE_RECORD>0</HIDE_RECORD></X_SEND_MSG>'
    )
    return xtea_engine.build_envelope(0x03EC, xml, encoding="utf-8")


class LanBridgeDemoRunner:
    def __init__(self, sandbox_ip: str = "172.31.121.133"):
        self.sandbox_ip = sandbox_ip
        self.host_ip = "172.31.112.1"
        self.dynamic_port = 53782
        self.user_id = DEFAULT_USER_ID
        self.nick = "LanBridge-Bot"
        self.group = "内网通联系人"

        # State
        self.sock_9011: Optional[socket.socket] = None
        self.sock_9012: Optional[socket.socket] = None
        self.sock_dyn: Optional[socket.socket] = None

        self.out_peer = 0
        self.in_sess = 0
        self.out_sess = 0
        self.header_flag = 0x8000
        self.my_time = 0x4000
        self.my_seq = 1

        self.handshake_completed = False
        self.handshake_started = False
        self.frag_assembler: Dict[int, Dict] = {}
        self.processed_msg_ids = set()

    def init_sockets(self):
        # UDP 9011
        self.sock_9011 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_9011.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_9011.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock_9011.bind((self.host_ip, 9011))
        self.sock_9011.setblocking(False)

        # UDP 9012
        self.sock_9012 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_9012.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_9012.bind((self.host_ip, 9012))
        self.sock_9012.setblocking(False)

        # Dynamic port
        self.sock_dyn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_dyn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_dyn.bind((self.host_ip, self.dynamic_port))
        self.sock_dyn.setblocking(False)

    def close_sockets(self):
        for s in (self.sock_9011, self.sock_9012, self.sock_dyn):
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    def send_discovery(self):
        pkt = build_nwt_discovery_packet(cmd=1, user_id=self.user_id, dynamic_port=self.dynamic_port)
        self.sock_9011.sendto(pkt, (self.sandbox_ip, 9011))
        logger.info("[TX:9011] Discovery packet sent to %s:9011", self.sandbox_ip)

    def send_connect_0x82(self):
        cid = bytes.fromhex("e1485eae")
        self.my_time = (self.my_time + 1) & 0xFFFF
        hdr = struct.pack(">HH", 0x8FFF, self.my_time)
        body = (
            b"\x82\xff\x00\x01\x00\x00\x00\x00\x00\x00\x05\x78\x00\x01\x00\x00\x00\x00\x00\x01"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x88\x00\x00\x00\x02\x00\x00\x00\x02"
            + cid[:4]
            + b"\x00\x00\x00\x00"
        )
        self.sock_9012.sendto(hdr + body, (self.sandbox_ip, 9012))
        self.handshake_started = True
        logger.info("[TX:9012] Sent ENet Connect 0x82 to %s:9012", self.sandbox_ip)

    def send_stage5_profile(self):
        profile_env = build_native_profile(nick=self.nick, user_id=self.user_id, group=self.group)
        tot_len = len(profile_env)
        chunks = [profile_env[i : i + 1372] for i in range(0, tot_len, 1372)]
        start_seq = self.my_seq

        for idx, chk in enumerate(chunks):
            self.my_time = (self.my_time + 1) & 0xFFFF
            hdr = struct.pack(">HH", self.header_flag, self.my_time)
            cmd = struct.pack(">BBH", 0x88, 0x00, self.my_seq)
            frag_hdr = struct.pack(">HHIIII", start_seq, len(chk), len(chunks), idx, tot_len, idx * 1372)
            self.sock_9012.sendto(hdr + cmd + frag_hdr + chk, (self.sandbox_ip, 9012))
            self.my_seq = (self.my_seq + 1) & 0xFFFF
        logger.info("[TX:9012] Sent Stage 5 Profile (%d fragments) to %s:9012", len(chunks), self.sandbox_ip)

    def send_reliable_envelope(self, env: bytes):
        tot_len = len(env)
        if tot_len <= 1372:
            self.my_time = (self.my_time + 1) & 0xFFFF
            hdr = struct.pack(">HH", self.header_flag, self.my_time)
            cmd = struct.pack(">BBHH", 0x86, 0x00, self.my_seq, tot_len)
            self.my_seq = (self.my_seq + 1) & 0xFFFF
            self.sock_9012.sendto(hdr + cmd + env, (self.sandbox_ip, 9012))
        else:
            chunks = [env[i : i + 1372] for i in range(0, tot_len, 1372)]
            start_seq = self.my_seq
            for idx, chk in enumerate(chunks):
                self.my_time = (self.my_time + 1) & 0xFFFF
                hdr = struct.pack(">HH", self.header_flag, self.my_time)
                cmd = struct.pack(">BBH", 0x88, 0x00, self.my_seq)
                frag_hdr = struct.pack(">HHIIII", start_seq, len(chk), len(chunks), idx, tot_len, idx * 1372)
                self.sock_9012.sendto(hdr + cmd + frag_hdr + chk, (self.sandbox_ip, 9012))
                self.my_seq = (self.my_seq + 1) & 0xFFFF

    def send_chat(self, text: str, msg_id: int = 1) -> Tuple[str, str]:
        """Send chat message, returns (msg_uuid, raw_json)."""
        env, msg_uuid, raw_json = build_custom_send_msg(text, msg_id=msg_id)
        self.send_reliable_envelope(env)
        logger.info("[CHAT:9012] >>> SENT MESSAGE (id=%d, uuid=%s): %s", msg_id, msg_uuid, text)
        return msg_uuid, raw_json

    def send_shake(self):
        """Send window shake / flash screen."""
        env = build_x_flash_screen_envelope(shake_type=1)
        self.send_reliable_envelope(env)
        logger.info("[ACTION:9012] >>> SENT WINDOW SHAKE (发送窗口抖动) to %s:9012", self.sandbox_ip)

    def send_recall(self, target_uuid: str, target_raw_json: str, msg_id: int = 99):
        """Send message recall."""
        env = build_authentic_recall(target_uuid=target_uuid, target_raw_json=target_raw_json, msg_id=msg_id)
        self.send_reliable_envelope(env)
        logger.info("[ACTION:9012] >>> SENT MESSAGE RECALL (撤回消息 UUID=%s)", target_uuid)

    def process_incoming(self, sock: socket.socket, port: int):
        try:
            data, addr = sock.recvfrom(4096)
        except (BlockingIOError, OSError):
            return
        src_ip, src_port = addr

        # Discovery reply
        if port == 9011 and len(data) == 304:
            logger.info("[RX:9011] Discovery response from %s:%d", src_ip, src_port)
            if not self.handshake_started:
                self.send_connect_0x82()
            return

        # 9012 ENet
        if port == 9012 and len(data) >= 8:
            if data[4] == 0x83:  # VERIFY_CONNECT
                flag_peer, sb_sent_time = struct.unpack(">HH", data[:4])
                self.out_peer, self.in_sess, self.out_sess = struct.unpack(">HBB", data[8:12])
                logger.info("[RX:9012] Received VerifyConnect (0x83) outPeer=%d inSess=%d", self.out_peer, self.in_sess)

                # Frame 11
                self.header_flag = 0x8000 | ((self.in_sess & 3) << 12) | (self.out_peer & 0x0FFF)
                self.my_time = (self.my_time + 0x66) & 0xFFFF
                hdr = struct.pack(">HH", self.header_flag, self.my_time)
                cmd_ack = struct.pack(">BBHHH", 0x01, 0xFF, 0x0001, 0x0001, sb_sent_time)
                cmd_ping = struct.pack(">BBH", 0x85, 0xFF, 0x0002)
                sock.sendto(hdr + cmd_ack + cmd_ping, addr)

                # Frame 17 (304B)
                self.my_time = (self.my_time + 0x65) & 0xFFFF
                hdr17 = struct.pack(">HH", self.header_flag, self.my_time)
                cmd17 = struct.pack(">BBHH", 0x86, 0x00, 0x0001, 304)
                disc_d = build_nwt_discovery_packet(cmd=4, user_id=self.user_id, dynamic_port=self.dynamic_port)
                sock.sendto(hdr17 + cmd17 + disc_d, addr)

                # Stage 5 profile
                self.my_seq = 2
                self.send_stage5_profile()
                return

            h_val = struct.unpack(">H", data[:2])[0]
            offset = 4 if (h_val & 0x8000) else 2
            r_time = struct.unpack(">H", data[2:4])[0] if (h_val & 0x8000) else 0

            acks_to_send = []
            while offset < len(data):
                if offset + 4 > len(data): break
                c_byte, c_chan, c_seq = struct.unpack(">BBH", data[offset : offset + 4])
                c_type = c_byte & 0x0F
                offset += 4

                if c_type == 1:  # ACK
                    offset += 4
                elif c_type == 8:  # SEND_FRAGMENT
                    s_seq, d_len, f_cnt, f_num, tot_l, f_off = struct.unpack(">HHIIII", data[offset : offset + 20])
                    f_data = data[offset + 20 : offset + 20 + d_len]
                    offset += 20 + d_len
                    acks_to_send.append((c_chan, c_seq))
                    if s_seq not in self.frag_assembler:
                        self.frag_assembler[s_seq] = {"parts": {}, "count": f_cnt}
                    self.frag_assembler[s_seq]["parts"][f_num] = f_data
                    if len(self.frag_assembler[s_seq]["parts"]) == f_cnt:
                        full_p = b"".join(self.frag_assembler[s_seq]["parts"][i] for i in range(f_cnt))
                        self._handle_assembled_payload(full_p, sock, addr)
                elif c_type == 6:  # SEND_RELIABLE
                    d_len = struct.unpack(">H", data[offset : offset + 2])[0]
                    p_data = data[offset + 2 : offset + 2 + d_len]
                    offset += 2 + d_len
                    acks_to_send.append((c_chan, c_seq))
                    self._handle_assembled_payload(p_data, sock, addr)
                elif c_type == 5:  # PING
                    acks_to_send.append((c_chan, c_seq))
                else:
                    break

            if acks_to_send:
                ack_hdr = struct.pack(">H", 0x1000 | (self.out_peer & 0x0FFF))
                ack_cmds = bytearray()
                for ch, sq in acks_to_send:
                    ack_cmds.extend(struct.pack(">BBHHH", 0x01, ch, sq, sq, r_time))
                sock.sendto(ack_hdr + ack_cmds, addr)

    def _handle_assembled_payload(self, p_data: bytes, sock: socket.socket, addr: Tuple[str, int]):
        if len(p_data) < 8: return
        tot_len, op = struct.unpack(">2I", p_data[:8])
        raw_dec = xtea_engine.decrypt(p_data[8:])
        try:
            dec_xml = raw_dec.decode("utf-8")
        except UnicodeDecodeError:
            dec_xml = raw_dec.decode("gbk", errors="ignore")

        if op == 0x03FA:  # X_READY
            logger.info("[RX:9012] Received Sandbox X_READY! Sending Host X_READY...")
            ready_env = build_x_ready_envelope(self.user_id)
            self.my_time = (self.my_time + 1) & 0xFFFF
            hdr = struct.pack(">HH", self.header_flag, self.my_time)
            cmd_r = struct.pack(">BBHH", 0x86, 0x00, self.my_seq, len(ready_env))
            self.my_seq = (self.my_seq + 1) & 0xFFFF
            sock.sendto(hdr + cmd_r + ready_env, addr)
            self.handshake_completed = True
            logger.info("=" * 65)
            logger.info("*** NATIVE HANDSHAKE COMPLETED! Contact is now ONLINE in '内网通联系人' ***")
            logger.info("=" * 65)

        elif op == 0x03EC:  # X_SEND_MSG
            msg_id = extract_msg_id(dec_xml)
            ack_env = build_x_send_msg_ack_envelope(msg_id)
            self.my_time = (self.my_time + 1) & 0xFFFF
            h_ack = struct.pack(">HH", self.header_flag, self.my_time)
            cmd_ack = struct.pack(">BBHH", 0x86, 0x00, self.my_seq, len(ack_env))
            self.my_seq = (self.my_seq + 1) & 0xFFFF
            sock.sendto(h_ack + cmd_ack + ack_env, addr)

            if msg_id not in self.processed_msg_ids:
                self.processed_msg_ids.add(msg_id)
                msg_text = extract_chat_message(dec_xml)
                logger.info("=" * 65)
                logger.info("[CHAT:9012] <<< RECEIVED MESSAGE FROM SANDBOX: %s", msg_text)
                logger.info("=" * 65)
                # Auto reply
                reply_text = f"LanBridge Bot 自动应答: {msg_text} 👍"
                self.send_chat(reply_text, msg_id=msg_id + 100)

        elif op == 0x03EF:  # X_SEND_FLASH_SCREEN
            logger.info("=" * 65)
            logger.info("[ACTION:9012] <<< RECEIVED WINDOW SHAKE FROM SANDBOX!")
            logger.info("=" * 65)
            self.send_chat("LanBridge Bot 收到您的窗口抖动！", msg_id=888)

    def run_demo(self, wait_seconds: int = 40):
        self.init_sockets()
        logger.info("=" * 65)
        logger.info("  LanBridge Host -> Windows Sandbox Live Full-Feature Demo")
        logger.info("  Target Sandbox IP:  %s", self.sandbox_ip)
        logger.info("  Virtual Contact:    %s", self.nick)
        logger.info("=" * 65)

        self.send_discovery()
        self.send_connect_0x82()

        start_time = time.time()
        step = 0
        target_uuid = ""
        target_json = ""
        next_action_time = 0

        try:
            while time.time() - start_time < wait_seconds:
                now = time.time()
                socks = [s for s in (self.sock_9011, self.sock_9012, self.sock_dyn) if s]
                readable, _, _ = select.select(socks, [], [], 0.05)
                for s in readable:
                    port = 9011 if s == self.sock_9011 else (9012 if s == self.sock_9012 else self.dynamic_port)
                    self.process_incoming(s, port)

                # Demonstration Progression once Handshake is complete
                if self.handshake_completed:
                    if step == 0:
                        # Step 1: Send Greeting Message
                        time.sleep(0.3)
                        self.send_chat("你好！我是宿主机运行的 LanBridge 原生接入机器人 😊，当前握手成功已点亮！🎉", msg_id=1)
                        step = 1
                        next_action_time = now + 3.0

                    elif step == 1 and now >= next_action_time:
                        # Step 2: Send Window Shake
                        self.send_shake()
                        step = 2
                        next_action_time = now + 4.0

                    elif step == 2 and now >= next_action_time:
                        # Step 3: Send Message to be recalled
                        target_uuid, target_json = self.send_chat("这是一条即将在 3 秒后被撤回的测试消息 [114514]", msg_id=2)
                        step = 3
                        next_action_time = now + 3.5

                    elif step == 3 and now >= next_action_time:
                        # Step 4: Recall the Message
                        self.send_recall(target_uuid=target_uuid, target_raw_json=target_json, msg_id=3)
                        step = 4
                        logger.info("=" * 65)
                        logger.info(">>> DEMO SEQUENCE COMPLETED! All 4 features demonstrated successfully.")
                        logger.info(">>> You can now type messages in Sandbox to test automatic echo replies!")
                        logger.info("=" * 65)

        except KeyboardInterrupt:
            logger.info("Demo interrupted by user.")
        finally:
            self.close_sockets()
            logger.info("Demo sockets closed.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="LanBridge Host -> Sandbox Live Demo Runner")
    parser.add_argument("sandbox_ip", nargs="?", default="172.31.121.133", help="Target Sandbox IP")
    parser.add_argument("--sandbox-ip", dest="opt_ip", default=None, help="Target Sandbox IP")
    parser.add_argument("--wait", type=int, default=45, help="Wait seconds for interactive demo")
    args = parser.parse_args()

    target_ip = args.opt_ip or args.sandbox_ip
    runner = LanBridgeDemoRunner(sandbox_ip=target_ip)
    runner.run_demo(wait_seconds=args.wait)
