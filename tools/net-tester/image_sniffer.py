#!/usr/bin/env python3
"""LanBridge Image & Message Sniffer (image_sniffer.py).

Maintains a live native connection with Windows Sandbox (172.31.121.133),
and logs the exact raw structure of any image, file, or message sent by the Sandbox user.
"""

import os
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass

import json
import uuid
import struct
import select
import socket
from typing import Dict, List, Optional, Set, Tuple

# Ensure paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from crypto_engine import XteaEngine
from tester import (
    DEFAULT_USER_ID,
    DEFAULT_VERSION,
    build_handshake_reply,
    build_native_profile,
    build_nwt_discovery_packet,
    build_x_ready_envelope,
    build_x_send_msg_ack_envelope,
    build_x_heartbeat_envelope,
)

xtea = XteaEngine()
sandbox_ip = sys.argv[1] if len(sys.argv) > 1 else "172.31.121.133"

s9012 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s9012.bind(("0.0.0.0", 9012))

s9011 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s9011.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s9011.bind(("0.0.0.0", 9011))

tcp9013 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp9013.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    tcp9013.bind(("0.0.0.0", 9013))
    tcp9013.listen(5)
    tcp9013.setblocking(False)
    print("[*] TCP 9013 server listening for direct P2P image/file data transfers.")
except Exception as e:
    print(f"[!] Warning: Cannot bind TCP 9013: {e}")
    tcp9013 = None

print("=" * 65)
print(f"LanBridge Image Sniffer started -> Target: {sandbox_ip}")
print("Please send an image or screenshot in the Sandbox chat window!")
print("=" * 65)

# Discovery
disc = build_nwt_discovery_packet(user_id=DEFAULT_USER_ID, version=DEFAULT_VERSION)
s9011.sendto(disc, (sandbox_ip, 9011))

# ENet Connect 0x82
cid = bytes.fromhex(DEFAULT_USER_ID)
hdr = struct.pack(">HH", 0x8000, 0x0001)
body = (
    b"\x82\xff\x00\x01\x00\x00\x00\x00\x00\x00\x05\x78\x00\x01\x00\x00\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x88\x00\x00\x00\x02\x00\x00\x00\x02"
    + cid[:4]
    + b"\x00\x00\x00\x00"
)
s9012.sendto(hdr + body, (sandbox_ip, 9012))

my_seq = 1
my_time = 1
header_flag = 0x8000
handshake_completed = False
last_heartbeat = time.time()
processed_msg_ids = set()

# State for fragment reassembly and TCP clients
fragment_buffers = {}
tcp_clients = []
tcp_buffers = {}
output_dir = os.path.join(PROJECT_ROOT, "captures", "images")
os.makedirs(output_dir, exist_ok=True)


def check_and_save_image(raw_bytes: bytes) -> Optional[str]:
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


def send_reliable(env: bytes):
    global my_seq, my_time
    tot_len = len(env)
    if tot_len <= 1372:
        my_time = (my_time + 1) & 0xFFFF
        h = struct.pack(">HH", header_flag, my_time)
        cmd = struct.pack(">BBHH", 0x86, 0x00, my_seq, tot_len)
        my_seq = (my_seq + 1) & 0xFFFF
        s9012.sendto(h + cmd + env, (sandbox_ip, 9012))
    else:
        chunks = [env[i : i + 1372] for i in range(0, tot_len, 1372)]
        start_s = my_seq
        for idx, chk in enumerate(chunks):
            my_time = (my_time + 1) & 0xFFFF
            h = struct.pack(">HH", header_flag, my_time)
            cmd = struct.pack(">BBH", 0x88, 0x00, my_seq)
            frag_hdr = struct.pack(
                ">HHIIII", start_s, len(chk), len(chunks), idx, tot_len, idx * 1372
            )
            s9012.sendto(h + cmd + frag_hdr + chk, (sandbox_ip, 9012))
            my_seq = (my_seq + 1) & 0xFFFF


def dispatch_envelope(op: int, dec_xml: str, addr: Tuple[str, int]):
    global handshake_completed
    if op == 0x03E8:  # Handshake
        reply = build_handshake_reply(bytes())
        send_reliable(reply)
        ready = build_x_ready_envelope(DEFAULT_USER_ID)
        send_reliable(ready)
        handshake_completed = True
        print("\n" + "=" * 65)
        print("[+] HANDSHAKE SUCCESS! LanBridge-Bot is ONLINE.")
        print("[+] Ready to receive messages, emoticons, and images from Sandbox!")
        print("=" * 65 + "\n")

    elif op == 0x03FA:  # Ready
        ready = build_x_ready_envelope(DEFAULT_USER_ID)
        send_reliable(ready)

    elif op == 0x03EC:  # X_SEND_MSG
        start_id = dec_xml.find("<MSG_ID>")
        end_id = dec_xml.find("</MSG_ID>")
        msg_id = int(dec_xml[start_id + 8 : end_id]) if start_id != -1 and end_id != -1 else 1

        ack_env = build_x_send_msg_ack_envelope(msg_id)
        send_reliable(ack_env)

        if msg_id not in processed_msg_ids:
            processed_msg_ids.add(msg_id)
            print("\n" + "#" * 65)
            print(f"### [CHAT MESSAGE RECEIVED] MSG_ID = {msg_id} ###")
            print("#" * 65)

            start_m = dec_xml.find("<MSG>")
            end_m = dec_xml.find("</MSG>")
            if start_m != -1 and end_m != -1:
                raw_m = dec_xml[start_m + 5 : end_m].strip()
                unesc = (
                    raw_m.replace("&quot;", '"')
                    .replace("&nbsp;", " ")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&amp;", "&")
                )
                try:
                    js = json.loads(unesc)
                    print(f"  App:     {js.get('app')}")
                    print(f"  Ver:     {js.get('ver')}")
                    print(f"  Msg ID:  {js.get('id')}")

                    dt = js.get("dt", [])
                    print(f"\n  [Nodes ({len(dt)})]:")
                    img_count = 0
                    for idx, node in enumerate(dt):
                        if "txt" in node:
                            txt = node["txt"]
                            print(f"    [{idx}] TEXT: {txt.get('v')} (format: {txt.get('t')})")
                        elif "img" in node:
                            img = node["img"]
                            itype = img.get("t")
                            ival = img.get("v")
                            img_count += 1
                            print(f"    [{idx}] >> IMAGE DETECTED << type={itype}, value={ival}")
                        elif "retrieve" in node:
                            print(f"    [{idx}] RETRIEVE: {node['retrieve']}")
                        else:
                            print(f"    [{idx}] OTHER: {node}")

                    # Auto echo reply
                    reply_text = f"收到你的消息 (ID {msg_id})！"
                    if img_count > 0:
                        reply_text += f" 成功解析出 {img_count} 个图片/表情节点！"
                    reply_env = build_x_send_msg_envelope(
                        reply_text, msg_id=int(time.time()) % 100000
                    )
                    send_reliable(reply_env)

                except Exception as e:
                    print("[!] JSON parse error:", e)
                    print(unesc)
            print("#" * 65 + "\n")

    elif op in (0x03F1, 0x03F2, 0x03F3, 0x03F4, 0x03F5, 0x03FB):
        print("\n" + "=" * 65)
        print(f"[!] RECEIVED FILE/IMAGE TRANSFER OPCODE 0x{op:04x} ({op}):")
        print(dec_xml)
        print("=" * 65 + "\n")

    else:
        print(f"[*] Opcode 0x{op:04x}: {dec_xml[:80]}")


try:
    while True:
        now = time.time()
        watch_list = [s9011, s9012]
        if tcp9013:
            watch_list.append(tcp9013)
        watch_list.extend(tcp_clients)

        readable, _, _ = select.select(watch_list, [], [], 0.05)
        for s in readable:
            if s == s9011:
                data, addr = s.recvfrom(2048)
                continue

            elif s == tcp9013:
                conn, caddr = tcp9013.accept()
                conn.setblocking(False)
                tcp_clients.append(conn)
                tcp_buffers[conn] = bytearray()
                print(f"\n[TCP 9013] Inbound connection established from {caddr}!")
                continue

            elif s in tcp_clients:
                try:
                    chunk = s.recv(8192)
                    if not chunk:
                        print("[TCP 9013] Remote closed connection.")
                        tcp_clients.remove(s)
                        s.close()
                        if s in tcp_buffers:
                            del tcp_buffers[s]
                        continue

                    tcp_buffers[s].extend(chunk)
                    print(f"[TCP 9013] Received chunk {len(chunk)} bytes (Total: {len(tcp_buffers[s])} bytes)")

                    saved = check_and_save_image(bytes(tcp_buffers[s]))
                    if saved:
                        print("\n" + "*" * 65)
                        print(f"*** [SUCCESS] EXTRACTED & SAVED IMAGE TO DISK! ***")
                        print(f"*** Path: {saved} ({os.path.getsize(saved)} bytes)")
                        print("*" * 65 + "\n")

                except Exception as e:
                    print("[TCP 9013] Error reading socket:", e)
                    tcp_clients.remove(s)
                    s.close()
                    if s in tcp_buffers:
                        del tcp_buffers[s]
                continue

            elif s == s9012:
                data, addr = s.recvfrom(4096)
                if len(data) < 8:
                    continue

                cmd = data[4]
                if cmd == 0x83:  # VerifyConnect
                    my_time = (my_time + 1) & 0xFFFF
                    h = struct.pack(">HH", header_flag, my_time)
                    ack = struct.pack(">BBH", 0x01, 0x00, 0)
                    cmd_ack = struct.pack(">BBH", 0x84, 0x00, 0)
                    s9012.sendto(h + ack + cmd_ack, addr)

                    prof = build_native_profile(
                        nick="LanBridge-Bot",
                        user_id=DEFAULT_USER_ID,
                        group="内网通联系人",
                        tcp_file_port=9013,
                    )
                    send_reliable(prof)

                elif cmd == 0x86:  # SendReliable
                    p_seq = struct.unpack(">H", data[6:8])[0]
                    h_ack = struct.pack(">HH", 0x0000, 0)
                    b_ack = struct.pack(">BBH", 0x01, 0x00, p_seq)
                    s9012.sendto(h_ack + b_ack, addr)

                    payload = data[10:]
                    try:
                        op, dec_xml = xtea.parse_envelope(payload)
                        dispatch_envelope(op, dec_xml, addr)
                    except Exception:
                        pass

                elif cmd == 0x88:  # SendFragment
                    p_seq = struct.unpack(">H", data[6:8])[0]
                    h_ack = struct.pack(">HH", 0x0000, 0)
                    b_ack = struct.pack(">BBH", 0x01, 0x00, p_seq)
                    s9012.sendto(h_ack + b_ack, addr)

                    if len(data) >= 28:
                        start_s = struct.unpack(">H", data[8:10])[0]
                        frag_len = struct.unpack(">H", data[10:12])[0]
                        total_frags = struct.unpack(">I", data[12:16])[0]
                        frag_idx = struct.unpack(">I", data[16:20])[0]
                        total_len = struct.unpack(">I", data[20:24])[0]
                        frag_offset = struct.unpack(">I", data[24:28])[0]
                        chunk = data[28 : 28 + frag_len]

                        if start_s not in fragment_buffers:
                            fragment_buffers[start_s] = {}
                        fragment_buffers[start_s][frag_idx] = chunk

                        if len(fragment_buffers[start_s]) == total_frags:
                            full_payload = b"".join(
                                fragment_buffers[start_s][i] for i in range(total_frags)
                            )
                            del fragment_buffers[start_s]

                            try:
                                op, dec_xml = xtea.parse_envelope(full_payload)
                                dispatch_envelope(op, dec_xml, addr)
                            except Exception as e:
                                print(f"[!] Reassembled fragment parse error: {e}")

        # Keepalive
        if handshake_completed and now - last_heartbeat > 10.0:
            last_heartbeat = now
            send_reliable(build_x_heartbeat_envelope())

except KeyboardInterrupt:
    print("\nSniffer stopped by user.")
finally:
    s9012.close()
    s9011.close()
    if tcp9013:
        tcp9013.close()
    for c in tcp_clients:
        try:
            c.close()
        except Exception:
            pass
