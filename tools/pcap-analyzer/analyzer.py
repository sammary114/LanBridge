#!/usr/bin/env python3
"""LanBridge PCAP / PCAPNG Network Packet Analyzer.

A lightweight, modular packet analyzer for inspecting and reverse-engineering
network protocols from PCAP/PCAPNG capture files.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


def check_dependencies() -> None:
    """Check if required third-party packages are available."""
    try:
        import scapy.all  # noqa: F401
    except ImportError as e:
        sys.stderr.write(
            "Error: Missing required dependency 'scapy'.\n"
            "Please install it using: pip install scapy\n"
        )
        sys.exit(1)


def format_hexdump(data: bytes, prefix: str = "  ") -> str:
    """Format bytes into a standard hexdump string."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk[:8])
        if len(chunk) > 8:
            hex_bytes += "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{prefix}{i:04x}  {hex_bytes:<48}  |{ascii_chars}|")
    return "\n".join(lines)


def format_ascii_preview(data: bytes, max_len: int = 120) -> str:
    """Format bytes into a single-line ASCII preview."""
    preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:max_len])
    if len(data) > max_len:
        preview += "..."
    return preview


def parse_http_payload(data: bytes) -> Optional[Dict[str, Any]]:
    """Attempt to parse HTTP request or response from raw bytes."""
    try:
        if data.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/")):
            header_end = data.find(b"\r\n\r\n")
            if header_end != -1:
                header_part = data[:header_end].decode("iso-8859-1")
                lines = header_part.split("\r\n")
                first_line = lines[0]
                headers = {}
                for line in lines[1:]:
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        headers[k.strip()] = v.strip()

                body = data[header_end + 4 :]
                body_info = {
                    "body_len": len(body),
                    "body_preview": format_ascii_preview(body, 200),
                }

                # Check for urlencoded json body
                if b"json=" in body:
                    try:
                        raw_body_str = body.decode("utf-8", errors="replace")
                        parsed_qs = urllib.parse.parse_qs(raw_body_str)
                        if "json" in parsed_qs:
                            json_str = parsed_qs["json"][0]
                            body_info["decoded_json"] = json.loads(json_str)
                    except Exception:
                        pass

                return {
                    "type": "HTTP",
                    "first_line": first_line,
                    "headers": headers,
                    "body": body_info,
                }
    except Exception:
        pass
    return None


def parse_tls_payload(data: bytes) -> Optional[Dict[str, Any]]:
    """Attempt to parse TLS ClientHello or basic TLS record."""
    if len(data) < 5:
        return None
    content_type = data[0]
    version_major = data[1]
    version_minor = data[2]
    # TLS Content Types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData
    if content_type in (20, 21, 22, 23) and version_major == 3:
        record_type = {
            20: "ChangeCipherSpec",
            21: "Alert",
            22: "Handshake",
            23: "ApplicationData",
        }.get(content_type, f"Unknown({content_type})")

        info: Dict[str, Any] = {
            "type": "TLS",
            "record_type": record_type,
            "version": f"3.{version_minor}",
            "record_length": int.from_bytes(data[3:5], "big"),
        }

        # Check if Handshake ClientHello (type 1)
        if content_type == 22 and len(data) > 9 and data[5] == 1:
            info["handshake_type"] = "ClientHello"
            # Attempt to extract SNI (Server Name Indication)
            try:
                # Skip to session id length
                idx = 5 + 4 + 2 + 32  # hs header + ver + random
                if idx < len(data):
                    sess_len = data[idx]
                    idx += 1 + sess_len
                    if idx + 2 <= len(data):
                        cipher_len = int.from_bytes(data[idx : idx + 2], "big")
                        idx += 2 + cipher_len
                        if idx + 1 <= len(data):
                            comp_len = data[idx]
                            idx += 1 + comp_len
                            if idx + 2 <= len(data):
                                ext_total_len = int.from_bytes(data[idx : idx + 2], "big")
                                idx += 2
                                ext_end = min(len(data), idx + ext_total_len)
                                while idx + 4 <= ext_end:
                                    ext_type = int.from_bytes(data[idx : idx + 2], "big")
                                    ext_len = int.from_bytes(data[idx + 2 : idx + 4], "big")
                                    idx += 4
                                    if ext_type == 0:  # SNI extension
                                        sni_list_len = int.from_bytes(data[idx : idx + 2], "big")
                                        if idx + 2 + sni_list_len <= ext_end:
                                            # host_name type 0
                                            if data[idx + 2] == 0:
                                                name_len = int.from_bytes(data[idx + 3 : idx + 5], "big")
                                                server_name = data[idx + 5 : idx + 5 + name_len].decode("ascii", errors="replace")
                                                info["sni"] = server_name
                                                break
                                    idx += ext_len
            except Exception:
                pass
        elif content_type == 22 and len(data) > 6 and data[5] == 2:
            info["handshake_type"] = "ServerHello"

        return info
    return None


def parse_ipmsg_payload(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse IPMSG / 飞鸽 / 飞秋 protocol packet on port 2425."""
    try:
        if data.startswith((b"1:", b"1_")) or b"@shiyeline:" in data[:30]:
            text = data.decode("gbk", errors="replace")
            parts = text.split(":", 5)
            if len(parts) >= 5:
                info: Dict[str, Any] = {
                    "type": "IPMSG",
                    "ver": parts[0],
                    "packet_no": parts[1],
                    "user": parts[2],
                    "host": parts[3],
                    "command": parts[4],
                }
                cmd_names = {
                    "1": "BR_ENTRY (Online)",
                    "2": "BR_EXIT (Offline)",
                    "3": "ANSENTRY (AckOnline)",
                    "32": "SENDMSG",
                    "33": "RECVMSG",
                }
                info["cmd_name"] = cmd_names.get(parts[4], parts[4])
                if len(parts) > 5:
                    extra = parts[5].split("\x00")
                    info["nick"] = extra[0] if len(extra) > 0 else ""
                    if len(extra) > 1 and extra[1]:
                        info["group"] = extra[1]
                    if len(extra) > 2 and extra[2]:
                        info["user_id"] = extra[2]
                return info
    except Exception:
        pass
    return None


def parse_nwt_discovery_payload(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse Nwt 9011 discovery broadcast or unicast reply (length 304)."""
    if len(data) == 304 and data[:4] == b"\x00\x00\x01\x30":
        cmd = int.from_bytes(data[4:8], "big")
        cmd_name = {1: "DiscoveryBroadcast", 2: "DiscoveryReply", 4: "DiscoveryHandshake"}.get(cmd, f"Cmd_{cmd}")
        magic = data[12:16].hex()
        bcast_ip = ".".join(str(b) for b in data[20:24])
        ver_str = data[24:30].decode("ascii", errors="replace").strip("\x00")
        user_id = data[30:62].decode("ascii", errors="replace").strip("\x00")
        guid = data[96:112].hex()
        dyn_port = int.from_bytes(data[165:167], "big") if data[165:167] != b"\x00\x00" else None
        return {
            "type": "NWT_DISCOVERY_9011",
            "command": cmd_name,
            "magic": magic,
            "broadcast_ip": bcast_ip,
            "version": ver_str,
            "user_id": user_id,
            "guid": guid,
            "dynamic_port": dyn_port,
        }
    return None


def parse_nwt_udp_payload(data: bytes) -> Optional[Dict[str, Any]]:
    """Analyze UDP payload for Nwt / ShiYeLine binary protocol characteristics."""
    if len(data) < 8:
        return None

    hdr0 = data[0]
    # Check for Request/Command (0x80, 0x8f, 0x90)
    is_req = (hdr0 & 0x80) != 0 and (hdr0 in (0x80, 0x8F, 0x90))
    # Check for ACK (0x00, 0x10)
    is_ack = (hdr0 & 0x80) == 0 and (hdr0 in (0x00, 0x10))

    if is_req:
        seq = int.from_bytes(data[2:4], "big")
        opcode = data[4]
        info: Dict[str, Any] = {
            "type": "NWT_REQ",
            "seq_id": f"0x{seq:04x}",
            "opcode": f"0x{opcode:02x}",
            "total_len": len(data),
        }
        if len(data) == 8:
            info["subtype"] = "Heartbeat/Ping"
            info["sub_id"] = f"0x{int.from_bytes(data[6:8], 'big'):04x}"
        elif opcode == 0x82:
            info["subtype"] = "HandshakeInit"
            if len(data) >= 8:
                info["channel_id"] = f"0x{int.from_bytes(data[6:8], 'big'):04x}"
        elif opcode == 0x83:
            info["subtype"] = "HandshakeReply"
            if len(data) >= 8:
                info["channel_id"] = f"0x{int.from_bytes(data[6:8], 'big'):04x}"
        elif opcode == 0x8A:
            info["subtype"] = "HandshakeFinal"
        elif opcode == 0x86 and len(data) >= 16:
            info["channel_id"] = f"0x{int.from_bytes(data[6:8], 'big'):04x}"
            info["inner_len"] = int.from_bytes(data[8:10], "big")
            data_bytes = data[16:]
            info["data_len"] = len(data_bytes)
            info["data_hex"] = data_bytes.hex()
            if len(data_bytes) == 298 and data_bytes[:2] == b"\x00\x04":
                info["subtype"] = "DiscoveryHandshake (304B/Cmd4)"
            elif len(data_bytes) == 304 and data_bytes[:4] == b"\x00\x00\x01\x30":
                info["subtype"] = "EncapsulatedDiscovery (304B)"
            elif len(data_bytes) >= 2:
                prefix = (data_bytes[0], data_bytes[1])
                subtypes = {
                    (3, 0xf8): "Data/Exchange",
                    (3, 0xe9): "Status/StateUpdate",
                    (3, 0xed): "MsgAck/Receipt",
                    (3, 0xf0): "TypingIndicator",
                    (3, 0xec): "TextMessage",
                    (3, 0xfa): "SessionProbe",
                }
                info["subtype"] = subtypes.get(prefix, f"Data({len(data_bytes)}B)")
            else:
                info["subtype"] = f"Data({len(data_bytes)}B)"
        elif opcode == 0x88 and len(data) >= 28:
            info["total_frags"] = int.from_bytes(data[12:16], "big")
            info["frag_idx"] = int.from_bytes(data[16:20], "big")
            info["total_msg_len"] = int.from_bytes(data[20:24], "big")
            info["frag_offset"] = int.from_bytes(data[24:28], "big")
            frag_bytes = data[28:]
            info["frag_len"] = len(frag_bytes)
            extra_tag = ""
            if info["frag_idx"] == 0 and len(frag_bytes) >= 8:
                if frag_bytes[6:8] == b"\x03\xec":
                    extra_tag = "TextMessage, "
                elif frag_bytes[6:8] == b"\x03\xe8":
                    extra_tag = "Profile/Handshark, "
            info["subtype"] = f"Fragment ({extra_tag}{info['frag_idx'] + 1}/{info['total_frags']}, len={len(frag_bytes)}B, total={info['total_msg_len']}B)"
        return info

    if is_ack:
        ack_type = data[2]
        ack_seq = int.from_bytes(data[8:10], "big") if len(data) >= 10 else int.from_bytes(data[-2:], "big")
        info = {
            "type": "NWT_ACK",
            "ack_type": f"0x{ack_type:02x}",
            "ack_seq_id": f"0x{ack_seq:04x}",
            "total_len": len(data),
        }
        if len(data) >= 8:
            info["channel_or_sub"] = f"0x{int.from_bytes(data[4:6], 'big'):04x}"
        if len(data) > 10:
            info["subtype"] = f"MultiACK ({len(data)}B)"
        return info

    return None


class PcapAnalyzer:
    """Analyzer engine for PCAP/PCAPNG capture files."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self._validate_file()
        self.raw_packets: List[Any] = []
        self.analyzed_packets: List[Dict[str, Any]] = []
        self.tcp_streams: List[Dict[str, Any]] = []
        self.udp_flows: List[Dict[str, Any]] = []
        self.summary: Dict[str, Any] = {}

    def _validate_file(self) -> None:
        """Validate existence, permissions, and non-emptiness of the capture file."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Capture file not found: {self.filepath}")

        if not os.path.isfile(self.filepath):
            raise ValueError(f"Path is not a regular file: {self.filepath}")

        file_size = os.path.getsize(self.filepath)
        if file_size == 0:
            raise ValueError(f"Capture file is empty (0 bytes): {self.filepath}")

    def load_and_analyze(
        self,
        filter_ip: Optional[str] = None,
        filter_port: Optional[int] = None,
        filter_proto: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Load packets and execute protocol decoding, session tracking, and filtering."""
        check_dependencies()
        from scapy.all import IP, IPv6, Raw, TCP, UDP, rdpcap
        from scapy.error import Scapy_Exception

        try:
            self.raw_packets = rdpcap(self.filepath)
        except (Scapy_Exception, Exception) as e:
            raise ValueError(f"Unable to parse capture file '{self.filepath}': {e}") from e

        if len(self.raw_packets) == 0:
            raise ValueError(f"Capture file contains 0 packets: {self.filepath}")

        base_time = float(self.raw_packets[0].time)
        start_time_iso = datetime.datetime.fromtimestamp(base_time, datetime.timezone.utc).isoformat()
        end_time_raw = float(self.raw_packets[-1].time)
        end_time_iso = datetime.datetime.fromtimestamp(end_time_raw, datetime.timezone.utc).isoformat()
        duration = max(0.0, end_time_raw - base_time)

        protocol_counts: Dict[str, int] = {}
        endpoints_ip: set[str] = set()
        ip_pairs: Dict[str, int] = {}

        analyzed_pkts: List[Dict[str, Any]] = []

        # Stream tracking dicts
        tcp_stream_buckets: Dict[Tuple[str, int, str, int], List[Dict[str, Any]]] = {}
        udp_flow_buckets: Dict[Tuple[str, int, str, int], List[Dict[str, Any]]] = {}

        for idx, pkt in enumerate(self.raw_packets, start=1):
            pkt_time = float(pkt.time)
            rel_time = round(pkt_time - base_time, 6)

            src_ip = ""
            dst_ip = ""
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            if src_ip:
                endpoints_ip.add(src_ip)
            if dst_ip:
                endpoints_ip.add(dst_ip)
            if src_ip and dst_ip:
                pair_key = " <-> ".join(sorted([src_ip, dst_ip]))
                ip_pairs[pair_key] = ip_pairs.get(pair_key, 0) + 1

            proto = "OTHER"
            sport: Optional[int] = None
            dport: Optional[int] = None
            tcp_flags = ""
            tcp_seq = None
            tcp_ack = None
            udp_len = None

            if TCP in pkt:
                proto = "TCP"
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                tcp_flags = str(pkt[TCP].flags)
                tcp_seq = int(pkt[TCP].seq)
                tcp_ack = int(pkt[TCP].ack)
            elif UDP in pkt:
                proto = "UDP"
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
                udp_len = int(pkt[UDP].len)

            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            payload_bytes = bytes(pkt[Raw].load) if Raw in pkt else b""
            payload_hex = payload_bytes.hex()
            payload_len = len(payload_bytes)

            app_info: Optional[Dict[str, Any]] = None
            if payload_len > 0:
                if proto == "TCP":
                    app_info = parse_http_payload(payload_bytes) or parse_tls_payload(payload_bytes)
                elif proto == "UDP":
                    app_info = (
                        parse_nwt_discovery_payload(payload_bytes)
                        or parse_ipmsg_payload(payload_bytes)
                        or parse_nwt_udp_payload(payload_bytes)
                    )

            pkt_dict: Dict[str, Any] = {
                "index": idx,
                "relative_time": rel_time,
                "timestamp": pkt_time,
                "wire_len": len(pkt),
                "protocol": proto,
                "src_ip": src_ip,
                "src_port": sport,
                "dst_ip": dst_ip,
                "dst_port": dport,
                "payload_len": payload_len,
                "payload_hex": payload_hex,
                "payload_ascii": format_ascii_preview(payload_bytes, 100),
                "app_info": app_info,
            }

            if proto == "TCP":
                pkt_dict["tcp_flags"] = tcp_flags
                pkt_dict["tcp_seq"] = tcp_seq
                pkt_dict["tcp_ack"] = tcp_ack
                # Bucket for TCP stream: canonical 4-tuple key
                assert sport is not None and dport is not None
                if (src_ip, sport) <= (dst_ip, dport):
                    stream_key = (src_ip, sport, dst_ip, dport)
                else:
                    stream_key = (dst_ip, dport, src_ip, sport)
                tcp_stream_buckets.setdefault(stream_key, []).append(pkt_dict)

            elif proto == "UDP":
                pkt_dict["udp_len"] = udp_len
                assert sport is not None and dport is not None
                if (src_ip, sport) <= (dst_ip, dport):
                    flow_key = (src_ip, sport, dst_ip, dport)
                else:
                    flow_key = (dst_ip, dport, src_ip, sport)
                udp_flow_buckets.setdefault(flow_key, []).append(pkt_dict)

            # Filtering
            matches_filter = True
            if filter_ip and filter_ip not in (src_ip, dst_ip):
                matches_filter = False
            if filter_port is not None and filter_port not in (sport, dport):
                matches_filter = False
            if filter_proto and proto.upper() != filter_proto.upper():
                matches_filter = False

            if matches_filter:
                analyzed_pkts.append(pkt_dict)

        # Aggregate TCP streams
        stream_id = 1
        tcp_streams_summary = []
        for (ip1, port1, ip2, port2), spkts in tcp_stream_buckets.items():
            first_p = spkts[0]
            # Identify client: the sender of the first packet (typically SYN)
            client = f"{first_p['src_ip']}:{first_p['src_port']}"
            server = f"{first_p['dst_ip']}:{first_p['dst_port']}"
            bytes_c2s = sum(p["payload_len"] for p in spkts if f"{p['src_ip']}:{p['src_port']}" == client)
            bytes_s2c = sum(p["payload_len"] for p in spkts if f"{p['src_ip']}:{p['src_port']}" == server)
            flags_all = set(p.get("tcp_flags", "") for p in spkts)

            # App detection across stream
            app_summary = "TCP"
            for p in spkts:
                if p.get("app_info"):
                    ai = p["app_info"]
                    if ai["type"] == "HTTP":
                        app_summary = f"HTTP {ai['first_line']}"
                        break
                    elif ai["type"] == "TLS":
                        sni = ai.get("sni", "")
                        app_summary = f"TLS {ai.get('handshake_type', 'Traffic')} (SNI: {sni})" if sni else f"TLS {ai.get('handshake_type', 'Traffic')}"
                        break

            tcp_streams_summary.append({
                "stream_id": stream_id,
                "client": client,
                "server": server,
                "packet_count": len(spkts),
                "duration_seconds": round(spkts[-1]["relative_time"] - spkts[0]["relative_time"], 4),
                "bytes_c2s": bytes_c2s,
                "bytes_s2c": bytes_s2c,
                "flags": sorted(list(flags_all)),
                "app_summary": app_summary,
            })
            stream_id += 1

        # Aggregate UDP flows
        flow_id = 1
        udp_flows_summary = []
        for (ip1, port1, ip2, port2), upkts in udp_flow_buckets.items():
            ep1 = f"{ip1}:{port1}"
            ep2 = f"{ip2}:{port2}"
            bytes_1to2 = sum(p["payload_len"] for p in upkts if f"{p['src_ip']}:{p['src_port']}" == ep1)
            bytes_2to1 = sum(p["payload_len"] for p in upkts if f"{p['src_ip']}:{p['src_port']}" == ep2)

            nwt_reqs = [p for p in upkts if (p.get("app_info") or {}).get("type") == "NWT_REQ"]
            nwt_acks = [p for p in upkts if (p.get("app_info") or {}).get("type") == "NWT_ACK"]
            nwt_disc = [p for p in upkts if (p.get("app_info") or {}).get("type") == "NWT_DISCOVERY_9011"]
            ipmsg_pkts = [p for p in upkts if (p.get("app_info") or {}).get("type") == "IPMSG"]

            flow_desc = "UDP"
            if nwt_disc:
                flow_desc = f"Nwt Discovery (9011) ({len(nwt_disc)} pkts)"
            elif ipmsg_pkts:
                flow_desc = f"IPMSG Protocol (2425) ({len(ipmsg_pkts)} pkts)"
            elif nwt_reqs or nwt_acks:
                flow_desc = f"Nwt Protocol ({len(nwt_reqs)} Reqs, {len(nwt_acks)} ACKs)"

            udp_flows_summary.append({
                "flow_id": flow_id,
                "endpoint_a": ep1,
                "endpoint_b": ep2,
                "packet_count": len(upkts),
                "duration_seconds": round(upkts[-1]["relative_time"] - upkts[0]["relative_time"], 4),
                "bytes_a_to_b": bytes_1to2,
                "bytes_b_to_a": bytes_2to1,
                "flow_description": flow_desc,
            })
            flow_id += 1

        self.analyzed_packets = analyzed_pkts
        self.tcp_streams = tcp_streams_summary
        self.udp_flows = udp_flows_summary

        self.summary = {
            "filepath": os.path.abspath(self.filepath),
            "filesize_bytes": os.path.getsize(self.filepath),
            "total_packets": len(self.raw_packets),
            "filtered_packets": len(analyzed_pkts),
            "start_time": start_time_iso,
            "end_time": end_time_iso,
            "duration_seconds": round(duration, 4),
            "protocols": protocol_counts,
            "endpoints": sorted(list(endpoints_ip)),
            "conversations": ip_pairs,
        }

        return {
            "summary": self.summary,
            "tcp_streams": self.tcp_streams,
            "udp_flows": self.udp_flows,
            "packets": self.analyzed_packets,
        }

    def print_text_report(self, verbose: bool = False, show_hexdump: bool = False, summary_only: bool = False) -> None:
        """Print formatted human-readable report to stdout."""
        s = self.summary
        print("=" * 80)
        print(" LanBridge PCAP Analyzer - Analysis Report")
        print("=" * 80)
        print(f"File:       {s['filepath']}")
        print(f"Size:       {s['filesize_bytes']} bytes")
        print(f"Packets:    {s['filtered_packets']} displayed (Total in capture: {s['total_packets']})")
        print(f"Time Range: {s['start_time']} -> {s['end_time']} ({s['duration_seconds']}s)")
        print(f"Protocols:  " + ", ".join(f"{k}: {v}" for k, v in sorted(s["protocols"].items())))
        print(f"Endpoints:  " + ", ".join(s["endpoints"]))
        print("-" * 80)
        print("IP Conversations:")
        for conv, count in s["conversations"].items():
            print(f"  * {conv:<45} {count:>5} packets")

        print("-" * 80)
        print(f"TCP Streams Summary ({len(self.tcp_streams)} streams):")
        for stream in self.tcp_streams:
            print(
                f"  Stream #{stream['stream_id']}: {stream['client']} -> {stream['server']} "
                f"| {stream['packet_count']} pkts ({stream['duration_seconds']}s) "
                f"| C->S: {stream['bytes_c2s']}B, S->C: {stream['bytes_s2c']}B"
            )
            print(f"    App: {stream['app_summary']}")

        print("-" * 80)
        print(f"UDP Flows Summary ({len(self.udp_flows)} flows):")
        for flow in self.udp_flows:
            print(
                f"  Flow #{flow['flow_id']}: {flow['endpoint_a']} <-> {flow['endpoint_b']} "
                f"| {flow['packet_count']} pkts ({flow['duration_seconds']}s) "
                f"| A->B: {flow['bytes_a_to_b']}B, B->A: {flow['bytes_b_to_a']}B"
            )
            print(f"    Type: {flow['flow_description']}")

        if summary_only:
            print("=" * 80)
            return

        print("-" * 80)
        print("Packet Details:")
        print(f"{'#':<4} {'RelTime':<9} {'Proto':<5} {'Source':<26} {'Destination':<26} {'Len':<5} {'App / Summary'}")
        print("-" * 80)

        for p in self.analyzed_packets:
            src = f"{p['src_ip']}:{p['src_port']}" if p['src_port'] is not None else p['src_ip']
            dst = f"{p['dst_ip']}:{p['dst_port']}" if p['dst_port'] is not None else p['dst_ip']

            summary = ""
            if p.get("app_info"):
                ai = p["app_info"]
                if ai["type"] == "HTTP":
                    summary = f"HTTP {ai['first_line']}"
                elif ai["type"] == "TLS":
                    sni_str = f" SNI={ai['sni']}" if "sni" in ai else ""
                    summary = f"TLS {ai.get('handshake_type', ai['record_type'])}{sni_str}"
                elif ai["type"] == "NWT_DISCOVERY_9011":
                    port_str = f" dyn_port={ai['dynamic_port']}" if ai.get("dynamic_port") else ""
                    summary = f"NWT 9011 {ai['command']} uid={ai['user_id'][:8]}... ver={ai['version']}{port_str}"
                elif ai["type"] == "IPMSG":
                    summary = f"IPMSG {ai.get('cmd_name', ai['command'])} user={ai.get('user', '')} nick={ai.get('nick', '')}"
                elif ai["type"] == "NWT_REQ":
                    summary = f"NWT REQ seq={ai['seq_id']} op={ai['opcode']} {ai.get('subtype', '')}"
                elif ai["type"] == "NWT_ACK":
                    summary = f"NWT ACK for {ai['ack_seq_id']}"
            elif p["protocol"] == "TCP":
                summary = f"Flags=[{p.get('tcp_flags', '')}] Seq={p.get('tcp_seq')} Ack={p.get('tcp_ack')}"
            elif p["protocol"] == "UDP":
                summary = f"Len={p.get('udp_len')}"

            print(f"{p['index']:<4} {p['relative_time']:<9.4f} {p['protocol']:<5} {src:<26} {dst:<26} {p['wire_len']:<5} {summary}")

            if show_hexdump and p["payload_len"] > 0:
                raw_bytes = bytes.fromhex(p["payload_hex"])
                print(format_hexdump(raw_bytes, prefix="    "))

            if verbose and p.get("app_info") and p["app_info"].get("body", {}).get("decoded_json"):
                print("    Decoded JSON Payload:")
                json_lines = json.dumps(p["app_info"]["body"]["decoded_json"], indent=6).split("\n")
                for line in json_lines:
                    print(f"      {line}")

        print("=" * 80)


def analyze_pcap(
    filepath: str,
    filter_ip: Optional[str] = None,
    filter_port: Optional[int] = None,
    filter_proto: Optional[str] = None,
) -> Dict[str, Any]:
    """Helper function to load and analyze a PCAP file programmatically."""
    analyzer = PcapAnalyzer(filepath)
    return analyzer.load_and_analyze(
        filter_ip=filter_ip,
        filter_port=filter_port,
        filter_proto=filter_proto,
    )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="LanBridge PCAP/PCAPNG Packet Analyzer for Protocol Reverse Engineering"
    )
    parser.add_argument("pcap_path", help="Path to .pcap or .pcapng file")
    parser.add_argument("--ip", help="Filter by IP address (source or destination)")
    parser.add_argument("--port", type=int, help="Filter by TCP/UDP port (source or destination)")
    parser.add_argument("--proto", choices=["TCP", "UDP", "tcp", "udp", "OTHER", "other"], help="Filter by protocol")
    parser.add_argument("--summary", action="store_true", help="Display only summary statistics and session overviews")
    parser.add_argument("--hexdump", action="store_true", help="Print payload hex dump for each packet")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose details (e.g. decoded JSON bodies)")
    parser.add_argument("--json", dest="json_path", nargs="?", const="-", help="Export analysis result as JSON (specify file path or '-' for stdout)")

    args = parser.parse_args()

    try:
        analyzer = PcapAnalyzer(args.pcap_path)
        result = analyzer.load_and_analyze(
            filter_ip=args.ip,
            filter_port=args.port,
            filter_proto=args.proto,
        )

        if args.json_path == "-":
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.json_path:
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"[+] Successfully exported analysis JSON to: {args.json_path}")
            analyzer.print_text_report(verbose=args.verbose, show_hexdump=args.hexdump, summary_only=args.summary)
        else:
            analyzer.print_text_report(verbose=args.verbose, show_hexdump=args.hexdump, summary_only=args.summary)

    except FileNotFoundError as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Error: Unexpected failure during analysis: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
