"""Automated unit and integration tests for LanBridge PCAP Analyzer.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

# Ensure tools/pcap-analyzer is on the import path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
ANALYZER_DIR = os.path.join(PROJECT_ROOT, "tools", "pcap-analyzer")
if ANALYZER_DIR not in sys.path:
    sys.path.insert(0, ANALYZER_DIR)

from analyzer import PcapAnalyzer, analyze_pcap  # noqa: E402


class TestPcapAnalyzer(unittest.TestCase):
    """Test suite for PcapAnalyzer."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.nwt_pcap = os.path.join(PROJECT_ROOT, "captures", "nwt.pcapng")
        cls.synth_pcap = os.path.join(PROJECT_ROOT, "tests", "fixtures", "synthetic.pcap")
        cls.cli_script = os.path.join(ANALYZER_DIR, "analyzer.py")

    def test_synthetic_fixture_analysis(self) -> None:
        """Test analyzing synthetic fixture PCAP file."""
        analyzer = PcapAnalyzer(self.synth_pcap)
        result = analyzer.load_and_analyze()

        summary = result["summary"]
        self.assertEqual(summary["total_packets"], 3)
        self.assertEqual(summary["filtered_packets"], 3)
        self.assertEqual(summary["protocols"].get("TCP"), 2)
        self.assertEqual(summary["protocols"].get("UDP"), 1)
        self.assertEqual(len(result["tcp_streams"]), 1)
        self.assertEqual(len(result["udp_flows"]), 1)

    def test_nwt_pcapng_overall_statistics(self) -> None:
        """Test overall statistics on the real captures/nwt.pcapng capture."""
        self.assertTrue(os.path.exists(self.nwt_pcap), f"Capture file missing: {self.nwt_pcap}")
        analyzer = PcapAnalyzer(self.nwt_pcap)
        result = analyzer.load_and_analyze()

        summary = result["summary"]
        self.assertEqual(summary["total_packets"], 49)
        self.assertEqual(summary["filtered_packets"], 49)
        self.assertEqual(summary["protocols"]["TCP"], 39)
        self.assertEqual(summary["protocols"]["UDP"], 10)
        self.assertAlmostEqual(summary["duration_seconds"], 40.9473, places=2)

        # Endpoints validation
        expected_endpoints = {
            "172.31.112.1",
            "172.31.122.254",
            "20.184.175.2",
            "204.79.197.203",
            "47.57.13.180",
        }
        self.assertEqual(set(summary["endpoints"]), expected_endpoints)

        # Streams count
        self.assertEqual(len(result["tcp_streams"]), 4)
        self.assertEqual(len(result["udp_flows"]), 1)

    def test_filter_by_ip(self) -> None:
        """Test filtering packets by IP address."""
        # 172.31.112.1 only communicates via UDP with 172.31.122.254 (10 packets)
        res_host = analyze_pcap(self.nwt_pcap, filter_ip="172.31.112.1")
        self.assertEqual(res_host["summary"]["filtered_packets"], 10)

        # 47.57.13.180 participates in Stream 1 (7 pkts) and Stream 4 (2 pkts) = 9 pkts
        res_ext = analyze_pcap(self.nwt_pcap, filter_ip="47.57.13.180")
        self.assertEqual(res_ext["summary"]["filtered_packets"], 9)

    def test_filter_by_port(self) -> None:
        """Test filtering packets by port number."""
        res_9012 = analyze_pcap(self.nwt_pcap, filter_port=9012)
        self.assertEqual(res_9012["summary"]["filtered_packets"], 10)
        for pkt in res_9012["packets"]:
            self.assertIn(9012, (pkt["src_port"], pkt["dst_port"]))

        res_80 = analyze_pcap(self.nwt_pcap, filter_port=80)
        # Port 80 has Stream 1 (7 pkts) + Stream 3 (9 pkts) + Stream 4 (2 pkts) = 18 pkts
        self.assertEqual(res_80["summary"]["filtered_packets"], 18)

    def test_filter_by_proto(self) -> None:
        """Test filtering packets by protocol."""
        res_udp = analyze_pcap(self.nwt_pcap, filter_proto="UDP")
        self.assertEqual(res_udp["summary"]["filtered_packets"], 10)
        for pkt in res_udp["packets"]:
            self.assertEqual(pkt["protocol"], "UDP")

        res_tcp = analyze_pcap(self.nwt_pcap, filter_proto="TCP")
        self.assertEqual(res_tcp["summary"]["filtered_packets"], 39)
        for pkt in res_tcp["packets"]:
            self.assertEqual(pkt["protocol"], "TCP")

    def test_udp_nwt_protocol_decoding(self) -> None:
        """Verify parsing of Nwt binary UDP protocol frames on port 9012."""
        res = analyze_pcap(self.nwt_pcap, filter_port=9012)
        pkts = res["packets"]
        self.assertEqual(len(pkts), 10)

        # Packet 8: Request seq 0x9c7e, opcode 0x86, length 44
        p8 = pkts[0]
        self.assertEqual(p8["index"], 8)
        self.assertEqual(p8["wire_len"], 86)
        self.assertEqual(p8["payload_len"], 44)
        ai8 = p8["app_info"]
        self.assertIsNotNone(ai8)
        self.assertEqual(ai8["type"], "NWT_REQ")
        self.assertEqual(ai8["seq_id"], "0x9c7e")
        self.assertEqual(ai8["opcode"], "0x86")
        self.assertEqual(ai8["subtype"], "Data/Exchange")
        self.assertEqual(ai8["inner_len"], 34)

        # Packet 9: ACK for seq 0x9c7e
        p9 = pkts[1]
        self.assertEqual(p9["index"], 9)
        self.assertEqual(p9["payload_len"], 10)
        ai9 = p9["app_info"]
        self.assertEqual(ai9["type"], "NWT_ACK")
        self.assertEqual(ai9["ack_seq_id"], "0x9c7e")

        # Packet 10: Heartbeat request seq 0xef58, opcode 0x85, length 8
        p10 = pkts[2]
        self.assertEqual(p10["index"], 10)
        self.assertEqual(p10["payload_len"], 8)
        ai10 = p10["app_info"]
        self.assertEqual(ai10["type"], "NWT_REQ")
        self.assertEqual(ai10["seq_id"], "0xef58")
        self.assertEqual(ai10["opcode"], "0x85")
        self.assertEqual(ai10["subtype"], "Heartbeat/Ping")

        # Packet 11: ACK for seq 0xef58
        p11 = pkts[3]
        self.assertEqual(p11["index"], 11)
        ai11 = p11["app_info"]
        self.assertEqual(ai11["type"], "NWT_ACK")
        self.assertEqual(ai11["ack_seq_id"], "0xef58")

    def test_tcp_http_report_decoding(self) -> None:
        """Verify parsing of HTTP POST /api/report.php telemetry payload."""
        res = analyze_pcap(self.nwt_pcap, filter_port=55778)
        pkts = res["packets"]
        p4 = next(p for p in pkts if p["index"] == 4)

        ai = p4["app_info"]
        self.assertIsNotNone(ai)
        self.assertEqual(ai["type"], "HTTP")
        self.assertEqual(ai["first_line"], "POST /api/report.php HTTP/1.1")
        self.assertEqual(ai["headers"].get("Host"), "report.51nwt.com")

        # Verify decoded telemetry JSON body
        json_body = ai["body"].get("decoded_json")
        self.assertIsNotNone(json_body)
        self.assertEqual(json_body["app"], "syl")
        self.assertEqual(json_body["build num"], "3055")
        self.assertEqual(json_body["corp id"], "296becfde55172409ef2b81908044747")
        self.assertEqual(json_body["ip"], "172.31.122.254")

    def test_tcp_tls_sni_decoding(self) -> None:
        """Verify parsing of TLS ClientHello SNI in Microsoft telemetry stream."""
        res = analyze_pcap(self.nwt_pcap, filter_port=55779)
        pkts = res["packets"]
        p17 = next(p for p in pkts if p["index"] == 17)

        ai = p17["app_info"]
        self.assertIsNotNone(ai)
        self.assertEqual(ai["type"], "TLS")
        self.assertEqual(ai["handshake_type"], "ClientHello")
        self.assertEqual(ai.get("sni"), "mobile.events.data.microsoft.com")

    def test_discovery_trigger_pcapng(self) -> None:
        """Verify analysis of 02-discovery-trigger.pcapng (status toggle capture)."""
        dt_pcap = os.path.join(PROJECT_ROOT, "captures", "02-discovery-trigger.pcapng")
        if not os.path.exists(dt_pcap):
            return
        res = analyze_pcap(dt_pcap)
        summary = res["summary"]
        self.assertEqual(summary["total_packets"], 8)
        self.assertEqual(summary["protocols"].get("UDP"), 6)
        self.assertEqual(summary["protocols"].get("OTHER"), 2)

        # Check status update frame 1 (len 82 payload)
        p1 = res["packets"][0]
        self.assertEqual(p1["index"], 1)
        self.assertEqual(p1["wire_len"], 124)
        ai1 = p1["app_info"]
        self.assertIsNotNone(ai1)
        self.assertEqual(ai1["type"], "NWT_REQ")
        self.assertEqual(ai1["opcode"], "0x86")
        self.assertEqual(ai1["subtype"], "Status/StateUpdate")
        self.assertEqual(ai1["data_len"], 66)

    def test_text_message_pcapng(self) -> None:
        """Verify analysis of 04-text-message.pcapng (text message capture)."""
        msg_pcap = os.path.join(PROJECT_ROOT, "captures", "04-text-message.pcapng")
        if not os.path.exists(msg_pcap):
            return
        res = analyze_pcap(msg_pcap)
        summary = res["summary"]
        self.assertEqual(summary["total_packets"], 11)
        self.assertEqual(summary["protocols"].get("UDP"), 9)

        # Check Opcode 0x88 Fragment 1
        p3 = res["packets"][2]
        self.assertEqual(p3["index"], 3)
        ai3 = p3["app_info"]
        self.assertIsNotNone(ai3)
        self.assertEqual(ai3["type"], "NWT_REQ")
        self.assertEqual(ai3["opcode"], "0x88")
        self.assertEqual(ai3["total_frags"], 2)
        self.assertEqual(ai3["frag_idx"], 0)
        self.assertEqual(ai3["total_msg_len"], 1519)
        self.assertEqual(ai3["frag_len"], 1372)

        # Check Opcode 0x88 Fragment 2
        p4 = res["packets"][3]
        ai4 = p4["app_info"]
        self.assertEqual(ai4["opcode"], "0x88")
        self.assertEqual(ai4["frag_idx"], 1)
        self.assertEqual(ai4["frag_len"], 147)

        # Check MsgAck
        p6 = res["packets"][5]
        ai6 = p6["app_info"]
        self.assertEqual(ai6["opcode"], "0x86")
        self.assertEqual(ai6["subtype"], "MsgAck/Receipt")

    def test_sandbox_discovery_pcapng(self) -> None:
        """Verify analysis of 03-sandbox-discovery.pcapng (cold start discovery capture)."""
        disc_pcap = os.path.join(PROJECT_ROOT, "captures", "03-sandbox-discovery.pcapng")
        if not os.path.exists(disc_pcap):
            return
        res = analyze_pcap(disc_pcap)
        summary = res["summary"]
        self.assertEqual(summary["total_packets"], 166)
        self.assertEqual(summary["protocols"].get("UDP"), 76)
        self.assertEqual(summary["protocols"].get("TCP"), 64)

        # Check Frame 1: Nwt 9011 DiscoveryBroadcast
        p1 = res["packets"][0]
        ai1 = p1["app_info"]
        self.assertIsNotNone(ai1)
        self.assertEqual(ai1["type"], "NWT_DISCOVERY_9011")
        self.assertEqual(ai1["command"], "DiscoveryBroadcast")
        self.assertEqual(ai1["version"], "#3#4#4")
        self.assertEqual(ai1["user_id"], "3b9d1aadecebe74f8ea1cb3af56538fc")
        self.assertEqual(ai1["dynamic_port"], 62916)

        # Check Frame 3: IPMSG BR_ENTRY on port 2425
        p3 = res["packets"][2]
        ai3 = p3["app_info"]
        self.assertIsNotNone(ai3)
        self.assertEqual(ai3["type"], "IPMSG")
        self.assertIn("BR_ENTRY", ai3["cmd_name"])
        self.assertEqual(ai3["user"], "WDAGUtilit")
        self.assertEqual(ai3["nick"], "B070939D-A")

        # Check Frame 5: Nwt 9011 DiscoveryReply
        p5 = res["packets"][4]
        ai5 = p5["app_info"]
        self.assertIsNotNone(ai5)
        self.assertEqual(ai5["type"], "NWT_DISCOVERY_9011")
        self.assertEqual(ai5["command"], "DiscoveryReply")
        self.assertEqual(ai5["user_id"], "2158b475dfcfdd43989482c4dcf0337b")
        self.assertEqual(ai5["dynamic_port"], 53782)

        # Check Frame 23: Opcode 0x88 Profile Fragment
        p23 = res["packets"][22]
        ai23 = p23["app_info"]
        self.assertIsNotNone(ai23)
        self.assertEqual(ai23["type"], "NWT_REQ")
        self.assertEqual(ai23["opcode"], "0x88")
        self.assertEqual(ai23["total_frags"], 2)
        self.assertIn("Profile/Handshark", ai23["subtype"])

    def test_nonexistent_file_error(self) -> None:
        """Verify clear FileNotFoundError on missing file."""
        with self.assertRaises(FileNotFoundError):
            PcapAnalyzer("this_file_does_not_exist_at_all.pcap")

    def test_empty_file_error(self) -> None:
        """Verify clear ValueError on 0-byte file."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf_name = tf.name
        try:
            with self.assertRaises(ValueError) as ctx:
                PcapAnalyzer(tf_name)
            self.assertIn("empty", str(ctx.exception).lower())
        finally:
            if os.path.exists(tf_name):
                os.remove(tf_name)

    def test_corrupt_file_error(self) -> None:
        """Verify clear ValueError on corrupt capture file."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"NOT_A_VALID_PCAP_HEADER_DATA_12345")
            tf_name = tf.name
        try:
            analyzer = PcapAnalyzer(tf_name)
            with self.assertRaises(ValueError) as ctx:
                analyzer.load_and_analyze()
            self.assertIn("unable to parse", str(ctx.exception).lower())
        finally:
            import gc
            gc.collect()
            if os.path.exists(tf_name):
                try:
                    os.remove(tf_name)
                except OSError:
                    pass

    def test_cli_execution(self) -> None:
        """Test invoking the analyzer via CLI subprocess."""
        cmd = [sys.executable, self.cli_script, self.nwt_pcap, "--summary"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("LanBridge PCAP Analyzer", proc.stdout)
        self.assertIn("Packets:    49 displayed", proc.stdout)

    def test_cli_json_export(self) -> None:
        """Test exporting JSON via CLI."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tf:
            json_out = tf.name
        try:
            cmd = [sys.executable, self.cli_script, self.nwt_pcap, "--json", json_out]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(os.path.exists(json_out))

            with open(json_out, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["summary"]["total_packets"], 49)
            self.assertEqual(len(data["tcp_streams"]), 4)
            self.assertEqual(len(data["udp_flows"]), 1)
        finally:
            if os.path.exists(json_out):
                os.remove(json_out)


if __name__ == "__main__":
    unittest.main()
