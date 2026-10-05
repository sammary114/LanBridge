"""Unit tests for LanBridge Minimal Active Network Verification Tool (net-tester).
"""

from __future__ import annotations

import os
import sys
import unittest

# Ensure tools/ are on python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
TESTER_DIR = os.path.join(PROJECT_ROOT, "tools", "net-tester")
ANALYZER_DIR = os.path.join(PROJECT_ROOT, "tools", "pcap-analyzer")

for d in (TESTER_DIR, ANALYZER_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from tester import (  # noqa: E402
    build_ack_response,
    build_encapsulated_discovery,
    build_handshake_reply,
    build_ipmsg_packet,
    build_ipmsg_recv_ack,
    build_ipmsg_send_msg,
    build_multi_ack_response,
    build_native_profile,
    build_nwt_discovery_packet,
    build_opcode_01,
    build_opcode_84,
    build_opcode_88_fragments,
    build_opcode_8a,
    build_x_heartbeat_envelope,
    build_x_input_state,
    build_x_msg_ack,
    build_x_ready_envelope,
    build_x_send_msg,
    build_x_send_msg_ack_envelope,
    build_x_send_msg_envelope,
    build_x_flash_screen_envelope,
    build_x_operate_recv_file_envelope,
    build_x_operate_send_file_envelope,
    build_x_progress_recv_file_envelope,
    build_x_recall_msg_envelope,
    build_x_send_image_envelope,
    build_minifile_response,
    build_minifile_chunk,
    parse_minifile_packet,
    extract_chat_message,
)
from crypto_engine import (  # noqa: E402
    AesEngine,
    BlowfishEngine,
    NwtKeyDerivation,
    XteaEngine,
)
from enet_protocol import (  # noqa: E402
    ENetProtocolSession,
)
from analyzer import (  # noqa: E402
    parse_ipmsg_payload,
    parse_nwt_discovery_payload,
    parse_nwt_udp_payload,
)


class TestNetTester(unittest.TestCase):
    """Test suite for packet builders, responders, and crypto engines in net-tester."""

    def test_build_nwt_discovery_packet(self) -> None:
        """Verify construction of the 304-byte Nwt discovery packet."""
        user_id = "testuser000000000000000000000001"
        bcast_ip = "172.31.127.255"
        pkt = build_nwt_discovery_packet(
            cmd=1,
            user_id=user_id,
            broadcast_ip=bcast_ip,
            dynamic_port=53782,
        )

        # 1. Total length must be strictly 304 bytes
        self.assertEqual(len(pkt), 304)

        # 2. Offset 0x00 ~ 0x03: length declaration
        self.assertEqual(pkt[:4], b"\x00\x00\x01\x30")

        # 3. Offset 0x04 ~ 0x07: Cmd 1
        self.assertEqual(int.from_bytes(pkt[4:8], "big"), 1)

        # 4. Offset 0x0C ~ 0x0F: Magic
        self.assertEqual(pkt[12:16], bytes.fromhex("5fc1d8ec"))

        # 5. Offset 0x14 ~ 0x17: Directed broadcast IP
        self.assertEqual(pkt[20:24], bytes([172, 31, 127, 255]))

        # 6. Offset 0x18 ~ 0x1D: Version #3#4#4
        self.assertEqual(pkt[24:30], b"#3#4#4")

        # 7. Offset 0x1E ~ 0x3D: User ID
        self.assertEqual(pkt[30:62].decode("ascii"), user_id)

        # 8. Offset 0xA4 ~ 0xA7: Dynamic port
        self.assertEqual(int.from_bytes(pkt[165:167], "big"), 53782)

        # 9. Verify decodable by analyzer.py
        decoded = parse_nwt_discovery_payload(pkt)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["command"], "DiscoveryBroadcast")
        self.assertEqual(decoded["user_id"], user_id)
        self.assertEqual(decoded["dynamic_port"], 53782)
        self.assertEqual(decoded["broadcast_ip"], bcast_ip)

    def test_build_ipmsg_packet_standard(self) -> None:
        """Verify construction of standard UDP 2425 IPMSG packet (without @shiyeline)."""
        nick = "LanBridge-Bot"
        group = "内网通联系人"
        pkt = build_ipmsg_packet(
            command=1,
            packet_no=8888,
            user="Tester",
            host="HOST",
            nick=nick,
            group=group,
            use_shiyeline_prefix=False,
        )

        self.assertTrue(pkt.startswith(b"1:"))
        self.assertNotIn(b"@shiyeline", pkt)
        self.assertIn(b":8888:Tester:HOST:1:LanBridge-Bot\x00", pkt)

        decoded = parse_ipmsg_payload(pkt)
        self.assertIsNotNone(decoded)
        self.assertIn("BR_ENTRY", decoded["cmd_name"])
        self.assertEqual(decoded["nick"], nick)
        self.assertEqual(decoded["group"], group)

    def test_build_ipmsg_packet_shiyeline(self) -> None:
        """Verify construction of ShiYeLine proprietary IPMSG packet (with @shiyeline)."""
        user_id = "testuser000000000000000000000001"
        nick = "LanBridge-Test"
        pkt = build_ipmsg_packet(
            command=1,
            packet_no=8888,
            user="Tester",
            host="HOST",
            nick=nick,
            user_id=user_id,
            use_shiyeline_prefix=True,
        )

        self.assertTrue(pkt.startswith(b"1@shiyeline:"))
        self.assertIn(b":8888:Tester:HOST:1:LanBridge-Test\x00", pkt)

        decoded = parse_ipmsg_payload(pkt)
        self.assertIsNotNone(decoded)
        self.assertIn("BR_ENTRY", decoded["cmd_name"])
        self.assertEqual(decoded["nick"], nick)
        self.assertEqual(decoded["user_id"], user_id)

    def test_build_opcode_88_fragments(self) -> None:
        """Verify splitting and formatting of Opcode 0x88 UDP fragments."""
        payload = b"X" * 1490
        frags = build_opcode_88_fragments(payload, seq=0xf88f, base_sub_id=2, max_frag_size=1372)

        self.assertEqual(len(frags), 2)
        # Fragment 0: 28B header + 1372B data = 1400B
        self.assertEqual(len(frags[0]), 1400)
        self.assertEqual(frags[0][:2], b"\x90\x00")
        self.assertEqual(frags[0][2:4], b"\xf8\x8f")
        self.assertEqual(frags[0][4:6], b"\x88\x00")
        self.assertEqual(frags[0][6:8], b"\x00\x02")
        self.assertEqual(frags[0][8:10], b"\x00\x02")
        self.assertEqual(int.from_bytes(frags[0][12:16], "big"), 2)
        self.assertEqual(int.from_bytes(frags[0][16:20], "big"), 0)
        self.assertEqual(int.from_bytes(frags[0][20:24], "big"), 1490)

        # Fragment 1: 28B header + 118B data = 146B
        self.assertEqual(len(frags[1]), 146)
        self.assertEqual(frags[1][6:8], b"\x00\x03")
        self.assertEqual(int.from_bytes(frags[1][16:20], "big"), 1)

        parsed_frag0 = parse_nwt_udp_payload(frags[0])
        self.assertIsNotNone(parsed_frag0)
        self.assertEqual(parsed_frag0["opcode"], "0x88")
        self.assertEqual(parsed_frag0["total_frags"], 2)
        self.assertEqual(parsed_frag0["frag_idx"], 0)

    def test_build_multi_ack_response(self) -> None:
        """Verify construction of 18-byte MultiACK for Opcode 0x88 fragments."""
        seq_bytes = b"\x32\x81"
        ack = build_multi_ack_response(seq_bytes, b"\x00\x01", b"\x00\x02")
        self.assertEqual(len(ack), 18)
        self.assertEqual(ack[:2], b"\x10\x00")
        self.assertEqual(ack[2:4], b"\x01\x00")
        self.assertEqual(ack[4:6], b"\x00\x01")
        self.assertEqual(ack[8:10], seq_bytes)
        self.assertEqual(ack[10:12], b"\x01\x00")
        self.assertEqual(ack[12:14], b"\x00\x02")
        self.assertEqual(ack[16:18], seq_bytes)

        parsed = parse_nwt_udp_payload(ack)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["type"], "NWT_ACK")
        self.assertEqual(parsed["total_len"], 18)

    def test_build_ack_response_heartbeat(self) -> None:
        """Verify ACK response for Opcode 0x85 Heartbeat against real capture bytes."""
        req = bytes.fromhex("8000ef5885ff0004")
        expected_ack = bytes.fromhex("000001ff00040004ef58")

        ack = build_ack_response(req)
        self.assertEqual(ack, expected_ack)

        parsed = parse_nwt_udp_payload(ack)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["type"], "NWT_ACK")
        self.assertEqual(parsed["ack_seq_id"], "0xef58")

    def test_build_ack_response_data(self) -> None:
        """Verify ACK response for Opcode 0x86 Data transfer against real capture bytes."""
        req = bytes.fromhex("80009c7e86000006002200000022000003f8d529c5439de045c9d3dc11866769e1fedfa896e8e704a5532f3e")
        expected_ack = bytes.fromhex("00000100000600069c7e")

        ack = build_ack_response(req)
        self.assertEqual(ack, expected_ack)

    def test_build_ipmsg_send_msg(self) -> None:
        """Verify construction of IPMSG_SENDMSG text message."""
        msg = "Hello from LanBridge Bot!"
        pkt = build_ipmsg_send_msg(message=msg, packet_no=1002, need_check=True)
        self.assertTrue(pkt.startswith(b"1:1002:LanBridge:HOST-BOT:288:"))
        self.assertIn(msg.encode("gbk"), pkt)

        decoded = parse_ipmsg_payload(pkt)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["command"], "288")
        self.assertEqual(decoded["nick"], msg)

    def test_build_ipmsg_recv_ack(self) -> None:
        """Verify construction of IPMSG_RECVMSG delivery receipt ACK."""
        pkt = build_ipmsg_recv_ack(packet_no_ack="1002", packet_no=1003)
        self.assertEqual(pkt, b"1:1003:LanBridge:HOST-BOT:33:1002\x00")

        decoded = parse_ipmsg_payload(pkt)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["command"], "33")
        self.assertEqual(decoded["nick"], "1002")

    def test_build_opcode_01(self) -> None:
        """Verify construction of Opcode 0x01 channel synchronization packet."""
        pkt = build_opcode_01(echo_seq=b"\x30\xed", seq=0xf7c6)
        expected = bytes.fromhex("9000f7c601ff0001000130ed85ff0002")
        self.assertEqual(pkt, expected)
        self.assertEqual(len(pkt), 16)

    def test_build_opcode_84(self) -> None:
        """Verify construction of Opcode 0x84 auxiliary channel synchronization packet."""
        pkt = build_opcode_84(seq=0xf8f4)
        expected = bytes.fromhex("9000f8f484ff000200000000")
        self.assertEqual(pkt, expected)
        self.assertEqual(len(pkt), 12)

    def test_build_opcode_8a(self) -> None:
        """Verify construction of Opcode 0x8a HandshakeFinal packet."""
        pkt = build_opcode_8a(seq=0xfa87)
        expected = bytes.fromhex("9000fa878aff00030000000000000000")
        self.assertEqual(pkt, expected)
        self.assertEqual(len(pkt), 16)

    def test_build_x_send_msg(self) -> None:
        """Verify construction of native Nwt X_SEND_MSG (0x3ec) XML payload envelope."""
        msg = "Test native message"
        payload = build_x_send_msg(msg, msg_id=12345, timestamp=1600000000)
        self.assertEqual(payload[4:8], (0x03EC).to_bytes(4, "big"))
        total_len = int.from_bytes(payload[:4], "big")
        self.assertEqual(total_len, len(payload))
        self.assertIn(b"<X_SEND_MSG><MSG_ID>12345</MSG_ID>", payload)
        self.assertIn(b"<RECEIPT>1</RECEIPT>", payload)
        self.assertIn(b"<MSG>Test native message</MSG>", payload)
        self.assertIn(b"</X_SEND_MSG>", payload)

    def test_build_x_input_state(self) -> None:
        """Verify construction of 78B typing indicator frame."""
        pkt = build_x_input_state(seq=0xea51)
        self.assertEqual(len(pkt), 78)
        self.assertEqual(pkt[:2], b"\x80\x00")
        self.assertEqual(pkt[2:4], b"\xea\x51")
        self.assertEqual(pkt[4], 0x86)
        self.assertEqual(pkt[16:18], b"\x03\xf0")  # Subtype 1008

    def test_build_x_msg_ack(self) -> None:
        """Verify construction of 80B delivery receipt frame."""
        pkt = build_x_msg_ack(seq=0xb5c3)
        self.assertEqual(len(pkt), 80)
        self.assertEqual(pkt[:2], b"\x80\x00")
        self.assertEqual(pkt[2:4], b"\xb5\xc3")
        self.assertEqual(pkt[4], 0x86)
        self.assertEqual(pkt[16:18], b"\x03\xed")  # Subtype 1005

    def test_blowfish_engine_roundtrip(self) -> None:
        """Verify Blowfish ECB and CBC encryption/decryption roundtrip."""
        key = b"LanBridgeSecretKey123"
        engine = BlowfishEngine(key)

        # ECB Mode (multiples of 8 bytes)
        plaintext = b"HelloNwtBlowfish"
        ct_ecb = engine.encrypt_ecb(plaintext)
        self.assertEqual(len(ct_ecb), len(plaintext))
        self.assertNotEqual(ct_ecb, plaintext)
        pt_dec_ecb = engine.decrypt_ecb(ct_ecb)
        self.assertEqual(pt_dec_ecb, plaintext)

        # CBC Mode
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        ct_cbc = engine.encrypt_cbc(plaintext, iv=iv)
        self.assertEqual(len(ct_cbc), len(plaintext))
        self.assertNotEqual(ct_cbc, ct_ecb)
        pt_dec_cbc = engine.decrypt_cbc(ct_cbc, iv=iv)
        self.assertEqual(pt_dec_cbc, plaintext)

    def test_aes_engine_roundtrip(self) -> None:
        """Verify AES CBC encryption/decryption roundtrip with PKCS#7 padding."""
        key = b"0123456789abcdef"
        engine = AesEngine(key)

        msg = b"Native Nwt AES-encrypted payload verification test string."
        ct, iv = engine.encrypt_cbc(msg)
        self.assertEqual(len(ct) % 16, 0)
        self.assertNotEqual(ct, msg)

        pt_dec = engine.decrypt_cbc(ct, iv=iv)
        self.assertEqual(pt_dec, msg)

    def test_nwt_key_derivation(self) -> None:
        """Verify deterministic key derivation from user identifiers."""
        uid_a = "2158b475dfcfdd43989482c4dcf0337b"
        uid_b = "3b9d1aadecebe74f8ea1cb3af56538fc"

        # Symmetrical derivation (order of arguments does not change result)
        key_1 = NwtKeyDerivation.derive_key(uid_a, uid_b)
        key_2 = NwtKeyDerivation.derive_key(uid_b, uid_a)
        self.assertEqual(key_1, key_2)
        self.assertEqual(len(key_1), 16)

        # AES Key and IV derivation
        aes_k, aes_iv = NwtKeyDerivation.derive_aes_key_and_iv(uid_a, uid_b)
        self.assertEqual(len(aes_k), 16)
        self.assertEqual(len(aes_iv), 16)
        self.assertNotEqual(aes_k, aes_iv)

    def test_xtea_engine_roundtrip(self) -> None:
        """Verify XTEA 32-round block cipher roundtrip encryption and decryption."""
        engine = XteaEngine()
        data = b"Hello, this is a native Nwt XTEA encryption verification test string."
        ct = engine.encrypt(data)
        self.assertNotEqual(ct, data)
        self.assertEqual(len(ct), len(data))
        pt = engine.decrypt(ct)
        self.assertEqual(pt, data)

    def test_xtea_envelope_handling(self) -> None:
        """Verify packing and unpacking of native binary envelopes with XTEA."""
        engine = XteaEngine()
        test_xml = '<X_TEST docver="1"><VAL>测试文本</VAL></X_TEST>'
        envelope = engine.build_envelope(0x03EC, test_xml)

        self.assertGreaterEqual(len(envelope), 8)
        tot_len = int.from_bytes(envelope[:4], "big")
        self.assertEqual(tot_len, len(envelope))
        op = int.from_bytes(envelope[4:8], "big")
        self.assertEqual(op, 0x03EC)

        parsed_op, dec_bytes = engine.parse_envelope(envelope)
        self.assertEqual(parsed_op, 0x03EC)
        self.assertEqual(dec_bytes.decode("utf-8"), test_xml)

    def test_build_native_profile(self) -> None:
        """Verify dynamic native profile generation produces valid X_HANDSHARK."""
        engine = XteaEngine()
        profile_env = build_native_profile(nick="UnitTest-Bot", user_id="1234567890abcdef1234567890abcdef")
        self.assertGreater(len(profile_env), 500)

        op, dec_bytes = engine.parse_envelope(profile_env)
        self.assertEqual(op, 0x03E8)
        xml = dec_bytes.decode("utf-8")
        self.assertIn('<NAME>UnitTest-Bot</NAME>', xml)
        self.assertIn('<STATUS>0</STATUS>', xml)
        self.assertIn('<X_HANDSHARK', xml)

    def test_build_x_send_msg_envelope(self) -> None:
        """Verify native text message envelope contains expected JSON payload."""
        engine = XteaEngine()
        msg_env = build_x_send_msg_envelope("Hello World!", msg_id=42)
        op, dec_bytes = engine.parse_envelope(msg_env)
        self.assertEqual(op, 0x03EC)
        xml = dec_bytes.decode("utf-8")
        self.assertIn('<MSG_ID>42</MSG_ID>', xml)
        self.assertIn('&quot;v&quot;&nbsp;:&nbsp;&quot;Hello&nbsp;World!&quot;', xml)

    def test_extract_chat_message(self) -> None:
        """Verify robust extraction and entity unescaping of native chat messages."""
        engine = XteaEngine()
        chinese_msg = "你好！我是 LanBridge 原生接入机器人，已成功上线！"
        msg_env = build_x_send_msg_envelope(chinese_msg, msg_id=101)
        _, dec_bytes = engine.parse_envelope(msg_env)
        extracted = extract_chat_message(dec_bytes.decode("utf-8"))
        self.assertEqual(extracted, chinese_msg)

    def test_enet_protocol_session(self) -> None:
        """Verify ENet protocol session formatting, connect packet, and fragment building."""
        session = ENetProtocolSession()
        session.session_id = 2
        session.peer_id = 3

        hdr = session.get_header(has_sent_time=True)
        self.assertEqual(len(hdr), 4)
        h_val, sent_time = int.from_bytes(hdr[:2], "big"), int.from_bytes(hdr[2:4], "big")
        self.assertTrue(bool(h_val & 0x8000))
        self.assertEqual((h_val >> 12) & 3, 2)
        self.assertEqual(h_val & 0x0FFF, 3)

        # Test connect packet
        cid = b"\x12\x34\x56\x78"
        conn_pkt = session.build_connect(cid)
        self.assertEqual(len(conn_pkt), 52)
        self.assertEqual(conn_pkt[4], 0x82)
        self.assertIn(cid, conn_pkt)

        # Test fragmentation
        big_data = b"X" * 3000
        frags = session.build_fragments(channel=0, payload=big_data, max_chunk=1372)
        self.assertEqual(len(frags), 3)  # 1372 + 1372 + 256 = 3000

    def test_build_x_flash_screen_envelope(self) -> None:
        """Verify window shake / flash screen envelope generation (Opcode 0x03ef)."""
        engine = XteaEngine()
        env = build_x_flash_screen_envelope(shake_type=0)
        op, dec_bytes = engine.parse_envelope(env)
        self.assertEqual(op, 0x03EF)
        xml = dec_bytes.decode("utf-8")
        self.assertIn('<X_SEND_FLASH_SCREEN docver="1">', xml)
        self.assertIn('<TYPE>0</TYPE>', xml)

    def test_build_x_file_operation_envelopes(self) -> None:
        """Verify file receive, send, and progress envelopes."""
        engine = XteaEngine()

        # 1. Recv file accept (0x03f3)
        recv_env = build_x_operate_recv_file_envelope(task_id=987654321, op=1)
        op, dec = engine.parse_envelope(recv_env)
        self.assertEqual(op, 0x03F3)
        self.assertIn('<TASK_ID>987654321</TASK_ID>', dec.decode("utf-8"))
        self.assertIn('<OP>1</OP>', dec.decode("utf-8"))

        # 2. Send file cancel (0x03f2)
        send_env = build_x_operate_send_file_envelope(task_id=987654321, op=1)
        op, dec = engine.parse_envelope(send_env)
        self.assertEqual(op, 0x03F2)
        self.assertIn('<X_OPERATE_SEND_FILE', dec.decode("utf-8"))

        # 3. Progress sync (0x03f4)
        prog_env = build_x_progress_recv_file_envelope(task_id=987654321, total_size=1000, recvd_size=500, speed="2.0MB/s")
        op, dec = engine.parse_envelope(prog_env)
        self.assertEqual(op, 0x03F4)
        self.assertIn('<SPEED>2.0MB/s</SPEED>', dec.decode("utf-8"))

    def test_build_x_recall_msg_envelope(self) -> None:
        """Verify message recall envelope (Opcode 0x03ec, type 6)."""
        engine = XteaEngine()
        recall_env = build_x_recall_msg_envelope(target_msg_id=42, target_uuid="uuid-12345")
        op, dec = engine.parse_envelope(recall_env)
        self.assertEqual(op, 0x03EC)
        xml = dec.decode("utf-8")
        self.assertIn('&quot;type&quot;&nbsp;:&nbsp;&quot;6&quot;', xml)
        self.assertIn('&quot;t&quot;&nbsp;:&nbsp;&quot;recall&quot;', xml)
        self.assertIn('&quot;target_id&quot;&nbsp;:&nbsp;&quot;uuid-12345&quot;', xml)

    def test_build_x_send_image_envelope(self) -> None:
        """Verify inline image envelope generation (Opcode 0x03ec, feihu format)."""
        engine = XteaEngine()
        test_md5 = "d66e6ae5761641b65764b7d183ff7169"
        env = build_x_send_image_envelope(img_md5=test_md5, token=12345, caption="Test Image")
        op, dec = engine.parse_envelope(env)
        self.assertEqual(op, 0x03EC)
        xml = dec.decode("utf-8")
        self.assertIn('&quot;t&quot;&nbsp;:&nbsp;&quot;feihu&quot;', xml)
        self.assertIn(f'12345|{test_md5}', xml)
        self.assertIn('Test&nbsp;Image', xml)

    def test_minifile_protocol_roundtrip(self) -> None:
        """Verify Mini-File Command 2 (Response), Command 3 (Chunk), and parser roundtrip."""
        test_md5 = "d66e6ae5761641b65764b7d183ff7169"
        file_size = 53201

        # 1. Test Command 2 Response
        rsp = build_minifile_response(test_md5, file_size, status=0)
        self.assertEqual(len(rsp), 356)
        parsed_rsp = parse_minifile_packet(rsp)
        self.assertIsNotNone(parsed_rsp)
        self.assertEqual(parsed_rsp["cmd"], 2)
        self.assertEqual(parsed_rsp["status"], 0)
        self.assertEqual(parsed_rsp["md5"], test_md5)
        self.assertEqual(parsed_rsp["file_size"], file_size)

        # 2. Test Command 3 Data Chunk
        sample_data = b"JFIF_IMAGE_BYTES_12345"
        chunk_pkt = build_minifile_chunk(file_size, offset=100, chunk_data=sample_data)
        self.assertEqual(len(chunk_pkt), len(sample_data) + 0x98)
        parsed_chk = parse_minifile_packet(chunk_pkt)
        self.assertIsNotNone(parsed_chk)
        self.assertEqual(parsed_chk["cmd"], 3)
        self.assertEqual(parsed_chk["file_size"], file_size)
        self.assertEqual(parsed_chk["offset"], 100)
        self.assertEqual(parsed_chk["chunk_len"], len(sample_data))
        self.assertEqual(parsed_chk["chunk_data"], sample_data)


if __name__ == "__main__":
    unittest.main()


