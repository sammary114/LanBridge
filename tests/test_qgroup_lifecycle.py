#!/usr/bin/env python3
"""Tests for QGroup lifecycle management, typing state, and message recall."""

import unittest
from lanbridge.protocol.crypto import XteaEngine
from lanbridge.protocol.messages import (
    Opcode,
    build_x_qgroup_invite_envelope,
    build_x_qgroup_invite_rsp_envelope,
    build_x_qgroup_push_info_envelope,
    build_x_qgroup_push_user_envelope,
    build_x_qgroup_req_user_envelope,
    build_x_qgroup_req_user_rsp_envelope,
    build_x_qgroup_dismiss_envelope,
    build_x_qgroup_exit_envelope,
    build_x_qgroup_kick_envelope,
    build_x_qgroup_other_invite_envelope,
    build_x_send_writting_envelope,
    build_x_change_status_envelope,
    build_x_change_sign_envelope,
    build_x_recall_msg_envelope,
    extract_recall_info,
    parse_qgroup_xml,
)
from lanbridge.models import QGroup, TypingNotice, RecallNotice, Contact
from lanbridge.client import LanBridgeClient


class TestQGroupLifecycle(unittest.TestCase):
    """Test suite for QGroup信令构造、解析及客户端事件处理."""

    def setUp(self):
        self.xtea = XteaEngine()

    def test_qgroup_invite_envelope(self):
        """Test X_QGROUP_INVITE builder and parser."""
        env = build_x_qgroup_invite_envelope(
            qgroup_id="group_1234567890abcdef1234567890ab",
            name="项目架构攻坚组",
            master_id="master_user_001",
            intro="攻坚讨论",
            announcement="每日10点开会",
            version=2,
        )
        op, dec = self.xtea.parse_envelope(env)
        self.assertEqual(op, Opcode.X_QGROUP_INVITE)
        dec_str = dec.decode("utf-8")
        parsed = parse_qgroup_xml(dec_str)
        self.assertEqual(parsed["qgroup_id"], "group_1234567890abcdef1234567890ab")
        self.assertEqual(parsed["qgroup_name"], "项目架构攻坚组")
        self.assertEqual(parsed["qgroup_master"], "master_user_001")
        self.assertEqual(parsed["qgroup_intr"], "攻坚讨论")
        self.assertEqual(parsed["qgroup_ann"], "每日10点开会")
        self.assertEqual(parsed["qgroup_info_ver"], "2")

    def test_qgroup_invite_rsp_envelope(self):
        """Test X_QGROUP_INVITE_RSP builder and parser."""
        env = build_x_qgroup_invite_rsp_envelope(
            qgroup_id="group_1234567890abcdef1234567890ab",
            user_name="Alice_Engineer",
            action=1,
        )
        op, dec = self.xtea.parse_envelope(env)
        self.assertEqual(op, Opcode.X_QGROUP_INVITE_RSP)
        parsed = parse_qgroup_xml(dec.decode("utf-8"))
        self.assertEqual(parsed["qgroup_id"], "group_1234567890abcdef1234567890ab")
        self.assertEqual(parsed["user_name"], "Alice_Engineer")
        self.assertEqual(parsed["action"], "1")

    def test_qgroup_push_info_and_user_envelopes(self):
        """Test X_QGROUP_PUSH_INFO and X_QGROUP_PUSH_USER envelopes."""
        env_info = build_x_qgroup_push_info_envelope(
            qgroup_id="group_push_info_001",
            name="新组名",
            master_id="m01",
            intro="新简介",
            announcement="新公告",
            version=5,
        )
        op, dec = self.xtea.parse_envelope(env_info)
        self.assertEqual(op, Opcode.X_QGROUP_PUSH_INFO)
        p_info = parse_qgroup_xml(dec.decode("utf-8"))
        self.assertEqual(p_info["qgroup_name"], "新组名")
        self.assertEqual(p_info["qgroup_ann"], "新公告")

        env_user = build_x_qgroup_push_user_envelope(
            qgroup_id="group_push_user_001",
            name="成员同步组",
            master_id="m01",
        )
        op_u, dec_u = self.xtea.parse_envelope(env_user)
        self.assertEqual(op_u, Opcode.X_QGROUP_PUSH_USER)

    def test_qgroup_req_user_envelope_and_rsp(self):
        """Test X_QGROUP_REQ_USER and X_QGROUP_REQ_USER_RSP envelopes."""
        env_req = build_x_qgroup_req_user_envelope("group_req_001")
        op, dec = self.xtea.parse_envelope(env_req)
        self.assertEqual(op, Opcode.X_QGROUP_REQ_USER)
        parsed = parse_qgroup_xml(dec.decode("utf-8"))
        self.assertEqual(parsed["qgroup_id"], "group_req_001")

        env_rsp = build_x_qgroup_req_user_rsp_envelope("group_req_001", name="BotName", ret=0)
        op_r, dec_r = self.xtea.parse_envelope(env_rsp)
        self.assertEqual(op_r, Opcode.X_QGROUP_REQ_USER_RSP)
        p_rsp = parse_qgroup_xml(dec_r.decode("utf-8"))
        self.assertEqual(p_rsp["ret"], "0")
        self.assertEqual(p_rsp["qgroup_name"], "BotName")

    def test_qgroup_dismiss_exit_kick_other(self):
        """Test DISMISS, EXIT, KICK, and OTHER_INVITE envelopes."""
        env_dismiss = build_x_qgroup_dismiss_envelope("grp_dis")
        op_d, dec_d = self.xtea.parse_envelope(env_dismiss)
        self.assertEqual(op_d, Opcode.X_QGROUP_DISMISS)
        self.assertEqual(parse_qgroup_xml(dec_d.decode("utf-8"))["qgroup_id"], "grp_dis")

        env_exit = build_x_qgroup_exit_envelope("grp_exit")
        op_e, dec_e = self.xtea.parse_envelope(env_exit)
        self.assertEqual(op_e, Opcode.X_QGROUP_EXIT)
        self.assertEqual(parse_qgroup_xml(dec_e.decode("utf-8"))["qgroup_id"], "grp_exit")

        env_kick = build_x_qgroup_kick_envelope("grp_kick")
        op_k, dec_k = self.xtea.parse_envelope(env_kick)
        self.assertEqual(op_k, Opcode.X_QGROUP_KICK)
        self.assertEqual(parse_qgroup_xml(dec_k.decode("utf-8"))["qgroup_id"], "grp_kick")

        env_other = build_x_qgroup_other_invite_envelope("grp_other", "new_user_123")
        op_o, dec_o = self.xtea.parse_envelope(env_other)
        self.assertEqual(op_o, Opcode.X_QGROUP_OTHER_INVITE)
        p_oth = parse_qgroup_xml(dec_o.decode("utf-8"))
        self.assertEqual(p_oth["qgroup_id"], "grp_other")
        self.assertEqual(p_oth["id"], "new_user_123")

    def test_typing_state_envelope(self):
        """Test X_SEND_WRITTING typing indication."""
        env_typing = build_x_send_writting_envelope(typing=True)
        op, dec = self.xtea.parse_envelope(env_typing)
        self.assertEqual(op, Opcode.X_SEND_WRITTING)
        parsed = parse_qgroup_xml(dec.decode("utf-8"))
        self.assertEqual(parsed["param"], "1")

        env_stop = build_x_send_writting_envelope(typing=False)
        op_s, dec_s = self.xtea.parse_envelope(env_stop)
        self.assertEqual(op_s, Opcode.X_SEND_WRITTING)
        parsed_s = parse_qgroup_xml(dec_s.decode("utf-8"))
        self.assertEqual(parsed_s["param"], "0")

    def test_status_and_signature_envelopes(self):
        """Test X_CHANGE_STATUS and X_CHANGE_SIGN envelopes."""
        env_st = build_x_change_status_envelope(status=2)
        op, dec = self.xtea.parse_envelope(env_st)
        self.assertEqual(op, Opcode.X_CHANGE_STATUS)
        parsed_st = parse_qgroup_xml(dec.decode("utf-8"))
        self.assertEqual(parsed_st["status"], "2")

        env_sign = build_x_change_sign_envelope("千里之行，始于足下")
        op_s, dec_s = self.xtea.parse_envelope(env_sign)
        self.assertEqual(op_s, Opcode.X_CHANGE_SIGN)
        parsed_sign = parse_qgroup_xml(dec_s.decode("gbk"))
        self.assertEqual(parsed_sign["sign"], "千里之行，始于足下")

    def test_message_recall_direct_and_group(self):
        """Test direct chat and group chat message recall envelopes."""
        # 1. Direct Chat Recall
        env_recall_direct = build_x_recall_msg_envelope(
            target_msg_id=10086,
            target_uuid="msg_uuid_12345",
        )
        op_d, dec_d = self.xtea.parse_envelope(env_recall_direct)
        self.assertEqual(op_d, Opcode.X_SEND_MSG)
        recall_info_d = extract_recall_info(dec_d.decode("utf-8"))
        self.assertIsNotNone(recall_info_d)
        self.assertEqual(recall_info_d["target_msg_id"], 10086)
        self.assertEqual(recall_info_d["target_uuid"], "msg_uuid_12345")

        # 2. Group Chat Recall
        env_recall_grp = build_x_recall_msg_envelope(
            target_msg_id=20086,
            target_uuid="grp_msg_uuid_67890",
            qgroup_id="group_test_recall_001",
        )
        op_g, dec_g = self.xtea.parse_envelope(env_recall_grp)
        self.assertEqual(op_g, Opcode.X_QGROUP_SEND_MSG)
        recall_info_g = extract_recall_info(dec_g.decode("utf-8"))
        self.assertIsNotNone(recall_info_g)
        self.assertEqual(recall_info_g["target_msg_id"], 20086)
        self.assertEqual(recall_info_g["target_uuid"], "grp_msg_uuid_67890")

    def test_client_qgroup_and_chat_event_dispatch(self):
        """Test LanBridgeClient QGroup and typing/recall callbacks."""
        client = LanBridgeClient(user_id="test_local_bot", nickname="LocalBot")
        client.contacts["peer_u1"] = Contact(user_id="peer_u1", ip="192.168.1.100")

        # 1. Test create_qgroup locally
        qg = client.create_qgroup(name="本地测试组", intro="测试群组")
        self.assertIn(qg.qgroup_id, client.qgroups)
        self.assertEqual(client.qgroups[qg.qgroup_id].name, "本地测试组")
        self.assertEqual(client.qgroups[qg.qgroup_id].master_id, "test_local_bot")

        # 2. Test receiving X_QGROUP_INVITE
        invite_events = []
        client.on_qgroup_invite(lambda g: invite_events.append(g))
        inv_env = build_x_qgroup_invite_envelope(
            qgroup_id="inv_group_001",
            name="被邀请的群",
            master_id="peer_u1",
            intro="欢迎加入",
        )
        op, dec = self.xtea.parse_envelope(inv_env)
        replies = []
        client._process_inner_envelope(op, dec, "192.168.1.100", replies)
        self.assertEqual(len(invite_events), 1)
        self.assertEqual(invite_events[0].name, "被邀请的群")
        self.assertIn("inv_group_001", client.qgroups)

        # 3. Test receiving X_QGROUP_INVITE_RSP
        change_events = []
        client.on_qgroup_member_change(lambda g: change_events.append(g))
        rsp_env = build_x_qgroup_invite_rsp_envelope("inv_group_001", "PeerBob", action=1)
        op, dec = self.xtea.parse_envelope(rsp_env)
        client._process_inner_envelope(op, dec, "192.168.1.100", replies)
        self.assertEqual(len(change_events), 1)
        self.assertEqual(client.qgroups["inv_group_001"].members["peer_u1"], "PeerBob")

        # 4. Test typing notification
        typing_events = []
        client.on_typing(lambda tn: typing_events.append(tn))
        type_env = build_x_send_writting_envelope(typing=True)
        op, dec = self.xtea.parse_envelope(type_env)
        client._process_inner_envelope(op, dec, "192.168.1.100", replies)
        self.assertEqual(len(typing_events), 1)
        self.assertTrue(typing_events[0].is_typing)
        self.assertEqual(typing_events[0].sender_id, "peer_u1")

        # 5. Test direct recall notification
        recall_events = []
        client.on_message_recall(lambda rn: recall_events.append(rn))
        recall_env = build_x_recall_msg_envelope(target_msg_id=777, target_uuid="target_uuid_777")
        op, dec = self.xtea.parse_envelope(recall_env)
        client._process_inner_envelope(op, dec, "192.168.1.100", replies)
        self.assertEqual(len(recall_events), 1)
        self.assertEqual(recall_events[0].target_msg_id, 777)
        self.assertEqual(recall_events[0].target_uuid, "target_uuid_777")
        self.assertIsNone(recall_events[0].qgroup_id)

        # 6. Test group recall notification
        grp_recall_env = build_x_recall_msg_envelope(
            target_msg_id=888,
            target_uuid="target_uuid_888",
            qgroup_id="inv_group_001",
        )
        op, dec = self.xtea.parse_envelope(grp_recall_env)
        client._process_inner_envelope(op, dec, "192.168.1.100", replies)
        self.assertEqual(len(recall_events), 2)
        self.assertEqual(recall_events[1].target_msg_id, 888)
        self.assertEqual(recall_events[1].qgroup_id, "inv_group_001")

        # 7. Test dismiss group notification
        dismiss_events = []
        client.on_qgroup_dismiss(lambda gid: dismiss_events.append(gid))
        dis_env = build_x_qgroup_dismiss_envelope("inv_group_001")
        op, dec = self.xtea.parse_envelope(dis_env)
        client._process_inner_envelope(op, dec, "192.168.1.100", replies)
        self.assertEqual(len(dismiss_events), 1)
        self.assertEqual(dismiss_events[0], "inv_group_001")
        self.assertNotIn("inv_group_001", client.qgroups)


if __name__ == "__main__":
    unittest.main()
