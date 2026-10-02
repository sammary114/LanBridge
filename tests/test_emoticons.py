"""Unit tests for LanBridge Emoticons Engine (lanbridge/emoticons.py)."""

from __future__ import annotations

import unittest
from lanbridge.emoticons import (
    EMOTIONS_TABLE,
    ID_TO_EMOTION,
    INDEX_TO_EMOTION,
    TIPS_TO_EMOTION,
    emoji_to_nwt_dt,
    emoji_to_nwt_text,
    get_emotion_by_emoji,
    get_emotion_by_id,
    get_emotion_by_index,
    get_emotion_by_tips,
    nwt_dt_to_emoji_text,
    nwt_text_to_emoji,
)


class TestEmoticonsEngine(unittest.TestCase):
    """Test suite for Nwt native emoticon & Emoji mapper."""

    def test_table_integrity(self) -> None:
        """Verify the 84 standard emotions from Nwt Emotion.xml."""
        self.assertEqual(len(EMOTIONS_TABLE), 84)

        indices = [e.index for e in EMOTIONS_TABLE]
        self.assertEqual(indices, list(range(1, 85)))

        ids = [e.id for e in EMOTIONS_TABLE]
        self.assertEqual(len(set(ids)), 84)
        self.assertEqual(ids[0], "1251")
        self.assertEqual(ids[-1], "1334")

        tips = [e.tips for e in EMOTIONS_TABLE]
        self.assertEqual(len(set(tips)), 84)
        self.assertIn("微笑", tips)
        self.assertIn("真棒", tips)
        self.assertIn("庆贺", tips)
        self.assertIn("大便", tips)

    def test_lookups(self) -> None:
        """Test lookup helpers by ID, Index, Tips, and Emoji."""
        # By ID
        e1 = get_emotion_by_id("1251")
        self.assertIsNotNone(e1)
        assert e1 is not None
        self.assertEqual(e1.tips, "微笑")
        self.assertEqual(e1.emoji, "😊")
        self.assertEqual(e1.image, "101.gif")

        # By Index
        e47 = get_emotion_by_index(47)
        self.assertIsNotNone(e47)
        assert e47 is not None
        self.assertEqual(e47.tips, "真棒")
        self.assertEqual(e47.emoji, "👍")

        # By Tips
        e_bye = get_emotion_by_tips("再见")
        self.assertIsNotNone(e_bye)
        assert e_bye is not None
        self.assertEqual(e_bye.id, "1266")
        self.assertEqual(e_bye.emoji, "👋")

        # By Emoji (canonical & alias)
        self.assertEqual(get_emotion_by_emoji("😊"), e1)
        self.assertEqual(get_emotion_by_emoji("🙂"), e1)  # alias
        self.assertEqual(get_emotion_by_emoji("👍"), e47)
        self.assertIsNone(get_emotion_by_emoji("🦄"))  # unmapped

    def test_emoji_to_nwt_text(self) -> None:
        """Test converting Unicode Emojis in text to bracket tags."""
        self.assertEqual(emoji_to_nwt_text(""), "")
        self.assertEqual(emoji_to_nwt_text("Hello World!"), "Hello World!")
        self.assertEqual(emoji_to_nwt_text("Hello 😊!"), "Hello [微笑]!")
        self.assertEqual(emoji_to_nwt_text("干得漂亮 👍"), "干得漂亮 [真棒]")
        self.assertEqual(emoji_to_nwt_text("测试 🙂 和 😄"), "测试 [微笑] 和 [大笑1]")
        self.assertEqual(emoji_to_nwt_text("连续表情: 😊👍🎉"), "连续表情: [微笑][真棒][庆贺]")

    def test_nwt_text_to_emoji(self) -> None:
        """Test converting Nwt bracket & slash tags to Unicode Emojis."""
        self.assertEqual(nwt_text_to_emoji(""), "")
        self.assertEqual(nwt_text_to_emoji("Hello World!"), "Hello World!")
        self.assertEqual(nwt_text_to_emoji("收到 [微笑]"), "收到 😊")
        self.assertEqual(nwt_text_to_emoji("赞 [真棒] 庆祝 [庆贺]"), "赞 👍 庆祝 🎉")
        self.assertEqual(nwt_text_to_emoji("斜杠语法 /再见"), "斜杠语法 👋")
        # Unknown tags should remain unchanged
        self.assertEqual(nwt_text_to_emoji("未知标签 [未知] 保持原样"), "未知标签 [未知] 保持原样")

    def test_emoji_to_nwt_dt(self) -> None:
        """Test converting text with Emojis to native Nwt 'dt' array."""
        # Empty text
        self.assertEqual(emoji_to_nwt_dt(""), [{"txt": {"t": "normal", "v": ""}}])

        # Plain text
        dt1 = emoji_to_nwt_dt("纯文本消息")
        self.assertEqual(dt1, [{"txt": {"t": "normal", "v": "纯文本消息"}}])

        # Single emoji
        dt2 = emoji_to_nwt_dt("😊")
        self.assertEqual(dt2, [{"img": {"t": "sys", "v": "1251"}}])

        # Mixed text + emojis
        dt3 = emoji_to_nwt_dt("你好 😊，点赞 👍！")
        self.assertEqual(
            dt3,
            [
                {"txt": {"t": "normal", "v": "你好 "}},
                {"img": {"t": "sys", "v": "1251"}},
                {"txt": {"t": "normal", "v": "，点赞 "}},
                {"img": {"t": "sys", "v": "1297"}},
                {"txt": {"t": "normal", "v": "！"}},
            ],
        )

        # Alias emoji
        dt4 = emoji_to_nwt_dt("加油 🙂")
        self.assertEqual(
            dt4,
            [
                {"txt": {"t": "normal", "v": "加油 "}},
                {"img": {"t": "sys", "v": "1251"}},
            ],
        )

    def test_nwt_dt_to_emoji_text(self) -> None:
        """Test converting incoming Nwt 'dt' array to Emoji-embedded text."""
        # Sys image by ID
        dt1 = [
            {"txt": {"t": "normal", "v": "你好 "}},
            {"img": {"t": "sys", "v": "1251"}},
            {"txt": {"t": "normal", "v": " 欢迎 "}},
            {"img": {"t": "sys", "v": "1333"}},
        ]
        self.assertEqual(nwt_dt_to_emoji_text(dt1), "你好 😊 欢迎 🎉")

        # Sys image by Index
        dt2 = [{"img": {"t": "sys", "v": "47"}}]
        self.assertEqual(nwt_dt_to_emoji_text(dt2), "👍")

        # Feihu type (sent by real Nwt clients)
        dt_feihu = [
            {"img": {"t": "feihu", "v": "1252"}},
            {"txt": {"t": "normal", "v": "114514"}},
            {"img": {"t": "feihu", "v": "1317"}},
        ]
        self.assertEqual(nwt_dt_to_emoji_text(dt_feihu), "🤭114514☂️")

        # Embedded bracket tag inside txt
        dt3 = [{"txt": {"t": "normal", "v": "好样的 [真棒] 辛苦啦"}}]
        self.assertEqual(nwt_dt_to_emoji_text(dt3), "好样的 👍 辛苦啦")

        # Custom image wire format: <id>|<md5>
        dt_custom_img = [
            {"img": {"t": "feihu", "v": "16513|a69b587dfc63672f1d95eb3ee303b5d1"}},
            {"txt": {"t": "normal", "v": "图片文本"}},
        ]
        self.assertEqual(nwt_dt_to_emoji_text(dt_custom_img), "[图片]图片文本")

    def test_roundtrip(self) -> None:
        """Test end-to-end roundtrip conversion."""
        origin = "项目顺利上线！🎉 辛苦大家了 👏 喝杯咖啡 ☕"
        dt = emoji_to_nwt_dt(origin)
        recovered = nwt_dt_to_emoji_text(dt)
        self.assertEqual(recovered, origin)


if __name__ == "__main__":
    unittest.main()
