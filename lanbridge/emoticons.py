"""LanBridge Emoticons Engine: NeiWangTong (Nwt) native emoticon & Emoji mapper.

Provides bidirectional conversion between:
1. Standard Unicode Emoji characters (e.g. 😊, 👍, 🎉).
2. Nwt bracket / slash text tags (e.g. [微笑], [真棒], [庆贺]).
3. Nwt native rich text wire protocol data elements:
   {"img": {"t": "sys", "v": "1251"}} or {"img": {"t": "feihu", "v": "1251"}}
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class EmotionInfo:
    """Metadata for an Nwt native system emoticon."""

    index: int
    id: str
    tips: str
    image: str
    emoji: str


# 84 built-in system emoticons from Nwt 3.4.3055 Emotion\Emotion.xml (Group: "原创")
EMOTIONS_TABLE: List[EmotionInfo] = [
    EmotionInfo(1, "1251", "微笑", "101.gif", "😊"),
    EmotionInfo(2, "1252", "偷笑", "102.gif", "🤭"),
    EmotionInfo(3, "1253", "大笑1", "103.gif", "😄"),
    EmotionInfo(4, "1254", "调皮", "104.gif", "😜"),
    EmotionInfo(5, "1255", "憨笑", "105.gif", "😆"),
    EmotionInfo(6, "1256", "难过", "106.gif", "🙁"),
    EmotionInfo(7, "1257", "害羞", "107.gif", "😳"),
    EmotionInfo(8, "1258", "困倦", "108.gif", "🥱"),
    EmotionInfo(9, "1259", "擦汗", "109.gif", "😅"),
    EmotionInfo(10, "1260", "哭泣1", "110.gif", "😭"),
    EmotionInfo(11, "1261", "睡觉", "111.gif", "😴"),
    EmotionInfo(12, "1262", "奋斗", "112.gif", "😤"),
    EmotionInfo(13, "1263", "摆酷", "113.gif", "😎"),
    EmotionInfo(14, "1264", "疑问", "114.gif", "❓"),
    EmotionInfo(15, "1265", "晕", "115.gif", "😵"),
    EmotionInfo(16, "1266", "再见", "116.gif", "👋"),
    EmotionInfo(17, "1267", "大笑2", "201.gif", "😃"),
    EmotionInfo(18, "1268", "鼓掌1", "202.gif", "👏"),
    EmotionInfo(19, "1269", "得意", "203.gif", "😏"),
    EmotionInfo(20, "1270", "抽烟", "204.gif", "🚬"),
    EmotionInfo(21, "1271", "难受", "205.gif", "😣"),
    EmotionInfo(22, "1272", "不开心", "206.gif", "😞"),
    EmotionInfo(23, "1273", "郁闷", "207.gif", "😓"),
    EmotionInfo(24, "1274", "发脾气", "208.gif", "😡"),
    EmotionInfo(25, "1275", "发怒", "209.gif", "🤬"),
    EmotionInfo(26, "1276", "发狂", "210.gif", "😱"),
    EmotionInfo(27, "1277", "衰", "211.gif", "🤦"),
    EmotionInfo(28, "1278", "可怜", "212.gif", "🥺"),
    EmotionInfo(29, "1279", "惊讶", "213.gif", "😲"),
    EmotionInfo(30, "1280", "闭嘴", "214.gif", "🤐"),
    EmotionInfo(31, "1281", "不理你", "215.gif", "🙄"),
    EmotionInfo(32, "1282", "财迷", "216.gif", "🤑"),
    EmotionInfo(33, "1283", "囧", "217.gif", "😖"),
    EmotionInfo(34, "1284", "冷", "218.gif", "🥶"),
    EmotionInfo(35, "1285", "吐", "219.gif", "🤮"),
    EmotionInfo(36, "1286", "鄙视", "220.gif", "👎"),
    EmotionInfo(37, "1287", "查找", "221.gif", "🔍"),
    EmotionInfo(38, "1288", "色", "222.gif", "😍"),
    EmotionInfo(39, "1289", "抠鼻子", "223.gif", "🤪"),
    EmotionInfo(40, "1290", "思考", "224.gif", "🤔"),
    EmotionInfo(41, "1291", "贼贼的", "225.gif", "😈"),
    EmotionInfo(42, "1292", "认真", "226.gif", "🧐"),
    EmotionInfo(43, "1293", "哭泣2", "261.gif", "😢"),
    EmotionInfo(44, "1294", "握手", "117.gif", "🤝"),
    EmotionInfo(45, "1295", "OK", "118.gif", "👌"),
    EmotionInfo(46, "1296", "鼓掌2", "119.gif", "🙌"),
    EmotionInfo(47, "1297", "真棒", "120.gif", "👍"),
    EmotionInfo(48, "1298", "米饭", "121.gif", "🍚"),
    EmotionInfo(49, "1299", "蛋糕", "122.gif", "🍰"),
    EmotionInfo(50, "1300", "美酒", "123.gif", "🍷"),
    EmotionInfo(51, "1301", "篮球", "124.gif", "🏀"),
    EmotionInfo(52, "1302", "礼物", "125.gif", "🎁"),
    EmotionInfo(53, "1303", "邮件", "126.gif", "✉️"),
    EmotionInfo(54, "1304", "咖啡", "127.gif", "☕"),
    EmotionInfo(55, "1305", "台灯", "128.gif", "🏮"),
    EmotionInfo(56, "1306", "电话", "129.gif", "☎️"),
    EmotionInfo(57, "1307", "手机", "130.gif", "📱"),
    EmotionInfo(58, "1308", "音乐", "131.gif", "🎵"),
    EmotionInfo(59, "1309", "灯泡", "132.gif", "💡"),
    EmotionInfo(60, "1310", "时钟", "133.gif", "⏰"),
    EmotionInfo(61, "1311", "太阳", "228.gif", "☀️"),
    EmotionInfo(62, "1312", "月亮", "229.gif", "🌙"),
    EmotionInfo(63, "1313", "下雨", "230.gif", "🌧️"),
    EmotionInfo(64, "1314", "闪电", "231.gif", "⚡"),
    EmotionInfo(65, "1315", "彩虹", "232.gif", "🌈"),
    EmotionInfo(66, "1316", "雪花", "233.gif", "❄️"),
    EmotionInfo(67, "1317", "雨伞", "234.gif", "☂️"),
    EmotionInfo(68, "1318", "轿车", "235.gif", "🚗"),
    EmotionInfo(69, "1319", "苹果", "236.gif", "🍎"),
    EmotionInfo(70, "1320", "西瓜", "237.gif", "🍉"),
    EmotionInfo(71, "1321", "香蕉", "238.gif", "🍌"),
    EmotionInfo(72, "1322", "草莓", "239.gif", "🍓"),
    EmotionInfo(73, "1323", "葡萄", "240.gif", "🍇"),
    EmotionInfo(74, "1324", "蛋糕2", "241.gif", "🎂"),
    EmotionInfo(75, "1325", "饮料1", "242.gif", "🥤"),
    EmotionInfo(76, "1326", "糖", "243.gif", "🍬"),
    EmotionInfo(77, "1327", "雪糕", "244.gif", "🍦"),
    EmotionInfo(78, "1328", "饮料2", "245.gif", "🍺"),
    EmotionInfo(79, "1329", "女", "246.gif", "👧"),
    EmotionInfo(80, "1330", "男", "247.gif", "👦"),
    EmotionInfo(81, "1331", "足球", "248.gif", "⚽"),
    EmotionInfo(82, "1332", "羽毛球", "249.gif", "🏸"),
    EmotionInfo(83, "1333", "庆贺", "250.gif", "🎉"),
    EmotionInfo(84, "1334", "大便", "251.gif", "💩"),
]

# Quick lookup indexes
ID_TO_EMOTION: Dict[str, EmotionInfo] = {e.id: e for e in EMOTIONS_TABLE}
INDEX_TO_EMOTION: Dict[int, EmotionInfo] = {e.index: e for e in EMOTIONS_TABLE}
TIPS_TO_EMOTION: Dict[str, EmotionInfo] = {e.tips: e for e in EMOTIONS_TABLE}
CANONICAL_EMOJI_TO_EMOTION: Dict[str, EmotionInfo] = {e.emoji: e for e in EMOTIONS_TABLE}

# Common emoji variations and aliases mapping to Nwt emotions
EMOJI_ALIASES: Dict[str, EmotionInfo] = {
    # Smiles
    "🙂": TIPS_TO_EMOTION["微笑"],
    "😀": TIPS_TO_EMOTION["大笑1"],
    "😁": TIPS_TO_EMOTION["憨笑"],
    "😂": TIPS_TO_EMOTION["偷笑"],
    "🤣": TIPS_TO_EMOTION["大笑2"],
    "🥰": TIPS_TO_EMOTION["害羞"],
    "😘": TIPS_TO_EMOTION["色"],
    "❤️": TIPS_TO_EMOTION["色"],
    # Gestures / Celebration
    "🍻": TIPS_TO_EMOTION["饮料2"],
    "🎊": TIPS_TO_EMOTION["庆贺"],
    "✌️": TIPS_TO_EMOTION["得意"],
    "✨": TIPS_TO_EMOTION["庆贺"],
    "🌧": TIPS_TO_EMOTION["下雨"],
    "☀️": TIPS_TO_EMOTION["太阳"],
    "☕️": TIPS_TO_EMOTION["咖啡"],
    "☂": TIPS_TO_EMOTION["雨伞"],
    "✉": TIPS_TO_EMOTION["邮件"],
}

# Unified emoji mapping (canonical + aliases, sorted by length descending for regex matching)
ALL_EMOJI_MAP: Dict[str, EmotionInfo] = {**CANONICAL_EMOJI_TO_EMOTION, **EMOJI_ALIASES}
_SORTED_EMOJIS = sorted(ALL_EMOJI_MAP.keys(), key=len, reverse=True)
_EMOJI_REGEX = re.compile("|".join(re.escape(k) for k in _SORTED_EMOJIS))

# Regex for bracket / slash tags: [微笑], /微笑
_TAG_REGEX = re.compile(r"\[([a-zA-Z0-9\u4e00-\u9fa5]+)\]|/([a-zA-Z0-9\u4e00-\u9fa5]+)")


def get_emotion_by_id(emotion_id: str) -> Optional[EmotionInfo]:
    """Lookup emotion by its Nwt Id string (e.g. '1251')."""
    return ID_TO_EMOTION.get(str(emotion_id))


def get_emotion_by_index(index: int) -> Optional[EmotionInfo]:
    """Lookup emotion by 1-based index (1..84)."""
    return INDEX_TO_EMOTION.get(index)


def get_emotion_by_tips(tips: str) -> Optional[EmotionInfo]:
    """Lookup emotion by Chinese Tips name (e.g. '微笑')."""
    return TIPS_TO_EMOTION.get(tips)


def get_emotion_by_emoji(emoji_char: str) -> Optional[EmotionInfo]:
    """Lookup emotion by Unicode Emoji character (including aliases)."""
    return ALL_EMOJI_MAP.get(emoji_char)


def emoji_to_nwt_text(text: str) -> str:
    """Convert Unicode Emoji characters in text to Nwt bracket tags.

    Example:
        'Hello 😊, good job 👍!' -> 'Hello [微笑], good job [真棒]!'
    """
    if not text:
        return text

    def _replace(match: re.Match) -> str:
        emo = ALL_EMOJI_MAP.get(match.group(0))
        return f"[{emo.tips}]" if emo else match.group(0)

    return _EMOJI_REGEX.sub(_replace, text)


def nwt_text_to_emoji(text: str) -> str:
    """Convert Nwt bracket or slash tags in text to standard Unicode Emojis.

    Example:
        'Hello [微笑], good job [真棒]!' -> 'Hello 😊, good job 👍!'
        'Bye /再见' -> 'Bye 👋'
    """
    if not text:
        return text

    def _replace(match: re.Match) -> str:
        tag = match.group(1) or match.group(2)
        emo = TIPS_TO_EMOTION.get(tag)
        return emo.emoji if emo else match.group(0)

    return _TAG_REGEX.sub(_replace, text)


def emoji_to_nwt_dt(text: str) -> List[Dict[str, Any]]:
    """Parse text containing emojis into native Nwt rich text 'dt' blocks.

    Emoticons are emitted as native Nwt system image nodes:
        {"img": {"t": "sys", "v": "1251"}}
    Plain text is emitted as normal text nodes:
        {"txt": {"t": "normal", "v": "..."}}

    Example:
        'Hi 😊 good 👍' ->
        [
            {"txt": {"t": "normal", "v": "Hi "}},
            {"img": {"t": "sys", "v": "1251"}},
            {"txt": {"t": "normal", "v": " good "}},
            {"img": {"t": "sys", "v": "1297"}}
        ]
    """
    if not text:
        return [{"txt": {"t": "normal", "v": ""}}]

    dt: List[Dict[str, Any]] = []
    last_idx = 0

    for match in _EMOJI_REGEX.finditer(text):
        start, end = match.span()
        if start > last_idx:
            dt.append({"txt": {"t": "normal", "v": text[last_idx:start]}})

        matched_char = match.group(0)
        emo = ALL_EMOJI_MAP.get(matched_char)
        if emo:
            dt.append({"img": {"t": "sys", "v": emo.id}})
        else:
            dt.append({"txt": {"t": "normal", "v": matched_char}})
        last_idx = end

    if last_idx < len(text):
        dt.append({"txt": {"t": "normal", "v": text[last_idx:]}})

    return dt if dt else [{"txt": {"t": "normal", "v": ""}}]


def nwt_dt_to_emoji_text(dt_list: List[Dict[str, Any]]) -> str:
    """Convert an incoming Nwt 'dt' block list into clean text with Unicode Emojis.

    Handles:
    - {"img": {"t": "sys", "v": "1251"}} or {"img": {"t": "feihu", "v": "1251"}} -> '😊'
    - {"txt": {"v": "..."}} or {"txt": {"t": "normal", "v": "..."}}
      with optional embedded [Tips] tags -> converted to Emojis.
    """
    parts: List[str] = []
    for item in dt_list:
        if "txt" in item:
            txt_obj = item["txt"]
            val = txt_obj.get("v", "") if isinstance(txt_obj, dict) else str(txt_obj)
            parts.append(nwt_text_to_emoji(val))
        elif "img" in item:
            img_obj = item["img"]
            if isinstance(img_obj, dict):
                img_t = img_obj.get("t", "")
                img_v = str(img_obj.get("v", ""))
                if img_t in ("sys", "feihu"):
                    # Look up by ID or by Index
                    emo = ID_TO_EMOTION.get(img_v)
                    if not emo and img_v.isdigit():
                        emo = INDEX_TO_EMOTION.get(int(img_v))
                    parts.append(emo.emoji if emo else f"[{img_v}]")
                else:
                    parts.append("[图片]")
            else:
                parts.append("[图片]")
        elif "retrieve" in item:
            parts.append("[撤回消息]")

    return "".join(parts)
