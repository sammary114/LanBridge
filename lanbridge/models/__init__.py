"""LanBridge Data Models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Contact:
    """Represents a discovered Nwt network contact."""

    user_id: str
    nickname: str = "Unknown"
    group: str = "内网通联系人"
    ip: str = ""
    port: int = 9012
    dynamic_port: int = 53782
    status: int = 0  # 0 = Online, 1 = Away, 2 = Busy, 3 = Offline
    guid: bytes = b""
    version: str = "#3#4#4"
    last_seen: float = 0.0

    @property
    def is_online(self) -> bool:
        return self.status != 3


@dataclass
class ChatMessage:
    """Represents an instant message exchanged with a contact."""

    msg_id: int
    sender_id: str
    recipient_id: str
    text: str
    timestamp: float
    is_image: bool = False
    image_token: Optional[int] = None
    image_md5: Optional[str] = None
    raw_xml: Optional[str] = None


@dataclass
class FileTask:
    """Represents a file or folder transfer task."""

    task_id: int
    filename: str
    filesize: int
    md5: str
    direction: str  # 'send' or 'recv'
    transferred: int = 0
    status: str = "pending"  # pending, transferring, completed, failed, rejected
    error: Optional[str] = None
