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
    qgroup_id: Optional[str] = None


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


@dataclass
class GroupSharedFile:
    """Represents a file actively shared inside a group."""

    file_id: str
    qgroup_id: str
    filename: str
    filesize: int
    file_md5: str
    uploader_id: str
    uploader_name: str
    uploader_ip: str
    share_port: int = 2442
    created_time: float = 0.0
    pwd_protect: bool = False
    local_path: Optional[str] = None
    is_cached: bool = False
    last_accessed: float = 0.0
    is_pinned: bool = False

    def is_expired(self, ttl_seconds: float, current_time: Optional[float] = None) -> bool:
        """Check if the cached file has passed its retention TTL."""
        if self.is_pinned:
            return False
        import time
        now = current_time if current_time is not None else time.time()
        ref_time = self.last_accessed if self.last_accessed > 0 else self.created_time
        return (now - ref_time) > ttl_seconds

