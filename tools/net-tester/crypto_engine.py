#!/usr/bin/env python3
"""LanBridge Cryptographic Subsystem (crypto_engine.py).

Implements the multi-algorithm cryptographic layer reverse-engineered from
ShiYeLine.exe (offset 0x0085167e):
- Algorithm 5: none (plaintext XML)
- Algorithm 2: AES (Rijndael CBC, 16-byte block size, PKCS#7 padding)
- Algorithm 3: Blowfish (CBC/ECB, 8-byte block size)

Also provides session key and IV derivation routines (offset 0x0085d080).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional, Tuple

try:
    from Crypto.Cipher import AES, Blowfish
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger("crypto-engine")

# Default Nwt Blowfish / AES key seeds
DEFAULT_NWT_SALT = b"shiyeline_nwt_key_salt_2016"


class BlowfishEngine:
    """Blowfish symmetric cipher engine for Nwt protocol."""

    def __init__(self, key: bytes) -> None:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome (Crypto) is required for BlowfishEngine")
        # Blowfish key length must be between 4 and 56 bytes (32 to 448 bits)
        if len(key) < 4:
            key = key.ljust(4, b"\x00")
        elif len(key) > 56:
            key = key[:56]
        self.key = key

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using Blowfish ECB mode (padded to 8-byte boundary)."""
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        rem = len(plaintext) % 8
        padded = plaintext if rem == 0 else plaintext + (b"\x00" * (8 - rem))
        return cipher.encrypt(padded)

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using Blowfish ECB mode."""
        if len(ciphertext) % 8 != 0:
            raise ValueError(f"Ciphertext length ({len(ciphertext)}) must be multiple of 8")
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        return cipher.decrypt(ciphertext)

    def encrypt_cbc(self, plaintext: bytes, iv: bytes = b"\x00" * 8) -> bytes:
        """Encrypt plaintext using Blowfish CBC mode."""
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv=iv[:8])
        rem = len(plaintext) % 8
        padded = plaintext if rem == 0 else plaintext + (b"\x00" * (8 - rem))
        return cipher.encrypt(padded)

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes = b"\x00" * 8) -> bytes:
        """Decrypt ciphertext using Blowfish CBC mode."""
        if len(ciphertext) % 8 != 0:
            raise ValueError(f"Ciphertext length ({len(ciphertext)}) must be multiple of 8")
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv=iv[:8])
        return cipher.decrypt(ciphertext)


class AesEngine:
    """AES (Rijndael) symmetric cipher engine for Nwt protocol."""

    def __init__(self, key: bytes) -> None:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome (Crypto) is required for AesEngine")
        # Standard AES keys: 16 (128-bit), 24 (192-bit), or 32 (256-bit) bytes
        if len(key) not in (16, 24, 32):
            # Derive standard 16-byte key via MD5 if needed
            key = hashlib.md5(key).digest()
        self.key = key

    def encrypt_cbc(self, plaintext: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt plaintext using AES-128/256 CBC mode with PKCS#7 padding."""
        iv_bytes = iv[:16] if iv else (b"\x00" * 16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv_bytes)
        padded = pad(plaintext, 16)
        ct = cipher.encrypt(padded)
        return ct, iv_bytes

    def decrypt_cbc(self, ciphertext: bytes, iv: Optional[bytes] = None) -> bytes:
        """Decrypt ciphertext using AES-128/256 CBC mode and remove PKCS#7 padding."""
        if len(ciphertext) % 16 != 0:
            raise ValueError(f"Ciphertext length ({len(ciphertext)}) must be multiple of 16")
        iv_bytes = iv[:16] if iv else (b"\x00" * 16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv_bytes)
        decrypted = cipher.decrypt(ciphertext)
        try:
            return unpad(decrypted, 16)
        except ValueError:
            return decrypted


class NwtKeyDerivation:
    """Derives session keys and IVs matching ShiYeLine.exe crypto routines."""

    @staticmethod
    def derive_key(user_id_a: str, user_id_b: str, salt: bytes = DEFAULT_NWT_SALT) -> bytes:
        """Derive a deterministic symmetric key from two communication endpoints."""
        pair = sorted([user_id_a.lower().strip(), user_id_b.lower().strip()])
        combined = f"{pair[0]}:{pair[1]}".encode("ascii") + salt
        return hashlib.md5(combined).digest()

    @staticmethod
    def derive_blowfish_key(user_id: str, salt: bytes = DEFAULT_NWT_SALT) -> bytes:
        """Derive Blowfish key for user profile or single-user encryption."""
        return hashlib.md5(user_id.encode("ascii") + salt).digest()

    @staticmethod
    def derive_aes_key_and_iv(user_id_a: str, user_id_b: str) -> Tuple[bytes, bytes]:
        """Derive 16-byte AES key and 16-byte IV for high-security encrypted sessions."""
        pair = sorted([user_id_a.lower().strip(), user_id_b.lower().strip()])
        seed = f"{pair[0]}#{pair[1]}".encode("ascii")
        key = hashlib.md5(seed + b"_aes_key").digest()
        iv = hashlib.md5(seed + b"_aes_iv").digest()
        return key, iv


class XteaEngine:
    """XTEA (eXtended Tiny Encryption Algorithm) engine reverse-engineered from ShiYeLine.exe.
    
    Uses 32 rounds, delta = 0x9e3779b9, and hardcoded static key at offset 0x009ef1c8:
    b'8asfhj@k7*20hbla' (Hex: 38617366686a406b372a323068626c61).
    Encapsulates all native packets (X_HANDSHARK, X_READY, X_SEND_MSG, etc.).
    """

    DEFAULT_KEY = b"8asfhj@k7*20hbla"
    MASK = 0xFFFFFFFF
    DELTA = 0x9E3779B9
    DELTA_SUB = 0x61C88647 # -DELTA & MASK

    def __init__(self, key: bytes = DEFAULT_KEY) -> None:
        import struct
        self.struct = struct
        self.key_bytes = key[:16].ljust(16, b"\x00")
        k_words = list(struct.unpack("<4I", self.key_bytes))
        self.k_swapped = [self._bswap32(kw) for kw in k_words]

    @staticmethod
    def _bswap32(v: int) -> int:
        return ((v & 0xFF) << 24) | (((v >> 8) & 0xFF) << 16) | (((v >> 16) & 0xFF) << 8) | ((v >> 24) & 0xFF)

    def _encrypt_block(self, v0: int, v1: int) -> Tuple[int, int]:
        ecx = self._bswap32(v0)
        eax = self._bswap32(v1)
        edx = 0
        delta = self.DELTA
        k = self.k_swapped
        mask = self.MASK
        for _ in range(32):
            esi = edx & 3
            ebx = (k[esi] + edx) & mask
            shift = (((eax >> 5) ^ ((eax << 4) & mask)) + eax) & mask
            ebx = ebx ^ shift
            ecx = (ecx + ebx) & mask
            edx = (edx + delta) & mask

            esi = (edx >> 11) & 3
            ebx = (k[esi] + edx) & mask
            shift = (((ecx >> 5) ^ ((ecx << 4) & mask)) + ecx) & mask
            ebx = ebx ^ shift
            eax = (eax + ebx) & mask
        return self._bswap32(ecx), self._bswap32(eax)

    def _decrypt_block(self, v0: int, v1: int) -> Tuple[int, int]:
        ecx = self._bswap32(v0)
        eax = self._bswap32(v1)
        edx = 0xC6EF3720 # 32 * DELTA & MASK
        delta_sub = self.DELTA_SUB
        k = self.k_swapped
        mask = self.MASK
        while edx != 0:
            esi = (edx >> 11) & 3
            ebx = (k[esi] + edx) & mask
            shift = (((ecx >> 5) ^ ((ecx << 4) & mask)) + ecx) & mask
            ebx = ebx ^ shift
            edx = (edx + delta_sub) & mask
            eax = (eax - ebx) & mask

            esi = edx & 3
            ebx = (k[esi] + edx) & mask
            shift = (((eax >> 5) ^ ((eax << 4) & mask)) + eax) & mask
            ebx = ebx ^ shift
            ecx = (ecx - ebx) & mask
        return self._bswap32(ecx), self._bswap32(eax)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt binary data using Nwt XTEA block chaining."""
        out = bytearray()
        struct = self.struct
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            if len(block) == 8:
                v0, v1 = struct.unpack("<2I", block)
                c0, c1 = self._encrypt_block(v0, v1)
                out.extend(struct.pack("<2I", c0, c1))
            else:
                out.extend(block)
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt binary data using Nwt XTEA block chaining."""
        out = bytearray()
        struct = self.struct
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            if len(block) == 8:
                v0, v1 = struct.unpack("<2I", block)
                p0, p1 = self._decrypt_block(v0, v1)
                out.extend(struct.pack("<2I", p0, p1))
            else:
                out.extend(block)
        return bytes(out)

    def build_envelope(self, opcode: int, payload: bytes | str, encoding: str = "utf-8") -> bytes:
        """Wrap payload into native Nwt binary envelope [tot_len (4B), opcode (4B), ciphertext]."""
        if isinstance(payload, str):
            raw = payload.encode(encoding)
        else:
            raw = payload
        ciphertext = self.encrypt(raw)
        tot_len = len(ciphertext) + 8
        hdr = self.struct.pack(">2I", tot_len, opcode)
        return hdr + ciphertext

    def parse_envelope(self, data: bytes) -> Tuple[int, bytes]:
        """Parse native Nwt binary envelope, returning (opcode, decrypted_bytes)."""
        if len(data) < 8:
            raise ValueError(f"Packet too short for envelope header: {len(data)}B")
        tot_len, opcode = self.struct.unpack(">2I", data[:8])
        ciphertext = data[8:tot_len]
        plaintext = self.decrypt(ciphertext)
        return opcode, plaintext

