#!/usr/bin/env python3
"""LanBridge Cryptographic Subsystem (crypto.py).

Implements the authentic 32-round XTEA block cipher reverse-engineered from
ShiYeLine.exe, used for all native encrypted envelope communication on UDP 9012.
Also provides utility functions for GBK string encoding and padding.
"""

import struct
from typing import Tuple

# Hardcoded 128-bit XTEA key reverse-engineered from ShiYeLine.exe binary
# Reference: 0x00401000 - Capstone disassembly & live packet decryption verified
DEFAULT_XTEA_KEY: bytes = b'8asfhj@k7*20hbla'
XTEA_ROUNDS: int = 32
XTEA_DELTA: int = 0x9E3779B9
XTEA_MASK: int = 0xFFFFFFFF


def _parse_key(key: bytes) -> Tuple[int, int, int, int]:
    """Parse 16-byte key into four 32-bit unsigned little-endian integers."""
    if len(key) != 16:
        raise ValueError(f"XTEA key must be exactly 16 bytes, got {len(key)}")
    return struct.unpack("<4I", key)


def xtea_encrypt_block(v0: int, v1: int, k: Tuple[int, int, int, int], rounds: int = XTEA_ROUNDS) -> Tuple[int, int]:
    """Encrypt a single 64-bit block (v0, v1) using 32-round XTEA."""
    sum_val = 0
    for _ in range(rounds):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + k[sum_val & 3]))) & XTEA_MASK
        sum_val = (sum_val + XTEA_DELTA) & XTEA_MASK
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + k[(sum_val >> 11) & 3]))) & XTEA_MASK
    return v0, v1


def xtea_decrypt_block(v0: int, v1: int, k: Tuple[int, int, int, int], rounds: int = XTEA_ROUNDS) -> Tuple[int, int]:
    """Decrypt a single 64-bit block (v0, v1) using 32-round XTEA."""
    sum_val = (XTEA_DELTA * rounds) & XTEA_MASK
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + k[(sum_val >> 11) & 3]))) & XTEA_MASK
        sum_val = (sum_val - XTEA_DELTA) & XTEA_MASK
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + k[sum_val & 3]))) & XTEA_MASK
    return v0, v1


class XTEACipher:
    """XTEA 32-round ECB/CBC block cipher for LanBridge / NeiWangTong protocol."""

    def __init__(self, key: bytes = DEFAULT_XTEA_KEY):
        self.key = key
        self.k = _parse_key(key)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt arbitrary byte stream with zero-padding to 8-byte boundary."""
        pad_len = (8 - (len(data) % 8)) % 8
        padded = data + b"\x00" * pad_len
        out = bytearray(len(padded))
        for i in range(0, len(padded), 8):
            v0, v1 = struct.unpack_from("<2I", padded, i)
            ev0, ev1 = xtea_encrypt_block(v0, v1, self.k)
            struct.pack_into("<2I", out, i, ev0, ev1)
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt ciphertext.

        Input length must be a multiple of 8.
        """
        if len(data) % 8 != 0:
            raise ValueError(f"Ciphertext length must be multiple of 8, got {len(data)}")
        out = bytearray(len(data))
        for i in range(0, len(data), 8):
            v0, v1 = struct.unpack_from("<2I", data, i)
            dv0, dv1 = xtea_decrypt_block(v0, v1, self.k)
            struct.pack_into("<2I", out, i, dv0, dv1)
        return bytes(out)

    def decrypt_envelope(self, payload: bytes) -> Tuple[int, bytes]:
        """Decrypt a 6-byte headed native envelope (2B Opcode + 4B Length + Ciphertext).

        Returns:
            (opcode, decrypted_plain_bytes)
        """
        if len(payload) < 6:
            raise ValueError(f"Envelope payload too short: {len(payload)} bytes")
        opcode, data_len = struct.unpack_from("<HI", payload, 0)
        ciphertext = payload[6:]
        plain = self.decrypt(ciphertext)
        return opcode, plain[:data_len]

    def encrypt_envelope(self, opcode: int, plain_data: bytes) -> bytes:
        """Pack and encrypt plain data into a native envelope.

        Header: 2B Opcode (little endian) + 4B Data Length (little endian). Body:
        XTEA-encrypted bytes.
        """
        data_len = len(plain_data)
        ciphertext = self.encrypt(plain_data)
        return struct.pack("<HI", opcode, data_len) + ciphertext
