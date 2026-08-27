"""Authenticated encryption and session-key derivation."""

import hashlib
import os
import struct
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SUPPORTED_CIPHERS = ("aes-256-gcm", "chacha20-poly1305")
_NONCE_PREFIX = b"VPN1"


def derive_aes_key(shared_secret: bytes, info: bytes = b"vpn session") -> bytes:
    """Compatibility helper retained for callers of the original project."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def derive_session_keys(
    shared_secret: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    transcript_hash: bytes,
) -> tuple[bytes, bytes]:
    """Derive independent client->server and server->client keys."""
    salt = hashlib.sha256(b"vpn session salt v1" + client_nonce + server_nonce).digest()
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"vpn session keys v1" + transcript_hash,
    ).derive(shared_secret)
    return material[:32], material[32:]


def _make_aead(cipher: str, key: bytes):
    if len(key) != 32:
        raise ValueError("session keys must be 32 bytes")
    if cipher == "aes-256-gcm":
        return AESGCM(key)
    if cipher == "chacha20-poly1305":
        return ChaCha20Poly1305(key)
    raise ValueError(f"unsupported cipher: {cipher}")


class SessionCipher:
    """One ordered, authenticated direction of a VPN session.

    Each direction has a separate key and monotonically increasing counter.
    TCP preserves ordering, so rejecting a counter other than the next one
    also gives the data channel basic replay and reordering protection.
    """

    def __init__(self, key: bytes, cipher: str):
        self._aead = _make_aead(cipher, key)
        self._send_sequence = 0
        self._receive_sequence = 0
        self._send_lock = threading.Lock()

    @staticmethod
    def _nonce(sequence: int) -> bytes:
        return _NONCE_PREFIX + struct.pack("!Q", sequence)

    @staticmethod
    def _aad(sequence: int) -> bytes:
        return b"vpn-record-v1" + struct.pack("!Q", sequence)

    def encrypt(self, plaintext: bytes) -> bytes:
        with self._send_lock:
            sequence = self._send_sequence
            self._send_sequence += 1
            encrypted = self._aead.encrypt(
                self._nonce(sequence), plaintext, self._aad(sequence)
            )
            return struct.pack("!Q", sequence) + encrypted

    def decrypt(self, encrypted: bytes) -> bytes:
        if len(encrypted) < 8 + 16:
            raise ValueError("encrypted record is too short")
        sequence = struct.unpack("!Q", encrypted[:8])[0]
        if sequence != self._receive_sequence:
            raise ValueError(
                f"unexpected record sequence {sequence}; "
                f"expected {self._receive_sequence}"
            )
        plaintext = self._aead.decrypt(
            self._nonce(sequence),
            encrypted[8:],
            self._aad(sequence),
        )
        self._receive_sequence += 1
        return plaintext


def encryptPacket(packet: bytes, key: bytes, cipher: str = "aes-256-gcm") -> bytes:
    """Legacy random-nonce record format for compatibility.

    New connections use SessionCipher.  Keeping this function avoids
    breaking small scripts that imported the original helper.
    """
    nonce = os.urandom(12)
    encrypted = _make_aead(cipher, key).encrypt(nonce, packet, None)
    return nonce + encrypted


def decryptPacket(
    encrypted: bytes, key: bytes, cipher: str = "aes-256-gcm"
) -> bytes:
    if len(encrypted) < 12 + 16:
        raise ValueError("encrypted packet too short")
    nonce = encrypted[:12]
    return _make_aead(cipher, key).decrypt(nonce, encrypted[12:], None)
