"""Persistent device identity primitives used by the VPN and chat layers."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


DEVICE_AUTH_CONTEXT = b"vpn1 device authentication v1\0"


def _tag_from_random() -> str:
    return "dev-" + base64.b32encode(secrets.token_bytes(8)).decode("ascii").rstrip("=").lower()


class DeviceIdentity:
    """An Ed25519 identity persisted on the client device.

    The file contains only the raw 32-byte private seed and is created with
    restrictive permissions.  The public key fingerprint, rather than an IP
    address or username, is the stable device identifier.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        path: Path | None = None,
        direct_private_key: X25519PrivateKey | None = None,
    ):
        self.private_key = private_key
        self.path = path
        self.direct_private_key = direct_private_key or X25519PrivateKey.generate()

    @classmethod
    def load_or_create(cls, path: str | os.PathLike[str]) -> "DeviceIdentity":
        key_path = Path(path).expanduser()
        key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if key_path.exists():
            raw = key_path.read_bytes()
            if len(raw) != 32:
                raise ValueError(f"device key must contain a 32-byte seed: {key_path}")
            private_key = Ed25519PrivateKey.from_private_bytes(raw)
        else:
            private_key = Ed25519PrivateKey.generate()
            raw = private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            descriptor = os.open(key_path, flags, 0o600)
            try:
                os.write(descriptor, raw)
            finally:
                os.close(descriptor)
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
        direct_path = key_path.with_name(key_path.name + ".direct")
        if direct_path.exists():
            direct_raw = direct_path.read_bytes()
            if len(direct_raw) != 32:
                raise ValueError(f"direct encryption key must contain 32 bytes: {direct_path}")
            direct_private = X25519PrivateKey.from_private_bytes(direct_raw)
        else:
            direct_private = X25519PrivateKey.generate()
            direct_raw = direct_private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            descriptor = os.open(direct_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, direct_raw)
            finally:
                os.close(descriptor)
        try:
            direct_path.chmod(0o600)
        except OSError:
            pass
        return cls(private_key, key_path, direct_private)

    @property
    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def device_id(self) -> str:
        return hashlib.sha256(self.public_key_bytes).hexdigest()

    @property
    def direct_public_key_bytes(self) -> bytes:
        return self.direct_private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(DEVICE_AUTH_CONTEXT + message)

    def export_public_key(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode("ascii")


def verify_device_signature(public_key_bytes: bytes, message: bytes, signature: bytes):
    if len(public_key_bytes) != 32:
        raise ValueError("device public key must be 32 bytes")
    Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
        signature, DEVICE_AUTH_CONTEXT + message
    )


class InMemoryDeviceDirectory:
    """Small adapter used by tests and local development.

    Production uses the Kafka-backed directory in ``chat/kafka_backend.py``.
    """

    def __init__(self):
        self._records: dict[str, dict] = {}

    def register_or_get(self, public_key_bytes: bytes, encryption_public_key: bytes | None = None) -> str:
        device_id = hashlib.sha256(public_key_bytes).hexdigest()
        record = self._records.get(device_id)
        if record:
            return record["device_tag"]
        tag = _tag_from_random()
        self._records[device_id] = {
            "device_id": device_id,
            "device_tag": tag,
            "public_key": base64.b64encode(public_key_bytes).decode("ascii"),
            "encryption_public_key": base64.b64encode(encryption_public_key or b"").decode("ascii"),
            "username": None,
        }
        return tag

    def get(self, device_id: str) -> dict | None:
        return self._records.get(device_id)
