"""Abstract object store interface.

All file content reaching this layer is already encrypted by the client-side
crypto agent. This layer never sees plaintext.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class ObjectStore(ABC):
    """Minimal interface for encrypted blob storage."""

    @abstractmethod
    def upload(self, key: str, data: bytes, metadata: dict | None = None) -> str:
        """Upload *data* under *key* and return a time-limited download URL."""

    @abstractmethod
    def download(self, key: str) -> bytes:
        """Download and return the raw bytes stored under *key*."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete the object stored under *key*. Silently ignore missing keys."""

    @abstractmethod
    def presign(self, key: str, expires_in: int = 3600) -> str:
        """Return a presigned GET URL for *key* valid for *expires_in* seconds."""
