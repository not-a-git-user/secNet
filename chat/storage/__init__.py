"""Cloud object store factory.

Set FILE_STORE_BACKEND to one of: s3, azure, gcp, r2
"""
from __future__ import annotations

import os

from .base import ObjectStore


def get_store() -> ObjectStore:
    backend = os.environ.get("FILE_STORE_BACKEND", "s3").lower()
    if backend == "s3":
        from .s3_store import S3Store
        return S3Store()
    if backend == "azure":
        from .azure_store import AzureStore
        return AzureStore()
    if backend == "gcp":
        from .gcp_store import GCPStore  # noqa: F401
        return GCPStore()
    if backend == "r2":
        from .r2_store import R2Store  # noqa: F401
        return R2Store()
    raise ValueError(f"Unknown FILE_STORE_BACKEND: {backend!r}. Choose s3, azure, gcp, or r2.")


__all__ = ["ObjectStore", "get_store"]
