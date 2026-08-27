"""Azure Blob Storage backend.

Required environment variables:
    AZURE_STORAGE_CONNECTION_STRING
    AZURE_CONTAINER_NAME
"""
from __future__ import annotations

import datetime
import os

from azure.storage.blob import (
    BlobServiceClient,
    BlobSasPermissions,
    generate_blob_sas,
)

from .base import ObjectStore


class AzureStore(ObjectStore):
    def __init__(self):
        conn_str = os.environ["AZURE_STORAGE_CONNECTION_STRING"]
        self._container = os.environ["AZURE_CONTAINER_NAME"]
        self._service = BlobServiceClient.from_connection_string(conn_str)
        self._container_client = self._service.get_container_client(self._container)
        # Ensure container exists (idempotent)
        try:
            self._container_client.create_container()
        except Exception:
            pass  # Already exists

    def upload(self, key: str, data: bytes, metadata: dict | None = None) -> str:
        blob_client = self._container_client.get_blob_client(key)
        blob_client.upload_blob(
            data,
            overwrite=True,
            metadata={k: str(v) for k, v in (metadata or {}).items()},
        )
        return self.presign(key)

    def download(self, key: str) -> bytes:
        blob_client = self._container_client.get_blob_client(key)
        try:
            return blob_client.download_blob().readall()
        except Exception as exc:
            raise FileNotFoundError(f"Azure blob not found: {key}") from exc

    def delete(self, key: str) -> None:
        try:
            self._container_client.get_blob_client(key).delete_blob()
        except Exception:
            pass

    def presign(self, key: str, expires_in: int = 3600) -> str:
        account = self._service.account_name
        account_key = self._service.credential.account_key
        expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
        sas_token = generate_blob_sas(
            account_name=account,
            container_name=self._container,
            blob_name=key,
            account_key=account_key,
            permission=BlobSasPermissions(read=True),
            expiry=expiry,
        )
        return (
            f"https://{account}.blob.core.windows.net"
            f"/{self._container}/{key}?{sas_token}"
        )
