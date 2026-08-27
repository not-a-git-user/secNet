"""Cloudflare R2 backend — NOT YET IMPLEMENTED.

TODO: Implement Cloudflare R2 backend (S3-compatible API).

Steps to implement:
    1. pip install boto3  (already in requirements — R2 uses S3-compatible API)
    2. Set the env vars below
    3. Replace this stub with a boto3 client pointed at the R2 endpoint:
       endpoint_url = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

Required environment variables (when implemented):
    R2_ACCOUNT_ID          Cloudflare account ID
    R2_ACCESS_KEY_ID       R2 API token (access key)
    R2_SECRET_ACCESS_KEY   R2 API token (secret)
    R2_BUCKET_NAME         R2 bucket name
"""
from .base import ObjectStore


class R2Store(ObjectStore):
    def __init__(self):
        raise NotImplementedError(
            "Cloudflare R2 backend is not yet implemented. "
            "Set FILE_STORE_BACKEND=s3 or FILE_STORE_BACKEND=azure instead."
        )

    def upload(self, key, data, metadata=None):
        raise NotImplementedError

    def download(self, key):
        raise NotImplementedError

    def delete(self, key):
        raise NotImplementedError

    def presign(self, key, expires_in=3600):
        raise NotImplementedError
