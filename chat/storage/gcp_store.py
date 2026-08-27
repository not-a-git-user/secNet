"""GCP Cloud Storage backend — NOT YET IMPLEMENTED.

TODO: Implement GCP Cloud Storage backend.

Steps to implement:
    1. pip install google-cloud-storage
    2. Set GOOGLE_APPLICATION_CREDENTIALS to your service account JSON path
    3. Set GCP_BUCKET_NAME to your bucket name
    4. Replace this stub with a real implementation using google.cloud.storage.Client

Required environment variables (when implemented):
    GOOGLE_APPLICATION_CREDENTIALS   Path to service account JSON key file
    GCP_BUCKET_NAME                   GCS bucket name
"""
from .base import ObjectStore


class GCPStore(ObjectStore):
    def __init__(self):
        raise NotImplementedError(
            "GCP Cloud Storage backend is not yet implemented. "
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
