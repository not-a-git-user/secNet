"""AWS S3 object store backend.

Required environment variables:
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_REGION          (default: us-east-1)
    S3_BUCKET_NAME
"""
from __future__ import annotations

import os

import boto3
from botocore.exceptions import ClientError

from .base import ObjectStore


class S3Store(ObjectStore):
    def __init__(self):
        region = os.environ.get("AWS_REGION", "us-east-1")
        self._bucket = os.environ["S3_BUCKET_NAME"]
        
        # If keys are missing, boto3 automatically uses the EC2 instance IAM role
        ak = os.environ.get("AWS_ACCESS_KEY_ID")
        sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
        
        if ak and sk:
            self._client = boto3.client(
                "s3",
                region_name=region,
                aws_access_key_id=ak,
                aws_secret_access_key=sk,
            )
        else:
            self._client = boto3.client("s3", region_name=region)

    def upload(self, key: str, data: bytes, metadata: dict | None = None) -> str:
        extra: dict = {"StorageClass": "ONEZONE_IA"}
        if metadata:
            # S3 metadata values must be strings
            extra["Metadata"] = {k: str(v) for k, v in metadata.items()}
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data, **extra)
        return self.presign(key)

    def download(self, key: str) -> bytes:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
            return response["Body"].read()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchKey":
                raise FileNotFoundError(f"S3 key not found: {key}") from exc
            raise

    def delete(self, key: str) -> None:
        try:
            self._client.delete_object(Bucket=self._bucket, Key=key)
        except ClientError:
            pass

    def presign(self, key: str, expires_in: int = 3600) -> str:
        return self._client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=expires_in,
        )
