"""
MinIO object storage backend for encrypted files.

Wraps the minio SDK so the rest of the app only calls
upload_file / download_file / delete_file.
"""

import io
import os

from minio import Minio
from minio.error import S3Error


class MinioStorage:
    def __init__(self):
        endpoint = os.environ.get("MINIO_ENDPOINT")
        if not endpoint:
            raise RuntimeError("MINIO_ENDPOINT is not set")

        self._bucket = os.environ.get("MINIO_BUCKET", "argus-encrypted-files")
        use_ssl = os.environ.get("MINIO_USE_SSL", "false").lower() == "true"

        # Client creation is local-only — no network call happens here.
        self._client = Minio(
            endpoint,
            access_key=os.environ.get("MINIO_ACCESS_KEY"),
            secret_key=os.environ.get("MINIO_SECRET_KEY"),
            secure=use_ssl,
        )
        self._bucket_ready = False

    def _ensure_bucket(self) -> None:
        if self._bucket_ready:
            return
        if not self._client.bucket_exists(self._bucket):
            self._client.make_bucket(self._bucket)
        self._bucket_ready = True

    def upload_file(self, storage_key: str, data: bytes) -> None:
        self._ensure_bucket()
        self._client.put_object(
            self._bucket,
            storage_key,
            io.BytesIO(data),
            length=len(data),
            content_type="application/octet-stream",
        )

    def download_file(self, storage_key: str) -> bytes:
        response = self._client.get_object(self._bucket, storage_key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def delete_file(self, storage_key: str) -> None:
        self._client.remove_object(self._bucket, storage_key)
