"""
MinIO object storage backend for encrypted files.

Wraps the minio SDK so the rest of the app only calls
upload_file / download_file / delete_file.
"""

import io
import os
import threading

from minio import Minio
from minio.error import S3Error


class MinioStorage:
    def __init__(self):
        # Configuration is read lazily so the app can boot even when object
        # storage isn't configured yet. The client is only created (and the
        # endpoint validated) the first time a file operation runs.
        self._bucket = os.environ.get("MINIO_BUCKET", "argus-encrypted-files")
        self._client = None
        self._bucket_ready = False
        self._lock = threading.Lock()

    def _get_client(self) -> Minio:
        if self._client is not None:
            return self._client

        with self._lock:
            if self._client is not None:
                return self._client

            endpoint = os.environ.get("MINIO_ENDPOINT")
            if not endpoint:
                raise RuntimeError(
                    "MINIO_ENDPOINT is not set — object storage is not configured. "
                    "Set the MINIO_* environment variables to enable file storage."
                )

            use_ssl = os.environ.get("MINIO_USE_SSL", "false").lower() == "true"
            self._client = Minio(
                endpoint,
                access_key=os.environ.get("MINIO_ACCESS_KEY"),
                secret_key=os.environ.get("MINIO_SECRET_KEY"),
                secure=use_ssl,
            )
            return self._client

    def _ensure_bucket(self) -> None:
        if self._bucket_ready:
            return

        client = self._get_client()
        with self._lock:
            if self._bucket_ready:
                return
            if not client.bucket_exists(self._bucket):
                try:
                    client.make_bucket(self._bucket)
                except S3Error as exc:
                    # A concurrent caller may have created the bucket between
                    # our check and this call — treat that as success.
                    if exc.code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                        raise
            self._bucket_ready = True

    def upload_file(self, storage_key: str, data: bytes) -> None:
        self._ensure_bucket()
        self._get_client().put_object(
            self._bucket,
            storage_key,
            io.BytesIO(data),
            length=len(data),
            content_type="application/octet-stream",
        )

    def download_file(self, storage_key: str) -> bytes:
        response = self._get_client().get_object(self._bucket, storage_key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def delete_file(self, storage_key: str) -> None:
        self._get_client().remove_object(self._bucket, storage_key)
