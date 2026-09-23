"""
Almacenamiento de objetos privado.

- `LocalObjectStorage`: desarrollo y pruebas. Directorio fuera de cualquier ruta servida,
  permisos 0600, llaves validadas (sin '..' ni rutas absolutas).
- `S3ObjectStorage`: producción. Cifrado del lado del servidor con KMS en CADA escritura,
  sin ACLs públicas, con checksum SHA-256. El bucket debe tener "Block Public Access",
  versionado y política que rechace PutObject sin cifrado (ver README).

Los objetos que se guardan ya vienen cifrados por la aplicación (FEK por archivo): aunque
el bucket se expusiera, su contenido es ilegible.
"""
from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path

from app.core.config import get_settings

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9/_-]{0,199}$")
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


class StorageError(Exception):
    pass


class ObjectNotFound(StorageError):
    pass


def _check(bucket: str, key: str) -> None:
    if not _BUCKET_RE.fullmatch(bucket):
        raise StorageError("Nombre de bucket inválido")
    if not _KEY_RE.fullmatch(key) or ".." in key or "//" in key:
        raise StorageError("Llave de objeto inválida")


class ObjectStorage(ABC):
    @abstractmethod
    def put(self, bucket: str, key: str, data: bytes) -> None: ...

    @abstractmethod
    def get(self, bucket: str, key: str) -> bytes: ...

    @abstractmethod
    def delete(self, bucket: str, key: str) -> None: ...

    @abstractmethod
    def exists(self, bucket: str, key: str) -> bool: ...


class LocalObjectStorage(ObjectStorage):
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, bucket: str, key: str) -> Path:
        _check(bucket, key)
        p = (self.root / bucket / key).resolve()
        if self.root not in p.parents:
            raise StorageError("Ruta fuera del almacenamiento")
        return p

    def put(self, bucket: str, key: str, data: bytes) -> None:
        p = self._path(bucket, key)
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = p.with_name(p.name + "-tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, p)

    def get(self, bucket: str, key: str) -> bytes:
        p = self._path(bucket, key)
        if not p.is_file():
            raise ObjectNotFound(key)
        return p.read_bytes()

    def delete(self, bucket: str, key: str) -> None:
        p = self._path(bucket, key)
        p.unlink(missing_ok=True)

    def exists(self, bucket: str, key: str) -> bool:
        return self._path(bucket, key).is_file()


class S3ObjectStorage(ObjectStorage):
    def __init__(self, client, kms_key_id: str):
        if not kms_key_id:
            raise StorageError("S3ObjectStorage exige una llave KMS")
        self._s3 = client
        self._kms = kms_key_id

    def put(self, bucket: str, key: str, data: bytes) -> None:
        _check(bucket, key)
        self._s3.put_object(
            Bucket=bucket, Key=key, Body=data,
            ServerSideEncryption="aws:kms", SSEKMSKeyId=self._kms, BucketKeyEnabled=True,
            ContentType="application/octet-stream",   # siempre binario opaco: ya viene cifrado
            ChecksumAlgorithm="SHA256",
        )

    def get(self, bucket: str, key: str) -> bytes:
        _check(bucket, key)
        try:
            return self._s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except self._s3.exceptions.NoSuchKey:
            raise ObjectNotFound(key) from None

    def delete(self, bucket: str, key: str) -> None:
        _check(bucket, key)
        self._s3.delete_object(Bucket=bucket, Key=key)

    def exists(self, bucket: str, key: str) -> bool:
        _check(bucket, key)
        from botocore.exceptions import ClientError
        try:
            self._s3.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError as exc:
            # Solo "no existe" es False; un AccessDenied o un error de red NO deben parecer "no existe".
            if exc.response.get("Error", {}).get("Code") in {"404", "NoSuchKey", "NotFound"}:
                return False
            raise StorageError("No se pudo consultar el almacenamiento") from exc


@lru_cache
def get_storage() -> ObjectStorage:
    s = get_settings()
    if s.STORAGE_BACKEND == "s3":
        import boto3
        client = boto3.client("s3", region_name=s.S3_REGION, endpoint_url=s.S3_ENDPOINT_URL or None)
        return S3ObjectStorage(client, s.S3_KMS_KEY_ID or "")
    return LocalObjectStorage(s.STORAGE_LOCAL_ROOT)
