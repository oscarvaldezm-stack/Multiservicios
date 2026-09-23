"""
Escaneo antivirus.

`ClamdScanner` habla el protocolo INSTREAM de clamd por TCP sin dependencias externas:
    "zINSTREAM\\0"  +  [longitud 4 bytes big-endian + bloque]*  +  4 bytes en cero
Respuesta: "stream: OK" o "stream: <firma> FOUND".

Si el antivirus no responde, el archivo NO se da por limpio (falla cerrada): queda
pendiente y se reintenta.
"""
from __future__ import annotations

import socket
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import lru_cache

from app.core.config import get_settings

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class ScannerUnavailable(Exception):
    pass


@dataclass(frozen=True)
class ScanResult:
    clean: bool
    signature: str | None
    engine: str


class Scanner(ABC):
    @abstractmethod
    def scan(self, data: bytes) -> ScanResult: ...


class ClamdScanner(Scanner):
    CHUNK = 64 * 1024

    def __init__(self, host: str, port: int, timeout: float = 30.0):
        self.host, self.port, self.timeout = host, port, timeout

    def scan(self, data: bytes) -> ScanResult:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.sendall(b"zINSTREAM\0")
                for i in range(0, len(data), self.CHUNK):
                    chunk = data[i:i + self.CHUNK]
                    sock.sendall(struct.pack("!L", len(chunk)) + chunk)
                sock.sendall(struct.pack("!L", 0))
                reply = b""
                while not reply.endswith(b"\0"):
                    part = sock.recv(4096)
                    if not part:
                        break
                    reply += part
        except OSError as exc:
            raise ScannerUnavailable(f"clamd no disponible: {exc.__class__.__name__}") from exc

        text = reply.rstrip(b"\0").decode("utf-8", "replace").strip()
        if text.endswith("OK"):
            return ScanResult(True, None, "clamd")
        if text.endswith("FOUND"):
            sig = text.removeprefix("stream:").removesuffix("FOUND").strip()
            return ScanResult(False, sig[:120], "clamd")
        # "INSTREAM size limit exceeded", errores internos...: nunca se asume limpio.
        raise ScannerUnavailable(f"Respuesta inesperada de clamd: {text[:80]}")


class DevEicarScanner(Scanner):
    """SOLO desarrollo sin ClamAV: detecta la firma de prueba EICAR. La configuración
    impide usarlo en producción."""

    def scan(self, data: bytes) -> ScanResult:
        if EICAR in data:
            return ScanResult(False, "Eicar-Test-Signature", "dev-eicar")
        return ScanResult(True, None, "dev-eicar")


@lru_cache
def get_scanner() -> Scanner:
    s = get_settings()
    if s.KYC_SCANNER == "clamd":
        return ClamdScanner(s.CLAMD_HOST, s.CLAMD_PORT)
    return DevEicarScanner()
