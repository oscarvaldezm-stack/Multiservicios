"""Generadores de archivos de prueba (válidos, maliciosos y dañados)."""
from __future__ import annotations

import io
import socket
import struct
import threading
import zlib

from PIL import Image
from pypdf import PdfWriter

from app.security.scanner import EICAR

GPS_MARKER = "CamaraSecreta-GPS"


def jpeg(w: int = 900, h: int = 600, color: str = "navy", with_exif: bool = True, seed: int = 0) -> bytes:
    im = Image.new("RGB", (w, h), color)
    im.putpixel((seed % w, 0), (seed % 255, 1, 2))          # imágenes distintas por semilla
    buf = io.BytesIO()
    if with_exif:
        exif = im.getexif()
        exif[0x010F] = GPS_MARKER                              # fabricante (texto rastreable)
        exif[0x8825] = {1: "N", 2: (19.0, 25.0, 0.0)}          # GPS
        im.save(buf, "JPEG", exif=exif.tobytes())
    else:
        im.save(buf, "JPEG")
    return buf.getvalue()


def png(w: int = 900, h: int = 600) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (w, h), "white").save(buf, "PNG")
    return buf.getvalue()


def pdf(js: bool = False, pages: int = 1, encrypted: bool = False) -> bytes:
    wr = PdfWriter()
    for _ in range(pages):
        wr.add_blank_page(612, 792)
    if js:
        wr.add_js("app.alert('x');")
    if encrypted:
        wr.encrypt("secreto")
    buf = io.BytesIO()
    wr.write(buf)
    return buf.getvalue()


def png_bomb_header(w: int = 30000, h: int = 30000) -> bytes:
    """PNG válido en cabecera que declara 900 megapíxeles con un cuerpo diminuto."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    ihdr = struct.pack("!IIBBBBB", w, h, 8, 0, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\x00")) + chunk(b"IEND", b"")


def infected_jpeg() -> bytes:
    return jpeg(with_exif=False) + EICAR        # bytes después del fin de imagen: el visor los ignora


class FakeClamd:
    """Servidor TCP que habla INSTREAM como clamd. Reconstruye lo recibido para verificar el protocolo."""

    def __init__(self, reply: bytes = b"stream: OK\0"):
        self.reply = reply
        self.received = b""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        conn, _ = self.sock.accept()
        with conn:
            cmd = b""
            while not cmd.endswith(b"\0"):
                cmd += conn.recv(1)
            assert cmd == b"zINSTREAM\0"
            while True:
                size = struct.unpack("!L", self._exact(conn, 4))[0]
                if size == 0:
                    break
                self.received += self._exact(conn, size)
            conn.sendall(self.reply)
        self.sock.close()

    @staticmethod
    def _exact(conn, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            part = conn.recv(n - len(buf))
            if not part:
                raise ConnectionError
            buf += part
        return buf
