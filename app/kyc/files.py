"""
Inspección y saneamiento de archivos KYC. Nunca se confía en la extensión ni en el
Content-Type del cliente: el tipo real se decide por los bytes.

En la API (rápido, antes de guardar):  tamaño, bytes mágicos, extensión coherente,
    dimensiones declaradas en la cabecera de la imagen.
En el worker (aislado, después del antivirus): decodificación completa, re-codificación
    de imágenes sin metadatos (quita GPS/EXIF y cualquier contenido pegado al final),
    revisión estructural de PDF y conversión de sus páginas a imagen para el revisor.
"""
from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageFont, ImageOps

JPEG, PNG, PDF = "image/jpeg", "image/png", "application/pdf"
ALLOWED_MIME = frozenset({JPEG, PNG, PDF})
IMAGE_MIME = frozenset({JPEG, PNG})
_EXTENSIONS = {JPEG: {"jpg", "jpeg"}, PNG: {"png"}, PDF: {"pdf"}}
PREVIEW_MAX_SIDE = 2000


class FileRejected(Exception):
    def __init__(self, code: str, message: str, http_status: int = 422):
        super().__init__(message)
        self.code, self.http_status = code, http_status


@dataclass(frozen=True)
class UploadInfo:
    mime: str
    size: int
    sha256: str
    width: int | None = None
    height: int | None = None


def sniff(data: bytes) -> str | None:
    if data.startswith(b"\xff\xd8\xff"):
        return JPEG
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return PNG
    # El estándar permite basura antes de %PDF- (hasta 1024 bytes); aquí NO: debe ir al inicio.
    if data.startswith(b"%PDF-"):
        return PDF
    return None


def validate_upload(data: bytes, filename: str | None, declared_type: str | None, *,
                    allowed: frozenset[str], max_bytes: int, max_pixels: int) -> UploadInfo:
    if not data:
        raise FileRejected("FILE_EMPTY", "El archivo está vacío")
    if len(data) > max_bytes:
        raise FileRejected("FILE_TOO_LARGE", f"El archivo supera {max_bytes // (1024 * 1024)} MB", 413)
    mime = sniff(data)
    if mime is None or mime not in allowed:
        raise FileRejected("FILE_TYPE_NOT_ALLOWED", "Tipo de archivo no permitido", 415)
    ext = (filename or "").rsplit(".", 1)[-1].lower() if filename and "." in filename else ""
    if ext not in _EXTENSIONS[mime]:
        raise FileRejected("FILE_EXTENSION_MISMATCH", "La extensión no corresponde al contenido del archivo", 415)
    if declared_type and declared_type.split(";")[0].strip().lower() not in {mime, "application/octet-stream"}:
        raise FileRejected("FILE_CONTENT_TYPE_MISMATCH", "El tipo declarado no corresponde al contenido", 415)

    width = height = None
    if mime in IMAGE_MIME:
        Image.MAX_IMAGE_PIXELS = max_pixels
        try:
            with Image.open(io.BytesIO(data)) as im:       # solo lee la cabecera
                width, height = im.size
                if {"JPEG": JPEG, "PNG": PNG}.get(im.format) != mime:
                    raise FileRejected("FILE_CORRUPT", "La imagen está dañada o no es lo que dice ser", 415)
        except FileRejected:
            raise
        except Image.DecompressionBombError:
            raise FileRejected("IMAGE_TOO_LARGE", "La imagen tiene demasiados píxeles", 413) from None
        except Exception:  # noqa: BLE001
            raise FileRejected("FILE_CORRUPT", "La imagen está dañada o no es lo que dice ser", 415) from None
        if width * height > max_pixels:
            raise FileRejected("IMAGE_TOO_LARGE", "La imagen tiene demasiados píxeles", 413)
        if min(width, height) < 400:
            raise FileRejected("IMAGE_TOO_SMALL", "La imagen es demasiado pequeña para leerse (mínimo 400 px)")
    return UploadInfo(mime, len(data), hashlib.sha256(data).hexdigest(), width, height)


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------
def sanitize_image(data: bytes, max_pixels: int) -> tuple[bytes, int, int]:
    """Decodifica por completo y re-codifica a JPEG sin metadatos. Devuelve (jpeg, ancho, alto)."""
    Image.MAX_IMAGE_PIXELS = max_pixels   # Pillow lanza DecompressionBombError por encima de 2x
    try:
        with Image.open(io.BytesIO(data)) as probe:
            probe.verify()
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            if im.width * im.height > max_pixels:
                raise FileRejected("IMAGE_TOO_LARGE", "La imagen tiene demasiados píxeles", 413)
            im = ImageOps.exif_transpose(im)          # respeta la orientación y descarta el EXIF
            rgb = im.convert("RGB")
    except FileRejected:
        raise
    except Exception:  # noqa: BLE001  (incluye DecompressionBombError)
        raise FileRejected("FILE_CORRUPT", "No se pudo procesar la imagen") from None
    out = io.BytesIO()
    rgb.save(out, "JPEG", quality=90, optimize=True)   # sin exif=, sin icc_profile=: sin metadatos
    return out.getvalue(), rgb.width, rgb.height


# Nombres PDF que indican contenido activo o incrustado. Se buscan en la estructura (pypdf)
# y en los bytes, normalizando escapes "#xx" que se usan para ofuscar nombres (/J#61vaScript).
_PDF_DANGEROUS = ("/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/EmbeddedFiles", "/RichMedia",
                  "/XFA", "/AcroForm", "/SubmitForm", "/ImportData", "/GoToR", "/GoToE")
_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")


def _normalized(data: bytes) -> bytes:
    return _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def _walk(obj, seen: set[int], depth: int = 0):
    """Recorre el grafo de objetos PDF (acotado) buscando nombres peligrosos."""
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

    if depth > 60:
        return
    if isinstance(obj, IndirectObject):
        key = (obj.idnum, obj.generation)
        if key in seen:
            return
        seen.add(key)
        try:
            obj = obj.get_object()
        except Exception:  # noqa: BLE001
            return
    if isinstance(obj, DictionaryObject):
        for k, v in obj.items():
            if k in _PDF_DANGEROUS:
                yield str(k)
            if k == "/S" and str(v) in ("/JavaScript", "/Launch", "/SubmitForm", "/ImportData"):
                yield str(v)
            yield from _walk(v, seen, depth + 1)
    elif isinstance(obj, ArrayObject):
        for v in obj:
            yield from _walk(v, seen, depth + 1)


def inspect_pdf(data: bytes, max_pages: int) -> int:
    """Rechaza PDF cifrados, con contenido activo o incrustado, o con demasiadas páginas. Devuelve nº de páginas."""
    from pypdf import PdfReader

    flat = _normalized(data)
    for name in _PDF_DANGEROUS:
        # delimitador después del nombre para no confundir /JS con /JSomething
        if re.search(re.escape(name.encode()) + rb"[\s/<>\[\]()%]", flat):
            raise FileRejected("PDF_ACTIVE_CONTENT", "El PDF contiene elementos no permitidos (scripts, formularios o adjuntos)")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise FileRejected("PDF_ENCRYPTED", "El PDF está protegido con contraseña")
        pages = len(reader.pages)
        found = next(_walk(reader.trailer, set()), None)
    except FileRejected:
        raise
    except Exception:  # noqa: BLE001
        raise FileRejected("FILE_CORRUPT", "No se pudo leer el PDF") from None
    if found:
        raise FileRejected("PDF_ACTIVE_CONTENT", "El PDF contiene elementos no permitidos (scripts, formularios o adjuntos)")
    if pages < 1 or pages > max_pages:
        raise FileRejected("PDF_TOO_MANY_PAGES", f"El PDF debe tener entre 1 y {max_pages} páginas")
    return pages


def render_pdf_preview(data: bytes, max_pages: int, max_pixels: int) -> tuple[bytes, int, int]:
    """Convierte las páginas a UNA imagen JPEG vertical. El revisor nunca abre el PDF original."""
    import pypdfium2 as pdfium

    doc = pdfium.PdfDocument(data)
    try:
        images = []
        for i in range(min(len(doc), max_pages)):
            page = doc[i]
            w, h = page.get_size()
            scale = min(1.5, (max_pixels / max(1.0, w * h * max_pages)) ** 0.5)
            images.append(page.render(scale=scale).to_pil().convert("RGB"))
            page.close()
    finally:
        doc.close()
    width = max(im.width for im in images)
    height = sum(im.height for im in images)
    sheet = Image.new("RGB", (width, height), "white")
    y = 0
    for im in images:
        sheet.paste(im, (0, y))
        y += im.height
    return _downscale_jpeg(sheet)


def image_preview(sanitized_jpeg: bytes) -> tuple[bytes, int, int]:
    with Image.open(io.BytesIO(sanitized_jpeg)) as im:
        return _downscale_jpeg(im.convert("RGB"))


def _downscale_jpeg(im: Image.Image) -> tuple[bytes, int, int]:
    im = im.copy()
    im.thumbnail((PREVIEW_MAX_SIDE, PREVIEW_MAX_SIDE * 3))
    out = io.BytesIO()
    im.save(out, "JPEG", quality=85)
    return out.getvalue(), im.width, im.height


def watermark(preview_jpeg: bytes, text: str) -> bytes:
    """Marca de agua diagonal repetida con quién ve y cuándo. Si hay una captura filtrada, se sabe su origen."""
    with Image.open(io.BytesIO(preview_jpeg)) as base:
        base = base.convert("RGBA")
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    font = ImageFont.load_default(size=max(14, base.width // 40))
    step_y = max(80, base.height // 8)
    step_x = max(200, base.width // 3)
    for y in range(-base.height, base.height * 2, step_y):
        for x in range(-base.width, base.width * 2, step_x):
            draw.text((x + (y // 3), y), text, fill=(200, 0, 0, 70), font=font)
    overlay = overlay.rotate(30, resample=Image.BICUBIC, center=(base.width / 2, base.height / 2))
    out = io.BytesIO()
    Image.alpha_composite(base, overlay).convert("RGB").save(out, "JPEG", quality=85)
    return out.getvalue()
