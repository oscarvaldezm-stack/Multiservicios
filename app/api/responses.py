from fastapi import Response

# Cabeceras para servir la imagen de un documento: nada de caché, nada de rastreo por
# Referer, el navegador no puede reinterpretar el tipo, y si alguien abriera la URL
# como documento, el CSP impide ejecutar cualquier cosa.
DOCUMENT_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "Content-Disposition": 'inline; filename="documento.jpg"',
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; img-src 'self'; sandbox",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
}


def document_image(data: bytes) -> Response:
    return Response(content=data, media_type="image/jpeg", headers=DOCUMENT_HEADERS)
