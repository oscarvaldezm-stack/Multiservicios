"""
Saneamiento y filtros de texto para comentarios y respuestas.

- Se guarda TEXTO PLANO: sin marcado (se rechaza cualquier etiqueta), sin caracteres de
  control, Unicode normalizado (NFC) y espacios colapsados. Las apps (Flutter / panel)
  siempre lo muestran como texto, nunca como HTML.
- Sin datos de contacto (teléfonos, correos, enlaces): evita spam, que se saque el trato
  de la plataforma y que se publiquen datos personales de terceros.
- Lenguaje ofensivo: no se rechaza (una mala experiencia puede escribirse con enojo), se
  RETIENE para moderación. La lista es configurable y se compara por palabra completa
  o raíz, tras quitar acentos, "leet speak" y letras repetidas.
"""
from __future__ import annotations

import re
import unicodedata

from app.core.errors import DomainError

_CONTROL = re.compile("[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069]")
_MARKUP = re.compile(r"<\s*/?\s*[a-zA-Z!?][^>]*>|&[#a-zA-Z0-9]{2,10};")
_URL = re.compile(r"(?i)\b(?:https?://|www\.)\S+|\b[a-z0-9-]{2,}\.(?:com|mx|net|org|io|info|biz|co|me|app|link|ly)\b")
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+\s*(?:@|\(at\)|\[at\])\s*[a-z0-9.-]+\.[a-z]{2,}\b")
_PHONE = re.compile(r"(?:\+?\d[\s.\-()]*){10,}")

# Raíces (se comparan al inicio de cada palabra) y palabras exactas. Ampliable sin tocar la lógica.
OFFENSIVE_STEMS = ("pendej", "idiot", "imbecil", "estupid", "cabron", "chingad", "chingar", "mierd", "culer",
                   "maricon", "malparid", "babos")
OFFENSIVE_WORDS = frozenset({"puto", "puta", "putos", "putas", "joto", "jotos", "naco", "nacos", "chinga",
                             "chingas", "pinche", "pinches", "mamon", "mamona", "zorra", "perra", "verga",
                             "vergas", "marica", "hdp", "ptm", "ojete"})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


class ContentRejected(DomainError):
    http_status = 422
    code = "CONTENT_REJECTED"


def clean_text(value: str | None, *, max_len: int, field: str = "comment") -> str | None:
    if value is None:
        return None
    text = unicodedata.normalize("NFC", value)
    text = _CONTROL.sub("", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if not text:
        return None
    if len(text) > max_len:
        raise ContentRejected(f"El texto no puede exceder {max_len} caracteres", code="CONTENT_TOO_LONG",
                              extra={"field": field, "max": max_len})
    if _MARKUP.search(text):
        raise ContentRejected("No se permite HTML ni marcado en el texto", code="CONTENT_MARKUP_NOT_ALLOWED",
                              extra={"field": field})
    if _URL.search(text) or _EMAIL.search(text) or _PHONE.search(text):
        raise ContentRejected("No incluyas enlaces, correos ni teléfonos", code="CONTENT_CONTACT_NOT_ALLOWED",
                              extra={"field": field})
    return text


def _normalize_for_match(text: str) -> list[str]:
    no_accents = "".join(c for c in unicodedata.normalize("NFD", text.lower()) if unicodedata.category(c) != "Mn")
    # "p.u.t.o" / "p u t o": une letras sueltas separadas por signos o espacios
    joined = re.sub(r"\b(?:\w[\s.\-_*]){2,}\w\b", lambda m: re.sub(r"[\s.\-_*]", "", m.group(0)), no_accents)
    leet = joined.translate(_LEET)
    squeezed = re.sub(r"(\w)\1{2,}", r"\1", leet)          # "puuuuto" -> "puto"
    return re.findall(r"[a-zñ]+", squeezed)


def is_offensive(text: str | None) -> bool:
    if not text:
        return False
    for word in _normalize_for_match(text):
        collapsed = re.sub(r"(\w)\1+", r"\1", word)        # "pendejjo" -> "pendejo"
        for w in {word, collapsed}:
            if w in OFFENSIVE_WORDS or any(w.startswith(stem) for stem in OFFENSIVE_STEMS):
                return True
    return False
