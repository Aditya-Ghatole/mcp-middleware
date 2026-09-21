"""Text normalization utilities for defeating encoding-based injection bypasses."""

from __future__ import annotations

import base64
import re
import unicodedata

# Zero-width and invisible Unicode characters that attackers use to break pattern matching
_ZERO_WIDTH_PATTERN = re.compile(
    "["
    "\u200b"  # ZERO WIDTH SPACE
    "\u200c"  # ZERO WIDTH NON-JOINER
    "\u200d"  # ZERO WIDTH JOINER
    "\u2060"  # WORD JOINER
    "\ufeff"  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "\u00ad"  # SOFT HYPHEN
    "\u034f"  # COMBINING GRAPHEME JOINER
    "\u061c"  # ARABIC LETTER MARK
    "\u180e"  # MONGOLIAN VOWEL SEPARATOR
    "]"
)

# Cyrillic to Latin homoglyph map (the most common substitution attack)
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",  # U+0430 -> Latin a
    "\u0435": "e",  # U+0435 -> Latin e
    "\u043e": "o",  # U+043E -> Latin o
    "\u0440": "p",  # U+0440 -> Latin p
    "\u0441": "c",  # U+0441 -> Latin c
    "\u0443": "y",  # U+0443 -> Latin y
    "\u0445": "x",  # U+0445 -> Latin x
    "\u0456": "i",  # U+0456 -> Latin i
    "\u0458": "j",  # U+0458 -> Latin j
    "\u04bb": "h",  # U+04BB -> Latin h
    "\u0410": "A",  # U+0410 -> Latin A
    "\u0412": "B",  # U+0412 -> Latin B
    "\u0415": "E",  # U+0415 -> Latin E
    "\u041a": "K",  # U+041A -> Latin K
    "\u041c": "M",  # U+041C -> Latin M
    "\u041d": "H",  # U+041D -> Latin H
    "\u041e": "O",  # U+041E -> Latin O
    "\u0420": "P",  # U+0420 -> Latin P
    "\u0421": "C",  # U+0421 -> Latin C
    "\u0422": "T",  # U+0422 -> Latin T
    "\u0425": "X",  # U+0425 -> Latin X
}

# Regex to find potential Base64 encoded fragments (at least 20 chars, padded or unpadded)
_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def strip_zero_width(text: str) -> str:
    """Remove zero-width and invisible Unicode characters."""

    return _ZERO_WIDTH_PATTERN.sub("", text)


def normalize_homoglyphs(text: str) -> str:
    """Replace common Cyrillic homoglyphs with their Latin equivalents."""

    # First apply Unicode NFKC normalization to collapse compatibility characters
    text = unicodedata.normalize("NFKC", text)

    # Then replace known Cyrillic lookalikes
    return "".join(_HOMOGLYPH_MAP.get(char, char) for char in text)


def decode_base64_fragments(text: str) -> str:
    """Attempt to decode Base64 fragments and append decoded text for scanning.

    The original text is preserved intact. Decoded fragments are appended
    at the end so the heuristic and ML scanners can catch injections
    that were hidden via Base64 encoding.
    """

    decoded_fragments: list[str] = []

    for match in _BASE64_CANDIDATE.finditer(text):
        candidate = match.group()
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            decoded_text = decoded_bytes.decode("utf-8", errors="strict")
            # Only keep if the decoded text looks like readable content
            # (at least 80% printable characters)
            printable_ratio = sum(1 for c in decoded_text if c.isprintable() or c.isspace()) / max(
                len(decoded_text), 1
            )
            if printable_ratio >= 0.8:
                decoded_fragments.append(decoded_text)
        except (ValueError, UnicodeDecodeError):
            continue

    if decoded_fragments:
        return text + "\n[DECODED_BASE64]: " + " | ".join(decoded_fragments)
    return text


def normalize(text: str) -> str:
    """Apply the full normalization pipeline.

    Order matters:
    1. Strip zero-width chars first (they can hide inside Base64 or between homoglyphs)
    2. Normalize homoglyphs (so regex patterns match Cyrillic lookalikes)
    3. Decode Base64 last (append decoded content for downstream scanning)
    """

    text = strip_zero_width(text)
    text = normalize_homoglyphs(text)
    text = decode_base64_fragments(text)
    return text
