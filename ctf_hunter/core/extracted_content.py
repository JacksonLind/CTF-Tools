"""
ExtractedContent – a first-class object for content pulled out of a Finding.

Instances can be re-dispatched through the full analyzer suite as if they
were new files, enabling chained decode passes without ad-hoc hardcoding.
"""
from __future__ import annotations

import binascii
import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctf_hunter.core.report import Finding

# Maximum recursion depth allowed when re-dispatching extracted content
MAX_DEPTH = 5

# Regex that matches  raw_hex=<hex digits>  (optionally followed by space or |)
_RAW_HEX_RE = re.compile(r"raw_hex=([0-9a-fA-F]+)")

# Magic-byte → (mime_type, extension) mapping for common file types
_MAGIC_MAP: list[tuple[bytes, str, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png", "png"),
    (b"\xff\xd8\xff", "image/jpeg", "jpg"),
    (b"GIF87a", "image/gif", "gif"),
    (b"GIF89a", "image/gif", "gif"),
    (b"BM", "image/bmp", "bmp"),
    (b"PK\x03\x04", "application/zip", "zip"),
    (b"\x7fELF", "application/x-elf", "elf"),
    (b"%PDF", "application/pdf", "pdf"),
    (b"MZ", "application/x-dosexec", "exe"),
    (b"\x1f\x8b", "application/gzip", "gz"),
    (b"BZh", "application/x-bzip2", "bz2"),
    (b"\xfd7zXZ\x00", "application/x-xz", "xz"),
    (b"Rar!\x1a\x07", "application/x-rar", "rar"),
    (b"RIFF", "audio/wav", "wav"),
    (b"ID3", "audio/mpeg", "mp3"),
    (b"OggS", "audio/ogg", "ogg"),
    (b"fLaC", "audio/flac", "flac"),
    (b"SQLite format", "application/x-sqlite3", "sqlite"),
]


def _detect_mime(data: bytes) -> tuple[str, str]:
    """Return *(mime_type, extension)* for *data* using magic-byte matching.

    Falls back to ``("application/octet-stream", "bin")`` when unknown.
    """
    for magic, mime, ext in _MAGIC_MAP:
        if len(data) >= len(magic) and data[: len(magic)] == magic:
            return mime, ext
    return "application/octet-stream", "bin"


@dataclass
class ExtractedContent:
    """Represents content extracted from a Finding that can be re-analyzed.

    Instances carry enough provenance information to avoid infinite loops
    (via *depth* and *content_hash* deduplication) and to reconstruct the
    full decode chain that produced them (*encoding_chain*).
    """

    data: bytes
    label: str                  # human-readable description of what this is
    source_finding_id: str      # finding that produced this content
    source_analyzer: str        # analyzer that produced the source finding
    encoding_chain: list[str]   # ordered list of transforms applied so far
    content_hash: str           # SHA-256 of data, for deduplication
    depth: int                  # recursion depth; re-dispatch stops at MAX_DEPTH
    mime_hint: str = ""         # optional detected MIME type
    virtual_filename: str = ""  # optional synthetic filename for the dispatcher


def _make_extracted_content(
    data: bytes,
    label: str,
    finding: "Finding",
    encoding_chain: list[str],
    depth: int = 0,
) -> ExtractedContent:
    """Build an :class:`ExtractedContent` from raw *data* and a source *finding*."""
    content_hash = hashlib.sha256(data).hexdigest()
    mime_hint, ext = _detect_mime(data)
    virtual_filename = f"extracted_{content_hash[:8]}.{ext}"
    return ExtractedContent(
        data=data,
        label=label,
        source_finding_id=finding.id,
        source_analyzer=finding.analyzer,
        encoding_chain=encoding_chain,
        content_hash=content_hash,
        depth=depth,
        mime_hint=mime_hint,
        virtual_filename=virtual_filename,
    )


def extract_from_finding(finding: "Finding") -> list[ExtractedContent]:
    """Scan *finding.detail* and return extracted :class:`ExtractedContent` objects.

    Currently handled patterns
    --------------------------
    ``raw_hex=<hex>``
        Hex-encoded raw bytes, as produced by
        :func:`ctf_hunter.analyzers.steganalysis.decode_pipeline`.

    Each extracted object has *depth* = 0, meaning it has not yet been
    re-dispatched.  Callers are responsible for incrementing *depth* before
    each subsequent dispatch and for stopping when *depth* >= :data:`MAX_DEPTH`.
    """
    results: list[ExtractedContent] = []

    # ── raw_hex=<hex> ────────────────────────────────────────────────────────
    for match in _RAW_HEX_RE.finditer(finding.detail):
        hex_str = match.group(1)
        try:
            data = binascii.unhexlify(hex_str)
        except (binascii.Error, ValueError):
            continue
        if not data:
            continue
        ec = _make_extracted_content(
            data=data,
            label=f"raw hex data from finding '{finding.title}'",
            finding=finding,
            encoding_chain=["raw_hex"],
            depth=0,
        )
        results.append(ec)

    return results
