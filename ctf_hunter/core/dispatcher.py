"""
Magic-byte dispatcher: identifies file types and routes to all applicable analyzers.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from .report import Finding
from .deduplicator import deduplicate
from .external import run_file
from .ai_client import AIClient

# Analyzer imports
from analyzers.base import Analyzer
from analyzers.generic import GenericAnalyzer
from analyzers.image import ImageAnalyzer
from analyzers.audio import AudioAnalyzer
from analyzers.archive import ArchiveAnalyzer
from analyzers.document import DocumentAnalyzer
from analyzers.binary import BinaryAnalyzer
from analyzers.steganalysis import SteganalysisAnalyzer
from analyzers.encoding import EncodingAnalyzer
from analyzers.crypto import CryptoAnalyzer
from analyzers.pcap import PcapAnalyzer
from analyzers.filesystem import FilesystemAnalyzer
from analyzers.database import DatabaseAnalyzer
from analyzers.disassembly import DisassemblyAnalyzer
from analyzers.classical_cipher import ClassicalCipherAnalyzer
from analyzers.forensics_timeline import ForensicsTimelineAnalyzer
from analyzers.image_format import ImageFormatAnalyzer

# ---------------------------------------------------------------------------
# Magic byte signatures mapped to analyzer keys
# ---------------------------------------------------------------------------

_MAGIC_MAP: list[tuple[bytes, list[str]]] = [
    (b"\x89PNG\r\n\x1a\n",    ["image", "steganalysis", "image_format"]),
    (b"\xff\xd8\xff",          ["image", "steganalysis", "image_format"]),
    (b"GIF87a",                ["image", "steganalysis", "image_format"]),
    (b"GIF89a",                ["image", "steganalysis", "image_format"]),
    (b"BM",                    ["image", "steganalysis", "image_format"]),
    (b"RIFF",                  ["audio"]),
    (b"ID3",                   ["audio"]),
    (b"\xff\xfb",              ["audio"]),
    (b"fLaC",                  ["audio"]),
    (b"OggS",                  ["audio"]),
    (b"PK\x03\x04",           ["archive"]),
    (b"PK\x05\x06",           ["archive"]),
    (b"\x1f\x8b",             ["archive"]),
    (b"BZh",                   ["archive"]),
    (b"\xfd7zXZ\x00",         ["archive"]),
    (b"Rar!\x1a\x07",         ["archive"]),
    (b"%PDF",                  ["document"]),
    (b"\xd0\xcf\x11\xe0",     ["document"]),   # OLE (DOC, XLS, PPT)
    (b"\x7fELF",              ["binary", "disassembly"]),
    (b"MZ",                    ["binary", "disassembly"]),
    (b"\xca\xfe\xba\xbe",     ["binary", "disassembly"]),  # Mach-O
    (b"SQLite format 3\x00",   ["database"]),
]

_MIME_MAP: dict[str, list[str]] = {
    "image/png":              ["image", "steganalysis", "image_format"],
    "image/jpeg":             ["image", "steganalysis", "image_format"],
    "image/gif":              ["image", "steganalysis", "image_format"],
    "image/bmp":              ["image", "steganalysis", "image_format"],
    "image/tiff":             ["image", "steganalysis"],
    "audio/wav":              ["audio"],
    "audio/x-wav":            ["audio"],
    "audio/mpeg":             ["audio"],
    "audio/flac":             ["audio"],
    "audio/ogg":              ["audio"],
    "application/zip":        ["archive"],
    "application/x-rar":      ["archive"],
    "application/gzip":       ["archive"],
    "application/x-bzip2":    ["archive"],
    "application/x-xz":       ["archive"],
    "application/pdf":        ["document"],
    "application/msword":     ["document"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["document"],
    "application/x-elf":      ["binary", "disassembly"],
    "application/x-dosexec":  ["binary", "disassembly"],
    "application/vnd.tcpdump.pcap": ["pcap"],
    "application/x-pcapng":   ["pcap"],
    "application/x-sqlite3":  ["database"],
    "application/octet-stream": [],
}

_DISK_EXTS = {".dd", ".img", ".iso", ".raw", ".dmg"}

_ANALYZER_REGISTRY: dict[str, type[Analyzer]] = {
    "image":           ImageAnalyzer,
    "audio":           AudioAnalyzer,
    "archive":         ArchiveAnalyzer,
    "document":        DocumentAnalyzer,
    "binary":          BinaryAnalyzer,
    "steganalysis":    SteganalysisAnalyzer,
    "encoding":        EncodingAnalyzer,
    "crypto":          CryptoAnalyzer,
    "pcap":            PcapAnalyzer,
    "filesystem":      FilesystemAnalyzer,
    "database":        DatabaseAnalyzer,
    "disassembly":     DisassemblyAnalyzer,
    "classical_cipher": ClassicalCipherAnalyzer,
    "forensics_timeline": ForensicsTimelineAnalyzer,
    "image_format":    ImageFormatAnalyzer,
}


def dispatch(
    path: str,
    flag_pattern: re.Pattern,
    depth: str = "fast",
    ai_client: Optional[AIClient] = None,
) -> List[Finding]:
    """
    Identify file type, select all applicable analyzers, run them, and return
    deduplicated findings. GenericAnalyzer always runs.
    """
    data = _read_header(path)
    keys = _identify_analyzers(path, data)

    all_findings: List[Finding] = []

    # Always run generic
    generic = GenericAnalyzer()
    all_findings.extend(generic.analyze(path, flag_pattern, depth, ai_client))

    # Always run encoding, crypto, classical_cipher, and forensics_timeline
    for key in ("encoding", "crypto", "classical_cipher", "forensics_timeline"):
        analyzer = _ANALYZER_REGISTRY[key]()
        all_findings.extend(analyzer.analyze(path, flag_pattern, depth, ai_client))

    # Run type-specific analyzers
    for key in keys:
        if key in ("encoding", "crypto", "classical_cipher", "forensics_timeline"):
            continue   # already ran above
        cls = _ANALYZER_REGISTRY.get(key)
        if cls:
            try:
                analyzer = cls()
                all_findings.extend(analyzer.analyze(path, flag_pattern, depth, ai_client))
            except Exception as exc:
                all_findings.append(Finding(
                    file=path,
                    analyzer=key,
                    title=f"Analyzer error in {key}",
                    severity="INFO",
                    detail=str(exc),
                    confidence=0.1,
                ))

    return deduplicate(all_findings)


def _read_header(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(512)
    except Exception:
        return b""


def _identify_analyzers(path: str, data: bytes) -> list[str]:
    keys: list[str] = []

    # Check disk image extension
    if Path(path).suffix.lower() in _DISK_EXTS:
        keys.append("filesystem")

    # Magic bytes
    for sig, analyzer_keys in _MAGIC_MAP:
        if data.startswith(sig) or data.find(sig) != -1:
            for k in analyzer_keys:
                if k not in keys:
                    keys.append(k)
            break

    # MIME type via 'file' or python-magic
    mime = run_file(path)
    for mime_key, analyzer_keys in _MIME_MAP.items():
        if mime.startswith(mime_key):
            for k in analyzer_keys:
                if k not in keys:
                    keys.append(k)

    # PCAP extension fallback
    if Path(path).suffix.lower() in (".pcap", ".pcapng", ".cap") and "pcap" not in keys:
        keys.append("pcap")

    return keys
