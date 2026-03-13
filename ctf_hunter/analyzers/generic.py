"""
Generic analyzer: entropy, magic/extension mismatch, strings, null bytes.
Runs on every file regardless of type.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

# Known extension → expected leading magic bytes
_EXT_MAGIC: dict[str, list[bytes]] = {
    ".png":  [b"\x89PNG"],
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif":  [b"GIF87a", b"GIF89a"],
    ".bmp":  [b"BM"],
    ".zip":  [b"PK\x03\x04", b"PK\x05\x06"],
    ".gz":   [b"\x1f\x8b"],
    ".pdf":  [b"%PDF"],
    ".elf":  [b"\x7fELF"],
    ".exe":  [b"MZ"],
    ".mp3":  [b"ID3", b"\xff\xfb"],
    ".wav":  [b"RIFF"],
    ".ogg":  [b"OggS"],
    ".flac": [b"fLaC"],
    ".sqlite": [b"SQLite format 3"],
    ".db":   [b"SQLite format 3"],
}


class GenericAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception as exc:
            return [self._finding(path, "Read error", str(exc), severity="INFO", confidence=0.1)]

        # --- Entropy ---
        findings.extend(self._check_entropy(path, data))

        # --- Magic / extension mismatch ---
        findings.extend(self._check_magic_mismatch(path, data))

        # --- Null byte clusters ---
        findings.extend(self._check_null_clusters(path, data))

        # --- String extraction + flag pattern ---
        findings.extend(self._check_strings(path, data, flag_pattern, depth))

        return findings

    # ------------------------------------------------------------------

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def _check_entropy(self, path: str, data: bytes) -> List[Finding]:
        if len(data) < 64:
            return []
        ent = self._shannon_entropy(data)
        if ent > 7.2:
            return [self._finding(
                path,
                f"High Shannon entropy: {ent:.3f}",
                "Entropy >7.2 suggests encryption or packing.",
                severity="HIGH",
                confidence=0.75,
            )]
        if ent > 6.5:
            return [self._finding(
                path,
                f"Elevated Shannon entropy: {ent:.3f}",
                "Entropy >6.5 may indicate compression or encoding.",
                severity="MEDIUM",
                confidence=0.55,
            )]
        return []

    def _check_magic_mismatch(self, path: str, data: bytes) -> List[Finding]:
        suffix = Path(path).suffix.lower()
        expected = _EXT_MAGIC.get(suffix)
        if not expected:
            return []
        if not any(data.startswith(m) for m in expected):
            actual = data[:8].hex()
            return [self._finding(
                path,
                f"Magic/extension mismatch for {suffix}",
                f"Expected magic for {suffix}, got 0x{actual}",
                severity="HIGH",
                confidence=0.85,
            )]
        return []

    def _check_null_clusters(self, path: str, data: bytes) -> List[Finding]:
        findings: List[Finding] = []
        MIN_CLUSTER = 64
        i = 0
        while i < len(data):
            if data[i] == 0:
                j = i
                while j < len(data) and data[j] == 0:
                    j += 1
                cluster_len = j - i
                if cluster_len >= MIN_CLUSTER:
                    findings.append(self._finding(
                        path,
                        f"Null byte cluster at 0x{i:x} ({cluster_len} bytes)",
                        "Large null-byte region may indicate hidden data or steganography.",
                        severity="MEDIUM",
                        offset=i,
                        confidence=0.5,
                    ))
                i = j
            else:
                i += 1
        return findings

    def _check_strings(
        self,
        path: str,
        data: bytes,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        strings = run_strings(path, min_len=4)
        flag_hits = []
        for s in strings:
            if self._check_flag(s, flag_pattern):
                flag_hits.append(s)
        if flag_hits:
            for hit in flag_hits[:20]:  # cap at 20 shown
                # Find offset in raw bytes
                offset = data.find(hit.encode("latin-1", errors="replace"))
                findings.append(self._finding(
                    path,
                    f"Flag pattern match in strings: {hit[:80]}",
                    f"Matched flag pattern: {hit}",
                    severity="HIGH",
                    offset=offset,
                    flag_match=True,
                    confidence=0.95,
                ))
        return findings
