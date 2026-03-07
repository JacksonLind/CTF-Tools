"""
Crypto analyzer: hash identification, known-plaintext XOR recovery.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

# Hash patterns: (name, regex)
_HASH_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("MD5",    re.compile(r"\b[0-9a-fA-F]{32}\b")),
    ("SHA1",   re.compile(r"\b[0-9a-fA-F]{40}\b")),
    ("SHA256", re.compile(r"\b[0-9a-fA-F]{64}\b")),
    ("SHA512", re.compile(r"\b[0-9a-fA-F]{128}\b")),
    ("bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    ("NTLM",   re.compile(r"\b[0-9a-fA-F]{32}\b")),   # same as MD5 length
    ("MySQL",  re.compile(r"\*[0-9A-F]{40}\b")),
    ("Cisco",  re.compile(r"\$1\$[^$]{8}\$[A-Za-z0-9./]{22}")),
]

# Flag prefixes for known-plaintext XOR
_FLAG_PREFIXES = [b"CTF{", b"flag{", b"HTB{", b"picoCTF{", b"DUCTF{", b"FLAG{"]


class CryptoAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Hash identification
        findings.extend(self._identify_hashes(path, flag_pattern))

        # Known-plaintext XOR recovery
        if depth == "deep":
            findings.extend(self._xor_known_plaintext(path, flag_pattern))

        return findings

    # ------------------------------------------------------------------

    def _identify_hashes(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        strings = run_strings(path, min_len=16)
        seen: set[str] = set()
        for s in strings:
            for hash_name, pattern in _HASH_PATTERNS:
                for match in pattern.finditer(s):
                    val = match.group()
                    key = f"{hash_name}:{val}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(self._finding(
                            path,
                            f"Potential {hash_name} hash found",
                            val,
                            severity="MEDIUM",
                            confidence=0.65,
                        ))
        return findings

    def _xor_known_plaintext(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return []

        for prefix in _FLAG_PREFIXES:
            if len(prefix) > len(data):
                continue
            # XOR first N bytes of data with prefix to get candidate key
            candidate_key = bytes(data[i] ^ prefix[i] for i in range(len(prefix)))
            # Try the full decryption with this key (cycled)
            decrypted = bytes(data[i] ^ candidate_key[i % len(candidate_key)] for i in range(len(data)))
            try:
                text = decrypted.decode("utf-8", errors="replace")
            except Exception:
                continue
            if self._check_flag(text, flag_pattern):
                findings.append(self._finding(
                    path,
                    f"Known-plaintext XOR recovery with prefix {prefix!r}",
                    f"Key={candidate_key.hex()}: {text[:300]}",
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.90,
                ))
            elif sum(1 for c in text[:200] if c.isprintable()) / max(len(text[:200]), 1) > 0.85:
                findings.append(self._finding(
                    path,
                    f"Possible XOR decryption with key derived from prefix {prefix!r}",
                    f"Key={candidate_key.hex()}: {text[:200]}",
                    severity="MEDIUM",
                    confidence=0.55,
                ))

        return findings
