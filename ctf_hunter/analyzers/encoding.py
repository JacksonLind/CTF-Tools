"""
Encoding analyzer: Base64/32/85, hex, ROT13, morse, binary, XOR key guesser.
"""
from __future__ import annotations

import base64
import binascii
import re
import string
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

_MORSE_MAP = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
}


def _is_printable(text: str, threshold: float = 0.85) -> bool:
    if not text:
        return False
    printable_chars = sum(1 for c in text if c in string.printable)
    return printable_chars / len(text) >= threshold


def _decode_base64(s: str) -> Optional[str]:
    try:
        padded = s + "=" * (4 - len(s) % 4)
        decoded = base64.b64decode(padded, validate=False)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_base32(s: str) -> Optional[str]:
    try:
        padded = s.upper() + "=" * ((8 - len(s) % 8) % 8)
        decoded = base64.b32decode(padded, casefold=True)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_base85(s: str) -> Optional[str]:
    try:
        decoded = base64.b85decode(s)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _decode_hex(s: str) -> Optional[str]:
    clean = re.sub(r"\s+", "", s)
    if len(clean) % 2 != 0 or not all(c in "0123456789abcdefABCDEF" for c in clean):
        return None
    try:
        return bytes.fromhex(clean).decode("utf-8", errors="replace")
    except Exception:
        return None


def _rot13(s: str) -> str:
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))


def _decode_morse(s: str) -> Optional[str]:
    s = s.strip()
    if not re.match(r"^[\.\-\s/]+$", s):
        return None
    words = s.split("/")
    result = []
    for word in words:
        chars = word.strip().split()
        decoded_word = ""
        for code in chars:
            decoded_word += _MORSE_MAP.get(code, "?")
        result.append(decoded_word)
    decoded = " ".join(result)
    if "?" in decoded and decoded.count("?") / len(decoded) > 0.3:
        return None
    return decoded


def _decode_binary(s: str) -> Optional[str]:
    clean = re.sub(r"\s+", "", s)
    if not all(c in "01" for c in clean):
        return None
    if len(clean) % 8 != 0:
        return None
    try:
        result = ""
        for i in range(0, len(clean), 8):
            result += chr(int(clean[i:i+8], 2))
        return result
    except Exception:
        return None


class EncodingAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
    ) -> List[Finding]:
        findings: List[Finding] = []
        strings = run_strings(path, min_len=8)

        for s in strings[:2000]:  # cap to avoid excessive processing
            s_stripped = s.strip()
            if len(s_stripped) < 8:
                continue

            # Base64
            if re.match(r"^[A-Za-z0-9+/=]{16,}$", s_stripped):
                decoded = _decode_base64(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        f"Base64 decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.80 if fm else 0.55,
                    ))
                    continue

            # Base32
            if re.match(r"^[A-Z2-7=]{16,}$", s_stripped.upper()):
                decoded = _decode_base32(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Base32 decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.78 if fm else 0.52,
                    ))
                    continue

            # Hex
            if re.match(r"^[0-9a-fA-F]{16,}$", s_stripped):
                decoded = _decode_hex(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Hex decoded string",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.78 if fm else 0.52,
                    ))
                    continue

            # Morse
            if re.match(r"^[\.\-\s/]{8,}$", s_stripped):
                decoded = _decode_morse(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Morse code decoded",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.72 if fm else 0.48,
                    ))
                    continue

            # Binary
            if re.match(r"^[01\s]{16,}$", s_stripped):
                decoded = _decode_binary(s_stripped)
                if decoded and _is_printable(decoded):
                    fm = self._check_flag(decoded, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "Binary-to-ASCII decoded",
                        f"Input: {s_stripped[:60]!r} → {decoded[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.72 if fm else 0.48,
                    ))
                    continue

            # ROT13
            rot = _rot13(s_stripped)
            if rot != s_stripped:
                fm = self._check_flag(rot, flag_pattern)
                if fm:
                    findings.append(self._finding(
                        path,
                        f"ROT13 decoded flag match",
                        f"Input: {s_stripped[:60]!r} → {rot[:200]}",
                        severity="HIGH",
                        flag_match=True,
                        confidence=0.90,
                    ))

        # XOR key guesser on the raw file bytes
        if depth == "deep":
            findings.extend(self._xor_guesser(path, flag_pattern))

        return findings

    def _xor_guesser(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception:
            return []

        # Only operate on high-entropy blobs
        from analyzers.generic import GenericAnalyzer
        ga = GenericAnalyzer()
        ent = ga._shannon_entropy(data)
        if ent < 6.0:
            return []

        # Single-byte XOR
        sample = data[:4096]
        for key in range(256):
            xored = bytes(b ^ key for b in sample)
            try:
                text = xored.decode("utf-8", errors="replace")
            except Exception:
                continue
            if _is_printable(text, 0.75):
                fm = self._check_flag(text, flag_pattern)
                findings.append(self._finding(
                    path,
                    f"XOR key 0x{key:02x} produces printable data",
                    f"Key=0x{key:02x}: {text[:200]}",
                    severity="HIGH" if fm else "MEDIUM",
                    flag_match=fm,
                    confidence=0.80 if fm else 0.55,
                ))

        # Common multi-byte keys
        common_keys = [b"key", b"flag", b"secret", b"xor", b"\xde\xad\xbe\xef"]
        for key in common_keys:
            xored = bytes(sample[i] ^ key[i % len(key)] for i in range(len(sample)))
            try:
                text = xored.decode("utf-8", errors="replace")
            except Exception:
                continue
            if _is_printable(text, 0.80):
                fm = self._check_flag(text, flag_pattern)
                findings.append(self._finding(
                    path,
                    f"XOR with key {key!r} produces printable data",
                    f"Key={key!r}: {text[:200]}",
                    severity="HIGH" if fm else "MEDIUM",
                    flag_match=fm,
                    confidence=0.78 if fm else 0.53,
                ))

        return findings
