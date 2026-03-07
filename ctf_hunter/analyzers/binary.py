"""
Binary analyzer: ELF/PE headers, packed sections, overlay data, suspicious imports.
"""
from __future__ import annotations

import math
import re
import struct
from collections import Counter
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_strings
from .base import Analyzer

_SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "system", "exec", "popen", "execve", "execl",
    "InternetOpenUrl", "URLDownloadToFile", "WinHttpOpen",
    "CryptEncrypt", "CryptDecrypt",
}


class BinaryAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = Path(path).read_bytes()
        except Exception as exc:
            return [self._finding(path, "Read error", str(exc), confidence=0.1)]

        if data[:4] == b"\x7fELF":
            findings.extend(self._analyze_elf(path, data, depth))
        elif data[:2] == b"MZ":
            findings.extend(self._analyze_pe(path, data, depth))

        # Overlay data
        findings.extend(self._check_overlay(path, data, flag_pattern))

        # Suspicious imports via strings
        findings.extend(self._check_imports(path, flag_pattern))

        return findings

    # ------------------------------------------------------------------

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def _analyze_elf(self, path: str, data: bytes, depth: str) -> List[Finding]:
        findings: List[Finding] = []
        if len(data) < 64:
            return []
        # EI_CLASS: 1=32bit, 2=64bit
        ei_class = data[4]
        ei_data = data[5]  # 1=LE, 2=BE
        e_type = struct.unpack_from("<H", data, 16)[0]
        type_map = {1: "Relocatable", 2: "Executable", 3: "Shared Object", 4: "Core"}
        elf_type = type_map.get(e_type, f"Unknown({e_type})")
        findings.append(self._finding(
            path,
            f"ELF binary: {'32-bit' if ei_class == 1 else '64-bit'} {elf_type}",
            f"EI_CLASS={ei_class}, EI_DATA={ei_data}, e_type={e_type}",
            severity="INFO",
            confidence=0.7,
        ))

        # Parse section headers for entropy (64-bit LE only for simplicity)
        if ei_class == 2 and ei_data == 1 and len(data) >= 64:
            try:
                e_shoff = struct.unpack_from("<Q", data, 40)[0]
                e_shentsize = struct.unpack_from("<H", data, 58)[0]
                e_shnum = struct.unpack_from("<H", data, 60)[0]
                for i in range(min(e_shnum, 40)):
                    sh_offset_pos = e_shoff + i * e_shentsize
                    if sh_offset_pos + 64 > len(data):
                        break
                    sh_type = struct.unpack_from("<I", data, sh_offset_pos + 4)[0]
                    sh_offset = struct.unpack_from("<Q", data, sh_offset_pos + 24)[0]
                    sh_size = struct.unpack_from("<Q", data, sh_offset_pos + 32)[0]
                    if sh_type in (1, 9, 11) and sh_size > 0:  # SHT_PROGBITS, SHT_REL, SHT_DYNSYM
                        section_data = data[sh_offset:sh_offset + sh_size]
                        ent = self._shannon_entropy(section_data)
                        if ent > 6.8:
                            findings.append(self._finding(
                                path,
                                f"High-entropy ELF section at offset 0x{sh_offset:x} (H={ent:.3f})",
                                "High entropy section may be packed, encrypted, or contain embedded data.",
                                severity="HIGH",
                                offset=sh_offset,
                                confidence=0.75,
                            ))
            except Exception:
                pass
        return findings

    def _analyze_pe(self, path: str, data: bytes, depth: str) -> List[Finding]:
        findings: List[Finding] = []
        if len(data) < 64:
            return []
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data):
                return [self._finding(path, "PE header truncated", "", severity="INFO", confidence=0.4)]
            pe_sig = data[pe_offset:pe_offset + 4]
            if pe_sig != b"PE\x00\x00":
                return [self._finding(
                    path, "MZ file but invalid PE signature",
                    f"Got {pe_sig.hex()} at 0x{pe_offset:x}",
                    severity="MEDIUM", confidence=0.6,
                )]
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            machine_map = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64"}
            arch = machine_map.get(machine, f"unknown(0x{machine:x})")
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            findings.append(self._finding(
                path,
                f"PE binary: {arch}, {num_sections} sections",
                f"Machine=0x{machine:x}, Sections={num_sections}",
                severity="INFO",
                confidence=0.7,
            ))

            # Section table
            opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            section_table_offset = pe_offset + 24 + opt_header_size
            for i in range(num_sections):
                sec_off = section_table_offset + i * 40
                if sec_off + 40 > len(data):
                    break
                sec_name = data[sec_off:sec_off + 8].decode("latin-1", errors="replace").rstrip("\x00")
                raw_offset = struct.unpack_from("<I", data, sec_off + 20)[0]
                raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
                if raw_size > 0 and raw_offset + raw_size <= len(data):
                    sec_data = data[raw_offset:raw_offset + raw_size]
                    ent = self._shannon_entropy(sec_data)
                    if ent > 6.8:
                        findings.append(self._finding(
                            path,
                            f"High-entropy PE section '{sec_name}' (H={ent:.3f})",
                            f"Section '{sec_name}' at 0x{raw_offset:x}, size={raw_size}",
                            severity="HIGH",
                            offset=raw_offset,
                            confidence=0.75,
                        ))
        except Exception as exc:
            findings.append(self._finding(path, "PE parse error", str(exc), confidence=0.2))
        return findings

    def _check_overlay(self, path: str, data: bytes, flag_pattern: re.Pattern) -> List[Finding]:
        """Check for data appended after last PE section."""
        findings: List[Finding] = []
        if len(data) < 64 or data[:2] != b"MZ":
            return []
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return []
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            section_table_offset = pe_offset + 24 + opt_header_size
            last_end = 0
            for i in range(num_sections):
                sec_off = section_table_offset + i * 40
                if sec_off + 40 > len(data):
                    break
                raw_offset = struct.unpack_from("<I", data, sec_off + 20)[0]
                raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
                end = raw_offset + raw_size
                if end > last_end:
                    last_end = end
            if last_end > 0 and last_end < len(data) - 4:
                overlay = data[last_end:]
                text = overlay.decode("latin-1", errors="replace")
                fm = self._check_flag(text, flag_pattern)
                findings.append(self._finding(
                    path,
                    f"PE overlay data: {len(overlay)} bytes after last section",
                    f"Overlay at 0x{last_end:x}: {overlay[:64].hex()}",
                    severity="HIGH" if fm else "MEDIUM",
                    offset=last_end,
                    flag_match=fm,
                    confidence=0.80 if fm else 0.65,
                ))
        except Exception:
            pass
        return findings

    def _check_imports(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        strings = run_strings(path, min_len=4)
        hits = [s for s in strings if any(imp in s for imp in _SUSPICIOUS_IMPORTS)]
        if hits:
            findings.append(self._finding(
                path,
                f"Suspicious imported symbols: {len(hits)} found",
                ", ".join(hits[:20]),
                severity="HIGH",
                confidence=0.75,
            ))
        # Flag in strings
        for s in strings:
            if self._check_flag(s, flag_pattern):
                findings.append(self._finding(
                    path,
                    f"Flag pattern in binary strings: {s[:80]}",
                    s,
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.95,
                ))
        return findings
