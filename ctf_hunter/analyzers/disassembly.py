"""
Disassembly analyzer: x86/x64/ARM disassembly via Capstone + optional AI summary.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer


def _get_capstone_arch(data: bytes):
    """Determine capstone arch/mode from ELF/PE header."""
    try:
        import capstone as cs
        if data[:4] == b"\x7fELF":
            ei_class = data[4]  # 1=32, 2=64
            e_machine = struct.unpack_from("<H", data, 18)[0]
            if e_machine == 0x28:   # ARM
                return cs.CS_ARCH_ARM, cs.CS_MODE_ARM
            if e_machine == 0xb7:   # AArch64
                return cs.CS_ARCH_ARM64, cs.CS_MODE_ARM
            if ei_class == 2:
                return cs.CS_ARCH_X86, cs.CS_MODE_64
            return cs.CS_ARCH_X86, cs.CS_MODE_32
        elif data[:2] == b"MZ":
            # Check PE optional header magic for 32/64
            try:
                pe_off = struct.unpack_from("<I", data, 0x3C)[0]
                machine = struct.unpack_from("<H", data, pe_off + 4)[0]
                if machine == 0x8664:
                    return cs.CS_ARCH_X86, cs.CS_MODE_64
                return cs.CS_ARCH_X86, cs.CS_MODE_32
            except Exception:
                return cs.CS_ARCH_X86, cs.CS_MODE_32
    except ImportError:
        pass
    return None, None


def _find_code_section(data: bytes) -> tuple[int, bytes]:
    """Return (offset, code_bytes) for the first executable section."""
    if data[:4] == b"\x7fELF":
        # ELF: find first SHT_PROGBITS section with EXECINSTR flag
        try:
            ei_class = data[4]
            if ei_class == 2:  # 64-bit
                e_shoff = struct.unpack_from("<Q", data, 40)[0]
                e_shentsize = struct.unpack_from("<H", data, 58)[0]
                e_shnum = struct.unpack_from("<H", data, 60)[0]
                for i in range(min(e_shnum, 40)):
                    sh_off = e_shoff + i * e_shentsize
                    sh_type = struct.unpack_from("<I", data, sh_off + 4)[0]
                    sh_flags = struct.unpack_from("<Q", data, sh_off + 8)[0]
                    sh_offset = struct.unpack_from("<Q", data, sh_off + 24)[0]
                    sh_size = struct.unpack_from("<Q", data, sh_off + 32)[0]
                    SHF_EXECINSTR = 0x4
                    if sh_type == 1 and sh_flags & SHF_EXECINSTR:
                        return sh_offset, data[sh_offset:sh_offset + sh_size]
        except Exception:
            pass
        return 0, data[:4096]
    elif data[:2] == b"MZ":
        try:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_off:pe_off+4] != b"PE\x00\x00":
                return 0, data[:4096]
            num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
            opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
            sec_tab = pe_off + 24 + opt_size
            for i in range(num_sections):
                sec_off = sec_tab + i * 40
                characteristics = struct.unpack_from("<I", data, sec_off + 36)[0]
                IMAGE_SCN_CNT_CODE = 0x20
                IMAGE_SCN_MEM_EXECUTE = 0x20000000
                if characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE):
                    raw_offset = struct.unpack_from("<I", data, sec_off + 20)[0]
                    raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
                    return raw_offset, data[raw_offset:raw_offset + raw_size]
        except Exception:
            pass
        return 0, data[:4096]
    return 0, data[:4096]


class DisassemblyAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            import capstone
        except ImportError:
            return [self._finding(
                path,
                "Disassembly skipped: capstone not installed",
                "",
                severity="INFO",
                confidence=0.1,
            )]

        try:
            data = Path(path).read_bytes()
        except Exception as exc:
            return [self._finding(path, f"Read error: {exc}", "", confidence=0.1)]

        arch, mode = _get_capstone_arch(data)
        if arch is None:
            return [self._finding(
                path,
                "Disassembly skipped: unrecognized binary format",
                "",
                severity="INFO",
                confidence=0.1,
            )]

        code_offset, code_bytes = _find_code_section(data)
        if not code_bytes:
            return [self._finding(
                path,
                "No executable section found",
                "",
                severity="INFO",
                confidence=0.3,
            )]

        try:
            md = capstone.Cs(arch, mode)
            md.detail = False
            if depth == "fast":
                insns = list(md.disasm(code_bytes, code_offset))[:100]
            else:
                insns = list(md.disasm(code_bytes, code_offset))
        except Exception as exc:
            return [self._finding(path, f"Disassembly error: {exc}", "", confidence=0.2)]

        if not insns:
            return [self._finding(
                path,
                "No instructions disassembled",
                "",
                severity="INFO",
                confidence=0.2,
            )]

        # Format output
        lines = [f"0x{ins.address:08x}:  {ins.mnemonic:<10} {ins.op_str}" for ins in insns]
        asm_text = "\n".join(lines)

        severity = "INFO"
        detail = f"Disassembled {len(insns)} instructions from offset 0x{code_offset:x}"

        findings.append(self._finding(
            path,
            f"Disassembly ({len(insns)} instructions, arch={'x64' if mode == capstone.CS_MODE_64 else 'x86/ARM'})",
            detail + "\n\n" + asm_text[:3000],
            severity=severity,
            offset=code_offset,
            confidence=0.6,
        ))

        # AI summary in deep mode
        if depth == "deep" and ai_client and ai_client.available:
            summary = ai_client.explain_disassembly(asm_text)
            if summary:
                findings.append(self._finding(
                    path,
                    "AI disassembly summary",
                    summary,
                    severity="MEDIUM",
                    offset=code_offset,
                    confidence=0.65,
                ))

        return findings
