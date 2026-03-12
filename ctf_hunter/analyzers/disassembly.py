"""
Disassembly analyzer: r2pipe (radare2) primary engine with Capstone linear fallback.

Supports ELF, PE, and .so files.  Extracts imports, exports, relocations, GOT
entries, a consolidated Symbol Map, per-function CFGs, and entry-point
disassembly.  Falls back to the original Capstone linear disassembler when
r2pipe / radare2 are not installed.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Imports that are commonly abused in CTF pwn/exploit challenges
_DANGEROUS_IMPORTS: set[str] = {
    "system", "execve", "gets", "strcpy", "printf",
    "read", "mmap", "mprotect",
}


# ---------------------------------------------------------------------------
# Helpers shared by both engines
# ---------------------------------------------------------------------------

def _is_supported_binary(data: bytes) -> bool:
    """Return True if *data* looks like an ELF, PE, or shared-object binary."""
    return data[:4] == b"\x7fELF" or data[:2] == b"MZ"


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
            # Check PE optional header machine field for 32/64
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
            if data[pe_off:pe_off + 4] != b"PE\x00\x00":
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


# ---------------------------------------------------------------------------
# Capstone fallback (original linear disassembly path)
# ---------------------------------------------------------------------------

def _capstone_fallback(
    analyzer: "DisassemblyAnalyzer",
    path: str,
    data: bytes,
    depth: str,
    ai_client: Optional[AIClient],
    findings: List[Finding],
) -> List[Finding]:
    """Run the original Capstone linear disassembly as a fallback engine."""
    import capstone

    arch, mode = _get_capstone_arch(data)
    if arch is None:
        findings.append(analyzer._finding(
            path,
            "Disassembly skipped: unrecognized binary format",
            "",
            severity="INFO",
            confidence=0.1,
        ))
        return findings

    code_offset, code_bytes = _find_code_section(data)
    if not code_bytes:
        findings.append(analyzer._finding(
            path,
            "No executable section found",
            "",
            severity="INFO",
            confidence=0.3,
        ))
        return findings

    try:
        md = capstone.Cs(arch, mode)
        md.detail = False
        if depth == "fast":
            insns = list(md.disasm(code_bytes, code_offset))[:100]
        else:
            insns = list(md.disasm(code_bytes, code_offset))
    except Exception as exc:
        findings.append(analyzer._finding(
            path, f"Disassembly error: {exc}", "", confidence=0.2,
        ))
        return findings

    if not insns:
        findings.append(analyzer._finding(
            path,
            "No instructions disassembled",
            "",
            severity="INFO",
            confidence=0.2,
        ))
        return findings

    lines = [
        f"0x{ins.address:08x}:  {ins.mnemonic:<10} {ins.op_str}"
        for ins in insns
    ]
    asm_text = "\n".join(lines)
    detail = f"Disassembled {len(insns)} instructions from offset 0x{code_offset:x}"

    findings.append(analyzer._finding(
        path,
        f"Disassembly ({len(insns)} instructions, "
        f"arch={'x64' if mode == capstone.CS_MODE_64 else 'x86/ARM'})",
        detail + "\n\n" + asm_text[:3000],
        severity="INFO",
        offset=code_offset,
        confidence=0.6,
    ))

    if depth == "deep" and ai_client and ai_client.available:
        summary = ai_client.explain_disassembly(asm_text)
        if summary:
            findings.append(analyzer._finding(
                path,
                "AI disassembly summary",
                summary,
                severity="MEDIUM",
                offset=code_offset,
                confidence=0.65,
            ))

    return findings


# ---------------------------------------------------------------------------
# r2pipe primary engine
# ---------------------------------------------------------------------------

def _r2_analyze(
    analyzer: "DisassemblyAnalyzer",
    path: str,
    data: bytes,
    depth: str,
    ai_client: Optional[AIClient],
) -> List[Finding]:
    """Full r2pipe-based analysis: symbols, relocations, GOT, CFG, disassembly.

    Opens the binary with ``r2pipe.open(path, flags=["-2", "-A"])`` so that
    radare2 suppresses stderr (-2) and runs a full auto-analysis on open (-A,
    equivalent to ``aaa``).  The session is always closed in a ``finally``
    block to prevent zombie r2 processes.
    """
    import r2pipe  # noqa: F401 – ImportError propagates to caller for fallback

    findings: List[Finding] = []
    r2 = None
    try:
        # -2: suppress stderr   -A: run aaa (full analysis) on open
        r2 = r2pipe.open(path, flags=["-2", "-A"])

        # Detect whether this is a shared library by file name
        p = Path(path)
        is_so = p.suffix == ".so" or ".so." in p.name

        # ------------------------------------------------------------------ #
        # Step 2a – Imports (iij)                                              #
        # ------------------------------------------------------------------ #
        imports_raw: list = r2.cmdj("iij") or []
        dangerous_found: list[tuple[int, str]] = []
        import_rows: list[str] = []

        for imp in imports_raw:
            name: str = imp.get("name", "")
            plt: int = imp.get("plt", imp.get("vaddr", 0)) or 0
            # Strip leading underscores and '@plt' suffix for matching
            base_name = name.split("@")[0].lstrip("_")
            import_rows.append(f"  0x{plt:08x}  {name}")
            if base_name in _DANGEROUS_IMPORTS:
                dangerous_found.append((plt, name))

        if import_rows:
            findings.append(analyzer._finding(
                path,
                f"Imports ({len(import_rows)} found)",
                "\n".join(import_rows),
                severity="INFO",
                confidence=0.7,
            ))

        for plt_addr, imp_name in dangerous_found:
            findings.append(analyzer._finding(
                path,
                f"Dangerous import: {imp_name}",
                f"PLT address 0x{plt_addr:08x} — commonly exploited in CTF challenges",
                severity="HIGH",
                offset=plt_addr,
                confidence=0.85,
            ))

        # ------------------------------------------------------------------ #
        # Step 2b – Exports (iEj)                                              #
        # ------------------------------------------------------------------ #
        # r2 command: iEj = exports as JSON.  For .so files this is the
        # primary entry-point list (all publicly visible symbols).
        exports_raw: list = r2.cmdj("iEj") or []

        for exp in exports_raw:
            name: str = exp.get("name", "")
            vaddr: int = exp.get("vaddr", 0) or 0
            real_name: str = exp.get("realname", name)
            findings.append(analyzer._finding(
                path,
                f"Export: {name}",
                f"Address 0x{vaddr:08x}  (demangled: {real_name})",
                severity="MEDIUM" if is_so else "INFO",
                offset=vaddr,
                confidence=0.75,
            ))

        # ------------------------------------------------------------------ #
        # Step 2c – Relocations (irj)                                          #
        # ------------------------------------------------------------------ #
        relocs_raw: list = r2.cmdj("irj") or []

        unresolved = [r for r in relocs_raw if not r.get("name")]
        if unresolved:
            reloc_lines = [
                f"  0x{r.get('vaddr', 0):08x}  type={r.get('type', '?')}"
                for r in unresolved[:50]
            ]
            findings.append(analyzer._finding(
                path,
                f"Unresolved relocations ({len(unresolved)})",
                "\n".join(reloc_lines),
                severity="INFO",
                confidence=0.6,
            ))

        # ------------------------------------------------------------------ #
        # Step 2d – GOT entries                                                #
        # Extract GOT entries from relocation table: any relocation whose     #
        # type contains "GOT" is a GOT slot.                                  #
        # ------------------------------------------------------------------ #
        got_entries = [
            r for r in relocs_raw
            if "GOT" in r.get("type", "").upper()
        ]
        if got_entries:
            got_lines = [
                f"  0x{r.get('vaddr', 0):08x}  {r.get('name', '<unnamed>')}"
                for r in got_entries[:50]
            ]
            findings.append(analyzer._finding(
                path,
                f"GOT entries ({len(got_entries)})",
                "\n".join(got_lines),
                severity="INFO",
                confidence=0.65,
            ))

        # ------------------------------------------------------------------ #
        # Step 2e – Consolidated Symbol Map (INFO, for AI consumption)         #
        # ------------------------------------------------------------------ #
        sym_lines: list[str] = ["=== IMPORTS ==="]
        sym_lines += import_rows or ["  (none)"]
        sym_lines.append("=== EXPORTS ===")
        sym_lines += [
            f"  0x{e.get('vaddr', 0):08x}  {e.get('name', '')}"
            for e in exports_raw
        ] or ["  (none)"]
        sym_lines.append("=== RELOCATIONS ===")
        sym_lines += [
            f"  0x{r.get('vaddr', 0):08x}  "
            f"{r.get('name', '<unnamed>')}  type={r.get('type', '?')}"
            for r in relocs_raw[:50]
        ] or ["  (none)"]

        findings.append(analyzer._finding(
            path,
            "Symbol Map",
            "\n".join(sym_lines),
            severity="INFO",
            confidence=0.7,
        ))

        # ------------------------------------------------------------------ #
        # Step 3 – Function list (aflj) + per-function CFG (agfj)              #
        # ------------------------------------------------------------------ #
        funcs: list = r2.cmdj("aflj") or []

        if funcs:
            func_limit = 20 if depth == "fast" else len(funcs)
            cfg_lines: list[str] = []

            for func in funcs[:func_limit]:
                fname: str = func.get("name", "?")
                faddr: int = func.get("offset", 0) or 0
                cfg_raw = r2.cmdj(f"agfj @ 0x{faddr:x}") or []
                n_blocks = (
                    len(cfg_raw[0].get("blocks", []))
                    if cfg_raw and len(cfg_raw) > 0 else 0
                )
                cfg_lines.append(
                    f"  0x{faddr:08x}  {fname}  basic_blocks={n_blocks}"
                )

            findings.append(analyzer._finding(
                path,
                f"Function list ({len(funcs)} functions, "
                f"showing {min(func_limit, len(funcs))})",
                "\n".join(cfg_lines),
                severity="INFO",
                confidence=0.7,
            ))

        # ------------------------------------------------------------------ #
        # Entry-point disassembly for AI context                               #
        # ------------------------------------------------------------------ #
        entries_raw: list = r2.cmdj("iej") or []
        entry_addr: Optional[int] = None
        for entry in entries_raw:
            if entry.get("type") == "program" or not entry_addr:
                entry_addr = entry.get("vaddr")
                break

        if entry_addr is None and funcs:
            entry_addr = funcs[0].get("offset")

        asm_text = ""
        if entry_addr is not None:
            n_insns = 50 if depth == "fast" else 200
            disasm = r2.cmd(f"pd {n_insns} @ 0x{entry_addr:x}") or ""
            asm_text = disasm.strip()
            if asm_text:
                findings.append(analyzer._finding(
                    path,
                    f"Disassembly at entry 0x{entry_addr:08x}",
                    asm_text[:3000],
                    severity="INFO",
                    offset=entry_addr,
                    confidence=0.7,
                ))

        if depth == "deep" and ai_client and ai_client.available and asm_text:
            summary = ai_client.explain_disassembly(asm_text)
            if summary:
                findings.append(analyzer._finding(
                    path,
                    "AI disassembly summary",
                    summary,
                    severity="MEDIUM",
                    offset=entry_addr if entry_addr is not None else -1,
                    confidence=0.65,
                ))

    finally:
        # Always close the r2 session to prevent zombie r2 processes
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# Analyzer class
# ---------------------------------------------------------------------------

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
            data = Path(path).read_bytes()
        except Exception as exc:
            return [self._finding(path, f"Read error: {exc}", "", confidence=0.1)]

        if not _is_supported_binary(data):
            return [self._finding(
                path,
                "Disassembly skipped: unrecognized binary format",
                "",
                severity="INFO",
                confidence=0.1,
            )]

        # ------------------------------------------------------------------ #
        # Primary engine: r2pipe                                               #
        # ------------------------------------------------------------------ #
        try:
            import r2pipe  # noqa: F401
            return _r2_analyze(self, path, data, depth, ai_client)
        except ImportError:
            findings.append(self._finding(
                path,
                "r2pipe not found — using linear disassembly fallback; "
                "install radare2 for full analysis",
                "",
                severity="INFO",
                confidence=0.3,
            ))

        # ------------------------------------------------------------------ #
        # Fallback engine: Capstone linear disassembly                         #
        # ------------------------------------------------------------------ #
        try:
            import capstone  # noqa: F401
        except ImportError:
            return findings + [self._finding(
                path,
                "Disassembly skipped: capstone not installed",
                "",
                severity="INFO",
                confidence=0.1,
            )]

        return _capstone_fallback(self, path, data, depth, ai_client, findings)
