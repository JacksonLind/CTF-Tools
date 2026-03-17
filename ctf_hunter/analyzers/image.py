"""
Image analyzer: LSB chi-square, appended data, EXIF, palette anomalies.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.external import run_exiftool
from .base import Analyzer


class ImageAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # EXIF metadata
        findings.extend(self._check_exif(path, flag_pattern))

        # Appended data after image end marker
        findings.extend(self._check_appended(path, flag_pattern))

        if depth == "deep":
            # LSB per-channel extraction with chi-square test and printability scoring
            findings.extend(self._check_lsb_chisquare(path, flag_pattern))
            # Palette anomalies
            findings.extend(self._check_palette(path))

        return findings

    # ------------------------------------------------------------------

    def _check_exif(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        findings: List[Finding] = []
        try:
            meta = run_exiftool(path)
        except Exception:
            return []
        for key, value in meta.items():
            s = str(value)
            if self._check_flag(s, flag_pattern):
                findings.append(self._finding(
                    path,
                    f"Flag pattern in EXIF field '{key}'",
                    f"{key}: {s}",
                    severity="HIGH",
                    flag_match=True,
                    confidence=0.95,
                ))
            elif key.lower() in ("comment", "usercomment", "imagedescription", "xpcomment",
                                  "software", "artist", "copyright", "description"):
                if s.strip():
                    findings.append(self._finding(
                        path,
                        f"Interesting EXIF field '{key}'",
                        f"{key}: {s[:200]}",
                        severity="MEDIUM",
                        confidence=0.5,
                    ))
        return findings

    def _check_appended(self, path: str, flag_pattern: re.Pattern) -> List[Finding]:
        try:
            data = Path(path).read_bytes()
        except Exception:
            return []

        markers = {
            b"\x89PNG\r\n\x1a\n": b"IEND\xaeB`\x82",
            b"\xff\xd8\xff":       b"\xff\xd9",
            b"GIF87a":             b"\x3b",
            b"GIF89a":             b"\x3b",
        }
        for start_sig, end_sig in markers.items():
            if data.startswith(start_sig):
                idx = data.rfind(end_sig)
                if idx != -1:
                    after = data[idx + len(end_sig):]
                    if len(after) > 4:
                        fm = self._check_flag(after.decode("latin-1", errors="replace"), flag_pattern)
                        findings = [self._finding(
                            path,
                            f"Appended data after image end ({len(after)} bytes)",
                            f"Data after end marker at offset 0x{idx + len(end_sig):x}: "
                            f"{after[:64].hex()}",
                            severity="HIGH" if fm else "MEDIUM",
                            offset=idx + len(end_sig),
                            flag_match=fm,
                            confidence=0.85 if fm else 0.70,
                        )]
                        return findings
        return []

    def _check_lsb_chisquare(
        self,
        path: str,
        flag_pattern: Optional[re.Pattern] = None,
    ) -> List[Finding]:
        """Per-channel LSB extraction with chi-square test, printability scoring, and flag check.

        For each channel (R, G, B, A, L as available) at bit-plane 0, row-major order:
          - Runs a chi-square test for uniform LSB distribution (stego indicator).
          - Extracts the raw LSB bit-stream and computes printable_ratio (chars 32-126).
          - Checks for a flag-pattern match on the raw stream and after ROT13.
          - Emits a finding if chi2 < 1.0 OR printable_ratio > 0.40 OR flag match.
          - Populates confidence_breakdown with channel, bit_plane, order, printable_ratio,
            flag_match, and chi2 so the score-breakdown UI can surface extraction parameters.
        """
        try:
            from PIL import Image
            import numpy as np
            img = Image.open(path)
        except Exception:
            return []

        try:
            arr = np.array(img)
        except Exception:
            return []

        mode = img.mode
        if arr.ndim == 2:
            channels = [("L", arr)]
        elif arr.ndim == 3 and len(mode) == arr.shape[2]:
            channels = [(mode[i], arr[:, :, i]) for i in range(arr.shape[2])]
        elif arr.ndim == 3:
            channels = [(str(i), arr[:, :, i]) for i in range(arr.shape[2])]
        else:
            return []

        findings: List[Finding] = []

        for ch_name, channel in channels:
            flat = channel.flatten()
            if len(flat) == 0:
                continue

            # Chi-square test on LSB distribution
            lsbs = (flat & 1).astype(int)
            n = int(len(lsbs))
            ones = int(lsbs.sum())
            expected = n / 2
            chi2 = (
                ((ones - expected) ** 2 + (n - ones - expected) ** 2) / expected
                if expected > 0
                else 0.0
            )

            # Extract LSB byte stream using numpy for efficiency
            # Pack every 8 consecutive LSBs into a byte (MSB first)
            lsbs_clipped = lsbs[:100_000]
            # Trim to nearest multiple of 8
            n_bytes = len(lsbs_clipped) // 8
            if n_bytes == 0:
                continue
            lsbs_trim = lsbs_clipped[: n_bytes * 8].reshape(n_bytes, 8)
            weights = np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint8)
            raw = bytes((lsbs_trim * weights).sum(axis=1).astype(np.uint8).tobytes())

            if not raw:
                continue

            # Printability scoring (chars 32-126)
            printable = sum(1 for b in raw if 0x20 <= b <= 0x7E)
            printable_ratio = printable / len(raw)

            # Flag-pattern check on raw stream and ROT13
            flag_match = False
            flag_transform = "none"
            if flag_pattern is not None:
                try:
                    text = raw.decode("latin-1", errors="replace")
                    if flag_pattern.search(text):
                        flag_match = True
                        flag_transform = "raw"
                except Exception:
                    pass

                if not flag_match:
                    try:
                        table = str.maketrans(
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
                        )
                        rot = raw.decode("latin-1", errors="replace").translate(table)
                        if flag_pattern.search(rot):
                            flag_match = True
                            flag_transform = "rot13"
                    except Exception:
                        pass

            # Emission gate: chi2 anomaly, printability, or flag match
            if chi2 >= 1.0 and printable_ratio <= 0.40 and not flag_match:
                continue

            breakdown: dict = {
                "channel": ch_name,
                "bit_plane": 0,
                "order": "row",
                "printable_ratio": round(printable_ratio, 4),
                "flag_match": flag_match,
                "chi2": round(chi2, 4),
            }
            if flag_transform != "none":
                breakdown["flag_transform"] = flag_transform

            raw_preview = raw[:64].decode("latin-1", errors="replace")
            raw_hex = raw[:64].hex()

            if chi2 < 1.0:
                # Very uniform LSB distribution — strong stego indicator
                detail = (
                    f"Uniform LSB distribution suggests LSB steganography. "
                    f"printable_ratio={printable_ratio:.3f} | raw_hex={raw_hex}"
                )
                if flag_match:
                    confidence = 0.92
                    severity = "HIGH"
                elif printable_ratio > 0.40:
                    confidence = 0.82
                    severity = "HIGH"
                else:
                    confidence = 0.70
                    severity = "MEDIUM"

                f = self._finding(
                    path,
                    f"LSB chi-square anomaly — channel={ch_name}, bit_plane=0, order=row"
                    f" (χ²={chi2:.3f})",
                    detail,
                    severity=severity,
                    confidence=confidence,
                    flag_match=flag_match,
                )
                f.confidence_breakdown = breakdown
                findings.append(f)
            else:
                # Printability gate or flag match passed without chi2 anomaly
                detail = (
                    f"raw_hex={raw_hex} | preview={raw_preview!r}"
                )
                confidence = 0.85 if flag_match else 0.60
                severity = "HIGH" if flag_match else "MEDIUM"

                f = self._finding(
                    path,
                    f"LSB extraction — channel={ch_name}, bit_plane=0, order=row"
                    f" (printable_ratio={printable_ratio:.3f})",
                    detail,
                    severity=severity,
                    confidence=confidence,
                    flag_match=flag_match,
                )
                f.confidence_breakdown = breakdown
                findings.append(f)

        return findings

    def _check_palette(self, path: str) -> List[Finding]:
        try:
            from PIL import Image
            img = Image.open(path)
            if img.mode != "P":
                return []
            palette = img.getpalette()
            if palette is None:
                return []
            # Count unique colors
            triples = [(palette[i], palette[i+1], palette[i+2])
                       for i in range(0, len(palette), 3)]
            unique = len(set(triples))
            if unique > 200 or unique < 2:
                palette_hex = bytes(palette).hex()
                return [self._finding(
                    path,
                    f"Abnormal palette size: {unique} unique colors",
                    f"Palette images with unusual color counts may hide data in palette entries.\nraw_hex={palette_hex}",
                    severity="MEDIUM",
                    confidence=0.55,
                )]
        except Exception:
            pass
        return []
