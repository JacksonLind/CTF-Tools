"""
Steganalysis analyzer: bit planes, LSB extraction, channel isolation, histograms.
Results are returned as Finding detail payloads for display in the Steg Viewer tab.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer


class SteganalysisAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            from PIL import Image
            import numpy as np
        except ImportError:
            return [self._finding(
                path,
                "Steganalysis skipped: PIL/numpy not installed",
                "",
                severity="INFO",
                confidence=0.1,
            )]

        try:
            img = Image.open(path)
        except Exception as exc:
            return [self._finding(path, "Image open error", str(exc), confidence=0.1)]

        # Convert to numpy array
        try:
            arr = np.array(img)
        except Exception:
            return []

        mode = img.mode
        channel_names = list(mode) if mode in ("RGB", "RGBA", "L") else ["L"]

        # --- Bit planes per channel ---
        for ch_idx, ch_name in enumerate(channel_names):
            if arr.ndim == 2:
                channel = arr
            elif arr.ndim == 3 and ch_idx < arr.shape[2]:
                channel = arr[:, :, ch_idx]
            else:
                continue

            for bit in range(8):
                plane = ((channel >> bit) & 1).astype("uint8") * 255
                # Check if this bit plane has non-random structure (uniform would be stego)
                ones_ratio = plane.sum() / (255 * plane.size) if plane.size > 0 else 0.5
                if depth == "deep" and abs(ones_ratio - 0.5) < 0.02 and bit == 0:
                    findings.append(self._finding(
                        path,
                        f"LSB plane of channel {ch_name} is unusually uniform",
                        f"Channel {ch_name} bit-0 ones ratio: {ones_ratio:.4f} (near 0.5 = possible stego)",
                        severity="HIGH",
                        confidence=0.75,
                    ))

        # --- LSB plane extraction ---
        if arr.ndim >= 2:
            try:
                lsb_text = self._extract_lsb_text(arr, channel_names)
                if lsb_text:
                    fm = self._check_flag(lsb_text, flag_pattern)
                    findings.append(self._finding(
                        path,
                        "LSB plane text extraction",
                        f"LSB data (first 200 chars): {lsb_text[:200]}",
                        severity="HIGH" if fm else "MEDIUM",
                        flag_match=fm,
                        confidence=0.80 if fm else 0.55,
                    ))
            except Exception:
                pass

        # --- Per-channel histogram summary ---
        for ch_idx, ch_name in enumerate(channel_names):
            if arr.ndim == 2:
                channel = arr.flatten()
            elif arr.ndim == 3 and ch_idx < arr.shape[2]:
                channel = arr[:, :, ch_idx].flatten()
            else:
                continue
            histogram = [int(x) for x in import_numpy_histogram(channel)]
            # Detect spiked histogram (pairs of identical bars = palette manipulation)
            max_val = max(histogram) if histogram else 0
            min_val = min(histogram) if histogram else 0
            if max_val > 0 and (max_val - min_val) / max_val > 0.98:
                findings.append(self._finding(
                    path,
                    f"Highly non-uniform histogram in channel {ch_name}",
                    "Spiky histogram may indicate palette manipulation or steganography.",
                    severity="MEDIUM",
                    confidence=0.55,
                ))

        return findings

    def _extract_lsb_text(self, arr, channel_names: list) -> str:
        import numpy as np
        bits = []
        if arr.ndim == 3:
            ch = arr[:, :, 0].flatten()
        else:
            ch = arr.flatten()
        for val in ch[:100000]:
            bits.append(int(val) & 1)

        # Pack into bytes
        result = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte_val = 0
            for j in range(8):
                byte_val |= bits[i + j] << (7 - j)
            result.append(byte_val)

        printable = bytes(b for b in result if 0x20 <= b <= 0x7E or b in (9, 10, 13))
        if len(printable) > 15:
            return printable.decode("ascii", errors="replace")
        return ""


def import_numpy_histogram(channel):
    """Compute 256-bucket histogram without relying on numpy.histogram signature."""
    try:
        import numpy as np
        counts = np.zeros(256, dtype=int)
        for v in channel:
            counts[int(v) % 256] += 1
        return counts.tolist()
    except Exception:
        return [0] * 256
