"""
ExtractedContent dataclass and helpers for CTF Hunter.

Represents a blob of binary data extracted from an analyzer Finding so that
the recursion pipeline can re-dispatch it through additional analyzers.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# Maximum recursion depth for nested content extraction.
# Callers must not create ExtractedContent with depth > MAX_DEPTH.
MAX_DEPTH = 5

# Regex for raw_hex= tokens embedded in finding detail strings.
# Matches a contiguous run of hex digits following the "raw_hex=" key.
_RAW_HEX_RE = re.compile(r"raw_hex=([0-9a-fA-F]+)")


@dataclass
class ExtractedContent:
    """A blob of binary data extracted from an analyzer Finding."""

    data: bytes
    label: str                  # human-readable description of what this is
    source_finding_id: str      # finding that produced this content
    source_analyzer: str        # analyzer that produced the source finding
    encoding_chain: list[str]   # ordered list of transforms applied so far
    content_hash: str           # SHA256 of data, for dedup
    depth: int                  # recursion depth, max 5
    mime_hint: str = ""         # optional detected mime type
    virtual_filename: str = ""  # optional synthetic filename for dispatcher

    def __post_init__(self) -> None:
        if self.depth > MAX_DEPTH:
            raise ValueError(
                f"ExtractedContent depth {self.depth} exceeds MAX_DEPTH {MAX_DEPTH}"
            )


def extract_from_finding(finding) -> list[ExtractedContent]:
    """Scan a Finding's detail field and return ExtractedContent objects.

    Currently handles:
    - ``raw_hex=<hexdata>`` tokens produced by the steganalysis decode pipeline.

    Each distinct hex blob in the detail string becomes one ExtractedContent
    entry.  Blobs that decode to zero bytes are silently skipped.

    Args:
        finding: A :class:`~ctf_hunter.core.report.Finding` instance.

    Returns:
        A (possibly empty) list of :class:`ExtractedContent` objects.
    """
    results: list[ExtractedContent] = []

    detail: str = getattr(finding, "detail", "") or ""
    finding_id: str = getattr(finding, "id", "")
    analyzer: str = getattr(finding, "analyzer", "")

    for match in _RAW_HEX_RE.finditer(detail):
        hex_str = match.group(1)
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            continue

        if not data:
            continue

        encoding_chain = ["raw_hex"]

        # Strip a 2-byte big-endian length prefix when its value exactly equals
        # the number of remaining bytes.  This handles payloads produced by
        # tools (e.g. steghide-style LSB encoders) that prepend a uint16 BE
        # length field to the actual content.  Without stripping, the extra
        # bytes corrupt the base64 alphabet ratio check in the classifier,
        # causing the downstream XOR brute-forcer to operate on the raw base64
        # characters instead of the decoded payload.
        if len(data) > 2:
            declared_length = int.from_bytes(data[:2], "big")
            if declared_length == len(data) - 2:
                data = data[2:]
                encoding_chain.append("length_prefix_stripped")

        content_hash = hashlib.sha256(data).hexdigest()
        label = f"raw_hex extract from finding '{getattr(finding, 'title', '')}'"

        results.append(
            ExtractedContent(
                data=data,
                label=label,
                source_finding_id=finding_id,
                source_analyzer=analyzer,
                encoding_chain=encoding_chain,
                content_hash=content_hash,
                depth=0,
            )
        )

    return results
