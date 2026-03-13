"""
ExtractedContent – a first-class object for re-dispatching decoded payloads.

Analyzers embed raw bytes inside Finding.detail using the ``raw_hex=<hexstring>``
convention.  :func:`extract_from_finding` parses those markers and returns a
list of :class:`ExtractedContent` objects that the dispatcher can treat exactly
like a new file, allowing chained analysis without hardcoding specific decode
sequences.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .report import Finding

# Maximum recursion depth to prevent infinite loops
MAX_DEPTH = 5

# Matches ``raw_hex=<one-or-more hex digits>`` anywhere in a detail string
_RAW_HEX_RE = re.compile(r"raw_hex=([0-9a-fA-F]+)")


@dataclass
class ExtractedContent:
    """A decoded/extracted payload that can be re-dispatched as a new file."""

    data: bytes
    label: str              # human-readable description of what this is
    source_finding_id: str  # finding that produced this content
    source_analyzer: str    # analyzer that produced the source finding
    encoding_chain: list[str]  # ordered list of transforms applied so far
    content_hash: str       # SHA256 of data, for dedup
    depth: int              # recursion depth, max MAX_DEPTH
    mime_hint: str = ""     # optional detected mime type
    virtual_filename: str = ""  # optional synthetic filename for dispatcher

    def __post_init__(self) -> None:
        if self.depth > MAX_DEPTH:
            raise ValueError(
                f"ExtractedContent depth {self.depth} exceeds MAX_DEPTH ({MAX_DEPTH})"
            )


def extract_from_finding(
    finding: Finding, parent_depth: int = 0
) -> list[ExtractedContent]:
    """Scan *finding.detail* and return extracted payloads as :class:`ExtractedContent` objects.

    Currently recognised patterns:

    * ``raw_hex=<hexstring>`` – hex-encoded raw bytes embedded by analyzers such
      as :class:`~ctf_hunter.analyzers.steganalysis.SteganalysisAnalyzer`.

    *parent_depth* should be set to the :attr:`ExtractedContent.depth` of the
    re-dispatched content that produced *finding*, so that each successive layer
    of extraction increments the depth counter.  Payloads whose depth would
    exceed :data:`MAX_DEPTH` are silently skipped to prevent runaway recursion.

    Returns a (possibly empty) list; duplicate hex strings within the same
    finding are deduplicated by their SHA-256 hash.
    """
    next_depth = parent_depth + 1
    if next_depth > MAX_DEPTH:
        return []

    results: list[ExtractedContent] = []
    seen_hashes: set[str] = set()

    for match in _RAW_HEX_RE.finditer(finding.detail):
        hex_str = match.group(1)
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            continue  # malformed hex – skip

        if not data:
            continue

        content_hash = hashlib.sha256(data).hexdigest()
        if content_hash in seen_hashes:
            continue  # deduplicate within this finding
        seen_hashes.add(content_hash)

        results.append(
            ExtractedContent(
                data=data,
                label=f"raw_hex payload from {finding.analyzer}: {finding.title}",
                source_finding_id=finding.id,
                source_analyzer=finding.analyzer,
                encoding_chain=["hex"],
                content_hash=content_hash,
                depth=next_depth,
            )
        )

    return results
