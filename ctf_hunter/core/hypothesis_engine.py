"""
Hypothesis Engine for CTF Hunter.

After confidence scoring completes, this module runs regardless of whether AI is
configured, providing rule-based hypotheses about the most likely attack path.

Rule-based path (always runs):
  - Maintains a decision tree of ~30 CTF attack patterns
  - Matches current session findings against the tree
  - Outputs an ordered list of Hypothesis objects

AI-augmented path (runs additionally if API key configured):
  - Serializes top 15 findings by confidence score into compact JSON
  - Sends to Claude with a CTF-solver system prompt
  - Parses response into AI Hypothesis objects
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .report import Finding, Session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hypothesis dataclass
# ---------------------------------------------------------------------------


@dataclass
class Hypothesis:
    """A structured hypothesis about a CTF challenge attack path."""

    title: str
    confidence: float
    category: str                       # e.g. "Steganography", "Crypto", "Binary"
    required_findings: List[str]        # finding IDs already present
    missing_findings: List[str]         # what to look for next (descriptions)
    suggested_command: str              # concrete shell command or transform chain
    reasoning: str                      # explanation
    source: str = "rule"               # "rule" | "ai"


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

@dataclass
class _Rule:
    """A single pattern rule in the decision tree."""
    title: str
    category: str
    match_fn: object        # callable(findings) -> Optional[tuple(confidence, required_ids, reasoning)]
    missing: List[str]
    command: str


def _matches_title(findings: List[Finding], keywords: List[str]) -> List[Finding]:
    """Return findings whose title contains any of the keywords (case-insensitive)."""
    hits = []
    for f in findings:
        title_lower = f.title.lower()
        if any(kw.lower() in title_lower for kw in keywords):
            hits.append(f)
    return hits


def _high_entropy_png_with_appended(findings: List[Finding]):
    png = _matches_title(findings, ["high entropy", "appended"])
    zip_magic = _matches_title(findings, ["zip", "magic", "embedded"])
    if png and zip_magic:
        ids = [f.id for f in png + zip_magic]
        return (0.82, ids, "High-entropy PNG with appended ZIP magic detected → likely binwalk extraction needed")
    return None


def _rsa_small_e(findings: List[Finding]):
    rsa = _matches_title(findings, ["rsa", "e=3", "small exponent"])
    ct = _matches_title(findings, ["ciphertext", "encrypted"])
    if rsa:
        ids = [f.id for f in rsa + ct]
        return (0.80, ids, "RSA with small public exponent (e=3) detected — cube root or Håstad broadcast applicable")
    return None


def _wiener_attack_hint(findings: List[Finding]):
    hits = _matches_title(findings, ["wiener", "small private exponent"])
    if hits:
        ids = [f.id for f in hits]
        return (0.88, ids, "Wiener's attack succeeded or is applicable")
    return None


def _base64_nested(findings: List[Finding]):
    b64 = _matches_title(findings, ["base64"])
    if len(b64) >= 2:
        ids = [f.id for f in b64]
        return (0.72, ids, "Multiple Base64 encodings found — nested encoding likely")
    return None


def _xor_encrypted(findings: List[Finding]):
    xor = _matches_title(findings, ["xor"])
    if xor:
        max_conf = max(f.confidence for f in xor)
        ids = [f.id for f in xor]
        return (max_conf, ids, "XOR encryption/encoding detected")
    return None


def _lsb_steganography(findings: List[Finding]):
    lsb = _matches_title(findings, ["lsb", "steganography", "steganalysis"])
    if lsb:
        ids = [f.id for f in lsb]
        return (0.75, ids, "LSB steganography detected in image — use zsteg or steghide")
    return None


def _hash_found_crackable(findings: List[Finding]):
    hashes = _matches_title(findings, ["hash found", "md5", "sha1", "sha256"])
    if hashes:
        cracked = _matches_title(findings, ["cracked", "decoded"])
        if cracked:
            ids = [f.id for f in hashes + cracked]
            return (0.90, ids, "Hash found and cracked")
        ids = [f.id for f in hashes]
        return (0.65, ids, "Hash found — attempt wordlist cracking")
    return None


def _pcap_credentials(findings: List[Finding]):
    hits = _matches_title(findings, ["credential", "http", "ftp", "smtp", "password"])
    if hits:
        ids = [f.id for f in hits]
        return (0.78, ids, "Credentials or authentication traffic found in PCAP")
    return None


def _elf_overflow(findings: List[Finding]):
    rop = _matches_title(findings, ["rop", "gadget", "ret2libc", "stack"])
    fmtstr = _matches_title(findings, ["format string", "%n", "%s%s"])
    if rop or fmtstr:
        ids = [f.id for f in rop + fmtstr]
        return (0.77, ids, "Exploit primitives detected (ROP gadgets / format string)")
    return None


def _zip_password_protected(findings: List[Finding]):
    hits = _matches_title(findings, ["encrypted", "password-protected", "archive"])
    if hits:
        cracked = _matches_title(findings, ["cracked", "password found"])
        if cracked:
            ids = [f.id for f in hits + cracked]
            return (0.88, ids, "Encrypted archive with cracked password")
        ids = [f.id for f in hits]
        return (0.60, ids, "Encrypted archive — try rockyou or extracted file strings as password")
    return None


def _morse_or_classical(findings: List[Finding]):
    hits = _matches_title(findings, ["morse", "caesar", "vigenere", "rot13", "atbash", "rail fence"])
    if hits:
        ids = [f.id for f in hits]
        return (0.70, ids, "Classical cipher or encoding detected")
    return None


def _flag_direct(findings: List[Finding]):
    hits = [f for f in findings if f.flag_match and f.confidence >= 0.85]
    if hits:
        ids = [f.id for f in hits]
        return (0.99, ids, "Direct flag match found at high confidence")
    return None


def _pdf_javascript(findings: List[Finding]):
    hits = _matches_title(findings, ["javascript", "embedded", "pdf"])
    if hits:
        ids = [f.id for f in hits]
        return (0.72, ids, "Suspicious PDF JavaScript or embedded object detected")
    return None


def _entropy_anomaly(findings: List[Finding]):
    hits = _matches_title(findings, ["high entropy", "entropy"])
    if hits:
        ids = [f.id for f in hits]
        return (0.60, ids, "High entropy region detected — possible encryption or compression")
    return None


def _polybius_or_tap(findings: List[Finding]):
    hits = _matches_title(findings, ["polybius", "tap code", "baconian", "baudot"])
    if hits:
        ids = [f.id for f in hits]
        return (0.68, ids, "Alternative encoding cipher detected")
    return None


def _rsa_factored(findings: List[Finding]):
    hits = _matches_title(findings, ["factored", "factordb"])
    if hits:
        ids = [f.id for f in hits]
        return (0.92, ids, "RSA modulus successfully factored — private key can be recovered")
    return None


def _common_modulus(findings: List[Finding]):
    hits = _matches_title(findings, ["common modulus", "hastad", "broadcast"])
    if hits:
        ids = [f.id for f in hits]
        return (0.85, ids, "RSA common modulus or Håstad broadcast vulnerability detected")
    return None


def _dns_covert(findings: List[Finding]):
    hits = _matches_title(findings, ["dns", "covert", "tunnel"])
    if hits:
        ids = [f.id for f in hits]
        return (0.70, ids, "DNS covert channel detected in PCAP")
    return None


def _file_hidden_in_image(findings: List[Finding]):
    appended = _matches_title(findings, ["appended", "overlay", "after EOF", "after end"])
    if appended:
        ids = [f.id for f in appended]
        return (0.75, ids, "Hidden data appended after image/file end — run binwalk or foremost")
    return None


def _magic_mismatch(findings: List[Finding]):
    hits = _matches_title(findings, ["magic mismatch", "extension mismatch"])
    if hits:
        ids = [f.id for f in hits]
        return (0.72, ids, "File extension/magic byte mismatch — file may be disguised")
    return None


_RULES: List[_Rule] = [
    _Rule(
        title="Direct flag match",
        category="Flag",
        match_fn=_flag_direct,
        missing=[],
        command="# Flag already found — check Flag Summary tab",
    ),
    _Rule(
        title="RSA factored — recover private key",
        category="Crypto/RSA",
        match_fn=_rsa_factored,
        missing=[],
        command="python3 -c \"p,q=FACTORS; d=pow(e,-1,(p-1)*(q-1)); print(pow(c,d,n).to_bytes(128,'big'))\"",
    ),
    _Rule(
        title="Wiener's attack — small private exponent",
        category="Crypto/RSA",
        match_fn=_wiener_attack_hint,
        missing=[],
        command="# d already recovered by analyzer — use it to decrypt: pow(c,d,n)",
    ),
    _Rule(
        title="RSA Håstad broadcast / common modulus attack",
        category="Crypto/RSA",
        match_fn=_common_modulus,
        missing=["Three ciphertexts encrypted with e=3 and different N"],
        command="# Use CTF analyzer or RsaCtfTool: python3 RsaCtfTool.py --attack hastads",
    ),
    _Rule(
        title="RSA small exponent (e=3) cube root",
        category="Crypto/RSA",
        match_fn=_rsa_small_e,
        missing=[],
        command="python3 -c \"import gmpy2; print(gmpy2.iroot(c,3))\"",
    ),
    _Rule(
        title="PNG with appended ZIP — binwalk extraction",
        category="Steganography",
        match_fn=_high_entropy_png_with_appended,
        missing=["Confirm ZIP magic at file tail"],
        command="binwalk --extract --carve suspicious.png",
    ),
    _Rule(
        title="LSB steganography in image",
        category="Steganography",
        match_fn=_lsb_steganography,
        missing=[],
        command="zsteg -a image.png  # or: steghide extract -sf image.jpg",
    ),
    _Rule(
        title="File hidden after image/file end",
        category="Forensics",
        match_fn=_file_hidden_in_image,
        missing=[],
        command="binwalk -e file  # or: foremost -i file -o output/",
    ),
    _Rule(
        title="File extension / magic byte mismatch",
        category="Forensics",
        match_fn=_magic_mismatch,
        missing=[],
        command="file suspicious_file  # then rename and open with correct tool",
    ),
    _Rule(
        title="XOR encryption — key guessing",
        category="Crypto/XOR",
        match_fn=_xor_encrypted,
        missing=[],
        command="python3 -c \"data=open('file','rb').read(); [print(bytes(b^k for b in data[:100])) for k in range(256)]\"",
    ),
    _Rule(
        title="Nested Base64 encoding",
        category="Encoding",
        match_fn=_base64_nested,
        missing=[],
        command="python3 -c \"import base64; s=open('file').read().strip(); s2=base64.b64decode(s); print(base64.b64decode(s2))\"",
    ),
    _Rule(
        title="Hash cracking — wordlist attack",
        category="Crypto/Hash",
        match_fn=_hash_found_crackable,
        missing=[],
        command="john --wordlist=rockyou.txt hashfile  # or: hashcat -a 0 hash.txt rockyou.txt",
    ),
    _Rule(
        title="PCAP credential extraction",
        category="Network",
        match_fn=_pcap_credentials,
        missing=[],
        command="tshark -r capture.pcap -Y 'http.request' -T fields -e http.authorization",
    ),
    _Rule(
        title="Encrypted archive — password cracking",
        category="Archive",
        match_fn=_zip_password_protected,
        missing=[],
        command="fcrackzip -u -D -p rockyou.txt archive.zip  # or: john --format=zip archive.zip",
    ),
    _Rule(
        title="ELF exploit — ROP / format string",
        category="Binary/Pwn",
        match_fn=_elf_overflow,
        missing=[],
        command="ROPgadget --binary binary --rop  # or: checksec binary",
    ),
    _Rule(
        title="Classical cipher / encoding",
        category="Encoding",
        match_fn=_morse_or_classical,
        missing=[],
        command="# Use CyberChef or the CTF Hunter Transform Pipeline for decode chain",
    ),
    _Rule(
        title="PDF suspicious JavaScript / embedded object",
        category="Document",
        match_fn=_pdf_javascript,
        missing=[],
        command="pdf-parser --search javascript suspicious.pdf",
    ),
    _Rule(
        title="High entropy region — likely encrypted/compressed",
        category="Forensics",
        match_fn=_entropy_anomaly,
        missing=["Identify algorithm (magic bytes, key material, IVs)"],
        command="binwalk --entropy file  # identify high-entropy sections",
    ),
    _Rule(
        title="Alternative encoding (Polybius / Tap / Baconian / Baudot)",
        category="Encoding",
        match_fn=_polybius_or_tap,
        missing=[],
        command="# Use CyberChef or CTF Hunter Transform Pipeline — Polybius/Tap decode",
    ),
    _Rule(
        title="DNS covert channel in PCAP",
        category="Network",
        match_fn=_dns_covert,
        missing=[],
        command="tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort -u",
    ),
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class HypothesisEngine:
    """
    Generates ordered attack hypotheses from session findings.

    Usage::

        engine = HypothesisEngine(ai_client=ai_client)
        hypotheses = engine.generate(session)
    """

    def __init__(self, ai_client=None) -> None:
        self._ai_client = ai_client

    def generate(self, session: Session) -> List[Hypothesis]:
        """Return an ordered list of Hypothesis objects (highest confidence first)."""
        findings = [f for f in session.findings if f.duplicate_of is None]

        hypotheses: List[Hypothesis] = []

        # Rule-based path
        hypotheses.extend(self._rule_based(findings))

        # AI-augmented path
        if self._ai_client and self._ai_client.available:
            ai_hyps = self._ai_augmented(findings, session)
            hypotheses.extend(ai_hyps)

        # Sort by confidence descending
        hypotheses.sort(key=lambda h: -h.confidence)
        # Deduplicate by title
        seen_titles: set = set()
        unique: List[Hypothesis] = []
        for h in hypotheses:
            if h.title not in seen_titles:
                seen_titles.add(h.title)
                unique.append(h)
        return unique

    # ------------------------------------------------------------------

    def _rule_based(self, findings: List[Finding]) -> List[Hypothesis]:
        results: List[Hypothesis] = []
        for rule in _RULES:
            try:
                match = rule.match_fn(findings)
            except Exception:
                continue
            if match is None:
                continue
            confidence, required_ids, reasoning = match
            results.append(Hypothesis(
                title=rule.title,
                confidence=confidence,
                category=rule.category,
                required_findings=required_ids,
                missing_findings=rule.missing,
                suggested_command=rule.command,
                reasoning=reasoning,
                source="rule",
            ))
        return results

    # ------------------------------------------------------------------

    def _ai_augmented(
        self,
        findings: List[Finding],
        session: Session,
    ) -> List[Hypothesis]:
        """Call Claude to generate AI-powered hypotheses."""
        top = sorted(
            [f for f in findings if f.confidence >= 0.4],
            key=lambda f: -f.confidence,
        )[:15]

        summary = [
            {
                "title": f.title,
                "severity": f.severity,
                "confidence": round(f.confidence, 2),
                "analyzer": f.analyzer,
                "detail_snippet": f.detail[:200],
                "flag_match": f.flag_match,
            }
            for f in top
        ]

        prompt = (
            "You are an expert CTF solver. Given the following findings from an automated analysis tool, "
            "identify the most likely challenge category and return a JSON attack plan.\n\n"
            "Findings:\n"
            + json.dumps(summary, indent=2)
            + "\n\nReturn ONLY a JSON object with this schema:\n"
            "{\n"
            '  "category": "string",\n'
            '  "techniques": ["string"],\n'
            '  "ordered_steps": ["string"],\n'
            '  "flag_format_guess": "string",\n'
            '  "hypotheses": [\n'
            '    {"title": "string", "confidence": 0.0-1.0, "reasoning": "string", "command": "string"}\n'
            "  ]\n"
            "}"
        )

        try:
            response = self._ai_client.complete(prompt)
            # Extract JSON from response
            json_match = re.search(r"\{[\s\S]+\}", response)
            if not json_match:
                return []
            data = json.loads(json_match.group())
            results: List[Hypothesis] = []
            for h in data.get("hypotheses", []):
                results.append(Hypothesis(
                    title=h.get("title", "AI Hypothesis"),
                    confidence=float(h.get("confidence", 0.5)),
                    category=data.get("category", "Unknown"),
                    required_findings=[],
                    missing_findings=[],
                    suggested_command=h.get("command", ""),
                    reasoning=h.get("reasoning", ""),
                    source="ai",
                ))
            return results
        except Exception as exc:
            logger.debug("AI hypothesis generation failed: %s", exc)
            return []
