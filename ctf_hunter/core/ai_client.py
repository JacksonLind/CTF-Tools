"""
Claude AI client wrapper for CTF Hunter.
Uses the Anthropic Python SDK with claude-sonnet-4-20250514.
"""
from __future__ import annotations

import os
from typing import List, Optional

_ANTHROPIC_AVAILABLE = False
try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    pass

MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 1024


class AIClient:
    """Wraps the Anthropic Claude API; silently disabled if key is not set."""

    def __init__(self, api_key: Optional[str] = None):
        self._key: Optional[str] = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._client = None
        self._init_client()

    def _init_client(self) -> None:
        if _ANTHROPIC_AVAILABLE and self._key:
            try:
                self._client = anthropic.Anthropic(api_key=self._key)
            except Exception:
                self._client = None

    def set_api_key(self, key: str) -> None:
        self._key = key
        self._init_client()

    @property
    def available(self) -> bool:
        return self._client is not None

    def _ask(self, prompt: str) -> str:
        if not self.available:
            return ""
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text if response.content else ""
        except Exception as exc:
            return f"[AI error: {exc}]"

    def analyze_findings(
        self,
        file_path: str,
        findings_summary: str,
        hex_context: str,
    ) -> str:
        """Return plain-English attack hypothesis for a single file."""
        prompt = (
            f"You are a CTF (Capture the Flag) challenge analyst. "
            f"Analyze the following findings for the file '{file_path}' and provide a "
            f"concise plain-English hypothesis about what steganographic, cryptographic, "
            f"or forensic technique might be hiding the flag.\n\n"
            f"Findings:\n{findings_summary}\n\n"
            f"Hex context (256 bytes around highest-confidence offset):\n{hex_context}\n\n"
            f"Provide a numbered list of the most likely attack paths to try."
        )
        return self._ask(prompt)

    def explain_disassembly(self, asm_text: str) -> str:
        """Return plain-English summary of disassembled code."""
        prompt = (
            "You are a reverse-engineering expert. Summarize the following x86/x64/ARM "
            "disassembly in plain English, avoiding heavy jargon. Focus on what the code "
            "does at a high level, any suspicious operations, and any patterns relevant to "
            "a CTF challenge.\n\n"
            f"Assembly:\n{asm_text[:4000]}"
        )
        return self._ask(prompt)

    def holistic_analysis(self, all_findings_summary: str) -> str:
        """Return prioritized recommendation across all files in the session."""
        prompt = (
            "You are a CTF competition analyst. Below are findings from multiple files "
            "in a CTF challenge session. Identify the most promising lead and explain "
            "step-by-step what to investigate first.\n\n"
            f"All findings:\n{all_findings_summary[:6000]}"
        )
        return self._ask(prompt)
