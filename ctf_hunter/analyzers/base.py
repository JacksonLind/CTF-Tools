"""Abstract base class for all analyzers."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient


class Analyzer(ABC):
    """Base class for all CTF analyzers."""

    @abstractmethod
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
    ) -> List[Finding]:
        """Run analysis and return a list of Findings."""
        ...

    # ------------------------------------------------------------------
    # Convenience helpers shared by all analyzers
    # ------------------------------------------------------------------

    def _finding(
        self,
        path: str,
        title: str,
        detail: str = "",
        severity: str = "INFO",
        offset: int = -1,
        flag_match: bool = False,
        confidence: float = 0.5,
    ) -> Finding:
        return Finding(
            file=path,
            analyzer=self.__class__.__name__,
            title=title,
            severity=severity,
            offset=offset,
            detail=detail,
            flag_match=flag_match,
            confidence=confidence,
        )

    def _check_flag(self, text: str, pattern: re.Pattern) -> bool:
        try:
            return bool(pattern.search(text))
        except Exception:
            return False
