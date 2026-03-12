"""
Finding dataclass and session serialization for CTF Hunter.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional


@dataclass
class Finding:
    """Represents a single anomaly or observation detected by an analyzer."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    file: str = ""
    analyzer: str = ""
    title: str = ""
    severity: str = "INFO"          # HIGH | MEDIUM | LOW | INFO
    offset: int = -1
    detail: str = ""
    flag_match: bool = False
    confidence: float = 0.5
    duplicate_of: Optional[str] = None
    corroboration_count: int = 1
    corroboration: List[str] = field(default_factory=list)  # IDs of supporting findings

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Session:
    """Full analysis session state, saved/loaded as .ctfs JSON."""

    files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: dict[str, str] = field(default_factory=dict)   # path -> note text
    flag_pattern: str = r"CTF\{[^}]+\}"
    depth: str = "fast"    # fast | deep | auto
    watchfolder_path: str = ""
    pipeline_configs: list[dict] = field(default_factory=list)  # saved transform pipelines

    def to_dict(self) -> dict:
        return {
            "files": self.files,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
            "flag_pattern": self.flag_pattern,
            "depth": self.depth,
            "watchfolder_path": self.watchfolder_path,
            "pipeline_configs": self.pipeline_configs,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(
            files=data.get("files", []),
            findings=findings,
            notes=data.get("notes", {}),
            flag_pattern=data.get("flag_pattern", r"CTF\{[^}]+\}"),
            depth=data.get("depth", "fast"),
            watchfolder_path=data.get("watchfolder_path", ""),
            pipeline_configs=data.get("pipeline_configs", []),
        )

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "Session":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))
