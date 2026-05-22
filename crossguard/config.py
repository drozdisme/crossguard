from __future__ import annotations
import tomllib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class AnalysisConfig:
    l1: str = ""
    l2: str = ""
    detectors: List[str] = field(default_factory=lambda: ["all"])
    fail_on: str = "HIGH"
    output_format: str = "terminal"
    output_file: Optional[str] = None
    color: bool = True
    parser_timeout_ms: int = 30_000
    max_path_depth: int = 10

    @classmethod
    def load(cls, path: str = "crossguard.toml") -> 'AnalysisConfig':
        p = Path(path)
        if not p.exists():
            return cls()
        try:
            data = tomllib.loads(p.read_text()) if p.suffix == '.toml' else json.loads(p.read_text())
            t = data.get("tool", {}).get("crossguard", data)
            return cls(
                l1=t.get("l1_contract", ""),
                l2=t.get("l2_contract", ""),
                detectors=t.get("detectors", ["all"]),
                fail_on=t.get("fail_on", "HIGH").upper(),
                output_format=t.get("output_format", "terminal"),
                output_file=t.get("output_file"),
                color=t.get("color", True),
                parser_timeout_ms=t.get("parser_timeout_ms", 30_000),
                max_path_depth=t.get("max_path_depth", 10),
            )
        except Exception:
            return cls()
