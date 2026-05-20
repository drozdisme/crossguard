from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List
import hashlib
from ..ir.graph import Graph, Loc


class Sev(Enum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"
    MEDIUM = "MEDIUM"; LOW = "LOW"; INFO = "INFO"


class Cat(Enum):
    AUTH = "Authorization"; TYPE = "TypeSafety"
    ASSET = "AssetSafety"; LOGIC = "Logic"


@dataclass
class Finding:
    did: str; title: str; desc: str
    sev: Sev; cat: Cat; loc: Loc
    fid: str = ""
    rec: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.fid:
            raw = f"{self.did}:{self.loc.file}:{self.loc.line}:{self.loc.col}"
            self.fid = "CG-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()

    def to_dict(self):
        return {"id": self.fid, "detector": self.did, "severity": self.sev.value,
                "category": self.cat.value, "title": self.title, "description": self.desc,
                "location": str(self.loc), "recommendation": self.rec, **self.extra}


class Detector:
    did: str = "base"
    def run(self, g: Graph) -> List[Finding]: raise NotImplementedError
