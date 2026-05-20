from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from ..ir.graph import Graph
from ..parsers.solidity import SolParser
from ..parsers.cairo import CaiParser
from ..detectors.base import Finding
from ..detectors.d1_sender import SenderCheckDetector
from ..detectors.d2_types import TypeMismatchDetector
from ..detectors.d3_fee import FeeDetector
from .correlator import Correlator


@dataclass
class Ctx:
    graph: Graph = field(default_factory=Graph)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def critical(self):
        from ..detectors.base import Sev
        return any(f.sev == Sev.CRITICAL for f in self.findings)


class Engine:
    def __init__(self):
        self.detectors = [SenderCheckDetector(), TypeMismatchDetector(), FeeDetector()]
        self._hooks: List[Callable[[Finding], None]] = []

    def on_finding(self, fn): self._hooks.append(fn); return self

    def analyze(self, *, l1_path=None, l2_path=None, l1_data=None, l2_data=None) -> Ctx:
        ctx = Ctx()
        self._l1(ctx, l1_path, l1_data)
        self._l2(ctx, l2_path, l2_data)
        Correlator().run(ctx.graph)
        for d in self.detectors:
            try:
                for f in d.run(ctx.graph):
                    ctx.findings.append(f)
                    for h in self._hooks: h(f)
            except Exception as e:
                ctx.errors.append(f"[{d.did}] {e}")
        return ctx

    def _l1(self, ctx, path, data):
        try:
            p = SolParser.load(path) if path else SolParser.from_dict(data)
            for s in p.parse(): ctx.graph.add_send(s)
        except Exception as e: ctx.errors.append(f"[l1] {e}")

    def _l2(self, ctx, path, data):
        try:
            p = CaiParser.load(path) if path else CaiParser.from_dict(data)
            for h in p.parse(): ctx.graph.add_handler(h)
        except Exception as e: ctx.errors.append(f"[l2] {e}")
