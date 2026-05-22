from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..ir.graph import Graph
from ..parsers.solidity import SolParser
from ..parsers.cairo import CaiParser
from ..parsers.solidity_source import SolSourceParser
from ..parsers.cairo_source import CaiSourceParser
from ..detectors.base import Finding, Sev
from ..detectors.d1_sender import SenderCheckDetector
from ..detectors.d2_types import TypeMismatchDetector
from ..detectors.d3_fee import FeeDetector
from ..detectors.d4_cancellation import CancellationDetector
from ..detectors.d5_replay import ReplayRiskDetector
from .correlator import Correlator
from .taint import TaintEngine


@dataclass
class Ctx:
    graph: Graph = field(default_factory=Graph)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    taint_violations: List = field(default_factory=list)

    @property
    def critical(self):
        return any(f.sev == Sev.CRITICAL for f in self.findings)

    @property
    def summary(self) -> Dict[str, int]:
        return {s.value: sum(1 for f in self.findings if f.sev == s) for s in Sev}


class Engine:
    def __init__(self, extra_detectors=None):
        self.detectors = [
            SenderCheckDetector(), TypeMismatchDetector(), FeeDetector(),
            CancellationDetector(), ReplayRiskDetector(),
        ]
        if extra_detectors:
            self.detectors.extend(extra_detectors)
        self._hooks: List[Callable[[Finding], None]] = []

    def on_finding(self, fn):
        self._hooks.append(fn)
        return self

    def analyze(self, *, l1_path=None, l2_path=None, l1_data=None, l2_data=None) -> Ctx:
        ctx = Ctx()
        self._ingest_l1(ctx, l1_path, l1_data)
        self._ingest_l2(ctx, l2_path, l2_data)
        Correlator().run(ctx.graph)
        ctx.taint_violations = TaintEngine().run(ctx.graph)
        for d in self.detectors:
            try:
                for f in d.run(ctx.graph):
                    ctx.findings.append(f)
                    for h in self._hooks:
                        h(f)
            except Exception as e:
                ctx.errors.append(f"[{d.did}] {type(e).__name__}: {e}")
        ctx.findings.sort(key=lambda f: (list(Sev).index(f.sev), str(f.loc)))
        return ctx

    def _ingest_l1(self, ctx, path, data):
        if path and os.path.exists(path):
            ext = Path(path).suffix.lower()
            if ext == '.sol':
                self._l1_source(ctx, path); return
            elif ext in ('.json', '.ast'):
                self._l1_json(ctx, path=path); return
        if data:
            self._l1_json(ctx, data=data)

    def _l1_source(self, ctx, path):
        try:
            p = SolSourceParser.load(path)
            for s in p.parse_sends():
                ctx.graph.add_send(s)
            cancellations = p.parse_cancellations()
            if not hasattr(ctx.graph, 'cancellations'):
                ctx.graph.cancellations = []
            ctx.graph.cancellations.extend(cancellations)
        except Exception as e:
            ctx.errors.append(f"[l1-source] {type(e).__name__}: {e}")

    def _l1_json(self, ctx, path=None, data=None):
        try:
            p = SolParser.load(path) if path else SolParser.from_dict(data)
            for s in p.parse():
                ctx.graph.add_send(s)
        except Exception as e:
            ctx.errors.append(f"[l1] {type(e).__name__}: {e}")

    def _ingest_l2(self, ctx, path, data):
        if path and os.path.exists(path):
            ext = Path(path).suffix.lower()
            if ext == '.cairo':
                self._l2_source(ctx, path); return
            elif ext in ('.json', '.sierra'):
                self._l2_json(ctx, path=path); return
        if data:
            self._l2_json(ctx, data=data)

    def _l2_source(self, ctx, path):
        try:
            p = CaiSourceParser.load(path)
            for h in p.parse():
                ctx.graph.add_handler(h)
        except Exception as e:
            ctx.errors.append(f"[l2-source] {type(e).__name__}: {e}")

    def _l2_json(self, ctx, path=None, data=None):
        try:
            p = CaiParser.load(path) if path else CaiParser.from_dict(data)
            for h in p.parse():
                ctx.graph.add_handler(h)
        except Exception as e:
            ctx.errors.append(f"[l2] {type(e).__name__}: {e}")
