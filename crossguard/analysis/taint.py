from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
import re
from ..ir.graph import Graph, Handler, Edge

_PRIV_SINK = re.compile(
    r'\b(transfer|mint|burn|withdraw|set_owner|set_admin|upgrade|'
    r'emit|send_message_to_l1|dispatch|execute|approve)\s*[\(!(]'
)
_SANITIZER = re.compile(
    r'\bassert[!]?\s*\(\s*from_address\s*==|\bfrom_address\s*==\s*self\.\w+\.read'
)


@dataclass
class TaintViolation:
    handler_fn: str
    param_name: str
    sink_hint: str
    path_note: str


class TaintEngine:
    def run(self, g: Graph) -> List[TaintViolation]:
        out = []
        for h in g.handlers:
            out.extend(self._analyze_handler(h))
        return out

    def _analyze_handler(self, h: Handler) -> List[TaintViolation]:
        body = getattr(h, '_body', '')
        if not body:
            ti = getattr(h, '_taint', None)
            if ti and not ti.is_verified and ti.has_priv_sink:
                return [TaintViolation(h.fn, 'from_address',
                    'privileged operation (source body not available)',
                    'taint inferred from parser annotation')]
            return []

        if not h.params or not _PRIV_SINK.search(body):
            return []
        if not _SANITIZER.search(body):
            ti = getattr(h, '_taint', None)
            if ti and not ti.is_verified:
                return [TaintViolation(h.fn, 'from_address',
                    self._first_sink(body) or 'privileged operation',
                    'no from_address assertion found before privileged sink')]
        return []

    @staticmethod
    def _first_sink(body: str) -> Optional[str]:
        m = _PRIV_SINK.search(body)
        return m.group(1) if m else None
