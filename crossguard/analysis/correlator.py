from __future__ import annotations
import re
from ..ir.graph import Graph, Edge
from .selector import sn_keccak


class Correlator:
    def run(self, g: Graph):
        by_sel = {h.sel: h for h in g.handlers}
        by_name = {h.fn.lower(): h for h in g.handlers}

        for s in g.sends:
            h, how = self._match(s, by_sel, by_name, g)
            if h:
                g.add_edge(Edge(s, h, h.sel, how))

    def _match(self, s, by_sel, by_name, g):
        if s.sel_val is not None:
            h = by_sel.get(s.sel_val)
            if h: return h, "exact"

        expr = (s.sel_expr or "").strip()
        if expr.startswith("0x"):
            try:
                h = by_sel.get(int(expr, 16))
                if h: return h, "hex"
            except ValueError: pass

        name = self._guess(expr)
        if name:
            h = by_sel.get(sn_keccak(name)) or by_name.get(name.lower())
            if h: return h, "name"

        if len(g.handlers) == 1:
            return g.handlers[0], "fallback"

        return None, "?"

    @staticmethod
    def _guess(expr: str) -> str:
        if not expr or expr.startswith("0x") or expr.isdigit(): return ""
        s = re.sub(r"([a-z])([A-Z])", r"\1_\2", expr).lower()
        return s.replace("selector", "").strip("_")
