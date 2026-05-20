from __future__ import annotations
import json, re
from typing import Any, Dict, List, Optional, Tuple
from ..ir.graph import Send, Loc
from ..ir.types import Lattice, T

_SEND = frozenset({"sendMessageToL2", "send_message_to_l2"})


class SolParser:
    def __init__(self, ast: dict, fname: str = "?"):
        self._ast = ast
        self._f = fname
        self._con = "?"; self._fn = "?"

    @classmethod
    def load(cls, path: str):
        with open(path) as f: d = json.load(f)
        return cls(d.get("ast") or d.get("AST") or d, path)

    @classmethod
    def from_dict(cls, d: dict, fname="Bridge.sol"):
        return cls(d.get("ast") or d.get("AST") or d, fname)

    def parse(self) -> List[Send]:
        out: List[Send] = []
        self._walk(self._ast, out)
        return out

    def _walk(self, n: Any, out: List[Send]):
        if not isinstance(n, dict): return
        nt = n.get("nodeType", "")

        if nt == "ContractDefinition":
            old = self._con; self._con = n.get("name", "?")
            self._kids(n, out); self._con = old; return

        if nt == "FunctionDefinition":
            old = self._fn; self._fn = n.get("name") or "<fb>"
            self._kids(n, out); self._fn = old; return

        if nt == "FunctionCall" and self._is_send(n):
            s = self._extract(n)
            if s: out.append(s); return

        self._kids(n, out)

    def _kids(self, n: dict, out: List[Send]):
        for v in n.values():
            if isinstance(v, dict): self._walk(v, out)
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, dict): self._walk(x, out)

    def _is_send(self, n: dict) -> bool:
        e = n.get("expression", {})
        if not isinstance(e, dict): return False
        nt = e.get("nodeType")
        if nt == "MemberAccess": return e.get("memberName") in _SEND
        if nt == "FunctionCallOptions":
            ie = e.get("expression", {})
            return isinstance(ie, dict) and ie.get("nodeType") == "MemberAccess" \
                   and ie.get("memberName") in _SEND
        if nt == "Identifier": return e.get("name") in _SEND
        return False

    def _extract(self, n: dict) -> Optional[Send]:
        loc = Loc(self._f, self._src(n.get("src", "0:0:0")))
        args = n.get("arguments", [])
        if len(args) < 2: return None
        sv, se = self._sel(args[1])
        payload = self._payload(args[2]) if len(args) > 2 else []
        return Send(
            contract=self._con, fn=self._fn, loc=loc,
            to=self._es(args[0]), sel_val=sv, sel_expr=se,
            payload=payload, has_fee=self._fee(n),
        )

    def _sel(self, a: dict) -> Tuple[Optional[int], str]:
        nt = a.get("nodeType", "")
        if nt == "Literal":
            raw = a.get("value") or a.get("hexValue", "")
            try: return int(raw, 0), raw
            except: pass
        if nt == "Identifier": return None, a.get("name", "?")
        return None, self._es(a)

    def _payload(self, n: dict) -> List[T]:
        nt = n.get("nodeType", "")
        items = []
        if nt == "TupleExpression": items = n.get("components") or []
        elif nt == "FunctionCall":  items = n.get("arguments") or []
        out = []
        for c in items:
            if not c: continue
            ts = (c.get("typeDescriptions") or {}).get("typeString", "")
            out.append(Lattice.sol(ts.split()[0] if ts else "unknown"))
        return out

    def _fee(self, n: dict) -> bool:
        e = n.get("expression", {})
        if isinstance(e, dict) and e.get("nodeType") == "FunctionCallOptions":
            return "value" in (e.get("names") or [])
        return False

    def _es(self, n: Any) -> str:
        if not isinstance(n, dict): return str(n)
        nt = n.get("nodeType", "")
        if nt == "Literal":    return str(n.get("value") or n.get("hexValue", "?"))
        if nt == "Identifier": return n.get("name", "?")
        if nt == "MemberAccess": return f"{self._es(n.get('expression', {}))}.{n.get('memberName','?')}"
        if nt == "FunctionCall":
            fn = self._es(n.get("expression", {}))
            return f"{fn}({', '.join(self._es(a) for a in n.get('arguments', []))})"
        return (n.get("typeDescriptions") or {}).get("typeString", "<e>")

    @staticmethod
    def _src(s: str) -> int:
        try: return int(s.split(":")[0])
        except: return 0
