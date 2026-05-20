from typing import List
from .base import Detector, Finding, Sev, Cat
from ..ir.graph import Graph, Edge
from ..ir.types import T, K

_FROM = frozenset({"from_address", "l1_sender", "l1_address", "sender", "from_addr"})

_U256_REC = (
    "Split uint256 into two slots:\n"
    "  payload[i]   = uint128(v);        // low\n"
    "  payload[i+1] = uint128(v >> 128); // high"
)
_SLOT_REC = (
    "Each uint256 in payload must occupy 2 slots (low u128, high u128).\n"
    "Use: function _enc256(uint256 v) returns (uint256, uint256) { return (uint128(v), uint128(v>>128)); }"
)


class TypeMismatchDetector(Detector):
    did = "cross-layer-type-mismatch"

    def run(self, g: Graph) -> List[Finding]:
        out = []
        for e in g.edges:
            out.extend(self._check(e))
        return out

    def _check(self, e: Edge) -> List[Finding]:
        params = [p for p in e.handler.params if p.name not in _FROM]
        pl = e.send.payload
        if not pl and not params: return []

        out = []
        l1s = sum(t.slots() for t in pl if t.slots() > 0)
        l2s = sum(p.typ.slots() for p in params if p.typ.slots() > 0)
        dyn = any(t.slots() < 0 for t in pl) or any(p.typ.slots() < 0 for p in params)

        if not dyn and l1s != l2s:
            out.append(Finding(self.did, "Payload Slot Count Mismatch",
                f"`{e.send.fn}` sends {l1s} slot(s), `{e.handler.fn}` expects {l2s}. "
                "Cairo will deserialise arguments from wrong offsets (caret shift).",
                Sev.CRITICAL, Cat.TYPE, e.send.loc, rec=_SLOT_REC,
                extra={"l1_slots": l1s, "l2_slots": l2s}))
            return out

        for i, (lt, lp) in enumerate(zip(pl, params)):
            if lt.is_u256() and lp.typ.is_u256():
                out.append(Finding(self.did, "U256 Encoding Warning",
                    f"Arg #{i+1}: `uint256` → `u256` — must be serialised as (low128, high128). "
                    "Wrong order silently corrupts the value.",
                    Sev.HIGH, Cat.TYPE, e.send.loc, rec=_U256_REC,
                    extra={"detector_sub": "U256_ENCODING_WARNING", "arg": i+1,
                           "l1": repr(lt), "l2": repr(lp.typ)}))
            elif not self._compat(lt, lp.typ):
                s1, s2 = lt.slots(), lp.typ.slots()
                sev = Sev.CRITICAL if s1 != s2 else Sev.MEDIUM
                out.append(Finding(self.did, "Type Mismatch",
                    f"Arg #{i+1}: L1 `{lt!r}` ({s1} slot) vs L2 `{lp.typ!r}` ({s2} slot).",
                    sev, Cat.TYPE, e.send.loc,
                    extra={"arg": i+1, "l1": repr(lt), "l2": repr(lp.typ)}))

        if not dyn and len(pl) != len(params):
            out.append(Finding(self.did, "Arg Count Mismatch",
                f"L1 payload has {len(pl)} arg(s), L2 handler expects {len(params)}.",
                Sev.HIGH, Cat.TYPE, e.send.loc,
                extra={"l1_args": len(pl), "l2_args": len(params)}))
        return out

    @staticmethod
    def _compat(a: T, b: T) -> bool:
        if K.UNK in (a.kind, b.kind): return True
        if a.kind == b.kind: return (a.bits == b.bits) if a.bits and b.bits else True
        if frozenset({a.kind, b.kind}) == frozenset({K.ADDR, K.FELT}): return True
        return False
