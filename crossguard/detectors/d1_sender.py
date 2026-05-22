from typing import List
from .base import Detector, Finding, Sev, Cat
from ..ir.graph import Graph, Handler

_FROM = frozenset({"from_address", "l1_sender", "l1_address", "sender", "from_addr"})

_REC = (
    "Validate from_address before any state change:\n"
    "  let auth = self.l1_bridge.read();\n"
    "  assert(from_address == auth, 'unauthorized');"
)


class SenderCheckDetector(Detector):
    did = "missing-l1handler-sender-check"

    def run(self, g: Graph) -> List[Finding]:
        out = []
        for h in g.handlers:
            if not h.params:
                out.append(Finding(self.did, "Handler Has No Params",
                    f"`{h.contract}::{h.fn}` has no parameters — `from_address: EthAddress` is required.",
                    Sev.CRITICAL, Cat.AUTH, h.loc, rec="Add `from_address: EthAddress` as first param."))
            elif not h.checked:
                out.append(Finding(self.did, "Missing from_address Validation",
                    f"`{h.contract}::{h.fn}` (sel={h.sel:#x}) does not validate `from_address`. "
                    "Any L1 address can trigger this handler.",
                    Sev.CRITICAL, Cat.AUTH, h.loc, rec=_REC,
                    extra={"handler": h.fn, "selector": hex(h.sel)}))
        return out
