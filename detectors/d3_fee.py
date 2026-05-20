from typing import List
from .base import Detector, Finding, Sev, Cat
from ..ir.graph import Graph

_REC = (
    "Mark function payable and forward msg.value:\n"
    "  STARKNET.sendMessageToL2{value: msg.value}(to, sel, payload);"
)


class FeeDetector(Detector):
    did = "missing-l1-fee-validation"

    def run(self, g: Graph) -> List[Finding]:
        return [
            Finding(self.did, "sendMessageToL2 Without msg.value",
                f"`{s.contract}::{s.fn}` calls sendMessageToL2 without forwarding msg.value. "
                "Sequencer will reject or silently drop the message.",
                Sev.HIGH, Cat.ASSET, s.loc, rec=_REC,
                extra={"contract": s.contract, "fn": s.fn})
            for s in g.sends if not s.has_fee
        ]
