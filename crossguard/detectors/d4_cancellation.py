from __future__ import annotations
from typing import List
from .base import Detector, Finding, Sev, Cat
from ..ir.graph import Graph, Loc

_REC = (
    "Restrict cancellation to the original depositor or an admin role:\n"
    "  require(msg.sender == originalSender[nonce], 'not original sender');\n"
    "  // or: onlyOwner / onlyRole(CANCELLER_ROLE)"
)


class CancellationDetector(Detector):
    did = "unrestricted-message-cancellation"

    def run(self, g: Graph) -> List[Finding]:
        out = []
        for c in getattr(g, 'cancellations', []):
            if not c.has_access_control:
                out.append(Finding(
                    self.did,
                    "Unrestricted Message Cancellation",
                    (
                        f"`{c.contract}::{c.fn}` calls `startL1ToL2MessageCancellation` "
                        "without access control. Any address can cancel pending messages, "
                        "enabling griefing: attacker cancels victim's deposit after L2 "
                        "has already updated state, leaving funds permanently locked."
                    ),
                    Sev.HIGH, Cat.LOGIC, c.loc,
                    rec=_REC,
                    extra={"contract": c.contract, "fn": c.fn},
                ))
        return out
