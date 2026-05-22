from __future__ import annotations
import re
from typing import List
from .base import Detector, Finding, Sev, Cat
from ..ir.graph import Graph, Handler, Loc

_SEND_L1 = re.compile(r'\bsend_message_to_l1_syscall\b|\bsend_message_to_l1\b', re.IGNORECASE)
_NONCE    = re.compile(r'\bnonce\b|\bserial\b|\bsequence\b', re.IGNORECASE)
_CONSUMED = re.compile(r'\bconsumed\b|\bprocessed\b|\bseen\b|\bused\b', re.IGNORECASE)

_REC = (
    "Track consumed messages on L2 to prevent replay:\n"
    "  // In L2 storage\n"
    "  consumed_nonces: LegacyMap<felt252, bool>;\n"
    "  // In the sending function\n"
    "  assert(!self.consumed_nonces.read(nonce), 'already consumed');\n"
    "  self.consumed_nonces.write(nonce, true);\n\n"
    "  // On L1: consumeMessageFromL2 is one-time per payload hash —\n"
    "  // but verify the L1 consumer does not call it multiple times."
)


class ReplayRiskDetector(Detector):
    did = "l2-to-l1-replay-risk"

    def run(self, g: Graph) -> List[Finding]:
        out = []
        for h in g.handlers:
            body = getattr(h, '_body', '')
            if not body:
                continue
            if _SEND_L1.search(body) and not (_NONCE.search(body) or _CONSUMED.search(body)):
                out.append(Finding(
                    self.did,
                    "L2→L1 Message Without Replay Protection",
                    (
                        f"`{h.contract}::{h.fn}` sends a message to L1 via "
                        "`send_message_to_l1_syscall` but does not appear to track "
                        "consumed nonces or message hashes. An L1 consumer that calls "
                        "`consumeMessageFromL2` multiple times (or if re-org causes "
                        "re-delivery) can replay this message, enabling double-spend."
                    ),
                    Sev.MEDIUM, Cat.LOGIC, h.loc,
                    rec=_REC,
                    extra={"handler": h.fn},
                ))
        return out

    @staticmethod
    def _handler_body(h: Handler) -> str:
        return getattr(h, '_body', '')
