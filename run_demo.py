#!/usr/bin/env python3
"""
crossguard demo — run without real solc/starknet-compile output.
Uses embedded fixture data that simulates a vulnerable bridge contract.

Expected findings:
  CRITICAL  missing-l1handler-sender-check  process_deposit has no from_address check
  HIGH      cross-layer-type-mismatch        uint256 -> u256 encoding warning (both calls)
  HIGH      missing-l1-fee-validation        depositToL2NoFee sends without msg.value
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from crossguard.analysis.engine import Engine
from crossguard.analysis.selector import sn_keccak
from crossguard.output.fmt import Fmt

# Pre-compute selector so the fixture uses the real sn_keccak value
DEPOSIT_SEL = sn_keccak("process_deposit")

L1_DATA = {
    "absolutePath": "contracts/Bridge.sol",
    "nodeType": "SourceUnit",
    "nodes": [{
        "nodeType": "ContractDefinition",
        "name": "Bridge",
        "nodes": [
            # ── depositToL2 ─ correct fee, but uint256 payload ──────────────
            {
                "nodeType": "FunctionDefinition",
                "name": "depositToL2",
                "body": {"nodeType": "Block", "statements": [{
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "src": "312:120:0",
                        "expression": {
                            "nodeType": "FunctionCallOptions",
                            "names": ["value"],
                            "options": [{"nodeType": "MemberAccess", "memberName": "value",
                                         "expression": {"nodeType": "Identifier", "name": "msg"}}],
                            "expression": {
                                "nodeType": "MemberAccess",
                                "memberName": "sendMessageToL2",
                                "expression": {"nodeType": "Identifier", "name": "STARKNET_CORE"}
                            }
                        },
                        "arguments": [
                            {"nodeType": "Identifier", "name": "L2_BRIDGE",
                             "typeDescriptions": {"typeString": "uint256"}},
                            {"nodeType": "Literal", "value": str(DEPOSIT_SEL)},
                            {"nodeType": "FunctionCall", "arguments": [
                                {"nodeType": "Identifier", "name": "recipient",
                                 "typeDescriptions": {"typeString": "address"}},
                                {"nodeType": "Identifier", "name": "amount",
                                 "typeDescriptions": {"typeString": "uint256"}}
                            ]}
                        ]
                    }
                }]}
            },
            # ── depositToL2NoFee ─ no msg.value ─────────────────────────────
            {
                "nodeType": "FunctionDefinition",
                "name": "depositToL2NoFee",
                "body": {"nodeType": "Block", "statements": [{
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "FunctionCall",
                        "src": "580:110:0",
                        "expression": {
                            "nodeType": "MemberAccess",
                            "memberName": "sendMessageToL2",
                            "expression": {"nodeType": "Identifier", "name": "STARKNET_CORE"}
                        },
                        "arguments": [
                            {"nodeType": "Identifier", "name": "L2_BRIDGE",
                             "typeDescriptions": {"typeString": "uint256"}},
                            {"nodeType": "Literal", "value": str(DEPOSIT_SEL)},
                            {"nodeType": "FunctionCall", "arguments": [
                                {"nodeType": "Identifier", "name": "recipient",
                                 "typeDescriptions": {"typeString": "address"}},
                                {"nodeType": "Identifier", "name": "amount",
                                 "typeDescriptions": {"typeString": "uint256"}}
                            ]}
                        ]
                    }
                }]}
            },
        ]
    }]
}

L2_DATA = {
    "__filename": "src/bridge.cairo",
    "abi": [
        {"type": "impl", "name": "BridgeImpl"},
        {
            "type": "l1_handler", "name": "process_deposit", "__line": 42,
            "inputs": [
                {"name": "from_address", "type": "core::starknet::eth_address::EthAddress"},
                {"name": "recipient",    "type": "core::starknet::contract_address::ContractAddress"},
                {"name": "amount",       "type": "core::integer::u256"},
            ],
            "__crossguard_annotations": {"has_from_address_check": False},
        },
        {
            "type": "l1_handler", "name": "process_withdrawal", "__line": 78,
            "inputs": [
                {"name": "from_address", "type": "core::starknet::eth_address::EthAddress"},
                {"name": "amount",       "type": "core::integer::u256"},
            ],
            "__crossguard_annotations": {"has_from_address_check": True},
        },
    ],
}


def main():
    print(f"[*] process_deposit selector: {DEPOSIT_SEL:#066x}\n")

    ctx = Engine().analyze(l1_data=L1_DATA, l2_data=L2_DATA)

    print(f"[*] Graph: {len(ctx.graph.sends)} L1 sender(s), "
          f"{len(ctx.graph.handlers)} L2 handler(s), "
          f"{len(ctx.graph.edges)} edge(s)")
    for e in ctx.graph.edges:
        print(f"    ↳ {e.send.fn} → {e.handler.fn}  (method={e.how})")
    print()

    print(Fmt(color=True).render(ctx.findings, ctx.errors))


if __name__ == "__main__":
    main()
