import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from crossguard.analysis.engine import Engine
from crossguard.analysis.selector import sn_keccak
from crossguard.detectors.base import Sev, Cat
from crossguard.parsers.solidity_source import SolSourceParser
from crossguard.parsers.cairo_source import CaiSourceParser, TaintResult
from crossguard.output.sarif import SarifFormatter
from crossguard.ir.types import Lattice, K

DEPOSIT_SEL = sn_keccak("process_deposit")

def _vuln_l1_data(sel=None):
    sel = sel or DEPOSIT_SEL
    return {
        "nodeType": "SourceUnit",
        "nodes": [{"nodeType": "ContractDefinition", "name": "Bridge", "nodes": [
            {"nodeType": "FunctionDefinition", "name": "depositToL2",
             "body": {"nodeType": "Block", "statements": [{"nodeType": "ExpressionStatement",
             "expression": {"nodeType": "FunctionCall", "src": "100:60:0",
             "expression": {"nodeType": "MemberAccess", "memberName": "sendMessageToL2",
                            "expression": {"nodeType": "Identifier", "name": "STARKNET"}},
             "arguments": [
                 {"nodeType": "Identifier", "name": "L2_BRIDGE",
                  "typeDescriptions": {"typeString": "uint256"}},
                 {"nodeType": "Literal", "value": str(sel)},
                 {"nodeType": "FunctionCall", "arguments": [
                     {"nodeType": "Identifier", "name": "amount",
                      "typeDescriptions": {"typeString": "uint256"}}
                 ]}
             ]}}]}},
        ]}],
    }

def _vuln_l2_data(checked=False):
    return {
        "abi": [
            {"type": "impl", "name": "BridgeImpl"},
            {"type": "l1_handler", "name": "process_deposit", "__line": 10,
             "inputs": [
                 {"name": "from_address", "type": "core::starknet::eth_address::EthAddress"},
                 {"name": "amount", "type": "core::integer::u256"},
             ],
             "__crossguard_annotations": {"has_from_address_check": checked}},
        ]
    }


class TestD1SenderCheck:
    def test_fires_on_unchecked_handler(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        d1 = [f for f in ctx.findings if f.did == "missing-l1handler-sender-check"]
        assert d1
        assert d1[0].sev == Sev.CRITICAL

    def test_no_fire_on_checked_handler(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=True))
        assert not [f for f in ctx.findings if f.did == "missing-l1handler-sender-check"]

    def test_finding_has_location(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        f = next((f for f in ctx.findings if f.did == "missing-l1handler-sender-check"), None)
        assert f is not None
        assert f.loc is not None
        assert f.fid.startswith("CG-")

    def test_finding_has_recommendation(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        f = next((f for f in ctx.findings if f.did == "missing-l1handler-sender-check"), None)
        assert f and f.rec


class TestD2TypeMismatch:
    def test_u256_encoding_warning(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=True))
        d2 = [f for f in ctx.findings if f.did == "cross-layer-type-mismatch"]
        assert any("U256" in f.title or "256" in f.desc for f in d2)

    def test_slot_count_mismatch(self):
        l2 = {
            "abi": [
                {"type": "impl", "name": "BridgeImpl"},
                {"type": "l1_handler", "name": "process_deposit", "__line": 5,
                 "inputs": [
                     {"name": "from_address", "type": "core::starknet::eth_address::EthAddress"},
                 ],
                 "__crossguard_annotations": {"has_from_address_check": True}},
            ]
        }
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=l2)
        d2 = [f for f in ctx.findings if f.did == "cross-layer-type-mismatch"]
        assert any(f.sev in (Sev.CRITICAL, Sev.HIGH) for f in d2)

    def test_no_fire_on_compatible_types(self):
        l1 = {
            "nodeType": "SourceUnit",
            "nodes": [{"nodeType": "ContractDefinition", "name": "Safe", "nodes": [
                {"nodeType": "FunctionDefinition", "name": "send",
                 "body": {"nodeType": "Block", "statements": [{"nodeType": "ExpressionStatement",
                 "expression": {"nodeType": "FunctionCall", "src": "1:1:0",
                 "expression": {"nodeType": "FunctionCallOptions", "names": ["value"],
                     "options": [{"nodeType": "MemberAccess", "memberName": "value",
                                  "expression": {"nodeType": "Identifier", "name": "msg"}}],
                     "expression": {"nodeType": "MemberAccess", "memberName": "sendMessageToL2",
                                    "expression": {"nodeType": "Identifier", "name": "SN"}}},
                 "arguments": [
                     {"nodeType": "Identifier", "name": "L2", "typeDescriptions": {"typeString": "uint256"}},
                     {"nodeType": "Literal", "value": str(DEPOSIT_SEL)},
                     {"nodeType": "FunctionCall", "arguments": [
                         {"nodeType": "Identifier", "name": "addr",
                          "typeDescriptions": {"typeString": "address"}},
                     ]}
                 ]}}]}},
            ]}],
        }
        l2 = {
            "abi": [
                {"type": "impl", "name": "BridgeImpl"},
                {"type": "l1_handler", "name": "process_deposit", "__line": 1,
                 "inputs": [
                     {"name": "from_address", "type": "core::starknet::eth_address::EthAddress"},
                     {"name": "recipient", "type": "core::starknet::contract_address::ContractAddress"},
                 ],
                 "__crossguard_annotations": {"has_from_address_check": True}},
            ]
        }
        ctx = Engine().analyze(l1_data=l1, l2_data=l2)
        assert not [f for f in ctx.findings
                    if f.did == "cross-layer-type-mismatch" and f.sev == Sev.CRITICAL]


class TestD3Fee:
    def test_fires_without_fee(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=True))
        assert [f for f in ctx.findings if f.did == "missing-l1-fee-validation"]

    def test_no_fire_with_fee(self):
        l1 = {
            "nodeType": "SourceUnit",
            "nodes": [{"nodeType": "ContractDefinition", "name": "Safe", "nodes": [
                {"nodeType": "FunctionDefinition", "name": "deposit",
                 "body": {"nodeType": "Block", "statements": [{"nodeType": "ExpressionStatement",
                 "expression": {"nodeType": "FunctionCall", "src": "1:1:0",
                 "expression": {"nodeType": "FunctionCallOptions", "names": ["value"],
                     "options": [{"nodeType": "MemberAccess", "memberName": "value",
                                  "expression": {"nodeType": "Identifier", "name": "msg"}}],
                     "expression": {"nodeType": "MemberAccess", "memberName": "sendMessageToL2",
                                    "expression": {"nodeType": "Identifier", "name": "SN"}}},
                 "arguments": [
                     {"nodeType": "Identifier", "name": "L2", "typeDescriptions": {"typeString": "uint256"}},
                     {"nodeType": "Literal", "value": str(DEPOSIT_SEL)},
                     {"nodeType": "FunctionCall", "arguments": []}
                 ]}}]}},
            ]}],
        }
        ctx = Engine().analyze(l1_data=l1, l2_data=_vuln_l2_data(checked=True))
        assert not [f for f in ctx.findings if f.did == "missing-l1-fee-validation"]


class TestD4Cancellation:
    def _ctx_with_cancellation(self, has_access_control):
        from crossguard.parsers.solidity_source import CancellationCall
        from crossguard.ir.graph import Loc
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=True))
        ctx.graph.cancellations = [CancellationCall("Bridge", "cancel", Loc("Bridge.sol", 42), has_access_control)]
        from crossguard.detectors.d4_cancellation import CancellationDetector
        return CancellationDetector().run(ctx.graph)

    def test_fires_without_access_control(self):
        findings = self._ctx_with_cancellation(has_access_control=False)
        assert findings
        assert findings[0].sev == Sev.HIGH

    def test_no_fire_with_access_control(self):
        assert not self._ctx_with_cancellation(has_access_control=True)


class TestSolSourceParser:
    SAMPLE_SOL = """
    pragma solidity ^0.8.0;
    contract Bridge {
        function deposit(address recipient, uint256 amount) external payable {
            STARKNET.sendMessageToL2{value: msg.value}(
                L2_BRIDGE, 0xdeadbeef,
                abi.encode(recipient, amount)
            );
        }
        function cancelDeposit(uint256 sel, uint256[] calldata p, uint256 n) external {
            STARKNET.startL1ToL2MessageCancellation(L2_BRIDGE, sel, p, n);
        }
    }
    """

    def test_parses_send(self):
        assert SolSourceParser(self.SAMPLE_SOL, "test.sol").parse_sends()

    def test_detects_fee(self):
        sends = SolSourceParser(self.SAMPLE_SOL, "test.sol").parse_sends()
        assert any(s.has_fee for s in sends)

    def test_parses_cancellation(self):
        assert SolSourceParser(self.SAMPLE_SOL, "test.sol").parse_cancellations()

    def test_no_fee_detection(self):
        sol = "contract B { function send() external { STARKNET.sendMessageToL2(L2, sel, payload); } }"
        sends = SolSourceParser(sol, "b.sol").parse_sends()
        assert sends and not sends[0].has_fee


class TestCaiSourceParser:
    SAMPLE_CAIRO = """
    #[starknet::contract]
    mod Bridge {
        #[storage]
        struct Storage { l1_bridge: EthAddress, }

        #[l1_handler]
        fn process_deposit(
            ref self: ContractState,
            from_address: EthAddress,
            recipient: ContractAddress,
            amount: u256,
        ) {
            assert(from_address == self.l1_bridge.read(), 'bad sender');
            let bal = self.balances.read(recipient);
            self.balances.write(recipient, bal + amount);
        }

        #[l1_handler]
        fn unchecked_handler(
            ref self: ContractState,
            from_address: EthAddress,
            amount: u256,
        ) {
            self.balances.write(some_addr, amount);
        }
    }
    """

    def test_parses_handlers(self):
        assert len(CaiSourceParser(self.SAMPLE_CAIRO, "bridge.cairo").parse()) == 2

    def test_detects_check(self):
        handlers = CaiSourceParser(self.SAMPLE_CAIRO, "bridge.cairo").parse()
        checked = {h.fn: h.checked for h in handlers}
        assert checked["process_deposit"] is True
        assert checked["unchecked_handler"] is False

    def test_selector_computed(self):
        for h in CaiSourceParser(self.SAMPLE_CAIRO, "bridge.cairo").parse():
            assert h.sel > 0


class TestTypeLattice:
    def test_sol_uint256(self):
        t = Lattice.sol("uint256")
        assert t.kind == K.UINT and t.bits == 256 and t.slots() == 2

    def test_cai_u256(self):
        t = Lattice.cai("core::integer::u256")
        assert t.kind == K.UINT and t.bits == 256

    def test_address_mapping(self):
        assert Lattice.sol("address").kind == K.ADDR
        assert Lattice.cai("core::starknet::eth_address::EthAddress").kind == K.ADDR

    def test_unknown_type(self):
        assert Lattice.sol("MyCustomType").kind == K.UNK


class TestSarifOutput:
    def test_sarif_is_valid_json(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        sarif = json.loads(SarifFormatter().format(ctx.findings, ctx.errors))
        assert sarif["version"] == "2.1.0" and "runs" in sarif and len(sarif["runs"]) == 1

    def test_sarif_has_results(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        sarif = json.loads(SarifFormatter().format(ctx.findings, ctx.errors))
        assert len(sarif["runs"][0]["results"]) == len(ctx.findings)

    def test_sarif_levels(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        sarif = json.loads(SarifFormatter().format(ctx.findings, ctx.errors))
        for r in sarif["runs"][0]["results"]:
            assert r["level"] in ("error", "warning", "note", "none")

    def test_sarif_fingerprints(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        sarif = json.loads(SarifFormatter().format(ctx.findings, ctx.errors))
        for r in sarif["runs"][0]["results"]:
            assert "crossguard/v1" in r["fingerprints"]


class TestGraphCorrelation:
    def test_single_handler_fallback(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        assert ctx.graph.sends and ctx.graph.handlers and ctx.graph.edges

    def test_selector_matching(self):
        ctx = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        for e in ctx.graph.edges:
            assert e.how in ("exact", "hex", "name", "fallback")


class TestEndToEndFixtures:
    FIXTURES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")

    def test_vuln_fixtures_produce_findings(self):
        vuln_sol = os.path.join(self.FIXTURES, "StarkBridge_vuln.sol")
        vuln_cairo = os.path.join(self.FIXTURES, "bridge_vuln.cairo")
        if not (os.path.exists(vuln_sol) and os.path.exists(vuln_cairo)):
            pytest.skip("Fixture files not found")
        ctx = Engine().analyze(l1_path=vuln_sol, l2_path=vuln_cairo)
        assert ctx.findings
        assert [f for f in ctx.findings if f.sev == Sev.CRITICAL]

    def test_safe_fixtures_no_critical(self):
        safe_sol = os.path.join(self.FIXTURES, "StarkBridge_safe.sol")
        safe_cairo = os.path.join(self.FIXTURES, "bridge_safe.cairo")
        if not (os.path.exists(safe_sol) and os.path.exists(safe_cairo)):
            pytest.skip("Safe fixture files not found")
        ctx = Engine().analyze(l1_path=safe_sol, l2_path=safe_cairo)
        crits = [f for f in ctx.findings if f.sev == Sev.CRITICAL]
        assert not crits, f"Safe fixtures should have no CRITICAL findings, got: {crits}"


class TestDeterminism:
    def test_same_input_same_output(self):
        ctx1 = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        ctx2 = Engine().analyze(l1_data=_vuln_l1_data(), l2_data=_vuln_l2_data(checked=False))
        assert sorted(f.fid for f in ctx1.findings) == sorted(f.fid for f in ctx2.findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
