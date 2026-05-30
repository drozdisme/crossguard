# CrossGuard Audit: StarkGate Token Bridge

**Tool:** CrossGuard v0.1.0  
**Date:** May 2026  
**Commit analyzed:** starknet-io/starkgate-contracts@cairo-1  
- L1: `src/solidity/StarknetTokenBridge.sol`  
- L2: `src/cairo/token_bridge.cairo`

---

## Raw output

6 findings: 4× D1 CRITICAL, 2× D4 HIGH.

---

## Analysis

### D1 — handle_deposit (L2:995)
### D1 — handle_token_deposit (L2:1014)
### D1 — handle_deposit_with_message (L2:1029)
### D1 — handle_token_deployment (L2:1067)

**Detector says:** handler missing `assert(from_address == ...)` in body.

**Reality:** Each handler delegates to `self.only_from_l1_bridge(:from_address)`,
an internal function defined as:

```rust
fn only_from_l1_bridge(self: @ContractState, from_address: felt252) {
    let l1_bridge_address = self.get_l1_bridge_address();
    assert(from_address == l1_bridge_address.into(), 'EXPECTED_FROM_BRIDGE_ONLY');
}
```

The assertion exists and is correct. CrossGuard v0.1.0 matches the pattern
`assert(from_address ==` directly in the handler body and does not follow
internal function calls. This is a false positive.

**Status:** False positive. Bridge is correctly protected.  
**Planned fix in CrossGuard:** call-graph analysis — follow one level of
internal function calls before concluding validation is absent (v0.2.0).

---

### D4 — depositCancelRequest (L1:524)
### D4 — depositWithMessageCancelRequest (L1:543)

**Detector says:** `startL1ToL2MessageCancellation` without access control modifier.

**Reality:** Both functions are intentionally callable by anyone. The Starknet
messaging contract enforces at the protocol level that only the address that
sent the original message can cancel it, matched by nonce. No contract-level
`onlyOwner` is needed or appropriate here.

**Status:** Informational — acceptable by design.  
**Planned fix in CrossGuard:** add a heuristic: if the cancellation function
emits an event with `msg.sender` and does not modify state beyond the
messaging call, treat it as caller-restricted by protocol (v0.2.0).

---

## Conclusion

CrossGuard found **0 exploitable vulnerabilities** in the StarkGate Token Bridge.

All 6 findings are false positives, documenting two known limitations of v0.1.0:

| Limitation | Affected detectors | Fix |
|---|---|---|
| No intra-contract call-graph | D1 | v0.2.0 |
| No protocol-level cancellation semantics | D4 | v0.2.0 |

These findings are useful: they define the exact next engineering tasks
for CrossGuard and show the tool runs cleanly on production-grade bridge code.

---

## Reproduce

```bash
git clone --depth=1 --branch cairo-1 \
  https://github.com/starknet-io/starkgate-contracts.git

crossguard-cli analyze \
  --l1 starkgate-contracts/src/solidity/StarknetTokenBridge.sol \
  --l2 starkgate-contracts/src/cairo/token_bridge.cairo \
  --format json -o starkgate-2026-05.json
```
