# CrossGuard

Static analyzer for Starknet bridge contracts.

## The problem

Starknet bridges consist of two separate programs: an L1 contract (Solidity)
and an L2 contract (Cairo). Each can be analyzed in isolation by existing
tools — Slither for Solidity, Cairo-specific linters for Cairo. Neither tool
can see across the boundary, which is exactly where the most severe bugs live.

Concretely: the L1 contract calls `sendMessageToL2(address, selector, payload[])`.
The L2 contract declares `#[l1_handler] fn process_deposit(from_address, amount: u256)`.
The connection between them is a 252-bit selector hash and a raw felt array.
No compiler checks this. No existing tool checks this.

CrossGuard builds a graph that links the two sides, then runs detectors over it.

## What it finds

**Missing `from_address` validation (D1, CRITICAL)**
An `#[l1_handler]` that does not assert `from_address == self.l1_bridge.read()`
can be called by any Ethereum address. The handler has no other access control.
This is the most common critical bug in Starknet bridge code.

**Type/encoding mismatch (D2, CRITICAL/HIGH)**
Solidity's `uint256` is 256 bits in one slot. Cairo's `u256` is two felt252 values:
`(low: u128, high: u128)`. If the L1 side passes `amount` as a single slot and
the L2 handler reads it as `u256`, values above 2^128 are silently corrupted.
CrossGuard flags this by correlating the payload layout on both sides.

**Missing fee forwarding (D3, HIGH)**
`sendMessageToL2` requires an ETH fee paid as `msg.value`. Without it, the
sequencer accepts the transaction but silently drops the message. Funds are lost.

**Unrestricted cancellation (D4, HIGH)**
`startL1ToL2MessageCancellation` without access control lets anyone cancel a
pending message after the L2 side has already processed it and updated state.

**L2-to-L1 replay (D5, MEDIUM)**
`send_message_to_l1_syscall` without nonce tracking allows the L1 consumer to
call `consumeMessageFromL2` multiple times on the same payload.

## Input

CrossGuard reads source files directly — no compiler required for the PoC.

```bash
crossguard analyze --l1 contracts/Bridge.sol --l2 src/bridge.cairo
```

Output formats: `terminal`, `json`, `sarif` (GitHub Code Scanning), `html`.

Configuration in `crossguard.toml`:

```toml
[tool.crossguard]
l1_contract = "contracts/Bridge.sol"
l2_contract = "src/bridge.cairo"
fail_on = "HIGH"
```

## Architecture

```
.sol / .cairo  ->  Parser  ->  IR (Send, Handler, Param, Type)
                                      |
                               Correlator (selector matching)
                                      |
                               CrossLayerGraph
                                      |
                           Detectors (D1–D5)  +  TaintEngine
                                      |
                            Terminal / SARIF / HTML
```

The IR represents both sides in a common type system. The correlator links
`Send` nodes to `Handler` nodes by matching the selector hash. Detectors then
reason over edges — things that require both sides to be visible simultaneously.

## PoC state

5 detectors, 31 tests, real-source parsing, SARIF output, CI integration.
Tested against the vulnerable fixture contracts in `fixtures/`.

False positive targets: CRITICAL <3%, HIGH <8%.

## What requires grant funding

The PoC parses source files with regex. Production-grade analysis requires:

- Full Sierra IR compilation (scarb's output, not source text)
- Interprocedural taint with SSA form and fixpoint iteration
- Mainnet indexer to run continuously against deployed contracts
- A labeled corpus of 100+ bridge contracts for FP/FN calibration
- D6+: cross-layer reentrancy, authorization propagation, liveness

The research contribution is the cross-layer IR and the detector model.
Everything else is engineering that requires sustained effort.
