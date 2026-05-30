# CrossGuard

Static security analyzer for Starknet bridge contracts. Detects cross-layer vulnerabilities between L1 Solidity and L2 Cairo.

```
$ crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo

[CRITICAL]  D1  Missing from_address validation
  at L2:28  (process_deposit)
  Handler does not validate that from_address == registered L1 bridge.

[HIGH]  D3  Missing fee check in sendMessageToL2
  at L1:62  (depositToL2NoFee)
  sendMessageToL2 called without msg.value. Message may be silently dropped.

2 findings  1 critical  1 high
```

## Detectors

| ID | Severity | Description |
|----|----------|-------------|
| D1 | CRITICAL | `#[l1_handler]` without `assert(from_address == ...)` |
| D2 | CRITICAL | `uint256` on L1 paired with `u256` on L2 (encoding mismatch) |
| D3 | HIGH | `sendMessageToL2` without `{value: msg.value}` |
| D4 | HIGH | `startL1ToL2MessageCancellation` without access control |
| D5 | MEDIUM | L2→L1 message without nonce tracking |
| D6 | MEDIUM | `#[l1_handler]` decodes payload without length check |

## Build

```bash
# Ubuntu
sudo apt-get install build-essential cmake

# macOS
brew install cmake

git clone https://github.com/drozdisme/crossguard
cd crossguard
mkdir build && cd build
cmake ..
make
```

## Usage

```bash
# Analyze a bridge
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo

# Output formats
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format json -o report.json
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format sarif -o results.sarif
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format html  -o report.html

# Fail CI on HIGH+
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --fail-on HIGH

# Demo on built-in fixtures (no contracts needed)
./build/crossguard-cli demo

# Run tests
cd build && ctest --output-on-failure
```

## Supported inputs

| Layer | Format |
|-------|--------|
| L1 | `.sol` source, `solc --ast-json` output |
| L2 | `.cairo` source, Scarb Sierra `.json` |

## GitHub Actions

```yaml
- name: CrossGuard
  run: |
    crossguard-cli analyze \
      --l1 contracts/L1/Bridge.sol \
      --l2 contracts/L2/bridge.cairo \
      --format sarif -o crossguard.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: crossguard.sarif
```

Full workflow: [`.github/workflows/crossguard.yml`](.github/workflows/crossguard.yml)

## Architecture

```
.sol / .cairo
     │
  Parsers  ──  extract Sends (L1), Handlers (L2)
     │
  Correlator  ──  link by selector name
     │
  TaintEngine  ──  data-flow from_address → sink
     │
  Detectors D1–D6
     │
  Formatters  ──  terminal / json / sarif / html
```

## License

[MIT](LICENSE)
