# CrossGuard C++

Pure C++ implementation of CrossGuard - Static analyzer for Starknet bridge contracts.

This is a complete rewrite of the original Python implementation in C++17 with no Python dependencies.

## Features

- **D1: Missing from_address validation** - Detects handlers missing access control
- **D2: Type/encoding mismatch** - Finds uint256/u256 encoding incompatibilities
- **D3: Missing fee forwarding** - Identifies unchecked sendMessageToL2 calls
- **D4: Unrestricted cancellation** - Finds unprotected message cancellation
- **D5: L2-to-L1 replay risk** - Detects missing nonce tracking

## Building

### Requirements
- C++17 compiler (g++, clang, msvc)
- CMake 3.16+
- OpenSSL development libraries

### Build Instructions

```bash
mkdir build
cd build
cmake ..
make

# Run tests
make test

# Install
sudo make install
```

### macOS
```bash
brew install openssl
export LDFLAGS="-L/opt/homebrew/opt/openssl/lib"
export CPPFLAGS="-I/opt/homebrew/opt/openssl/include"
cmake ..
make
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get install libssl-dev build-essential cmake
cmake ..
make
```

### Windows
```bash
vcpkg install openssl:x64-windows
cmake -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake ..
cmake --build .
```

## Usage

### Basic Analysis
```bash
crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo
```

### With Options
```bash
# Output as JSON
crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format json -o report.json

# Output as SARIF for GitHub
crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format sarif

# Output as HTML report
crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format html -o report.html

# Fail if HIGH or above
crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --fail-on HIGH

# No color output
crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --no-color
```

### Supported Input Formats

**L1 Contracts:**
- `.sol` - Solidity source code
- `.json` / `.ast` - Solc AST output

**L2 Contracts:**
- `.cairo` - Cairo source code
- `.json` / `.sierra` - Scarb/Sierra JSON output

## Architecture

```
Input Files (.sol, .cairo, .json)
         ↓
    [Parsers] → Extract Sends, Handlers
         ↓
    [IR Graph] → Type system, locations
         ↓
   [Correlator] → Link L1/L2 by selector
         ↓
  [Taint Engine] → Track data flow
         ↓
   [Detectors D1-D5] → Run security checks
         ↓
   [Formatters] → Terminal/JSON/SARIF/HTML
```

## Project Structure

```
src/
  main.cpp              - CLI entry point
  engine.cpp            - Analysis engine
  solidity_parser.cpp   - Solidity contract parser
  cairo_parser.cpp      - Cairo contract parser
  detectors.cpp         - Security detectors (D1-D5)
  correlator.cpp        - L1/L2 linking
  taint_engine.cpp      - Taint analysis
  formatters.cpp        - Output formatting
  json.cpp              - JSON library implementation

include/
  types.hpp             - Core data types
  graph.hpp             - IR graph structure
  solidity_parser.hpp   - Solidity parser interface
  cairo_parser.hpp      - Cairo parser interface
  detectors.hpp         - Detector interfaces
  engine.hpp            - Engine interface
  correlator.hpp        - Correlator interface
  taint_engine.hpp      - Taint analysis interface
  formatters.hpp        - Formatter interfaces
  json.hpp              - JSON library header

tests/
  test_crossguard.cpp   - Unit tests

fixtures/
  [test contracts]
```

## Implementation Notes

### Key Differences from Python Version

1. **No External JSON Library** - Uses custom lightweight JSON parser implementation
2. **Type Safety** - Strong typing with no dynamic object attributes
3. **Memory Management** - Smart pointers (unique_ptr) for automatic cleanup
4. **Performance** - Compiled binary is significantly faster
5. **Portability** - Single C++17 codebase works across platforms

### Regex Support

Uses C++17 `<regex>` library for:
- Function signature extraction
- Pattern matching in source code
- Location tracking

### Thread Safety

Current implementation is single-threaded. Multi-threaded analysis can be added via:
- Thread pool for detector execution
- Concurrent graph building
- Atomic findings collection

## Testing

Run unit tests:
```bash
ctest --verbose
```

Run specific test:
```bash
./crossguard-tests
```

## Output Formats

### Terminal
Colored output with summary of findings

### JSON
Machine-readable format with detailed metadata:
```json
{
  "findings": [
    {
      "detector_id": "D1",
      "severity": "CRITICAL",
      "title": "...",
      "description": "...",
      "location": {...},
      "metadata": {...}
    }
  ],
  "errors": [...],
  "count": 5
}
```

### SARIF
GitHub Code Scanning compatible format (`.sarif` files)

### HTML
Interactive HTML report with styling

## Detector Details

### D1: Missing from_address validation (CRITICAL)
Triggers when an `#[l1_handler]` function doesn't validate the caller is the registered L1 bridge.

### D2: Type mismatch between L1 and L2 (CRITICAL/HIGH)
Detects encoding mismatches between uint256 (256-bit single slot) and u256 (two u128 felts).

### D3: Missing fee forwarding (HIGH)
Flags `sendMessageToL2` calls without msg.value verification that may be silently dropped.

### D4: Unrestricted cancellation (HIGH)
Finds `startL1ToL2MessageCancellation` without proper access control.

### D5: L2-to-L1 replay risk (MEDIUM)
Detects messages sent to L1 without nonce/uniqueness tracking allowing replays.

## Performance

Binary size: ~5-10 MB (stripped)
Analysis time: <100ms for typical contracts

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]

## References

- Starknet docs: https://docs.starknet.io
- Cairo language: https://cairo-lang.org
# crossguard
