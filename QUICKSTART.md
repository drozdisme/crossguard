# Quick Start

## Installation

### macOS
```bash
# Install dependencies
brew install cmake openssl

# Clone/extract repository
tar xzf crossguard-cpp.tar.gz
cd crossguard-cpp

# Build
make build

# Test
make test
```

### Linux (Ubuntu/Debian)
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev

# Extract and build
tar xzf crossguard-cpp.tar.gz
cd crossguard-cpp
make build
```

### Windows (MSVC)
```bash
# Install CMake and MSVC
# https://cmake.org/download/
# https://visualstudio.microsoft.com/

# With vcpkg
vcpkg install openssl:x64-windows

# Extract and build
tar xzf crossguard-cpp.tar.gz
cd crossguard-cpp
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
```

## Basic Usage

```bash
# Analyze contracts
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo

# Get JSON output
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format json

# Save to file
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo -o report.json

# GitHub Code Scanning format
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --format sarif -o results.sarif

# Fail if HIGH severity
./build/crossguard-cli analyze --l1 Bridge.sol --l2 bridge.cairo --fail-on HIGH
```

## Test with Fixtures

```bash
# Analyze vulnerable contract pair
./build/crossguard-cli analyze \
  --l1 fixtures/StarkBridge_vuln.sol \
  --l2 fixtures/bridge_vuln.cairo

# Analyze safe contract pair
./build/crossguard-cli analyze \
  --l1 fixtures/StarkBridge_safe.sol \
  --l2 fixtures/bridge_safe.cairo
```

## Project Structure

```
crossguard-cpp/
├── src/                      # Implementation files (.cpp)
│   ├── main.cpp             # CLI entry point
│   ├── engine.cpp           # Analysis engine
│   ├── *_parser.cpp         # Contract parsers
│   ├── detectors.cpp        # D1-D5 implementations
│   └── *.cpp                # Other implementations
│
├── include/                 # Header files (.hpp)
│   ├── types.hpp            # Core data structures
│   ├── graph.hpp            # IR graph
│   ├── engine.hpp           # Main engine API
│   └── *.hpp                # Other headers
│
├── tests/                   # Unit tests
│   └── test_crossguard.cpp
│
├── fixtures/                # Test contracts
│   ├── *.sol                # Solidity examples
│   ├── *.cairo              # Cairo examples
│   └── *.json               # AST/Sierra examples
│
├── CMakeLists.txt           # Build configuration
├── Makefile                 # Convenience targets
├── README.md                # Full documentation
├── ARCHITECTURE.md          # Design documentation
└── MIGRATION.md             # Python → C++ guide
```

## What Each Detector Finds

### D1: Missing from_address validation (CRITICAL)
```cairo
#[l1_handler]
fn process_deposit(from_address: felt252, amount: u256) {
    //  CRITICAL: No check that from_address == registered bridge
    self.balances.write(from_address, amount);
}
```

**Fix:**
```cairo
#[l1_handler]
fn process_deposit(from_address: felt252, amount: u256) {
    //  Validate sender
    assert(from_address == self.l1_bridge.read(), 'Unauthorized');
    self.balances.write(from_address, amount);
}
```

### D2: Type mismatch (CRITICAL)
```solidity
function deposit(uint256 amount) external {
    sendMessageToL2(amount);  //  256 bits
}
```

```cairo
#[l1_handler]
fn process_deposit(from_address: felt252, amount: u256) {
    //  CRITICAL: u256 is two u128s, not same as uint256
    let value = amount.low + amount.high;
}
```

### D3: Missing fee (HIGH)
```solidity
function deposit(uint256 amount) external {
    sendMessageToL2(address, selector, payload);
    //  HIGH: No fee provided - message may be dropped
}
```

**Fix:**
```solidity
function deposit(uint256 amount) external payable {
    require(msg.value >= FEE, "Insufficient fee");
    sendMessageToL2(address, selector, payload);
}
```

### D4: Unrestricted cancellation (HIGH)
```solidity
function cancelMessage(uint256 nonce) external {
    //  HIGH: Anyone can cancel messages
    startL1ToL2MessageCancellation(nonce);
}
```

**Fix:**
```solidity
function cancelMessage(uint256 nonce) external onlyAdmin {
    startL1ToL2MessageCancellation(nonce);
}
```

### D5: L2→L1 replay (MEDIUM)
```cairo
#[l1_handler]
fn process_withdrawal(user: felt252, amount: u256) {
    send_message_to_l1_syscall(user, amount);
    //  MEDIUM: No nonce - L1 can call consumeMessageFromL2 multiple times
}
```

## Example Output

### Terminal
```
=== CrossGuard Analysis Report ===

[CRITICAL] D1: Missing from_address validation
  Location: bridge.cairo:42:5
  An l1_handler that does not assert from_address == l1_bridge

[HIGH] D3: Missing fee forwarding
  Location: Bridge.sol:100:12
  sendMessageToL2 call without msg.value verification

=== Summary ===
CRITICAL: 1
HIGH:     1
MEDIUM:   0
LOW:      0
Total:    2 findings
```

### JSON
```json
{
  "findings": [
    {
      "detector_id": "D1",
      "severity": "CRITICAL",
      "title": "Missing from_address validation",
      "description": "Handler does not validate...",
      "location": {
        "file": "bridge.cairo",
        "line": 42,
        "column": 5
      },
      "metadata": { }
    }
  ],
  "errors": [],
  "count": 1
}
```

## Common Issues

### "Cannot find libssl"
```bash
# macOS
brew install openssl
export LDFLAGS="-L/opt/homebrew/opt/openssl/lib"
export CPPFLAGS="-I/opt/homebrew/opt/openssl/include"

# Linux
sudo apt-get install libssl-dev
```

### "CMake not found"
```bash
# macOS
brew install cmake

# Linux
sudo apt-get install cmake

# Windows
Download from https://cmake.org/download/
```

### "C++ compiler not found"
```bash
# macOS
xcode-select --install

# Linux Ubuntu
sudo apt-get install build-essential

# Windows
Visual Studio Community (with C++ workload)
```

## Next Steps

1. **Read the docs**: See `ARCHITECTURE.md` for detailed design
2. **Extend detectors**: Add D6+ by following `BaseDetector` pattern
3. **Integrate with CI**: Use SARIF output with GitHub Actions
4. **Optimize parsing**: Replace regex with finite automaton if needed

## Support Files

- `README.md` - Full documentation
- `ARCHITECTURE.md` - System design
- `MIGRATION.md` - Python to C++ guide
- `CMakeLists.txt` - Build configuration
- `Makefile` - Quick build targets

## Version Info

- **CrossGuard**: 0.1.0-poc
- **C++ Standard**: C++17
- **CMake**: 3.16+
- **OpenSSL**: 1.1.1+ or 3.0+
