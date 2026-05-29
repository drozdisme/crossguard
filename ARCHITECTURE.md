# CrossGuard Architecture

## Overview

CrossGuard is a static analyzer for Starknet bridge contracts that links L1 (Solidity) and L2 (Cairo) contract analysis to find cross-layer vulnerabilities.

## Core Components

### 1. Type System (`types.hpp`)

Fundamental data structures:

- **Severity**: CRITICAL, HIGH, MEDIUM, LOW
- **Location**: File, line, column, function name
- **Finding**: Detection result with severity, location, title, description
- **TypeInfo**: Type representation (name, bits, array flag, struct info)
- **Send**: L1 event/function that sends to L2
- **Handler**: L2 function with #[l1_handler] attribute
- **Cancellation**: L1 cancellation function
- **TypeMismatch**: Detected parameter type incompatibility
- **TaintViolation**: Tainted data flow from source to sink

### 2. IR Graph (`graph.hpp`)

Central data structure connecting L1 and L2:

```
Graph
├── Sends (L1)
├── Handlers (L2)
├── Cancellations
├── TypeMismatches
└── TaintViolations
```

Methods:
- `add_send()` / `add_handler()` - Add contract elements
- `find_handler_by_selector()` - Find L2 handler by selector
- `find_send_by_selector()` - Find L1 send by selector

### 3. Parsers

#### SolidityParser (`solidity_parser.hpp`)
- Loads from `.sol` source or `.json` AST
- Extracts function signatures, parameters
- Identifies `sendMessageToL2` and `startL1ToL2MessageCancellation` calls
- Detects fee checks with regex patterns

#### CairoParser (`cairo_parser.hpp`)
- Loads from `.cairo` source or `.sierra` JSON
- Extracts `#[l1_handler]` functions
- Detects from_address validation
- Extracts assertions and source lines

### 4. Analysis Engine (`engine.hpp`)

Main orchestrator:

```
Engine
├── load L1 contract (parse)
├── load L2 contract (parse)
├── run Correlator
├── run TaintEngine
├── run Detectors (D1-D5)
└── return AnalysisContext
```

Supports two modes:
- File-based: `analyze(l1_path, l2_path)`
- Data-based: `analyze_data(l1_json, l2_json)`

### 5. Correlator (`correlator.hpp`)

Links L1 and L2 by selector hash:

```
L1 Send("deposit")
    ↓ [compute_selector]
    → ["deposit_selector_hash"]
    ↓ [match]
    ↓
L2 Handler("process_deposit")
    ↑ [hash_selector]
    ← ["process_deposit_selector_hash"]
```

Also validates parameter compatibility:
- uint256 ↔ u256 (with warnings)
- Same type names (exact match)

### 6. Taint Engine (`taint_engine.hpp`)

Data flow analysis:

```
Parameter (user-controlled)
    ↓
  Flow through code
    ↓
State modification / Unsafe operation (sink)
```

Tracks:
- User-controllable parameters (from_address, amount, etc.)
- Flow to state mutations
- Missing validation points

### 7. Detectors (`detectors.hpp`)

Base class: `BaseDetector`

Five detector implementations:

#### D1: SenderCheckDetector (CRITICAL)
Checks if handlers validate `from_address == registered_bridge`

#### D2: TypeMismatchDetector (CRITICAL/HIGH)
Detects uint256 vs u256 encoding mismatches:
- uint256: 256 bits in single Solidity slot
- u256: Two u128 felts in Cairo

#### D3: FeeDetector (HIGH)
Checks if `sendMessageToL2` includes fee verification

#### D4: CancellationDetector (HIGH)
Verifies `startL1ToL2MessageCancellation` has access control

#### D5: ReplayRiskDetector (MEDIUM)
Checks for nonce/uniqueness tracking in L2→L1 messages

### 8. Formatters (`formatters.hpp`)

Output formats:

#### TerminalFormatter
- ANSI color support (optional)
- Human-readable summary
- Severity statistics

#### JsonFormatter
- Structured findings array
- Metadata per finding
- Error log

#### SarifFormatter
- GitHub Code Scanning format
- Rule definitions
- Location and region info

#### HtmlFormatter
- Styled HTML report
- Color-coded severity
- Responsive design

### 9. JSON Library (`json.hpp`)

Custom lightweight implementation:
- No external dependencies
- Supports parse/dump/access
- Variants for all JSON types

## Data Flow

```
┌─────────────────────────────────────────────────────┐
│                 Input Files                         │
│            Bridge.sol   bridge.cairo                │
└────────────┬─────────────────────────┬──────────────┘
             │                         │
    ┌────────▼────────┐      ┌─────────▼──────────┐
    │ SolidityParser   │      │  CairoParser       │
    │ • Extract sends  │      │ • Extract handlers │
    │ • Find fees      │      │ • Check validation │
    └────────┬────────┘      └─────────┬──────────┘
             │                         │
             └────────────┬────────────┘
                          │
                   ┌──────▼──────┐
                   │  IR Graph   │
                   │             │
                   │ Sends [L1]  │
                   │ Handlers[L2]│
                   │ Cancels [L1]│
                   └──────┬──────┘
                          │
                   ┌──────▼──────┐
                   │ Correlator  │
                   │ Link L1<>L2 │
                   └──────┬──────┘
                          │
                ┌─────────┼─────────┐
                │                   │
         ┌──────▼────────┐  ┌───────▼───────┐
         │ TaintEngine   │  │ Detectors D1-5│
         │ Track flows   │  │ Run checks    │
         └──────┬────────┘  └───────┬───────┘
                │                   │
                └─────────┬─────────┘
                          │
                   ┌──────▼──────┐
                   │  Findings   │
                   │ (sorted by  │
                   │  severity)  │
                   └──────┬──────┘
                          │
            ┌─────┬───────┼────────┬─────────┐
            │     │       │        │         │
    ┌───────▼─┐  ┌▼───┐  ┌▼────┐  ┌▼───┐  ┌──▼──┐
    │Terminal │  │JSON│  │SARIF│  │HTML│    ...
    └─────────┘  └────┘  └─────┘  └────┘  └─────┘
```

## Execution Flow

1. **Initialization**
   - Create Engine with default detectors
   - Register output hooks (optional)

2. **L1 Ingestion**
   - Detect file type (.sol, .json, .ast)
   - Load and parse contract
   - Extract Send and Cancellation objects
   - Add to graph

3. **L2 Ingestion**
   - Detect file type (.cairo, .json, .sierra)
   - Load and parse contract
   - Extract Handler objects
   - Add to graph

4. **Correlation**
   - Match Sends with Handlers by selector
   - Validate parameter compatibility
   - Flag type mismatches

5. **Taint Analysis**
   - Identify user-controllable data
   - Track flow through handlers
   - Detect unsafe sinks

6. **Detection**
   - Run each detector on the graph
   - Collect findings
   - Call hooks for each finding

7. **Formatting**
   - Sort findings by severity and location
   - Format according to selected format
   - Write to file or stdout

8. **Exit**
   - Check fail-on threshold
   - Return appropriate exit code

## Type Mapping

### Solidity → Cairo

| Solidity | Cairo | Bits | Notes |
|----------|-------|------|-------|
| uint256 | u256 | 256 | (low: u128, high: u128) |
| uint128 | u128 | 128 | Direct mapping |
| uint64 | u64 | 64 | Direct mapping |
| address | felt252 | 252 | Account address |
| bool | bool | 1 | Boolean |

### Potential Mismatches

1. **uint256 encoding**: Single 256-bit slot in Solidity vs two u128s in Cairo
2. **Array layouts**: Dynamic vs fixed size differences
3. **Struct packing**: Field alignment differences

## Error Handling

All components throw `std::exception` on errors:

- **Parser errors**: Malformed input, missing files
- **Type errors**: Incompatible parameter types
- **Graph errors**: Missing references, invalid states
- **Detector errors**: Caught and added to error log

## Performance Considerations

### Bottlenecks
1. **Regex parsing**: O(n) per file where n = file size
2. **Correlator**: O(m*k) where m = sends, k = handlers
3. **Taint analysis**: O(handlers * paths) in worst case

### Optimizations
1. Cache selector hashes
2. Use finite automaton instead of regex for critical paths
3. Parallel detector execution
4. Lazy handler body parsing

## Extensions

To add new detectors:

```cpp
class MyDetector : public BaseDetector {
    std::string detector_id() const override { return "D6"; }
    std::string name() const override { return "..."; }
    std::string description() const override { return "..."; }
    
    std::vector<Finding> run(const Graph& graph) override {
        std::vector<Finding> findings;
        // Implement detection logic
        return findings;
    }
};

// Register with engine
engine.add_detector(std::make_unique<MyDetector>());
```

## Testing Strategy

1. **Unit tests**: Type system, graph ops, detector logic
2. **Integration tests**: File parsing, full analysis
3. **Regression tests**: Known vulnerabilities in fixtures
4. **Output tests**: Format verification, metadata accuracy

Run with: `make test`
