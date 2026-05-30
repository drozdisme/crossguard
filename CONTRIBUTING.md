# Contributing

## Setup

```bash
sudo apt-get install build-essential cmake  # Ubuntu
brew install cmake                           # macOS

mkdir build && cd build && cmake .. && make
cd build && ctest --output-on-failure
```

## Adding a detector

1. Add class in `include/detectors.hpp` extending `BaseDetector`
2. Implement `run(const Graph&)` in `src/detectors.cpp`
3. Register in `Engine::Engine()` in `src/engine.cpp`
4. Add fixture pair in `fixtures/` (one vulnerable, one safe)
5. Add test in `tests/test_crossguard.cpp`

Planned: D7 (l1_handler reentrancy), D8 (selector collision).

## PR checklist

- All tests pass (`ctest`)
- New behavior has a test
- No new compiler warnings (`-Wall -Wextra`)

## Code style

C++17. `snake_case` for functions/variables, `PascalCase` for types. No raw owning pointers.
