# Roadmap

Grant period: 3 months after funding.

## Month 1

- Publish to GitHub Marketplace as a ready-to-use Action
- Detector D7: l1_handler reentrancy via send_message_to_l1_syscall
- Detector D8: selector collision (two functions, same keccak)
- Post to community.starknet.io and Discord #tooling
- Public audit of one Starknet bridge using CrossGuard

## Month 2

- Sierra JSON integration: parse Scarb `*.sierra.json` instead of source regex
- solc AST JSON: full coverage of multi-file L1 contracts
- HTML report with call-graph (D3.js)
- Second public audit

## Month 3

- `scarb crossguard check` plugin
- v1.0 release with binaries for Linux / macOS / Windows
- Community workshop (Starknet Discord)
- Target: 5+ bridge teams running CrossGuard in CI

## Success metrics

- 2+ real vulnerabilities found in production or testnet contracts
- 5+ repos using CrossGuard in CI
- Scarb plugin listed in the registry
