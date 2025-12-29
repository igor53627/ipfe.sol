# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `FunctionPrivateIPFE.sol` - Function-private variant based on 2017/004
  - Hides both x (plaintext) and y (function vector)
  - Double encryption with (s, t) and (u, v) secret vectors
  - SXDH security assumption
- `MIFE.sol` - Multi-input functional encryption based on 2016/425
  - 2 independent encryption slots (e.g., oracle + user)
  - Result: sum of inner products across slots
  - Use case: weighted price feeds without revealing individual inputs
- `IPFELiquidationEngine.sol` - Stablecoin liquidation with hidden thresholds
  - 5-feature scoring: ratio, volatility, utilization, age, size
  - Hidden weight vector for scoring function
  - 2x cheaper than TLO-LWE (215K vs 320K gas)
- MIFE test suite with 5 tests
- Liquidation engine test suite with 6 tests

### Gas Benchmarks
- MIFE n=4: Encrypt ~84K, Decrypt multi ~104K
- Liquidation check (n=5): ~215K gas (vs TLO-LWE ~320K)

## [0.1.0] - 2024-12-29

### Added
- Initial IPFE implementation using bn256 precompiles
- `encrypt()` function for vector encryption
- `decrypt()` function with DLog table lookup
- `initDlogTable()` for precomputing discrete log solutions
- Basic test suite with 8 tests, gas benchmarks
- README with usage examples

### Gas Benchmarks (IPFE n=10 dimensions)
- Encrypt: ~196K gas
- Decrypt: ~107K gas (excluding DLog table init)
