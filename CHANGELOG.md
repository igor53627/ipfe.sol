# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial IPFE implementation using bn256 precompiles
- `encrypt()` function for vector encryption
- `decrypt()` function with DLog table lookup
- `initDlogTable()` for precomputing discrete log solutions
- Basic test suite with gas benchmarks
- README with usage examples

### Gas Benchmarks (n=10 dimensions)
- Encrypt: ~196K gas
- Decrypt: ~107K gas (excluding DLog table init)
