# IPFE.sol

Inner Product Functional Encryption for EVM using bn256 precompiles.

## What is IPFE?

Inner Product Functional Encryption allows you to:
1. Encrypt a vector **x** 
2. Create a functional key for vector **y**
3. Decrypt to learn **only** ⟨x, y⟩ (the dot product) - nothing else leaks

This enables **hidden linear policies** on-chain: the weight vector y (your secret scoring function) and input x both remain hidden, only the result is revealed.

## Use Cases

- **Hidden liquidation thresholds**: Score = ⟨features, weights⟩, weights are secret
- **Private voting**: Tally = ⟨votes, weights⟩ without revealing individual votes
- **Obfuscated policies**: Decision based on hidden linear combination of public inputs

## Construction

Based on [Abdalla et al. 2015/017](https://eprint.iacr.org/2015/017) - Simple Functional Encryption Schemes for Inner Products.

Uses EVM precompiles:
- `ecAdd` (0x06): Point addition on bn256 G1
- `ecMul` (0x07): Scalar multiplication on bn256 G1
- `ecPairing` (0x08): Pairing check on bn256

## Gas Costs (estimated)

| Operation | n=10 | n=20 |
|-----------|------|------|
| Encrypt   | ~70K | ~140K |
| Decrypt   | ~500K | ~900K |

The bottleneck is pairings: 45,000 + 34,000 per pair.

## Limitations

- **DLog requirement**: Decryption produces `e(g,g)^⟨x,y⟩`. To recover the actual value, the result must be in a small range (e.g., < 2^20) for baby-step giant-step lookup.
- **bn256 security**: ~100-bit security (not 128-bit). Fine for most DeFi applications.
- **No function privacy**: The functional key `sk_y` reveals y. For hidden y, use the multi-key variant.

## Installation

```bash
forge install
```

## Usage

```solidity
import {IPFE} from "src/IPFE.sol";

// Setup (off-chain, one-time)
// Generate master secret key msk = [s_1, ..., s_n]
// Compute master public key mpk = [g^s_1, ..., g^s_n]

// Encrypt (on-chain or off-chain)
uint256[2][] memory ct = ipfe.encrypt(x, mpk, r);

// Key generation (off-chain, by key holder)
// sk_y = sum(s_i * y_i) for functional key

// Decrypt (on-chain)
uint256 result = ipfe.decrypt(ct, sk_y, y);
```

## Related Work

- [TLO](https://github.com/igor53627/tlo) - Topology-Lattice Obfuscation (archived)
- [LARC](https://github.com/igor53627/larc) - LWE-Activated Reversible Contracts (archived)
- [circuit-mixing-research](https://github.com/igor53627/circuit-mixing-research) - Hybrid obfuscation research

## References

1. Abdalla et al. "Simple Functional Encryption Schemes for Inner Products" (2015) - https://eprint.iacr.org/2015/017
2. Agrawal et al. "Practical Function-Private Inner Product Encryption" (2017) - https://eprint.iacr.org/2017/004
3. Cosmian DMCFE (Rust reference) - https://github.com/Cosmian/dmcfe

## License

MIT
