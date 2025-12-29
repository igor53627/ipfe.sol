# IPFE.sol

Inner Product Functional Encryption for EVM using bn256 precompiles.

## What is IPFE?

Inner Product Functional Encryption allows you to:
1. Encrypt a vector **x** 
2. Create a functional key for vector **y**
3. Decrypt to learn **only** ⟨x, y⟩ (the dot product) - nothing else leaks

This enables **hidden linear policies** on-chain: the weight vector y (your secret scoring function) and input x both remain hidden, only the result is revealed.

## Contracts

| Contract | Description | Paper |
|----------|-------------|-------|
| `IPFE.sol` | Basic inner product FE | [Abdalla15](https://eprint.iacr.org/2015/017) |
| `FunctionPrivateIPFE.sol` | Hides both x AND y | [2017/004](https://eprint.iacr.org/2017/004) |
| `MIFE.sol` | Multi-input FE (2 independent encryptors) | [2016/425](https://eprint.iacr.org/2016/425) |

## Use Cases

- **Hidden liquidation thresholds**: Score = ⟨features, weights⟩, weights are secret
- **Private voting**: Tally = ⟨votes, weights⟩ without revealing individual votes
- **Multi-party computation**: Oracle encrypts prices, user encrypts weights, get weighted sum
- **Obfuscated policies**: Decision based on hidden linear combination of public inputs

## Gas Costs

| Operation | n=4 | n=10 |
|-----------|-----|------|
| IPFE Encrypt | ~80K | ~196K |
| IPFE Decrypt | ~54K | ~107K |
| MIFE Encrypt (per slot) | ~84K | ~196K |
| MIFE Decrypt (2 slots) | ~104K | ~210K |

## Quick Start

```bash
forge install
forge test -vv
```

## Usage

### Basic IPFE

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

### Multi-Input FE (MIFE)

```solidity
import {MIFE} from "src/MIFE.sol";

// Setup: Initialize 2 slots with different keys
mife.initSlot(0, mpk_oracle);  // Oracle's key
mife.initSlot(1, mpk_user);    // User's key

// Oracle encrypts prices
uint256[2][] memory ctPrices = mife.encryptSlot(0, prices, r1);

// User encrypts weights (independently!)
uint256[2][] memory ctWeights = mife.encryptSlot(1, weights, r2);

// Decrypt: get <prices, y1> + <weights, y2>
uint256 result = mife.decryptMulti(ctPrices, ctWeights, skY1, skY2, y1, y2);
```

## Construction Details

### Basic IPFE (Abdalla et al. 2015/017)
- **Encryption**: ct = (g^r, h_1^r * g^x_1, ..., h_n^r * g^x_n)
- **Decryption**: Compute g^⟨x,y⟩, solve DLog
- **Security**: DDH assumption on bn256 (~100-bit)

### Function-Private IPFE (2017/004)
- **Double encryption**: Two layers mask both x and y
- **Full privacy**: Neither x nor y is revealed to the other party
- **Security**: SXDH assumption (DDH in both G1 and G2)

### Multi-Input FE (2016/425)
- **Independent encryptors**: Each slot has its own keys
- **Result**: Sum of inner products across slots
- **Use case**: Untrusted parties contribute encrypted inputs

## Limitations

- **DLog requirement**: Decryption produces g^⟨x,y⟩. To recover the actual value, the result must be in a small range (e.g., < 2^16) for table lookup.
- **bn256 security**: ~100-bit security (not 128-bit). Fine for most DeFi applications.
- **No function privacy in basic IPFE**: The functional key sk_y reveals y. Use FunctionPrivateIPFE for hidden y.

## Related Work

- [circuit-mixing-research](https://github.com/igor53627/circuit-mixing-research) - Hybrid obfuscation research
- [iO-papers](https://github.com/igor53627/iO-papers) - 500+ iO research papers indexed
- [Cosmian DMCFE](https://github.com/Cosmian/dmcfe) - Rust reference implementation

## References

1. Abdalla et al. "Simple Functional Encryption Schemes for Inner Products" (2015) - https://eprint.iacr.org/2015/017
2. Agrawal et al. "Practical Function-Private Inner Product Encryption" (2017) - https://eprint.iacr.org/2017/004
3. Abdalla et al. "Multi-Input Inner-Product Functional Encryption from Pairings" (2016) - https://eprint.iacr.org/2016/425
4. Cosmian DMCFE (Rust reference) - https://github.com/Cosmian/dmcfe

## License

MIT
