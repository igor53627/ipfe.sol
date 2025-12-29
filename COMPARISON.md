# IPFE vs LARC vs TLO: Comparison

Comparison of obfuscation approaches for hidden liquidation thresholds.

## Gas Costs

| Approach | Operation | Gas | Notes |
|----------|-----------|-----|-------|
| **IPFE** | checkLiquidation (n=5) | ~215K | DDH security, permanent |
| **TLO-LWE** | evaluate (640 gates) | ~320K | LWE security, epoch-based |
| **LARC** | reveal (64n, 640 gates) | ~2.58M | LWE security, one-time |

**Winner: IPFE (12x cheaper than LARC, 1.5x cheaper than TLO)**

## Security Properties

| Property | IPFE | TLO-LWE | LARC |
|----------|------|---------|------|
| Assumption | DDH (bn256) | LWE + topology | LWE |
| Security Level | ~100-bit | ~108-bit + obfuscation | ~108-bit |
| Post-Quantum | No | Yes (LWE) | Yes (LWE) |
| Weight Privacy | Permanent | Epoch-bounded | One-time |
| Function Class | Linear (inner products) | Boolean circuits | Boolean circuits |

## Use Case Fit: Stablecoin Liquidation

For liquidation scoring where `score = <features, weights>`:

| Criterion | IPFE | TLO-LWE | LARC |
|-----------|------|---------|------|
| Fits Linear Scoring | [OK] Native | Requires circuit | Requires circuit |
| Gas Efficiency | [OK] Best | Medium | Worst |
| Weight Secrecy | [OK] Forever | Rotated per epoch | Until revealed |
| Setup Complexity | Simple MPK | Complex circuit gen | Complex circuit gen |

**Recommendation: Use IPFE for linear liquidation scoring.**

## When to Use Each

### IPFE
- Linear scoring functions: `score = w1*x1 + w2*x2 + ... + wn*xn`
- Weights must stay hidden forever
- Gas efficiency is critical
- Post-quantum not required

### TLO-LWE
- Arbitrary boolean functions (not just linear)
- Need post-quantum security
- Can tolerate epoch rotation
- Topology mixing adds defense-in-depth

### LARC
- One-time secret reveal (honeypots)
- Complex predicates (hash preimages, etc.)
- Post-quantum required
- Gas is not a concern

## Implementation Status

| Component | File | Tests |
|-----------|------|-------|
| IPFE Core | `src/IPFE.sol` | 8 pass |
| Function-Private | `src/FunctionPrivateIPFE.sol` | - |
| Multi-Input | `src/MIFE.sol` | 5 pass |
| Liquidation Engine | `src/IPFELiquidationEngine.sol` | 6 pass |

Total: 19 tests passing.
