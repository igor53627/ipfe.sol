// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPFE - Inner Product Functional Encryption
/// @notice Implements IPFE from Abdalla et al. 2015/017 using bn256 precompiles
/// @dev Security: DDH assumption on bn256 (~100-bit security)
///
/// CONSTRUCTION OVERVIEW:
/// - Setup: msk = [s_1, ..., s_n] random scalars
///          mpk = [h_1, ..., h_n] where h_i = g^s_i
/// - Encrypt(x, mpk): ct = (c_0, c_1, ..., c_n)
///          c_0 = g^r (random r)
///          c_i = h_i^r * g^x_i
/// - KeyGen(msk, y): sk_y = sum(s_i * y_i) mod p
/// - Decrypt(ct, sk_y, y): 
///          numerator = product(e(c_i, g^y_i))
///          denominator = e(c_0, g^sk_y)
///          result = numerator / denominator = e(g,g)^⟨x,y⟩
///          Solve DLog to get ⟨x,y⟩
contract IPFE {
    // bn256 curve parameters
    uint256 public constant P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant N = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // Generator point G1
    uint256 public constant G1_X = 1;
    uint256 public constant G1_Y = 2;
    
    // Generator point G2 (for pairing)
    uint256 public constant G2_X_IM = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 public constant G2_X_RE = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 public constant G2_Y_IM = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 public constant G2_Y_RE = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    
    // Precompile addresses
    address constant EC_ADD = address(0x06);
    address constant EC_MUL = address(0x07);
    address constant EC_PAIRING = address(0x08);
    
    // Max vector dimension (gas-limited)
    uint256 public constant MAX_DIM = 32;
    
    // DLog lookup table for small results
    // Maps e(g,g)^k -> k for k in [0, DLOG_MAX]
    uint256 public constant DLOG_MAX = 1 << 16; // 65536
    mapping(bytes32 => uint256) public dlogTable;
    bool public dlogTableInitialized;
    
    // Events
    event Encrypted(bytes32 indexed id, uint256 dimension);
    event Decrypted(bytes32 indexed id, uint256 result);
    
    /// @notice Scalar multiplication on G1: result = scalar * point
    function ecMul(uint256[2] memory point, uint256 scalar) public view returns (uint256[2] memory result) {
        uint256[3] memory input;
        input[0] = point[0];
        input[1] = point[1];
        input[2] = scalar;
        
        assembly {
            let success := staticcall(gas(), 0x07, input, 0x60, result, 0x40)
            if iszero(success) { revert(0, 0) }
        }
    }
    
    /// @notice Point addition on G1: result = p1 + p2
    function ecAdd(uint256[2] memory p1, uint256[2] memory p2) public view returns (uint256[2] memory result) {
        uint256[4] memory input;
        input[0] = p1[0];
        input[1] = p1[1];
        input[2] = p2[0];
        input[3] = p2[1];
        
        assembly {
            let success := staticcall(gas(), 0x06, input, 0x80, result, 0x40)
            if iszero(success) { revert(0, 0) }
        }
    }
    
    /// @notice Negate a G1 point (for subtraction)
    function ecNeg(uint256[2] memory point) public pure returns (uint256[2] memory) {
        if (point[0] == 0 && point[1] == 0) {
            return point; // Point at infinity
        }
        return [point[0], P - point[1]];
    }
    
    /// @notice Check pairing equation: e(a1, b1) * e(a2, b2) == 1
    /// @dev Returns true if the pairing product equals identity
    function checkPairing(
        uint256[2] memory a1,
        uint256[4] memory b1,
        uint256[2] memory a2,
        uint256[4] memory b2
    ) public view returns (bool) {
        uint256[12] memory input;
        
        // First pairing: (a1, b1)
        input[0] = a1[0];
        input[1] = a1[1];
        input[2] = b1[0]; // x_im
        input[3] = b1[1]; // x_re
        input[4] = b1[2]; // y_im
        input[5] = b1[3]; // y_re
        
        // Second pairing: (a2, b2)
        input[6] = a2[0];
        input[7] = a2[1];
        input[8] = b2[0];
        input[9] = b2[1];
        input[10] = b2[2];
        input[11] = b2[3];
        
        uint256[1] memory result;
        assembly {
            let success := staticcall(gas(), 0x08, input, 0x180, result, 0x20)
            if iszero(success) { revert(0, 0) }
        }
        
        return result[0] == 1;
    }
    
    /// @notice Encrypt a vector x using the master public key
    /// @param x The plaintext vector (each element < N)
    /// @param mpk Master public key [h_1, ..., h_n] where h_i = g^s_i
    /// @param r Random scalar for encryption
    /// @return ct Ciphertext [(c_0_x, c_0_y), (c_1_x, c_1_y), ...]
    function encrypt(
        uint256[] calldata x,
        uint256[2][] calldata mpk,
        uint256 r
    ) external view returns (uint256[2][] memory ct) {
        uint256 n = x.length;
        require(n > 0 && n <= MAX_DIM, "Invalid dimension");
        require(mpk.length == n, "MPK dimension mismatch");
        require(r > 0 && r < N, "Invalid randomness");
        
        ct = new uint256[2][](n + 1);
        
        // c_0 = g^r
        ct[0] = ecMul([G1_X, G1_Y], r);
        
        // c_i = h_i^r * g^x_i for i = 1..n
        for (uint256 i = 0; i < n; i++) {
            require(x[i] < N, "x[i] out of range");
            
            // h_i^r
            uint256[2] memory hiR = ecMul(mpk[i], r);
            
            // g^x_i
            uint256[2] memory gXi = ecMul([G1_X, G1_Y], x[i]);
            
            // c_i = h_i^r + g^x_i (point addition = multiplication in exponent)
            ct[i + 1] = ecAdd(hiR, gXi);
        }
    }
    
    /// @notice Decrypt a ciphertext using functional key sk_y
    /// @dev Returns the inner product ⟨x, y⟩ if it's in the DLog table
    /// @param ct Ciphertext from encrypt()
    /// @param skY Functional secret key = sum(s_i * y_i) mod N
    /// @param y The function vector (public)
    /// @return result The inner product ⟨x, y⟩
    function decrypt(
        uint256[2][] calldata ct,
        uint256 skY,
        uint256[] calldata y
    ) external view returns (uint256 result) {
        uint256 n = y.length;
        require(ct.length == n + 1, "Ciphertext dimension mismatch");
        require(dlogTableInitialized, "DLog table not initialized");
        
        // Compute: product(c_i^y_i) / c_0^sk_y
        // = product((h_i^r * g^x_i)^y_i) / g^(r*sk_y)
        // = product(h_i^(r*y_i) * g^(x_i*y_i)) / g^(r*sum(s_i*y_i))
        // = g^(r*sum(s_i*y_i)) * g^sum(x_i*y_i) / g^(r*sum(s_i*y_i))
        // = g^⟨x,y⟩
        
        // Numerator: sum of c_i * y_i
        uint256[2] memory numerator = [uint256(0), uint256(0)];
        for (uint256 i = 0; i < n; i++) {
            if (y[i] > 0) {
                uint256[2] memory term = ecMul(ct[i + 1], y[i]);
                if (numerator[0] == 0 && numerator[1] == 0) {
                    numerator = term;
                } else {
                    numerator = ecAdd(numerator, term);
                }
            }
        }
        
        // Denominator: c_0 * sk_y
        uint256[2] memory denominator = ecMul(ct[0], skY);
        
        // Result point: numerator - denominator = g^⟨x,y⟩
        uint256[2] memory resultPoint = ecAdd(numerator, ecNeg(denominator));
        
        // Look up DLog
        bytes32 pointHash = keccak256(abi.encodePacked(resultPoint[0], resultPoint[1]));
        result = dlogTable[pointHash];
        
        // Check for zero (identity point)
        if (resultPoint[0] == 0 && resultPoint[1] == 0) {
            return 0;
        }
        
        require(result != 0 || (resultPoint[0] == G1_X && resultPoint[1] == G1_Y), "DLog not found");
        if (resultPoint[0] == G1_X && resultPoint[1] == G1_Y) {
            return 1;
        }
    }
    
    /// @notice Initialize the DLog lookup table (expensive, do once)
    /// @dev Computes g^k for k in [0, batchEnd) and stores hash -> k
    /// @param batchStart Starting index
    /// @param batchSize Number of entries to compute
    /// @param markComplete Set to true on the final batch to mark table as initialized
    function initDlogTable(uint256 batchStart, uint256 batchSize, bool markComplete) external {
        require(batchStart + batchSize <= DLOG_MAX, "Batch exceeds max");
        
        uint256[2] memory point;
        uint256[2] memory g = [G1_X, G1_Y];
        
        if (batchStart == 0) {
            // g^0 = identity (point at infinity) - use a special marker
            // We'll handle 0 specially in decrypt
            point = g; // g^1
            dlogTable[keccak256(abi.encodePacked(point[0], point[1]))] = 1;
            
            // Continue from g^2
            point = ecAdd(point, g);
            for (uint256 k = 2; k < batchSize && k < DLOG_MAX; k++) {
                bytes32 h = keccak256(abi.encodePacked(point[0], point[1]));
                dlogTable[h] = k;
                point = ecAdd(point, g);
            }
        } else {
            // Start from g^batchStart
            point = ecMul(g, batchStart);
            
            for (uint256 k = batchStart; k < batchStart + batchSize && k < DLOG_MAX; k++) {
                bytes32 h = keccak256(abi.encodePacked(point[0], point[1]));
                dlogTable[h] = k;
                point = ecAdd(point, g);
            }
        }
        
        if (markComplete) {
            dlogTableInitialized = true;
        }
    }
    
    /// @notice Simplified init for testing - marks as complete after any init
    function initDlogTable(uint256 batchStart, uint256 batchSize) external {
        require(batchStart + batchSize <= DLOG_MAX, "Batch exceeds max");
        
        uint256[2] memory point;
        uint256[2] memory g = [G1_X, G1_Y];
        
        if (batchStart == 0) {
            point = g; // g^1
            dlogTable[keccak256(abi.encodePacked(point[0], point[1]))] = 1;
            point = ecAdd(point, g);
            
            for (uint256 k = 2; k < batchSize && k < DLOG_MAX; k++) {
                bytes32 h = keccak256(abi.encodePacked(point[0], point[1]));
                dlogTable[h] = k;
                point = ecAdd(point, g);
            }
        } else {
            point = ecMul(g, batchStart);
            
            for (uint256 k = batchStart; k < batchStart + batchSize && k < DLOG_MAX; k++) {
                bytes32 h = keccak256(abi.encodePacked(point[0], point[1]));
                dlogTable[h] = k;
                point = ecAdd(point, g);
            }
        }
        
        dlogTableInitialized = true;
    }
    
    /// @notice Check if a point is in the DLog table
    function lookupDlog(uint256[2] calldata point) external view returns (bool found, uint256 value) {
        bytes32 h = keccak256(abi.encodePacked(point[0], point[1]));
        value = dlogTable[h];
        found = (value != 0) || (point[0] == 0 && point[1] == 0);
    }
}
