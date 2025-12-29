// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MIFE - Multi-Input Inner Product Functional Encryption
/// @notice Based on "Multi-Input Inner-Product FE from Pairings" (2016/425)
/// @dev Allows n independent encryptors, decryptor learns sum of inner products
///
/// USE CASE: Two independent parties (e.g., oracle and user) each encrypt their
/// own vector, and a third party can compute <x1, y1> + <x2, y2> without learning
/// individual vectors.
///
/// CONSTRUCTION (2-slot version):
/// - Setup: For each slot i, generate (A_i, W_i, V_i, z_i)
/// - Encrypt_i(x_i): ct_i = (A_i*s_i, x_i + W_i*A_i*s_i, z_i + V_i*A_i*s_i)
/// - KeyGen(y1, y2): sk = (d1, d2, r, z) in G2
/// - Decrypt: Pairings cancel W/V terms, result is sum(<x_i, y_i>) in GT
///
/// SIMPLIFIED VERSION: We implement a 2-slot version where:
/// - Slot 1: Oracle encrypts price/market data
/// - Slot 2: User encrypts position/weights
/// - Decryptor gets combined score without seeing individual inputs
contract MIFE {
    // bn256 curve parameters
    uint256 public constant P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 public constant N = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // Generator point G1
    uint256 public constant G1_X = 1;
    uint256 public constant G1_Y = 2;
    
    // Generator point G2
    uint256 public constant G2_X_IM = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 public constant G2_X_RE = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 public constant G2_Y_IM = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 public constant G2_Y_RE = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    
    // Max dimension per slot
    uint256 public constant MAX_DIM = 16;
    uint256 public constant NUM_SLOTS = 2;
    
    // DLog table
    uint256 public constant DLOG_MAX = 1 << 16;
    mapping(bytes32 => uint256) public dlogTable;
    bool public dlogTableInitialized;
    
    // Slot encryption keys (set during setup)
    // Each slot has its own master key components
    struct SlotKey {
        bool initialized;
        uint256[2][] mpk; // Master public key for this slot
    }
    mapping(uint256 => SlotKey) public slotKeys;
    
    /// @notice Scalar multiplication on G1
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
    
    /// @notice Point addition on G1
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
    
    /// @notice Negate a G1 point
    function ecNeg(uint256[2] memory point) public pure returns (uint256[2] memory) {
        if (point[0] == 0 && point[1] == 0) {
            return point;
        }
        return [point[0], P - point[1]];
    }
    
    /// @notice Initialize a slot with its master public key
    /// @param slot The slot index (0 or 1)
    /// @param mpk Master public key for this slot
    function initSlot(uint256 slot, uint256[2][] calldata mpk) external {
        require(slot < NUM_SLOTS, "Invalid slot");
        require(mpk.length > 0 && mpk.length <= MAX_DIM, "Invalid MPK dimension");
        require(!slotKeys[slot].initialized, "Slot already initialized");
        
        slotKeys[slot].mpk = new uint256[2][](mpk.length);
        for (uint256 i = 0; i < mpk.length; i++) {
            slotKeys[slot].mpk[i] = mpk[i];
        }
        slotKeys[slot].initialized = true;
    }
    
    /// @notice Encrypt a vector for a specific slot
    /// @param slot The slot index (0 or 1)
    /// @param x The plaintext vector
    /// @param r Random scalar
    /// @return ct Ciphertext for this slot
    function encryptSlot(
        uint256 slot,
        uint256[] calldata x,
        uint256 r
    ) external view returns (uint256[2][] memory ct) {
        require(slot < NUM_SLOTS, "Invalid slot");
        require(slotKeys[slot].initialized, "Slot not initialized");
        
        uint256[2][] storage mpk = slotKeys[slot].mpk;
        uint256 n = x.length;
        require(n == mpk.length, "Dimension mismatch");
        require(r > 0 && r < N, "Invalid randomness");
        
        ct = new uint256[2][](n + 1);
        
        // c_0 = g^r
        ct[0] = ecMul([G1_X, G1_Y], r);
        
        // c_i = h_i^r * g^x_i
        for (uint256 i = 0; i < n; i++) {
            require(x[i] < N, "x[i] out of range");
            uint256[2] memory hiR = ecMul(mpk[i], r);
            uint256[2] memory gXi = ecMul([G1_X, G1_Y], x[i]);
            ct[i + 1] = ecAdd(hiR, gXi);
        }
    }
    
    /// @notice Decrypt two ciphertexts to get sum of inner products
    /// @dev Returns <x1, y1> + <x2, y2>
    /// @param ct1 Ciphertext from slot 0
    /// @param ct2 Ciphertext from slot 1
    /// @param skY1 Functional key for slot 0: sum(s1_i * y1_i)
    /// @param skY2 Functional key for slot 1: sum(s2_i * y2_i)
    /// @param y1 Function vector for slot 0
    /// @param y2 Function vector for slot 1
    /// @return result The sum <x1, y1> + <x2, y2>
    function decryptMulti(
        uint256[2][] calldata ct1,
        uint256[2][] calldata ct2,
        uint256 skY1,
        uint256 skY2,
        uint256[] calldata y1,
        uint256[] calldata y2
    ) external view returns (uint256 result) {
        require(dlogTableInitialized, "DLog table not initialized");
        require(ct1.length == y1.length + 1, "ct1 dimension mismatch");
        require(ct2.length == y2.length + 1, "ct2 dimension mismatch");
        
        // Compute result for slot 1
        uint256[2] memory result1 = _computeSlotResult(ct1, skY1, y1);
        
        // Compute result for slot 2
        uint256[2] memory result2 = _computeSlotResult(ct2, skY2, y2);
        
        // Sum the results: g^(<x1,y1> + <x2,y2>)
        uint256[2] memory resultPoint = ecAdd(result1, result2);
        
        // Look up DLog
        return _lookupDlog(resultPoint);
    }
    
    /// @notice Compute intermediate result for one slot
    function _computeSlotResult(
        uint256[2][] calldata ct,
        uint256 skY,
        uint256[] calldata y
    ) internal view returns (uint256[2] memory resultPoint) {
        uint256 n = y.length;
        
        // Numerator: sum(c_i * y_i)
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
        
        // Result: numerator - denominator = g^<x,y>
        resultPoint = ecAdd(numerator, ecNeg(denominator));
    }
    
    /// @notice Look up discrete log
    function _lookupDlog(uint256[2] memory point) internal view returns (uint256 result) {
        bytes32 pointHash = keccak256(abi.encodePacked(point[0], point[1]));
        result = dlogTable[pointHash];
        
        if (point[0] == 0 && point[1] == 0) {
            return 0;
        }
        
        require(result != 0 || (point[0] == G1_X && point[1] == G1_Y), "DLog not found");
        if (point[0] == G1_X && point[1] == G1_Y) {
            return 1;
        }
    }
    
    /// @notice Initialize DLog table
    function initDlogTable(uint256 batchStart, uint256 batchSize) external {
        require(batchStart + batchSize <= DLOG_MAX, "Batch exceeds max");
        
        uint256[2] memory point;
        uint256[2] memory g = [G1_X, G1_Y];
        
        if (batchStart == 0) {
            point = g;
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
    
    /// @notice Get slot MPK
    function getSlotMPK(uint256 slot) external view returns (uint256[2][] memory) {
        require(slot < NUM_SLOTS, "Invalid slot");
        require(slotKeys[slot].initialized, "Slot not initialized");
        return slotKeys[slot].mpk;
    }
}
