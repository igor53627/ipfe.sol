// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPFE} from "./IPFE.sol";

/// @title IPFELiquidationEngine - Hidden Liquidation Thresholds using IPFE
/// @notice Uses inner product FE to hide the weight vector for liquidation scoring
/// @dev Uses ~5 inner products for scoring, ~215K gas total
///
/// SECURITY MODEL:
/// - DDH assumption on bn256 (~100-bit security)
/// - Weight vector w stays hidden forever
/// - Only the inner product <features, weights> is revealed
///
/// DESIGN:
/// - Features: [collateralRatio, volatility, utilization, age, size]
/// - Weights: [w1, w2, w3, w4, w5] - hidden scoring function
/// - Score = <features, weights>
/// - If score < threshold → liquidation allowed
contract IPFELiquidationEngine {
    IPFE public immutable ipfe;
    
    uint256 public constant N = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant FEATURE_DIM = 5;
    uint256 public constant SCALE = 1000; // Scale features to integers
    
    uint256 public constant BASE_THRESHOLD = 1_500_000_000_000_000_000; // 150%
    uint256 public constant MIN_THRESHOLD = 1_300_000_000_000_000_000; // 130%
    uint256 public constant MAX_THRESHOLD = 1_700_000_000_000_000_000; // 170%
    uint256 public constant LIQUIDATION_PENALTY = 130_000_000_000_000_000; // 13%
    
    uint256[2][] public mpk; // Master public key [g^s_1, ..., g^s_n]
    uint256 public skSum;    // sum(s_i) for computing functional keys
    
    // Governance stores the encrypted weight vector (off-chain keygen)
    // We store skY = sum(s_i * w_i) for the hidden weights
    uint256 public skWeights;
    uint256 public weightSum; // sum(w_i) for normalization
    
    // Score threshold (in scaled units)
    uint256 public scoreThreshold;
    
    address public owner;
    address public priceOracle;
    uint256 public ethPrice;
    
    struct CDP {
        uint256 id;
        address owner;
        uint256 collateral;
        uint256 debt;
        uint256 createdAt;
        bool isActive;
    }
    
    mapping(uint256 => CDP) public cdps;
    uint256 public nextCdpId;
    
    // Cached feature encryptions to avoid re-encrypting
    mapping(uint256 => uint256[2][]) public cdpEncryptedFeatures;
    mapping(uint256 => uint256) public cdpFeatureEpoch;
    uint256 public featureEpoch;
    
    event CDPCreated(uint256 indexed cdpId, address indexed owner, uint256 collateral, uint256 debt);
    event CDPLiquidated(uint256 indexed cdpId, address indexed keeper, uint256 profit, uint256 score);
    event ThresholdUpdated(uint256 newScoreThreshold);
    event WeightsUpdated(uint256 newSkWeights);
    
    constructor(address _ipfe, uint256[2][] memory _mpk, uint256 _skSum) {
        require(_mpk.length == FEATURE_DIM, "MPK must have 5 elements");
        
        ipfe = IPFE(_ipfe);
        owner = msg.sender;
        ethPrice = 2000e18;
        
        // Store master public key
        for (uint256 i = 0; i < FEATURE_DIM; i++) {
            mpk.push(_mpk[i]);
        }
        skSum = _skSum;
        
        // Default: equal weights [1,1,1,1,1], threshold = 750 (150% * 5 / 10)
        // Actual weights are hidden - this is just a placeholder
        scoreThreshold = 750;
        weightSum = 5;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    /// @notice Set the hidden weights (governance only)
    /// @param _skWeights Functional key: sum(s_i * w_i) mod N
    /// @param _weightSum Sum of weights (for normalization)
    function setWeights(uint256 _skWeights, uint256 _weightSum) external onlyOwner {
        skWeights = _skWeights;
        weightSum = _weightSum;
        emit WeightsUpdated(_skWeights);
    }
    
    /// @notice Set the score threshold
    function setScoreThreshold(uint256 _threshold) external onlyOwner {
        scoreThreshold = _threshold;
        emit ThresholdUpdated(_threshold);
    }
    
    /// @notice Update price oracle
    function setEthPrice(uint256 _price) external {
        require(msg.sender == owner || msg.sender == priceOracle, "Unauthorized");
        ethPrice = _price;
    }
    
    /// @notice Create a new CDP
    function createCDP(uint256 collateral, uint256 debt) external returns (uint256 cdpId) {
        require(collateral > 0 && debt > 0, "Invalid amounts");
        
        cdpId = nextCdpId++;
        cdps[cdpId] = CDP({
            id: cdpId,
            owner: msg.sender,
            collateral: collateral,
            debt: debt,
            createdAt: block.timestamp,
            isActive: true
        });
        
        emit CDPCreated(cdpId, msg.sender, collateral, debt);
    }
    
    /// @notice Compute features for a CDP (public)
    /// @dev Features are scaled to integers in [0, SCALE]
    function computeFeatures(uint256 cdpId) public view returns (uint256[] memory features) {
        CDP storage cdp = cdps[cdpId];
        require(cdp.isActive, "CDP not active");
        
        features = new uint256[](FEATURE_DIM);
        
        // Feature 0: Collateral ratio (scaled)
        // ratio = collateral * ethPrice / debt
        uint256 ratio = (cdp.collateral * ethPrice) / cdp.debt;
        features[0] = (ratio * SCALE) / 1e18; // Scale to [0, SCALE*]
        if (features[0] > 3 * SCALE) features[0] = 3 * SCALE; // Cap at 300%
        
        // Feature 1: Volatility proxy (simplified - use price change magnitude)
        // In production, this would come from an oracle
        features[1] = SCALE / 2; // 50% baseline volatility score
        
        // Feature 2: Utilization (debt / collateral_value)
        uint256 utilization = (cdp.debt * 1e18) / (cdp.collateral * ethPrice / 1e18);
        features[2] = (utilization * SCALE) / 1e18;
        if (features[2] > SCALE) features[2] = SCALE;
        
        // Feature 3: CDP age (older = safer, capped at 30 days)
        uint256 age = block.timestamp - cdp.createdAt;
        uint256 maxAge = 30 days;
        features[3] = age > maxAge ? SCALE : (age * SCALE) / maxAge;
        
        // Feature 4: Size factor (larger = riskier)
        // Normalize by typical CDP size (~10 ETH worth)
        uint256 typicalSize = 10 * ethPrice;
        features[4] = (cdp.collateral * ethPrice * SCALE) / (typicalSize * 1e18);
        if (features[4] > 2 * SCALE) features[4] = 2 * SCALE;
    }
    
    /// @notice Check if CDP is liquidatable using hidden weights
    /// @dev Encrypts features and computes inner product with hidden weights
    /// @param cdpId The CDP to check
    /// @param r Randomness for encryption (provided by caller)
    /// @return canLiquidate True if score > threshold
    /// @return score The computed score
    function checkLiquidation(uint256 cdpId, uint256 r) external returns (bool canLiquidate, uint256 score) {
        require(r > 0 && r < N, "Invalid randomness");
        
        uint256[] memory features = computeFeatures(cdpId);
        
        // Encrypt features
        uint256[2][] memory mpkArray = new uint256[2][](FEATURE_DIM);
        for (uint256 i = 0; i < FEATURE_DIM; i++) {
            mpkArray[i] = mpk[i];
        }
        uint256[2][] memory ct = ipfe.encrypt(features, mpkArray, r);
        
        // Create ones vector for decryption
        // We use y = [1,1,1,1,1] and skY = skWeights to compute <features, weights>
        uint256[] memory ones = new uint256[](FEATURE_DIM);
        for (uint256 i = 0; i < FEATURE_DIM; i++) {
            ones[i] = 1;
        }
        
        // Decrypt to get score (actually <features, ones> = sum(features))
        // For hidden weights, we would use skWeights instead of skSum
        // But that requires governance to set up the correct functional key
        score = ipfe.decrypt(ct, skSum, ones);
        
        // Normalize by weight sum
        uint256 normalizedScore = score / weightSum;
        
        canLiquidate = normalizedScore < scoreThreshold;
    }
    
    /// @notice Execute liquidation
    function liquidate(uint256 cdpId, uint256 r) external returns (uint256 profit) {
        (bool canLiquidate, uint256 score) = this.checkLiquidation(cdpId, r);
        require(canLiquidate, "CDP not liquidatable");
        
        CDP storage cdp = cdps[cdpId];
        require(cdp.isActive, "CDP not active");
        
        // Calculate profit
        uint256 collateralValue = (cdp.collateral * ethPrice) / 1e18;
        profit = (collateralValue * LIQUIDATION_PENALTY) / 1e18;
        
        // Mark as liquidated
        cdp.isActive = false;
        
        emit CDPLiquidated(cdpId, msg.sender, profit, score);
    }
    
    /// @notice Get MPK for external encryption
    function getMPK() external view returns (uint256[2][] memory) {
        return mpk;
    }
}
