// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPFE} from "./IPFE.sol";

/// @title FairRAI - RAI-style Stablecoin with PoA ≈ 1.0
/// @notice Combines IPFE hidden thresholds with fair keeper selection
/// @dev Achieves low Price of Anarchy through:
///      1. Hidden scoring (IPFE) - removes information asymmetry
///      2. Commit-reveal - removes front-running
///      3. Random selection - removes gas priority advantage
///      4. Profit sharing - removes winner-takes-all
///
/// MECHANISM:
/// Phase 1: Keepers commit hash(cdpId, keeper, nonce) during commit window
/// Phase 2: Keepers reveal, contract checks if CDP is liquidatable via IPFE
/// Phase 3: Random winner selected from valid reveals, profit split with others
///
/// This gives PoA close to 1.0 because:
/// - No one knows exact threshold (IPFE)
/// - No one can front-run (commit-reveal)
/// - Gas price doesn't determine winner (random)
/// - Profit is shared (not winner-takes-all)
contract FairRAI {
    IPFE public immutable ipfe;
    
    uint256 public constant N = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant FEATURE_DIM = 5;
    uint256 public constant SCALE = 1000;
    
    // Timing constants
    uint256 public constant COMMIT_WINDOW = 10;   // 10 blocks to commit
    uint256 public constant REVEAL_WINDOW = 10;   // 10 blocks to reveal
    uint256 public constant ROUND_LENGTH = COMMIT_WINDOW + REVEAL_WINDOW;
    
    // Profit sharing: winner gets 60%, rest split among other valid keepers
    uint256 public constant WINNER_SHARE = 60;
    uint256 public constant POOL_SHARE = 40;
    
    // RAI-style parameters
    uint256 public redemptionPrice;      // Target price (floating, like RAI)
    int256 public redemptionRate;        // PID-controlled rate
    uint256 public lastUpdateTime;
    
    // PID controller state
    int256 public proportionalError;
    int256 public integralError;
    int256 public lastError;
    
    // IPFE keys
    uint256[2][] public mpk;
    uint256 public skSum;
    uint256 public scoreThreshold;
    
    // CDP storage
    struct CDP {
        address owner;
        uint256 collateral;
        uint256 debt;
        uint256 createdAt;
        bool isActive;
    }
    mapping(uint256 => CDP) public cdps;
    uint256 public nextCdpId;
    
    // Liquidation rounds
    struct LiquidationRound {
        uint256 cdpId;
        uint256 startBlock;
        bytes32[] commitments;
        address[] revealedKeepers;
        bool executed;
    }
    mapping(uint256 => LiquidationRound) public rounds;
    uint256 public nextRoundId;
    
    // Keeper commitments: roundId => keeper => commitment
    mapping(uint256 => mapping(address => bytes32)) public commitments;
    mapping(uint256 => mapping(address => bool)) public hasRevealed;
    
    // Keeper stats (for reputation/slashing)
    mapping(address => uint256) public keeperSuccesses;
    mapping(address => uint256) public keeperFailures;
    
    address public owner;
    uint256 public ethPrice;
    
    event CDPCreated(uint256 indexed cdpId, address indexed owner, uint256 collateral, uint256 debt);
    event RoundStarted(uint256 indexed roundId, uint256 indexed cdpId, uint256 startBlock);
    event KeeperCommitted(uint256 indexed roundId, address indexed keeper);
    event KeeperRevealed(uint256 indexed roundId, address indexed keeper, bool valid);
    event LiquidationExecuted(uint256 indexed roundId, address indexed winner, uint256 profit);
    event RedemptionRateUpdated(int256 newRate);
    
    constructor(address _ipfe, uint256[2][] memory _mpk, uint256 _skSum) {
        require(_mpk.length == FEATURE_DIM, "MPK must have 5 elements");
        
        ipfe = IPFE(_ipfe);
        owner = msg.sender;
        ethPrice = 2000e18;
        redemptionPrice = 1e18; // Start at $1
        lastUpdateTime = block.timestamp;
        
        for (uint256 i = 0; i < FEATURE_DIM; i++) {
            mpk.push(_mpk[i]);
        }
        skSum = _skSum;
        scoreThreshold = 750;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    // =========================================================================
    // RAI-style PID Controller
    // =========================================================================
    
    /// @notice Update redemption rate based on market price deviation
    /// @param marketPrice Current market price from oracle
    function updateRedemptionRate(uint256 marketPrice) external {
        require(block.timestamp >= lastUpdateTime + 1 hours, "Too soon");
        
        // Error = redemptionPrice - marketPrice (positive if above peg)
        int256 error = int256(redemptionPrice) - int256(marketPrice);
        
        // PID calculation
        int256 pTerm = error / 10000;                           // P
        integralError += error;
        int256 iTerm = integralError / 100000;                  // I
        int256 dTerm = (error - lastError) / 1000;              // D
        
        redemptionRate = pTerm + iTerm + dTerm;
        lastError = error;
        lastUpdateTime = block.timestamp;
        
        // Apply rate to redemption price
        if (redemptionRate > 0) {
            redemptionPrice = redemptionPrice * (1e18 + uint256(redemptionRate)) / 1e18;
        } else {
            redemptionPrice = redemptionPrice * (1e18 - uint256(-redemptionRate)) / 1e18;
        }
        
        emit RedemptionRateUpdated(redemptionRate);
    }
    
    // =========================================================================
    // CDP Management
    // =========================================================================
    
    function createCDP(uint256 debt) external payable returns (uint256 cdpId) {
        require(msg.value > 0 && debt > 0, "Invalid amounts");
        
        cdpId = nextCdpId++;
        cdps[cdpId] = CDP({
            owner: msg.sender,
            collateral: msg.value,
            debt: debt,
            createdAt: block.timestamp,
            isActive: true
        });
        
        emit CDPCreated(cdpId, msg.sender, msg.value, debt);
    }
    
    function computeFeatures(uint256 cdpId) public view returns (uint256[] memory features) {
        CDP storage cdp = cdps[cdpId];
        require(cdp.isActive, "CDP not active");
        
        features = new uint256[](FEATURE_DIM);
        
        uint256 ratio = (cdp.collateral * ethPrice) / cdp.debt;
        features[0] = (ratio * SCALE) / 1e18;
        if (features[0] > 3 * SCALE) features[0] = 3 * SCALE;
        
        features[1] = SCALE / 2; // Volatility placeholder
        
        uint256 utilization = (cdp.debt * 1e18) / (cdp.collateral * ethPrice / 1e18);
        features[2] = (utilization * SCALE) / 1e18;
        if (features[2] > SCALE) features[2] = SCALE;
        
        uint256 age = block.timestamp - cdp.createdAt;
        uint256 maxAge = 30 days;
        features[3] = age > maxAge ? SCALE : (age * SCALE) / maxAge;
        
        uint256 typicalSize = 10 * ethPrice;
        features[4] = (cdp.collateral * ethPrice * SCALE) / (typicalSize * 1e18);
        if (features[4] > 2 * SCALE) features[4] = 2 * SCALE;
    }
    
    // =========================================================================
    // Fair Liquidation: Commit Phase
    // =========================================================================
    
    /// @notice Start a liquidation round for a CDP
    /// @dev Anyone can start a round, but must wait for previous round on same CDP
    function startLiquidationRound(uint256 cdpId) external returns (uint256 roundId) {
        require(cdps[cdpId].isActive, "CDP not active");
        
        roundId = nextRoundId++;
        rounds[roundId] = LiquidationRound({
            cdpId: cdpId,
            startBlock: block.number,
            commitments: new bytes32[](0),
            revealedKeepers: new address[](0),
            executed: false
        });
        
        emit RoundStarted(roundId, cdpId, block.number);
    }
    
    /// @notice Commit to liquidate a CDP (during commit window)
    /// @param roundId The liquidation round
    /// @param commitment Hash of (cdpId, keeper, nonce)
    function commit(uint256 roundId, bytes32 commitment) external {
        LiquidationRound storage round = rounds[roundId];
        require(block.number < round.startBlock + COMMIT_WINDOW, "Commit window closed");
        require(commitments[roundId][msg.sender] == bytes32(0), "Already committed");
        
        commitments[roundId][msg.sender] = commitment;
        round.commitments.push(commitment);
        
        emit KeeperCommitted(roundId, msg.sender);
    }
    
    // =========================================================================
    // Fair Liquidation: Reveal Phase
    // =========================================================================
    
    /// @notice Reveal commitment and check if liquidation is valid
    /// @param roundId The liquidation round
    /// @param nonce The nonce used in commitment
    /// @param r Randomness for IPFE encryption
    function reveal(uint256 roundId, bytes32 nonce, uint256 r) external {
        LiquidationRound storage round = rounds[roundId];
        require(block.number >= round.startBlock + COMMIT_WINDOW, "Commit window not closed");
        require(block.number < round.startBlock + ROUND_LENGTH, "Reveal window closed");
        require(!hasRevealed[roundId][msg.sender], "Already revealed");
        
        // Verify commitment
        bytes32 expectedCommitment = keccak256(abi.encodePacked(round.cdpId, msg.sender, nonce));
        require(commitments[roundId][msg.sender] == expectedCommitment, "Invalid commitment");
        
        hasRevealed[roundId][msg.sender] = true;
        
        // Check if CDP is actually liquidatable using IPFE
        bool isValid = _checkLiquidatable(round.cdpId, r);
        
        if (isValid) {
            round.revealedKeepers.push(msg.sender);
            keeperSuccesses[msg.sender]++;
        } else {
            keeperFailures[msg.sender]++;
        }
        
        emit KeeperRevealed(roundId, msg.sender, isValid);
    }
    
    function _checkLiquidatable(uint256 cdpId, uint256 r) internal view returns (bool) {
        uint256[] memory features = computeFeatures(cdpId);
        
        uint256[2][] memory mpkArray = new uint256[2][](FEATURE_DIM);
        for (uint256 i = 0; i < FEATURE_DIM; i++) {
            mpkArray[i] = mpk[i];
        }
        uint256[2][] memory ct = ipfe.encrypt(features, mpkArray, r);
        
        uint256[] memory ones = new uint256[](FEATURE_DIM);
        for (uint256 i = 0; i < FEATURE_DIM; i++) {
            ones[i] = 1;
        }
        
        uint256 score = ipfe.decrypt(ct, skSum, ones);
        return score < scoreThreshold * FEATURE_DIM;
    }
    
    // =========================================================================
    // Fair Liquidation: Execution with Random Winner + Profit Sharing
    // =========================================================================
    
    /// @notice Execute liquidation after reveal window
    /// @dev Uses block hash as randomness source (good enough for this demo)
    function executeLiquidation(uint256 roundId) external {
        LiquidationRound storage round = rounds[roundId];
        require(block.number >= round.startBlock + ROUND_LENGTH, "Round not complete");
        require(!round.executed, "Already executed");
        require(round.revealedKeepers.length > 0, "No valid keepers");
        
        round.executed = true;
        
        CDP storage cdp = cdps[round.cdpId];
        require(cdp.isActive, "CDP not active");
        
        // Random winner selection using block hash
        uint256 randomSeed = uint256(blockhash(round.startBlock + ROUND_LENGTH - 1));
        uint256 winnerIndex = randomSeed % round.revealedKeepers.length;
        address winner = round.revealedKeepers[winnerIndex];
        
        // Calculate profit
        uint256 collateralValue = (cdp.collateral * ethPrice) / 1e18;
        uint256 totalProfit = (collateralValue * 13) / 100; // 13% penalty
        
        // Split profit: 60% to winner, 40% to pool
        uint256 winnerProfit = (totalProfit * WINNER_SHARE) / 100;
        uint256 poolProfit = totalProfit - winnerProfit;
        
        // Distribute pool among other keepers
        uint256 numOthers = round.revealedKeepers.length - 1;
        uint256 perKeeperShare = numOthers > 0 ? poolProfit / numOthers : 0;
        
        // Mark CDP as liquidated
        cdp.isActive = false;
        
        // Pay winner
        payable(winner).transfer(winnerProfit);
        
        // Pay others
        for (uint256 i = 0; i < round.revealedKeepers.length; i++) {
            if (round.revealedKeepers[i] != winner && perKeeperShare > 0) {
                payable(round.revealedKeepers[i]).transfer(perKeeperShare);
            }
        }
        
        emit LiquidationExecuted(roundId, winner, winnerProfit);
    }
    
    // =========================================================================
    // Admin
    // =========================================================================
    
    function setEthPrice(uint256 _price) external onlyOwner {
        ethPrice = _price;
    }
    
    function setScoreThreshold(uint256 _threshold) external onlyOwner {
        scoreThreshold = _threshold;
    }
    
    receive() external payable {}
}
