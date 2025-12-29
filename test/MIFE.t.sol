// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {MIFE} from "../src/MIFE.sol";

contract MIFETest is Test {
    MIFE public mife;
    
    uint256 constant N = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // Master secret keys for each slot
    uint256[] msk0;
    uint256[] msk1;
    
    function setUp() public {
        mife = new MIFE();
        
        // Initialize DLog table
        mife.initDlogTable(0, 2000);
    }
    
    function testSlotInitialization() public {
        uint256[2] memory g = [uint256(1), uint256(2)];
        
        // Initialize slot 0 with n=3
        uint256[2][] memory mpk0 = new uint256[2][](3);
        mpk0[0] = mife.ecMul(g, 2);
        mpk0[1] = mife.ecMul(g, 3);
        mpk0[2] = mife.ecMul(g, 5);
        
        mife.initSlot(0, mpk0);
        
        // Initialize slot 1 with n=3
        uint256[2][] memory mpk1 = new uint256[2][](3);
        mpk1[0] = mife.ecMul(g, 7);
        mpk1[1] = mife.ecMul(g, 11);
        mpk1[2] = mife.ecMul(g, 13);
        
        mife.initSlot(1, mpk1);
        
        // Verify slots are initialized
        uint256[2][] memory storedMpk0 = mife.getSlotMPK(0);
        assertEq(storedMpk0.length, 3);
        
        uint256[2][] memory storedMpk1 = mife.getSlotMPK(1);
        assertEq(storedMpk1.length, 3);
    }
    
    function testEncryptSlot() public {
        uint256[2] memory g = [uint256(1), uint256(2)];
        
        // Initialize slot 0
        uint256[2][] memory mpk0 = new uint256[2][](2);
        mpk0[0] = mife.ecMul(g, 2);
        mpk0[1] = mife.ecMul(g, 3);
        mife.initSlot(0, mpk0);
        
        // Encrypt x = [10, 20] for slot 0
        uint256[] memory x = new uint256[](2);
        x[0] = 10;
        x[1] = 20;
        
        uint256 r = 17;
        uint256[2][] memory ct = mife.encryptSlot(0, x, r);
        
        assertEq(ct.length, 3); // c_0, c_1, c_2
    }
    
    function testDecryptMultiSimple() public {
        uint256[2] memory g = [uint256(1), uint256(2)];
        
        // Slot 0: msk0 = [2, 3], mpk0 = [g^2, g^3]
        uint256[2][] memory mpk0 = new uint256[2][](2);
        mpk0[0] = mife.ecMul(g, 2);
        mpk0[1] = mife.ecMul(g, 3);
        mife.initSlot(0, mpk0);
        
        // Slot 1: msk1 = [5, 7], mpk1 = [g^5, g^7]
        uint256[2][] memory mpk1 = new uint256[2][](2);
        mpk1[0] = mife.ecMul(g, 5);
        mpk1[1] = mife.ecMul(g, 7);
        mife.initSlot(1, mpk1);
        
        // Slot 0: x1 = [10, 20]
        uint256[] memory x1 = new uint256[](2);
        x1[0] = 10;
        x1[1] = 20;
        
        // Slot 1: x2 = [30, 40]
        uint256[] memory x2 = new uint256[](2);
        x2[0] = 30;
        x2[1] = 40;
        
        // Encrypt both slots
        uint256[2][] memory ct1 = mife.encryptSlot(0, x1, 13);
        uint256[2][] memory ct2 = mife.encryptSlot(1, x2, 17);
        
        // Function vectors
        // y1 = [1, 2], y2 = [3, 4]
        uint256[] memory y1 = new uint256[](2);
        y1[0] = 1;
        y1[1] = 2;
        
        uint256[] memory y2 = new uint256[](2);
        y2[0] = 3;
        y2[1] = 4;
        
        // Expected:
        // <x1, y1> = 10*1 + 20*2 = 10 + 40 = 50
        // <x2, y2> = 30*3 + 40*4 = 90 + 160 = 250
        // Total = 50 + 250 = 300
        
        // Functional keys
        // skY1 = 2*1 + 3*2 = 2 + 6 = 8
        // skY2 = 5*3 + 7*4 = 15 + 28 = 43
        uint256 skY1 = 8;
        uint256 skY2 = 43;
        
        uint256 result = mife.decryptMulti(ct1, ct2, skY1, skY2, y1, y2);
        assertEq(result, 300);
    }
    
    function testDecryptMultiUseCase() public {
        // Realistic use case:
        // Slot 0: Oracle encrypts prices [ETH_price, BTC_price, ...]
        // Slot 1: User encrypts weights [w1, w2, ...]
        // Result: sum of weighted prices (without revealing individual prices or weights)
        
        uint256[2] memory g = [uint256(1), uint256(2)];
        
        // n=4 dimensions (4 assets)
        uint256 n = 4;
        
        // Slot 0: Oracle's key (msk0 = [2, 3, 5, 7])
        uint256[] memory msk0_local = new uint256[](n);
        msk0_local[0] = 2;
        msk0_local[1] = 3;
        msk0_local[2] = 5;
        msk0_local[3] = 7;
        
        uint256[2][] memory mpk0 = new uint256[2][](n);
        for (uint256 i = 0; i < n; i++) {
            mpk0[i] = mife.ecMul(g, msk0_local[i]);
        }
        mife.initSlot(0, mpk0);
        
        // Slot 1: User's key (msk1 = [11, 13, 17, 19])
        uint256[] memory msk1_local = new uint256[](n);
        msk1_local[0] = 11;
        msk1_local[1] = 13;
        msk1_local[2] = 17;
        msk1_local[3] = 19;
        
        uint256[2][] memory mpk1 = new uint256[2][](n);
        for (uint256 i = 0; i < n; i++) {
            mpk1[i] = mife.ecMul(g, msk1_local[i]);
        }
        mife.initSlot(1, mpk1);
        
        // Oracle encrypts prices (scaled to small integers for DLog)
        // prices = [100, 50, 200, 75] (e.g., $1000, $500, $2000, $750 scaled by 10)
        uint256[] memory prices = new uint256[](n);
        prices[0] = 100;
        prices[1] = 50;
        prices[2] = 200;
        prices[3] = 75;
        
        // User encrypts weights (portfolio allocation out of 10)
        // weights = [3, 2, 4, 1] (30%, 20%, 40%, 10%)
        uint256[] memory weights = new uint256[](n);
        weights[0] = 3;
        weights[1] = 2;
        weights[2] = 4;
        weights[3] = 1;
        
        // Encrypt
        uint256[2][] memory ctPrices = mife.encryptSlot(0, prices, 31);
        uint256[2][] memory ctWeights = mife.encryptSlot(1, weights, 37);
        
        // Function vectors (identity - just extract the encrypted values)
        // For slot 0 (prices): y1 = weights (to compute weighted sum)
        // For slot 1 (weights): y2 = prices (to compute weighted sum)
        // But in MIFE, we compute <x1,y1> + <x2,y2>
        // So we use y1 = [1,1,1,1] for slot 0 to get sum of prices
        // and y2 = [1,1,1,1] for slot 1 to get sum of weights
        // Then multiply off-chain
        
        // Alternative: Use y1 = y2 = [1,0,0,0] to extract first element
        // For weighted sum: need a different setup
        
        // Simple test: just sum all values in each slot
        uint256[] memory ones = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            ones[i] = 1;
        }
        
        // skY1 = sum(msk0[i] * 1) = 2 + 3 + 5 + 7 = 17
        // skY2 = sum(msk1[i] * 1) = 11 + 13 + 17 + 19 = 60
        uint256 skY1 = 17;
        uint256 skY2 = 60;
        
        // Expected:
        // <prices, ones> = 100 + 50 + 200 + 75 = 425
        // <weights, ones> = 3 + 2 + 4 + 1 = 10
        // Total = 435
        
        uint256 result = mife.decryptMulti(ctPrices, ctWeights, skY1, skY2, ones, ones);
        assertEq(result, 435);
    }
    
    function testGasCostsMIFE() public {
        uint256[2] memory g = [uint256(1), uint256(2)];
        uint256 n = 4; // Reduced to avoid stack too deep
        
        // Initialize both slots
        uint256[2][] memory mpk0 = new uint256[2][](n);
        uint256[2][] memory mpk1 = new uint256[2][](n);
        
        // msk0 = [2, 3, 4, 5], msk1 = [10, 11, 12, 13]
        mpk0[0] = mife.ecMul(g, 2);
        mpk0[1] = mife.ecMul(g, 3);
        mpk0[2] = mife.ecMul(g, 4);
        mpk0[3] = mife.ecMul(g, 5);
        
        mpk1[0] = mife.ecMul(g, 10);
        mpk1[1] = mife.ecMul(g, 11);
        mpk1[2] = mife.ecMul(g, 12);
        mpk1[3] = mife.ecMul(g, 13);
        
        mife.initSlot(0, mpk0);
        mife.initSlot(1, mpk1);
        
        // x1 = [5, 10, 15, 20], x2 = [3, 6, 9, 12]
        uint256[] memory x1 = new uint256[](n);
        x1[0] = 5; x1[1] = 10; x1[2] = 15; x1[3] = 20;
        
        uint256[] memory x2 = new uint256[](n);
        x2[0] = 3; x2[1] = 6; x2[2] = 9; x2[3] = 12;
        
        uint256 gasBefore = gasleft();
        uint256[2][] memory ct1 = mife.encryptSlot(0, x1, 41);
        uint256 encryptGas1 = gasBefore - gasleft();
        
        gasBefore = gasleft();
        uint256[2][] memory ct2 = mife.encryptSlot(1, x2, 43);
        uint256 encryptGas2 = gasBefore - gasleft();
        
        // y1 = y2 = [1, 1, 1, 1]
        uint256[] memory y1 = new uint256[](n);
        y1[0] = 1; y1[1] = 1; y1[2] = 1; y1[3] = 1;
        
        uint256[] memory y2 = new uint256[](n);
        y2[0] = 1; y2[1] = 1; y2[2] = 1; y2[3] = 1;
        
        // skY1 = 2+3+4+5 = 14, skY2 = 10+11+12+13 = 46
        uint256 skY1 = 14;
        uint256 skY2 = 46;
        
        gasBefore = gasleft();
        uint256 result = mife.decryptMulti(ct1, ct2, skY1, skY2, y1, y2);
        uint256 decryptGas = gasBefore - gasleft();
        
        console.log("MIFE n=4 Encrypt slot 0 gas:", encryptGas1);
        console.log("MIFE n=4 Encrypt slot 1 gas:", encryptGas2);
        console.log("MIFE n=4 Decrypt multi gas:", decryptGas);
        
        // Expected: sum(x1) + sum(x2) = (5+10+15+20) + (3+6+9+12) = 50 + 30 = 80
        assertEq(result, 80);
    }
}
