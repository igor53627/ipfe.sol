// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {IPFE} from "../src/IPFE.sol";

contract IPFETest is Test {
    IPFE public ipfe;
    
    // Test master secret key (in production, keep off-chain!)
    uint256[] msk;
    
    // Test master public key
    uint256[2][] mpk;
    
    uint256 constant N = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    function setUp() public {
        ipfe = new IPFE();
        
        // Initialize small DLog table for testing (k = 0..1000)
        // In production, do this in batches across multiple transactions
        ipfe.initDlogTable(0, 1000);
    }
    
    function testEcMul() public view {
        // Test: 2 * G = G + G
        uint256[2] memory g = [uint256(1), uint256(2)];
        uint256[2] memory result = ipfe.ecMul(g, 2);
        
        // 2G is a known point on bn256
        assertEq(result[0], 1368015179489954701390400359078579693043519447331113978918064868415326638035);
        assertEq(result[1], 9918110051302171585080402603319702774565515993150576347155970296011118125764);
    }
    
    function testEcAdd() public view {
        uint256[2] memory g = [uint256(1), uint256(2)];
        uint256[2] memory g2 = ipfe.ecMul(g, 2);
        uint256[2] memory g3_add = ipfe.ecAdd(g, g2);
        uint256[2] memory g3_mul = ipfe.ecMul(g, 3);
        
        // G + 2G should equal 3G
        assertEq(g3_add[0], g3_mul[0]);
        assertEq(g3_add[1], g3_mul[1]);
    }
    
    function testEcNeg() public view {
        uint256[2] memory g = [uint256(1), uint256(2)];
        uint256[2] memory negG = ipfe.ecNeg(g);
        uint256[2] memory zero = ipfe.ecAdd(g, negG);
        
        // G + (-G) = 0 (point at infinity)
        assertEq(zero[0], 0);
        assertEq(zero[1], 0);
    }
    
    function testDlogTableInit() public view {
        // Check that g^1 is in the table
        uint256[2] memory g = [uint256(1), uint256(2)];
        (bool found, uint256 value) = ipfe.lookupDlog(g);
        assertTrue(found, "g^1 should be found");
        assertEq(value, 1, "g^1 should map to 1");
        
        // Check g^10
        uint256[2] memory g10 = ipfe.ecMul(g, 10);
        (found, value) = ipfe.lookupDlog(g10);
        assertTrue(found, "g^10 should be found");
        assertEq(value, 10, "g^10 should map to 10");
        
        // Check g^100
        uint256[2] memory g100 = ipfe.ecMul(g, 100);
        (found, value) = ipfe.lookupDlog(g100);
        assertTrue(found, "g^100 should be found");
        assertEq(value, 100, "g^100 should map to 100");
    }
    
    function testEncryptDecryptSimple() public {
        // Setup: n=2 dimensions
        // msk = [3, 7]
        // mpk = [g^3, g^7]
        
        uint256[2] memory g = [uint256(1), uint256(2)];
        
        uint256[2][] memory testMpk = new uint256[2][](2);
        testMpk[0] = ipfe.ecMul(g, 3);  // h_1 = g^3
        testMpk[1] = ipfe.ecMul(g, 7);  // h_2 = g^7
        
        // Plaintext: x = [5, 11]
        uint256[] memory x = new uint256[](2);
        x[0] = 5;
        x[1] = 11;
        
        // Encrypt with random r = 13
        uint256 r = 13;
        uint256[2][] memory ct = ipfe.encrypt(x, testMpk, r);
        
        // Function vector: y = [2, 3]
        // Expected result: ⟨x, y⟩ = 5*2 + 11*3 = 10 + 33 = 43
        uint256[] memory y = new uint256[](2);
        y[0] = 2;
        y[1] = 3;
        
        // Functional key: sk_y = s_1*y_1 + s_2*y_2 = 3*2 + 7*3 = 6 + 21 = 27
        uint256 skY = 27;
        
        // Need to extend DLog table to include 43
        // Already initialized 0..1000 in setUp
        
        uint256 result = ipfe.decrypt(ct, skY, y);
        assertEq(result, 43);
    }
    
    function testEncryptDecryptLarger() public {
        // n=5 dimensions
        uint256[2] memory g = [uint256(1), uint256(2)];
        
        // msk = [2, 3, 5, 7, 11]
        uint256[] memory testMsk = new uint256[](5);
        testMsk[0] = 2;
        testMsk[1] = 3;
        testMsk[2] = 5;
        testMsk[3] = 7;
        testMsk[4] = 11;
        
        // mpk = [g^2, g^3, g^5, g^7, g^11]
        uint256[2][] memory testMpk = new uint256[2][](5);
        for (uint256 i = 0; i < 5; i++) {
            testMpk[i] = ipfe.ecMul(g, testMsk[i]);
        }
        
        // x = [10, 20, 30, 40, 50]
        uint256[] memory x = new uint256[](5);
        x[0] = 10;
        x[1] = 20;
        x[2] = 30;
        x[3] = 40;
        x[4] = 50;
        
        // y = [1, 1, 1, 1, 1] (sum all elements)
        uint256[] memory y = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) {
            y[i] = 1;
        }
        
        // Expected: ⟨x, y⟩ = 10 + 20 + 30 + 40 + 50 = 150
        
        // sk_y = sum(msk[i] * y[i]) = 2 + 3 + 5 + 7 + 11 = 28
        uint256 skY = 28;
        
        // Encrypt
        uint256 r = 17;
        uint256[2][] memory ct = ipfe.encrypt(x, testMpk, r);
        
        // Decrypt
        uint256 result = ipfe.decrypt(ct, skY, y);
        assertEq(result, 150);
    }
    
    function testZeroResult() public {
        uint256[2] memory g = [uint256(1), uint256(2)];
        
        // msk = [5]
        uint256[2][] memory testMpk = new uint256[2][](1);
        testMpk[0] = ipfe.ecMul(g, 5);
        
        // x = [0]
        uint256[] memory x = new uint256[](1);
        x[0] = 0;
        
        // y = [7]
        uint256[] memory y = new uint256[](1);
        y[0] = 7;
        
        // Expected: ⟨x, y⟩ = 0 * 7 = 0
        uint256 skY = 35; // 5 * 7
        
        uint256 r = 11;
        uint256[2][] memory ct = ipfe.encrypt(x, testMpk, r);
        
        uint256 result = ipfe.decrypt(ct, skY, y);
        assertEq(result, 0);
    }
    
    function testGasCosts() public {
        // First, extend the DLog table to cover larger results
        ipfe.initDlogTable(1000, 1000);
        
        uint256[2] memory g = [uint256(1), uint256(2)];
        
        // n=10 dimensions (realistic use case)
        uint256 n = 10;
        
        uint256[2][] memory testMpk = new uint256[2][](n);
        uint256[] memory testMsk = new uint256[](n);
        uint256[] memory x = new uint256[](n);
        uint256[] memory y = new uint256[](n);
        
        uint256 skY = 0;
        for (uint256 i = 0; i < n; i++) {
            testMsk[i] = i + 2;
            testMpk[i] = ipfe.ecMul(g, testMsk[i]);
            x[i] = (i + 1) * 5;
            y[i] = i + 1;
            skY += testMsk[i] * y[i];
        }
        skY = skY % N;
        
        // Expected: sum((i+1)*5 * (i+1)) for i=0..9
        // x = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
        // y = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        // ⟨x,y⟩ = 5*1 + 10*2 + 15*3 + 20*4 + 25*5 + 30*6 + 35*7 + 40*8 + 45*9 + 50*10
        //       = 5 + 20 + 45 + 80 + 125 + 180 + 245 + 320 + 405 + 500 = 1925
        
        uint256 r = 42;
        
        // Measure encrypt gas
        uint256 gasBefore = gasleft();
        uint256[2][] memory ct = ipfe.encrypt(x, testMpk, r);
        uint256 encryptGas = gasBefore - gasleft();
        
        // Measure decrypt gas
        gasBefore = gasleft();
        uint256 result = ipfe.decrypt(ct, skY, y);
        uint256 decryptGas = gasBefore - gasleft();
        
        console.log("n=10 Encrypt gas:", encryptGas);
        console.log("n=10 Decrypt gas:", decryptGas);
        
        assertEq(result, 1925);
    }
}
