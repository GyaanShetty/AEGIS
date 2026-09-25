// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier} from "../src/verifier/HonkVerifier.sol";

/// @notice End-to-end proof verification in the EVM. The proof and public inputs
///         are the real artifacts produced by the Noir circuit + Barretenberg
///         (bb 5.0.0, ultra_honk, -t evm) for the honest 1-leaf witness. If this
///         passes, the generated verifier accepts a genuine period proof on-chain.
contract AttestationTest is Test {
    HonkVerifier internal verifier;

    function setUp() public {
        verifier = new HonkVerifier();
    }

    function _publicInputs() internal view returns (bytes32[] memory pi) {
        bytes memory raw = vm.readFileBinary("test/fixtures/public_inputs.bin");
        require(raw.length % 32 == 0, "bad public inputs");
        uint256 n = raw.length / 32;
        pi = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 w;
            assembly {
                w := mload(add(add(raw, 0x20), mul(i, 0x20)))
            }
            pi[i] = w;
        }
    }

    function test_HonkVerifier_AcceptsGenuineProof() public {
        bytes memory proof = vm.readFileBinary("test/fixtures/proof.bin");
        bytes32[] memory pi = _publicInputs();
        assertEq(pi.length, 7, "expected 7 circuit public inputs");
        assertTrue(verifier.verify(proof, pi), "genuine proof must verify");
    }

    function test_HonkVerifier_RejectsTamperedPublicInput() public {
        bytes memory proof = vm.readFileBinary("test/fixtures/proof.bin");
        bytes32[] memory pi = _publicInputs();
        // flip the total_cap public input (index 1): the proof must no longer verify
        pi[1] = bytes32(uint256(pi[1]) + 1);
        // the verifier reverts (SumcheckFailed/ShpleminiFailed) or returns false
        try verifier.verify(proof, pi) returns (bool ok) {
            assertFalse(ok, "tampered public input must not verify");
        } catch {
            // revert on failed relation is also an acceptable rejection
        }
    }
}
