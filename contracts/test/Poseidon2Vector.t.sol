// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Field} from "../src/poseidon2/Field.sol";
import {Poseidon2_BN254} from "../src/poseidon2/Poseidon2.sol";

/// @notice DECISIVE consistency check: the vendored Solidity Poseidon2 must
///         reproduce the exact hashes the Noir circuit produces, or the on-chain
///         root will never equal the proof's root. Vectors generated from
///         noir-lang/poseidon v0.3.0 via `nargo test print_vectors --show-output`.
contract Poseidon2VectorTest is Test {
    using Field for *;

    Poseidon2_BN254 internal p;

    // Noir: Poseidon2::hash([1,2], 2)
    uint256 constant H2 = 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383;
    // Noir: Poseidon2::hash([1,2,3,4], 4)
    uint256 constant H4 = 0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9;

    function setUp() public {
        p = new Poseidon2_BN254();
    }

    function test_MatchesNoir_hash2() public view {
        assertEq(p.hash_2(uint256(1).toField(), uint256(2).toField()).toUint256(), H2);
    }

    function test_MatchesNoir_hash4() public view {
        Field.Type[] memory in4 = new Field.Type[](4);
        in4[0] = uint256(1).toField();
        in4[1] = uint256(2).toField();
        in4[2] = uint256(3).toField();
        in4[3] = uint256(4).toField();
        assertEq(p.hash(in4, 4, false).toUint256(), H4);
    }
}
