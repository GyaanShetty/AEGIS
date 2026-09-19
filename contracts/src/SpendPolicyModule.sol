// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ISpendPolicyModule} from "./interfaces/ISpendPolicyModule.sol";
import {Mandate} from "./libraries/Mandate.sol";

/// @title SpendPolicyModule
/// @notice ERC-4337 validation module enforcing a spending mandate and building
///         the commitment tree that the attestation proof is computed over.
///
/// @dev IMPLEMENTATION ORDER MATTERS. In authorisePayment:
///        1. verify session signature over (mandateId, counterparty, amount, nonce)
///        2. check window, revocation nonce, per-tx cap, cumulative cap, tx count
///        3. verify counterparty against allowlistRoot
///        4. EFFECTS: bump spent, bump txCount, mark nonce used
///        5. compute leaf = Poseidon(amount, counterparty, block.timestamp, salt)
///           where salt comes from THIS CONTRACT's entropy, never from the caller
///        6. insert leaf, update root, emit LeafInserted
///        7. INTERACTIONS: execute the transfer
///
///      Steps 4–6 must not be separable from the transfer. If an implementation
///      lets a payment settle without a leaf, the attestation proves nothing:
///      the operator could simply omit expensive payments. This is the single
///      most important property in the codebase.
contract SpendPolicyModule is ISpendPolicyModule {
    uint8 internal constant TREE_DEPTH = 7; // 128 leaves per mandate period

    // TODO(phase1): storage layout
    // mapping(bytes32 => Mandate.Data) internal _mandates;
    // mapping(bytes32 => uint256) internal _spent;
    // mapping(bytes32 => uint32)  internal _txCount;
    // mapping(address => uint64)  internal _principalNonce;
    // mapping(bytes32 => bool)    internal _usedNonces;
    // incremental Merkle state: filledSubtrees[TREE_DEPTH], root, nextIndex

    function registerMandate(Mandate.Data calldata, bytes calldata) external pure {
        revert("not implemented"); // TODO(phase1)
    }

    function revoke(bytes32) external pure {
        revert("not implemented"); // TODO(phase1): bump principal nonce
    }

    function authorisePayment(
        bytes32,
        address,
        uint256,
        bytes32[] calldata,
        bytes calldata
    ) external pure {
        revert("not implemented"); // TODO(phase1 checks, phase3 commitment)
    }

    function currentRoot(bytes32) external pure returns (bytes32) {
        revert("not implemented"); // TODO(phase3)
    }

    function spent(bytes32) external pure returns (uint256) {
        revert("not implemented"); // TODO(phase1)
    }

    function txCount(bytes32) external pure returns (uint32) {
        revert("not implemented"); // TODO(phase1)
    }
}
