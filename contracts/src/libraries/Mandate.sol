// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title Mandate
/// @notice The unit of delegated spending authority: what an agent may spend,
///         when, how much at a time, and with whom.
/// @dev Signed by the principal over EIP-712. The agent holds only a session key
///      scoped by this struct and can never widen it.
library Mandate {
    struct Data {
        bytes32 mandateId;
        address principal;
        address agentSessionKey;
        address token;            // stablecoin, e.g. USDC
        uint256 totalCap;         // cumulative ceiling over the window
        uint256 perTxCap;         // single-payment ceiling
        uint64  windowStart;
        uint64  windowEnd;
        bytes32 allowlistRoot;    // Merkle root over permitted counterparties
        uint32  maxTxCount;       // bounds the tree (depth 7 => 128)
        uint64  revocationNonce;  // principal bumps this to kill in-flight auths
    }

    /// @dev keccak256 of the EIP-712 type string. Regenerate if the struct changes
    ///      — a stale typehash silently accepts signatures over a different shape.
    bytes32 internal constant TYPEHASH = keccak256(
        "Mandate(bytes32 mandateId,address principal,address agentSessionKey,address token,uint256 totalCap,uint256 perTxCap,uint64 windowStart,uint64 windowEnd,bytes32 allowlistRoot,uint32 maxTxCount,uint64 revocationNonce)"
    );

    /// @notice Hash the struct for EIP-712 signing.
    /// @dev TODO(phase1): implement. Every field must be covered — an omitted
    ///      field is a field an attacker can vary freely.
    function hash(Data memory) internal pure returns (bytes32) {
        revert("Mandate: not implemented");
    }
}
