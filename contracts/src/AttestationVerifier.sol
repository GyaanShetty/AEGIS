// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title AttestationVerifier
/// @notice Verifies a period-compliance proof and emits the attestation.
/// @dev Verifying the proof is necessary but not sufficient. The verifier must
///      also bind the proof's public inputs to on-chain reality, or a valid
///      proof about a fabricated mandate would be accepted.
contract AttestationVerifier {
    event MandateCompliant(bytes32 indexed mandateId, uint64 periodEnd, bytes32 root, uint32 leafCount);

    error RootMismatch(bytes32 provided, bytes32 onChain);
    error MandateParamsMismatch();
    error InvalidProof();

    /// @param proof            the ZK proof bytes
    /// @param root             Merkle root the proof is computed over
    /// @param mandateId        which mandate
    /// @param totalCap         cap asserted in the proof
    /// @param windowStart      window asserted in the proof
    /// @param windowEnd        window asserted in the proof
    /// @param allowlistRoot    allowlist asserted in the proof
    /// @param leafCount        number of real (non-padding) leaves
    ///
    /// @dev MUST check, in this order:
    ///        1. root == SpendPolicyModule.currentRoot(mandateId)   [stale-root attack]
    ///        2. totalCap, windowStart, windowEnd, allowlistRoot all match the
    ///           registered mandate                                 [param-mismatch attack]
    ///        3. leafCount == module's txCount(mandateId)           [omission attack]
    ///        4. the proof itself verifies
    ///      Checking only (4) accepts a perfectly valid proof about a mandate
    ///      that never existed.
    function attest(
        bytes calldata proof,
        bytes32 root,
        bytes32 mandateId,
        uint256 totalCap,
        uint64 windowStart,
        uint64 windowEnd,
        bytes32 allowlistRoot,
        uint32 leafCount
    ) external pure {
        revert("not implemented"); // TODO(phase4)
    }
}
