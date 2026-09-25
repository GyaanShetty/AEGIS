// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Mandate} from "./libraries/Mandate.sol";

interface ISpendPolicyModuleView {
    function currentRoot(bytes32 mandateId) external view returns (bytes32);
    function txCount(bytes32 mandateId) external view returns (uint32);
    function mandate(bytes32 mandateId) external view returns (Mandate.Data memory);
}

/// @notice The bb-generated UltraHonk verifier exposes this.
interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// @title AttestationVerifier
/// @notice Verifies a period-compliance proof and emits the attestation.
/// @dev Verifying the proof is necessary but NOT sufficient. The verifier also
///      binds the proof's public inputs to on-chain reality, or a valid proof
///      about a fabricated mandate would be accepted.
///
///      Public-input order MUST match the circuit's `main` signature:
///        [root, totalCap, windowStart, windowEnd, allowlistRoot, mandateId, leafCount]
contract AttestationVerifier {
    IHonkVerifier public immutable verifier;
    ISpendPolicyModuleView public immutable module;

    event MandateCompliant(bytes32 indexed mandateId, uint64 periodEnd, bytes32 root, uint32 leafCount);

    error RootMismatch(bytes32 provided, bytes32 onChain);
    error MandateParamsMismatch();
    error LeafCountMismatch(uint32 provided, uint32 onChain);
    error InvalidProof();

    constructor(IHonkVerifier verifier_, ISpendPolicyModuleView module_) {
        verifier = verifier_;
        module = module_;
    }

    /// @notice Verify a period proof and emit the compliance attestation.
    /// @dev Checks, in order:
    ///        1. root == module.currentRoot(mandateId)          [stale-root attack]
    ///        2. cap/window/allowlistRoot match the registered mandate [param-mismatch]
    ///        3. leafCount == module.txCount(mandateId)          [omission attack]
    ///        4. the proof itself verifies                        [soundness]
    ///      Checking only (4) accepts a valid proof about a mandate that never existed.
    function attest(
        bytes calldata proof,
        bytes32 root,
        bytes32 mandateId,
        uint256 totalCap,
        uint64 windowStart,
        uint64 windowEnd,
        bytes32 allowlistRoot,
        uint32 leafCount
    ) external {
        // 1. stale-root
        bytes32 onChainRoot = module.currentRoot(mandateId);
        if (root != onChainRoot) revert RootMismatch(root, onChainRoot);

        // 2. param binding
        Mandate.Data memory m = module.mandate(mandateId);
        if (
            m.totalCap != totalCap || m.windowStart != windowStart || m.windowEnd != windowEnd
                || m.allowlistRoot != allowlistRoot
        ) {
            revert MandateParamsMismatch();
        }

        // 3. omission
        uint32 onChainCount = module.txCount(mandateId);
        if (leafCount != onChainCount) revert LeafCountMismatch(leafCount, onChainCount);

        // 4. proof
        bytes32[] memory publicInputs = new bytes32[](7);
        publicInputs[0] = root;
        publicInputs[1] = bytes32(totalCap);
        publicInputs[2] = bytes32(uint256(windowStart));
        publicInputs[3] = bytes32(uint256(windowEnd));
        publicInputs[4] = allowlistRoot;
        publicInputs[5] = mandateId;
        publicInputs[6] = bytes32(uint256(leafCount));
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        emit MandateCompliant(mandateId, windowEnd, root, leafCount);
    }
}
