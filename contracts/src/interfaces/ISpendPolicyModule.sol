// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Mandate} from "../libraries/Mandate.sol";

/// @title ISpendPolicyModule
/// @notice The security boundary. Everything the off-chain policy engine checks
///         is re-checked here, because the engine is bypassable and this is not.
interface ISpendPolicyModule {
    event MandateRegistered(bytes32 indexed mandateId, address indexed principal);
    event MandateRevoked(bytes32 indexed mandateId, uint64 newNonce);
    event PaymentAuthorised(
        bytes32 indexed mandateId,
        address indexed counterparty,
        uint256 amount,
        uint256 spentTotal,
        uint32 txCount
    );
    event LeafInserted(bytes32 indexed mandateId, uint32 index, bytes32 leaf, bytes32 newRoot);

    error MandateExpired();
    error MandateNotYetActive();
    error MandateRevokedError();
    error PerTxCapExceeded(uint256 amount, uint256 cap);
    error TotalCapExceeded(uint256 wouldBe, uint256 cap);
    error TxCountExceeded();
    error CounterpartyNotAllowed(address counterparty);
    error BadSessionSignature();
    error NonceAlreadyUsed(bytes32 nonce);

    function registerMandate(Mandate.Data calldata m, bytes calldata principalSig) external;

    function revoke(bytes32 mandateId) external;

    /// @notice Validate and record a payment.
    /// @dev MUST append the commitment leaf in the SAME transaction as the spend
    ///      accounting. There must exist no path through this function where a
    ///      payment is authorised and a leaf is not inserted. See CLAUDE.md.
    function authorisePayment(
        bytes32 mandateId,
        address counterparty,
        uint256 amount,
        bytes32[] calldata allowlistProof,
        bytes calldata sessionSig
    ) external;

    function currentRoot(bytes32 mandateId) external view returns (bytes32);
    function spent(bytes32 mandateId) external view returns (uint256);
    function txCount(bytes32 mandateId) external view returns (uint32);
}
