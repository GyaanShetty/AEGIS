// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title AgentAccount
/// @notice Minimal ERC-4337 account whose validation is delegated to
///         SpendPolicyModule. Holds the funds the agent operates against.
/// @dev The agent must have no path to move value except through the module.
///      In particular: no arbitrary `call(bytes)`, no token approvals granted to
///      the agent, no owner-equivalent role reachable by the session key.
contract AgentAccount {
    // TODO(phase1): principal, module address, ERC-4337 entrypoint wiring
    // TODO(phase1): validateUserOp delegating to SpendPolicyModule
    // TODO(phase1): principal-only withdraw path, never gated by the mandate
}
