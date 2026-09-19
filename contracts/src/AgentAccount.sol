// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ISpendPolicyModule} from "./interfaces/ISpendPolicyModule.sol";

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title AgentAccount
/// @notice Minimal smart account whose spending is delegated to SpendPolicyModule.
///         Holds the funds the agent operates against.
/// @dev The agent (session key) has NO path to move value except `pay`, which is
///      gated by the module. There is no arbitrary `call(bytes)`, no approval to
///      the agent, and the principal-only withdraw path is never gated by a mandate.
///
///      This is a deliberately simplified ERC-4337 account: it exercises the full
///      module security boundary via a direct `pay` entrypoint rather than the
///      EntryPoint/UserOp plumbing. Full 4337 bundler integration is Phase 2+ and
///      does not change the enforcement guarantees, which live in the module.
contract AgentAccount {
    address public immutable principal;
    ISpendPolicyModule public module;
    bool private _moduleSet;

    error NotPrincipal();
    error ModuleAlreadySet();
    error ModuleNotSet();
    error TransferFailed();

    event ModuleSet(address indexed module);
    event Withdrawn(address indexed token, address indexed to, uint256 amount);
    event Paid(bytes32 indexed mandateId, address indexed counterparty, address token, uint256 amount);

    constructor(address principal_) {
        principal = principal_;
    }

    modifier onlyPrincipal() {
        if (msg.sender != principal) revert NotPrincipal();
        _;
    }

    /// @notice Wire the module once. Set by the principal after both are deployed
    ///         (the module's constructor needs this account's address).
    function setModule(address module_) external onlyPrincipal {
        if (_moduleSet) revert ModuleAlreadySet();
        module = ISpendPolicyModule(module_);
        _moduleSet = true;
        emit ModuleSet(module_);
    }

    /// @notice Authorise a payment through the module, then transfer atomically.
    /// @dev Anyone may relay this (the session signature is the authority), but the
    ///      module re-checks everything and records the commitment before we touch
    ///      value. There is no path where the transfer executes without the module
    ///      having authorised and committed it in this same transaction.
    function pay(
        bytes32 mandateId,
        address token,
        address counterparty,
        uint256 amount,
        bytes32[] calldata allowlistProof,
        bytes calldata sessionSig
    ) external {
        if (!_moduleSet) revert ModuleNotSet();
        // Effects & commitment happen inside the module; this reverts on any breach.
        module.authorisePayment(mandateId, counterparty, amount, allowlistProof, sessionSig);
        if (!IERC20Minimal(token).transfer(counterparty, amount)) revert TransferFailed();
        emit Paid(mandateId, counterparty, token, amount);
    }

    /// @notice Principal-only withdrawal. Never gated by any mandate.
    function withdraw(address token, address to, uint256 amount) external onlyPrincipal {
        if (!IERC20Minimal(token).transfer(to, amount)) revert TransferFailed();
        emit Withdrawn(token, to, amount);
    }
}
