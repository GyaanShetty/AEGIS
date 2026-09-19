// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {SpendPolicyModule} from "../src/SpendPolicyModule.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {TestUSDC} from "../src/mocks/TestUSDC.sol";
import {Mandate} from "../src/libraries/Mandate.sol";
import {Field} from "../src/poseidon2/Field.sol";
import {LibPoseidon2} from "../src/poseidon2/LibPoseidon2.sol";

/// @notice Deploys the stack, registers a mandate, and makes N payments so the
///         indexer has LeafInserted events to reconstruct. Prints the addresses
///         and mandateId the off-chain tools need.
///
/// Usage (local anvil):
///   anvil &
///   forge script script/Demo.s.sol --rpc-url http://localhost:8545 --broadcast \
///     --unlocked --sender 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
contract Demo is Script {
    using Field for Field.Type;

    // anvil default key #0 as principal, a fixed session key.
    uint256 principalPk = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 sessionPk = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    function run() external {
        address principal = vm.addr(principalPk);
        address session = vm.addr(sessionPk);
        address cptyA = address(0xCA);
        address cptyB = address(0xCB);

        vm.startBroadcast(principalPk);

        TestUSDC usdc = new TestUSDC();
        AgentAccount acct = new AgentAccount(principal);
        SpendPolicyModule module = new SpendPolicyModule(address(acct));
        acct.setModule(address(module));
        usdc.mint(address(acct), 1_000_000e6);

        bytes32 allowRoot = _allowRoot(cptyA, cptyB);
        Mandate.Data memory m = Mandate.Data({
            mandateId: keccak256("demo-mandate"),
            principal: principal,
            agentSessionKey: session,
            token: address(usdc),
            totalCap: 1_000e6,
            perTxCap: 100e6,
            windowStart: 0,
            windowEnd: uint64(block.timestamp + 365 days),
            allowlistRoot: allowRoot,
            maxTxCount: 128,
            revocationNonce: 0
        });
        module.registerMandate(m, _signMandate(module, m));

        // Six payments of 10 USDC each to cptyA.
        for (uint256 i = 0; i < 6; i++) {
            uint32 nonce = module.txCount(m.mandateId);
            bytes memory sig = _signAuth(module, m.mandateId, cptyA, 10e6, nonce);
            bytes32[] memory proof = _proof(cptyB);
            acct.pay(m.mandateId, address(usdc), cptyA, 10e6, proof, sig);
        }

        vm.stopBroadcast();

        console2.log("USDC     ", address(usdc));
        console2.log("Account  ", address(acct));
        console2.log("Module   ", address(module));
        console2.log("mandateId");
        console2.logBytes32(m.mandateId);
        console2.log("txCount  ", module.txCount(m.mandateId));
        console2.log("root");
        console2.logBytes32(module.currentRoot(m.mandateId));
    }

    function _allowRoot(address a, address b) internal pure returns (bytes32) {
        uint256 la = uint256(uint160(a));
        uint256 lb = uint256(uint160(b));
        (uint256 lo, uint256 hi) = la <= lb ? (la, lb) : (lb, la);
        return bytes32(LibPoseidon2.hash_2(Field.toField(lo), Field.toField(hi)).toUint256());
    }

    function _proof(address sibling) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](1);
        p[0] = bytes32(uint256(uint160(sibling)));
    }

    function _ds(SpendPolicyModule module) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Aegis")),
                keccak256(bytes("1")),
                block.chainid,
                address(module)
            )
        );
    }

    function _signMandate(SpendPolicyModule module, Mandate.Data memory m) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _ds(module), Mandate.hash(m)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(principalPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signAuth(SpendPolicyModule module, bytes32 id, address cpty, uint256 amount, uint32 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Authorisation(bytes32 mandateId,address counterparty,uint256 amount,uint32 nonce)"),
                id,
                cpty,
                amount,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _ds(module), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionPk, digest);
        return abi.encodePacked(r, s, v);
    }
}
