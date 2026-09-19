// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SpendPolicyModule} from "../src/SpendPolicyModule.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {TestUSDC} from "../src/mocks/TestUSDC.sol";
import {Mandate} from "../src/libraries/Mandate.sol";

/// @dev Handler drives the module through arbitrary payment sequences from an
///      arbitrary caller. Every attempt re-signs with the live txCount, so the
///      handler models an honest relayer of a valid session key; the invariants
///      must still hold under any interleaving the fuzzer picks.
contract Handler is Test {
    SpendPolicyModule public module;
    AgentAccount public acct;
    TestUSDC public usdc;
    bytes32 public mandateId;
    uint256 public totalCap;
    uint256 sessionPk;
    address cpty;
    address sibling;

    uint256 public leafCountShadow;

    constructor(
        SpendPolicyModule _m,
        AgentAccount _a,
        TestUSDC _u,
        bytes32 _id,
        uint256 _cap,
        uint256 _pk,
        address _cpty,
        address _sibling
    ) {
        module = _m;
        acct = _a;
        usdc = _u;
        mandateId = _id;
        totalCap = _cap;
        sessionPk = _pk;
        cpty = _cpty;
        sibling = _sibling;
    }

    function _proof() internal view returns (bytes32[] memory p) {
        p = new bytes32[](1);
        p[0] = keccak256(abi.encodePacked(sibling));
    }

    function _sign(uint256 amount, uint32 nonce) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Authorisation(bytes32 mandateId,address counterparty,uint256 amount,uint32 nonce)"),
                mandateId,
                cpty,
                amount,
                nonce
            )
        );
        bytes32 ds = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Aegis")),
                keccak256(bytes("1")),
                block.chainid,
                address(module)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", ds, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function pay(uint256 amount) external {
        amount = bound(amount, 1, totalCap / 4 + 1);
        uint32 nonce = module.txCount(mandateId);
        bytes memory sig = _sign(amount, nonce);
        try acct.pay(mandateId, address(usdc), cpty, amount, _proof(), sig) {
            leafCountShadow += 1;
        } catch {}
    }
}

contract SpendPolicyInvariantTest is Test {
    SpendPolicyModule internal module;
    AgentAccount internal acct;
    TestUSDC internal usdc;
    Handler internal handler;

    uint256 internal principalPk = 0xA11CE;
    uint256 internal sessionPk = 0xB0B;
    bytes32 internal mandateId = keccak256("inv");
    uint256 internal constant CAP = 100_000e6;

    address internal cptyA = address(0xCA);
    address internal cptyB = address(0xCB);

    function setUp() public {
        address principal = vm.addr(principalPk);
        address session = vm.addr(sessionPk);

        usdc = new TestUSDC();
        acct = new AgentAccount(principal);
        module = new SpendPolicyModule(address(acct));
        vm.prank(principal);
        acct.setModule(address(module));
        usdc.mint(address(acct), 100_000_000e6);

        bytes32 la = keccak256(abi.encodePacked(cptyA));
        bytes32 lb = keccak256(abi.encodePacked(cptyB));
        bytes32 root = la <= lb ? keccak256(abi.encodePacked(la, lb)) : keccak256(abi.encodePacked(lb, la));

        Mandate.Data memory m = Mandate.Data({
            mandateId: mandateId,
            principal: principal,
            agentSessionKey: session,
            token: address(usdc),
            totalCap: CAP,
            perTxCap: CAP,
            windowStart: uint64(block.timestamp),
            windowEnd: uint64(block.timestamp + 3650 days),
            allowlistRoot: root,
            maxTxCount: 128,
            revocationNonce: 0
        });
        bytes32 ds = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Aegis")),
                keccak256(bytes("1")),
                block.chainid,
                address(module)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", ds, Mandate.hash(m)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(principalPk, digest);
        module.registerMandate(m, abi.encodePacked(r, s, v));

        handler = new Handler(module, acct, usdc, mandateId, CAP, sessionPk, cptyA, cptyB);
        targetContract(address(handler));
    }

    /// @dev Core safety property: spent(m) <= totalCap(m), always.
    function invariant_SpentNeverExceedsCap() public view {
        assertLe(module.spent(mandateId), CAP);
    }

    /// @dev txCount(m) equals the number of leaves inserted (handler shadow count).
    function invariant_LeafCountMatchesTxCount() public view {
        assertEq(uint256(module.txCount(mandateId)), handler.leafCountShadow());
    }
}
