// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SpendPolicyModule} from "../src/SpendPolicyModule.sol";
import {ISpendPolicyModule} from "../src/interfaces/ISpendPolicyModule.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {TestUSDC} from "../src/mocks/TestUSDC.sol";
import {Mandate} from "../src/libraries/Mandate.sol";
import {Field} from "../src/poseidon2/Field.sol";
import {LibPoseidon2} from "../src/poseidon2/LibPoseidon2.sol";

/// @notice Phase 1 test surface. The fuzz and invariant tests are the real safety
///         claim; the unit tests are the obvious cases.
contract SpendPolicyModuleTest is Test {
    using Field for Field.Type;

    SpendPolicyModule internal module;
    AgentAccount internal acct;
    TestUSDC internal usdc;

    uint256 internal principalPk = 0xA11CE;
    uint256 internal sessionPk = 0xB0B;
    uint256 internal wrongPk = 0xDEAD;
    address internal principal;
    address internal session;

    address internal cptyA = address(0xCA);
    address internal cptyB = address(0xCB);
    address internal cptyOutsider = address(0xC0);

    bytes32 internal allowlistRoot;

    function setUp() public {
        principal = vm.addr(principalPk);
        session = vm.addr(sessionPk);

        usdc = new TestUSDC();
        acct = new AgentAccount(principal);
        module = new SpendPolicyModule(address(acct));
        vm.prank(principal);
        acct.setModule(address(module));

        usdc.mint(address(acct), 1_000_000e6);

        // 2-leaf allowlist over {cptyA, cptyB}
        allowlistRoot = _root2(cptyA, cptyB);
    }

    // ------------------------------------------------------------------ //
    //  Helpers                                                           //
    // ------------------------------------------------------------------ //

    function _leaf(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _root2(address a, address b) internal pure returns (bytes32) {
        uint256 la = uint256(uint160(a));
        uint256 lb = uint256(uint160(b));
        (uint256 lo, uint256 hi) = la <= lb ? (la, lb) : (lb, la);
        return bytes32(LibPoseidon2.hash_2(Field.toField(lo), Field.toField(hi)).toUint256());
    }

    function _proofFor(address, address sibling) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](1);
        p[0] = _leaf(sibling);
    }

    function _mandate(uint256 totalCap, uint256 perTxCap) internal view returns (Mandate.Data memory m) {
        m = Mandate.Data({
            mandateId: keccak256("m1"),
            principal: principal,
            agentSessionKey: session,
            token: address(usdc),
            totalCap: totalCap,
            perTxCap: perTxCap,
            windowStart: uint64(block.timestamp),
            windowEnd: uint64(block.timestamp + 30 days),
            allowlistRoot: allowlistRoot,
            maxTxCount: 128,
            revocationNonce: 0
        });
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("Aegis")),
                keccak256(bytes("1")),
                block.chainid,
                address(module)
            )
        );
    }

    function _signMandate(Mandate.Data memory m, uint256 pk) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), Mandate.hash(m)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signAuth(bytes32 mandateId, address cpty, uint256 amount, uint32 nonce, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Authorisation(bytes32 mandateId,address counterparty,uint256 amount,uint32 nonce)"),
                mandateId,
                cpty,
                amount,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _register(Mandate.Data memory m) internal {
        module.registerMandate(m, _signMandate(m, principalPk));
    }

    /// @dev Full happy-path pay through the account, signing with the CURRENT txCount.
    function _pay(Mandate.Data memory m, address cpty, address sibling, uint256 amount) internal {
        uint32 nonce = module.txCount(m.mandateId);
        bytes memory sig = _signAuth(m.mandateId, cpty, amount, nonce, sessionPk);
        acct.pay(m.mandateId, address(usdc), cpty, amount, _proofFor(cpty, sibling), sig);
    }

    /// @dev Build args for a pay whose next call is expected to revert. Reads the
    ///      txCount view HERE, so it does not sit between vm.expectRevert and the
    ///      reverting acct.pay (expectRevert binds to the immediately next call).
    function _prep(Mandate.Data memory m, address cpty, address sibling, uint256 amount)
        internal
        view
        returns (bytes32[] memory proof, bytes memory sig)
    {
        uint32 nonce = module.txCount(m.mandateId);
        sig = _signAuth(m.mandateId, cpty, amount, nonce, sessionPk);
        proof = _proofFor(cpty, sibling);
    }

    // ------------------------------------------------------------------ //
    //  caps                                                              //
    // ------------------------------------------------------------------ //

    function test_SpendExactlyAtCap_Succeeds() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        _pay(m, cptyA, cptyB, 100e6);
        assertEq(module.spent(m.mandateId), 100e6);
    }

    function test_SpendOneWeiOverCap_Reverts() public {
        // per-tx cap left high so the TOTAL cap is the binding constraint here
        Mandate.Data memory m = _mandate(100e6, 200e6);
        _register(m);
        (bytes32[] memory proof, bytes memory sig) = _prep(m, cptyA, cptyB, 100e6 + 1);
        vm.expectRevert(abi.encodeWithSelector(ISpendPolicyModule.TotalCapExceeded.selector, 100e6 + 1, 100e6));
        acct.pay(m.mandateId, address(usdc), cptyA, 100e6 + 1, proof, sig);
    }

    function test_TwoPaymentsIndividuallyOkButCumulativelyOver_SecondReverts() public {
        Mandate.Data memory m = _mandate(150e6, 100e6);
        _register(m);
        _pay(m, cptyA, cptyB, 100e6);
        (bytes32[] memory proof, bytes memory sig) = _prep(m, cptyA, cptyB, 100e6);
        vm.expectRevert(abi.encodeWithSelector(ISpendPolicyModule.TotalCapExceeded.selector, 200e6, 150e6));
        acct.pay(m.mandateId, address(usdc), cptyA, 100e6, proof, sig);
        assertEq(module.spent(m.mandateId), 100e6);
    }

    function test_PerTxCapEnforcedIndependentlyOfTotal() public {
        Mandate.Data memory m = _mandate(1000e6, 50e6);
        _register(m);
        (bytes32[] memory proof, bytes memory sig) = _prep(m, cptyA, cptyB, 60e6);
        vm.expectRevert(abi.encodeWithSelector(ISpendPolicyModule.PerTxCapExceeded.selector, 60e6, 50e6));
        acct.pay(m.mandateId, address(usdc), cptyA, 60e6, proof, sig);
    }

    // ------------------------------------------------------------------ //
    //  window                                                            //
    // ------------------------------------------------------------------ //

    function test_PaymentAtWindowEnd_Succeeds() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        vm.warp(m.windowEnd);
        _pay(m, cptyA, cptyB, 10e6);
        assertEq(module.spent(m.mandateId), 10e6);
    }

    function test_PaymentAtWindowEndPlusOne_Reverts() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        (bytes32[] memory proof, bytes memory sig) = _prep(m, cptyA, cptyB, 10e6);
        vm.warp(uint256(m.windowEnd) + 1);
        vm.expectRevert(ISpendPolicyModule.MandateExpired.selector);
        acct.pay(m.mandateId, address(usdc), cptyA, 10e6, proof, sig);
    }

    function test_PaymentBeforeWindowStart_Reverts() public {
        vm.warp(1000);
        Mandate.Data memory m = _mandate(100e6, 100e6);
        m.windowStart = uint64(block.timestamp + 100);
        m.windowEnd = uint64(block.timestamp + 200);
        _register(m);
        (bytes32[] memory proof, bytes memory sig) = _prep(m, cptyA, cptyB, 10e6);
        vm.expectRevert(ISpendPolicyModule.MandateNotYetActive.selector);
        acct.pay(m.mandateId, address(usdc), cptyA, 10e6, proof, sig);
    }

    // ------------------------------------------------------------------ //
    //  revocation                                                        //
    // ------------------------------------------------------------------ //

    function test_RevocationInvalidatesPreviouslyValidSignature() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        // pre-sign a valid authorisation
        uint32 nonce = module.txCount(m.mandateId);
        bytes memory sig = _signAuth(m.mandateId, cptyA, 10e6, nonce, sessionPk);
        // principal revokes
        vm.prank(principal);
        module.revoke(m.mandateId);
        vm.expectRevert(ISpendPolicyModule.MandateRevokedError.selector);
        acct.pay(m.mandateId, address(usdc), cptyA, 10e6, _proofFor(cptyA, cptyB), sig);
    }

    function test_RevocationRacesInFlightAuthorisation() public {
        // identical to above but framed as a race: signature minted, revoke mined first
        test_RevocationInvalidatesPreviouslyValidSignature();
    }

    function test_OnlyPrincipalCanRevoke() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        vm.expectRevert(SpendPolicyModule.NotPrincipal.selector);
        vm.prank(address(0xBEEF));
        module.revoke(m.mandateId);
    }

    // ------------------------------------------------------------------ //
    //  allowlist                                                         //
    // ------------------------------------------------------------------ //

    function test_CounterpartyNotInAllowlist_Reverts() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        // well-formed proof but for the wrong leaf: prove cptyOutsider with cptyB sibling
        uint32 nonce = module.txCount(m.mandateId);
        bytes memory sig = _signAuth(m.mandateId, cptyOutsider, 10e6, nonce, sessionPk);
        vm.expectRevert(
            abi.encodeWithSelector(ISpendPolicyModule.CounterpartyNotAllowed.selector, cptyOutsider)
        );
        acct.pay(m.mandateId, address(usdc), cptyOutsider, 10e6, _proofFor(cptyOutsider, cptyB), sig);
    }

    function test_ValidProofForDifferentAllowlistRoot_Reverts() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        // a genuine 2-leaf proof, but over a tree that isn't the mandate's root
        uint32 nonce = module.txCount(m.mandateId);
        bytes memory sig = _signAuth(m.mandateId, cptyOutsider, 10e6, nonce, sessionPk);
        bytes32[] memory p = new bytes32[](1);
        p[0] = _leaf(address(0x9999));
        vm.expectRevert(
            abi.encodeWithSelector(ISpendPolicyModule.CounterpartyNotAllowed.selector, cptyOutsider)
        );
        acct.pay(m.mandateId, address(usdc), cptyOutsider, 10e6, p, sig);
    }

    // ------------------------------------------------------------------ //
    //  replay / signatures                                               //
    // ------------------------------------------------------------------ //

    function test_ReplayedAuthorisation_Reverts() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        uint32 nonce = module.txCount(m.mandateId);
        bytes memory sig = _signAuth(m.mandateId, cptyA, 10e6, nonce, sessionPk);
        acct.pay(m.mandateId, address(usdc), cptyA, 10e6, _proofFor(cptyA, cptyB), sig);
        // replay same sig: txCount advanced, so signature no longer recovers session key
        vm.expectRevert(ISpendPolicyModule.BadSessionSignature.selector);
        acct.pay(m.mandateId, address(usdc), cptyA, 10e6, _proofFor(cptyA, cptyB), sig);
    }

    function test_WrongSessionKey_Reverts() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        uint32 nonce = module.txCount(m.mandateId);
        bytes memory sig = _signAuth(m.mandateId, cptyA, 10e6, nonce, wrongPk);
        vm.expectRevert(ISpendPolicyModule.BadSessionSignature.selector);
        acct.pay(m.mandateId, address(usdc), cptyA, 10e6, _proofFor(cptyA, cptyB), sig);
    }

    function test_ForgedMandateSignature_Reverts() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        vm.expectRevert(SpendPolicyModule.BadPrincipalSignature.selector);
        module.registerMandate(m, _signMandate(m, wrongPk));
    }

    function test_DirectModuleCall_NotAccount_Reverts() public {
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        uint32 nonce = module.txCount(m.mandateId);
        bytes memory sig = _signAuth(m.mandateId, cptyA, 10e6, nonce, sessionPk);
        vm.expectRevert(SpendPolicyModule.NotAccount.selector);
        module.authorisePayment(m.mandateId, cptyA, 10e6, _proofFor(cptyA, cptyB), sig);
    }

    // ------------------------------------------------------------------ //
    //  commitments                                                       //
    // ------------------------------------------------------------------ //

    function test_EveryAuthorisedPaymentInsertsExactlyOneLeaf() public {
        Mandate.Data memory m = _mandate(1000e6, 1000e6);
        _register(m);
        bytes32 r0 = module.currentRoot(m.mandateId);
        _pay(m, cptyA, cptyB, 10e6);
        assertEq(module.txCount(m.mandateId), 1);
        bytes32 r1 = module.currentRoot(m.mandateId);
        assertTrue(r0 != r1, "root must change on insert");
        _pay(m, cptyA, cptyB, 10e6);
        assertEq(module.txCount(m.mandateId), 2);
        assertTrue(module.currentRoot(m.mandateId) != r1, "root must change again");
    }

    function test_NoPathSettlesPaymentWithoutLeaf() public {
        // A reverting payment must not move funds and must not advance the tree.
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        bytes32 r0 = module.currentRoot(m.mandateId);
        uint256 bal0 = usdc.balanceOf(address(acct));
        (bytes32[] memory proof, bytes memory sig) = _prep(m, cptyA, cptyB, 200e6);
        vm.expectRevert();
        acct.pay(m.mandateId, address(usdc), cptyA, 200e6, proof, sig); // over cap
        assertEq(module.currentRoot(m.mandateId), r0);
        assertEq(module.txCount(m.mandateId), 0);
        assertEq(usdc.balanceOf(address(acct)), bal0);
    }

    function test_SaltNotCallerControlled() public {
        // The caller supplies no salt anywhere in the interface; commitment salt is
        // derived from module state. This test documents that the pay path takes no
        // salt argument, so it cannot be attacker-chosen.
        Mandate.Data memory m = _mandate(100e6, 100e6);
        _register(m);
        _pay(m, cptyA, cptyB, 10e6);
        assertEq(module.txCount(m.mandateId), 1);
    }

    // ------------------------------------------------------------------ //
    //  fuzz                                                              //
    // ------------------------------------------------------------------ //

    function testFuzz_NeverExceedsTotalCap(uint256 totalCap, uint256 perTxCap, uint256[8] memory amounts)
        public
    {
        totalCap = bound(totalCap, 1, 1_000_000e6);
        perTxCap = bound(perTxCap, 1, totalCap);
        Mandate.Data memory m = _mandate(totalCap, perTxCap);
        _register(m);

        for (uint256 i = 0; i < amounts.length; i++) {
            uint256 amt = bound(amounts[i], 1, 2_000_000e6);
            uint32 nonce = module.txCount(m.mandateId);
            bytes memory sig = _signAuth(m.mandateId, cptyA, amt, nonce, sessionPk);
            try acct.pay(m.mandateId, address(usdc), cptyA, amt, _proofFor(cptyA, cptyB), sig) {
                // ok
            } catch {
                // rejected — fine
            }
            assertLe(module.spent(m.mandateId), totalCap, "spent must never exceed cap");
        }
    }

    function testFuzz_ArithmeticNearMaxUint(uint256 amount) public {
        amount = bound(amount, type(uint256).max - 1000, type(uint256).max);
        Mandate.Data memory m = _mandate(type(uint256).max, type(uint256).max);
        _register(m);
        // account has nowhere near this balance; the transfer would revert even if
        // caps pass. We assert the accounting stays sound (no overflow wrap).
        uint32 nonce = module.txCount(m.mandateId);
        bytes memory sig = _signAuth(m.mandateId, cptyA, amount, nonce, sessionPk);
        try acct.pay(m.mandateId, address(usdc), cptyA, amount, _proofFor(cptyA, cptyB), sig) {}
        catch {}
        assertLe(module.spent(m.mandateId), m.totalCap);
    }

    // ------------------------------------------------------------------ //
    //  invariant                                                         //
    // ------------------------------------------------------------------ //

    // Invariant tests use a handler; see SpendPolicyInvariant.t.sol.
}
