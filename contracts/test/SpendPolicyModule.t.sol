// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";

/// @notice Phase 1 test surface. Write these FIRST and watch them fail.
/// @dev The fuzz and invariant tests at the bottom are the real safety claim;
///      the unit tests above them are just the obvious cases.
contract SpendPolicyModuleTest is Test {
    function setUp() public {}

    // --- caps -------------------------------------------------------------
    function test_SpendExactlyAtCap_Succeeds() public {}
    function test_SpendOneWeiOverCap_Reverts() public {}
    function test_TwoPaymentsIndividuallyOkButCumulativelyOver_SecondReverts() public {}
    function test_PerTxCapEnforcedIndependentlyOfTotal() public {}

    // --- window -----------------------------------------------------------
    function test_PaymentAtWindowEnd_Succeeds() public {}
    function test_PaymentAtWindowEndPlusOne_Reverts() public {}
    function test_PaymentBeforeWindowStart_Reverts() public {}

    // --- revocation -------------------------------------------------------
    function test_RevocationInvalidatesPreviouslyValidSignature() public {}
    function test_RevocationRacesInFlightAuthorisation() public {}

    // --- allowlist --------------------------------------------------------
    function test_CounterpartyNotInAllowlist_Reverts() public {}
    function test_ValidProofForDifferentAllowlistRoot_Reverts() public {}

    // --- replay -----------------------------------------------------------
    function test_ReplayedAuthorisation_Reverts() public {}

    // --- commitments (phase 3) --------------------------------------------
    function test_EveryAuthorisedPaymentInsertsExactlyOneLeaf() public {}
    function test_NoPathSettlesPaymentWithoutLeaf() public {}
    function test_SaltNotCallerControlled() public {}

    // --- fuzz -------------------------------------------------------------
    function testFuzz_NeverExceedsTotalCap(uint256 totalCap, uint256 perTxCap, uint256[8] memory amounts) public {}
    function testFuzz_ArithmeticNearMaxUint(uint256 amount) public {}

    // --- invariant --------------------------------------------------------
    /// @dev The core safety property: spent(m) <= totalCap(m), always,
    ///      under any sequence of calls from any actor.
    function invariant_SpentNeverExceedsCap() public {}

    /// @dev txCount(m) always equals the number of leaves in the tree.
    function invariant_LeafCountMatchesTxCount() public {}
}
