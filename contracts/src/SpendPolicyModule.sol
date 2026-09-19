// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ISpendPolicyModule} from "./interfaces/ISpendPolicyModule.sol";
import {Mandate} from "./libraries/Mandate.sol";

/// @title SpendPolicyModule
/// @notice ERC-4337 validation module enforcing a spending mandate and building
///         the commitment tree that the attestation proof is computed over.
///
/// @dev IMPLEMENTATION ORDER (authorisePayment):
///        1. verify session signature over (mandateId, counterparty, amount, txCount)
///        2. check window, revocation, per-tx cap, cumulative cap, tx count
///        3. verify counterparty against allowlistRoot
///        4. EFFECTS: bump spent, bump txCount, mark nonce used
///        5. compute leaf and insert it into the incremental tree (Phase 3)
///        6. INTERACTIONS: execute the transfer (performed by AgentAccount)
///
///      The commitment insertion is not separable from the accounting: both happen
///      in this one call, before the account performs the transfer. See CLAUDE.md.
contract SpendPolicyModule is ISpendPolicyModule {
    uint8 internal constant TREE_DEPTH = 7; // 128 leaves per mandate period

    /// @dev EIP-712 domain, fixed at deployment.
    bytes32 private immutable _DOMAIN_SEPARATOR;
    bytes32 private constant _DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @dev Session authorisation typehash. The txCount acts as an implicit,
    ///      monotonic per-payment nonce — the interface carries no nonce field,
    ///      so we bind the signature to the mandate's current txCount. A replay
    ///      presents a stale txCount and fails signature recovery.
    bytes32 private constant _AUTH_TYPEHASH = keccak256(
        "Authorisation(bytes32 mandateId,address counterparty,uint256 amount,uint32 nonce)"
    );

    struct MandateState {
        bool registered;
        bool revoked;
        uint256 spent;
        uint32 txCount;
        uint64 revocationNonce;
    }

    mapping(bytes32 => Mandate.Data) internal _mandates;
    mapping(bytes32 => MandateState) internal _state;

    // Incremental Merkle state, per mandate (Phase 3).
    mapping(bytes32 => bytes32[TREE_DEPTH]) internal _filledSubtrees;
    mapping(bytes32 => bytes32) internal _root;

    /// @notice The account this module guards. Only it may call authorisePayment,
    ///         because authorisation and the value transfer must be atomic and the
    ///         transfer is performed by the account immediately after this returns.
    address public immutable account;

    error NotAccount();
    error MandateAlreadyRegistered();
    error MandateUnknown();
    error NotPrincipal();
    error BadPrincipalSignature();

    constructor(address account_) {
        account = account_;
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _DOMAIN_TYPEHASH,
                keccak256(bytes("Aegis")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // --------------------------------------------------------------------- //
    //  Registration & revocation                                            //
    // --------------------------------------------------------------------- //

    /// @inheritdoc ISpendPolicyModule
    function registerMandate(Mandate.Data calldata m, bytes calldata principalSig) external {
        if (_state[m.mandateId].registered) revert MandateAlreadyRegistered();

        bytes32 digest = _hashTypedData(Mandate.hash(m));
        address signer = _recover(digest, principalSig);
        if (signer != m.principal) revert BadPrincipalSignature();

        _mandates[m.mandateId] = m;
        MandateState storage s = _state[m.mandateId];
        s.registered = true;
        s.revocationNonce = m.revocationNonce;

        // Initialise incremental tree root to the empty-tree root.
        _root[m.mandateId] = _zeros(TREE_DEPTH);

        emit MandateRegistered(m.mandateId, m.principal);
    }

    /// @inheritdoc ISpendPolicyModule
    function revoke(bytes32 mandateId) external {
        MandateState storage s = _state[mandateId];
        if (!s.registered) revert MandateUnknown();
        if (msg.sender != _mandates[mandateId].principal) revert NotPrincipal();

        s.revoked = true;
        s.revocationNonce += 1;
        emit MandateRevoked(mandateId, s.revocationNonce);
    }

    // --------------------------------------------------------------------- //
    //  Authorisation — the security boundary                                //
    // --------------------------------------------------------------------- //

    /// @inheritdoc ISpendPolicyModule
    function authorisePayment(
        bytes32 mandateId,
        address counterparty,
        uint256 amount,
        bytes32[] calldata allowlistProof,
        bytes calldata sessionSig
    ) external {
        if (msg.sender != account) revert NotAccount();

        Mandate.Data storage m = _mandates[mandateId];
        MandateState storage s = _state[mandateId];
        if (!s.registered) revert MandateUnknown();

        // 1. session signature over current state (implicit nonce = txCount)
        bytes32 digest = _hashTypedData(
            keccak256(abi.encode(_AUTH_TYPEHASH, mandateId, counterparty, amount, s.txCount))
        );
        if (_recover(digest, sessionSig) != m.agentSessionKey) revert BadSessionSignature();

        // 2. window / revocation / caps / count
        if (s.revoked) revert MandateRevokedError();
        if (block.timestamp < m.windowStart) revert MandateNotYetActive();
        if (block.timestamp > m.windowEnd) revert MandateExpired();
        if (amount > m.perTxCap) revert PerTxCapExceeded(amount, m.perTxCap);

        uint256 wouldBe = s.spent + amount; // 0.8.x: reverts on overflow
        if (wouldBe > m.totalCap) revert TotalCapExceeded(wouldBe, m.totalCap);
        if (s.txCount >= m.maxTxCount) revert TxCountExceeded();

        // 3. counterparty allowlist
        bytes32 leafHash = keccak256(abi.encodePacked(counterparty));
        if (!_verifyProof(allowlistProof, m.allowlistRoot, leafHash)) {
            revert CounterpartyNotAllowed(counterparty);
        }

        // 4. EFFECTS
        uint32 index = s.txCount;
        s.spent = wouldBe;
        s.txCount = index + 1;

        // 5-6. commitment: append leaf atomically (Phase 3)
        bytes32 salt = _salt(mandateId, index);
        bytes32 leaf = _commit(amount, counterparty, uint64(block.timestamp), salt);
        bytes32 newRoot = _insert(mandateId, index, leaf);

        emit PaymentAuthorised(mandateId, counterparty, amount, s.spent, s.txCount);
        emit LeafInserted(mandateId, index, leaf, newRoot);
    }

    // --------------------------------------------------------------------- //
    //  Views                                                                //
    // --------------------------------------------------------------------- //

    function currentRoot(bytes32 mandateId) external view returns (bytes32) {
        return _root[mandateId];
    }

    function spent(bytes32 mandateId) external view returns (uint256) {
        return _state[mandateId].spent;
    }

    function txCount(bytes32 mandateId) external view returns (uint32) {
        return _state[mandateId].txCount;
    }

    function mandate(bytes32 mandateId) external view returns (Mandate.Data memory) {
        return _mandates[mandateId];
    }

    function isRevoked(bytes32 mandateId) external view returns (bool) {
        return _state[mandateId].revoked;
    }

    // --------------------------------------------------------------------- //
    //  Commitment tree (Phase 3)                                            //
    // --------------------------------------------------------------------- //

    /// @dev Leaf commitment. Poseidon is the SNARK-friendly target (Phase 4);
    ///      until the Poseidon hasher is wired in, keccak stands in so the tree
    ///      logic is exercised. The circuit MUST use the same hash. See TODO below.
    /// TODO(phase4): replace keccak with Poseidon(amount, counterparty, ts, salt).
    function _commit(uint256 amount, address counterparty, uint64 ts, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(amount, counterparty, ts, salt));
    }

    /// @dev Salt is derived from module state, never from the caller (tripwire 4).
    function _salt(bytes32 mandateId, uint32 index) internal view returns (bytes32) {
        return keccak256(abi.encode(address(this), mandateId, index, block.prevrandao));
    }

    /// @dev Append a leaf to the incremental Merkle tree and return the new root.
    ///      Bounded loop of TREE_DEPTH iterations (no unbounded loops).
    function _insert(bytes32 mandateId, uint32 index, bytes32 leaf) internal returns (bytes32) {
        bytes32 node = leaf;
        uint32 idx = index;
        bytes32[TREE_DEPTH] storage subtrees = _filledSubtrees[mandateId];
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            if (idx & 1 == 0) {
                // left child: remember it, sibling is empty
                subtrees[i] = node;
                node = _hashPair(node, _zeros(uint8(i)));
            } else {
                node = _hashPair(subtrees[i], node);
            }
            idx >>= 1;
        }
        _root[mandateId] = node;
        return node;
    }

    // --------------------------------------------------------------------- //
    //  Primitives                                                           //
    // --------------------------------------------------------------------- //

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return keccak256(abi.encode(a, b));
    }

    /// @dev Empty-subtree hashes for depths 0..TREE_DEPTH. z(0)=0, z(k)=H(z(k-1),z(k-1)).
    function _zeros(uint8 level) internal pure returns (bytes32 z) {
        z = bytes32(0);
        for (uint8 i = 0; i < level; i++) {
            z = keccak256(abi.encode(z, z));
        }
    }

    /// @dev Sorted-pair keccak Merkle proof verification (OZ-compatible layout,
    ///      leaf pre-hashed by the caller).
    function _verifyProof(bytes32[] calldata proof, bytes32 root, bytes32 leaf)
        internal
        pure
        returns (bool)
    {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            computed = computed <= p
                ? keccak256(abi.encodePacked(computed, p))
                : keccak256(abi.encodePacked(p, computed));
        }
        return computed == root;
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, structHash));
    }

    /// @dev Minimal ECDSA recover with malleability guard.
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        // reject high-s (EIP-2)
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
