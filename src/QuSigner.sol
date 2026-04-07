// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

import {IERC1271, ILegacyERC1271} from "@/interfaces/IERC1271.sol";
import {Address} from "@/libraries/Address.sol";
import {WOTSp} from "@/libraries/WOTSp.sol";

/// @title Quantum-Secure Signer
/// @dev This signer implements a rolling Lamport signature scheme.
contract QuSigner is IERC1271, ILegacyERC1271 {
    using WOTSp for WOTSp.Context;

    /// @notice The Winternitz parameter.
    /// @dev Can be either `4` or `16`.
    uint256 public immutable W;

    /// @notice The public seed used for randomizing WOTS+ hashes.
    bytes32 public immutable SEED;

    /// @notice The current WOTS+ public key L-tree root hash.
    /// @dev This signer implements a rolling signature scheme, where the public
    ///      key changes after every signature. This is because the WOTS+
    ///      signing scheme used by the contract is a one-time signature scheme,
    ///      meaning that a new private key needs to be used for every message.
    // forge-lint: disable-next-line(mixed-case-variable)
    bytes32 private $publicKey;

    /// @notice The signature count.
    /// @dev We use this count as the XMSS tree address for WOTS+ operations.
    // forge-lint: disable-next-line(mixed-case-variable)
    uint64 private $count;

    /// @notice The signed messages.
    /// @dev This mapping stores the hash of the public key that last signed a
    ///      particular message.
    // forge-lint: disable-next-line(mixed-case-variable)
    mapping(bytes32 message => bytes32 publicKey) private $signedMessages;

    /// @notice Event emitted that a signature was signed.
    /// @param publicKey The WOTS+ public key that signed the message.
    /// @param signatureIndex The index of the signature.
    /// @param message The signed message.
    event SignedMessage(bytes32 publicKey, uint64 signatureIndex, bytes32 message);

    /// @notice An invalid Winternitz paramter value.
    error InvalidWinternitzParameter();

    /// @notice An invalid public key.
    error InvalidPublicKey();

    /// @notice An invalid signature encoding.
    error InvalidSignature();

    /// @notice The signature could not be authenticated against the public key.
    error NotAuthenticated();

    /// @param w The Winternitz parameter.
    /// @param seed The public seed used for randomizing WOTS+ hashes.
    /// @param publicKey The initial public key used by the rolling signer.
    constructor(uint256 w, bytes32 seed, bytes32 publicKey) {
        require(w == 4 || w == 16, InvalidWinternitzParameter());
        require(publicKey != bytes32(0), InvalidPublicKey());

        W = w;
        SEED = seed;
        $publicKey = publicKey;
    }

    /// @notice Gets the current public key.
    /// @return result The current WOTS+ public key L-tree root hash.
    function getPublicKey() external view returns (bytes32 result) {
        return $publicKey;
    }

    /// @notice Gets the signature count.
    /// @return result The number of messages that have been signed.
    function getCount() external view returns (uint64 result) {
        return $count;
    }

    /// @notice Computes the signing message, that a WOTS+ private key actually
    ///         signs over, for a particular message.
    /// @dev The rolling signature scheme doesn't sign over messages directly,
    ///      but a hash of the message with the next public key. This ensures
    ///      that only authorized rollovers are possible.
    /// @param randomness Additional randomness used for hashing.
    /// @param nextPublicKey The public key to roll over to.
    /// @param signatureIndex The index of the signature.
    /// @param message The message to sign.
    function getSigningMessage(bytes32 randomness, bytes32 nextPublicKey, uint64 signatureIndex, bytes32 message)
        public
        view
        returns (bytes32 result)
    {
        // WARNING: Needs to be checked by an actual cryptographer.
        // We re-purpose the `M'` computation from the XMSS_sign algorithm from
        // RFC-8391 to compute a signing message, replacing `getRoot(SK)` with
        // the next public key L-tree hash, and `idx_sig` with the signature
        // index (which is closer to a tree address than an index within an XMSS
        // tree). This provides sufficient randomization on the signing message
        // to maintain the WOTS+ and XMSS cryptographic guarantees.
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 2)
            mstore(add(ptr, 0x20), randomness)
            mstore(add(ptr, 0x40), nextPublicKey)
            mstore(add(ptr, 0x60), signatureIndex)
            mstore(add(ptr, 0x80), message)
            if iszero(staticcall(gas(), 0x2, ptr, 0xa0, 0x00, 0x20)) { revert(0x00, 0x00) }
            result := mload(0x00)
        }
    }

    /// @notice Sign a message with the current one-time signature key and roll
    ///         over to a new key.
    /// @param randomness Additional randomness used for signing.
    /// @param nextPublicKey The public key to roll over to.
    /// @param message The message to sign.
    /// @param signature The Lamport signature over the hash of the message and
    ///                  the next public key.
    /// @return publicKey The public key used to sign the message.
    /// @return signatureIndex The index of the signature.
    function sign(bytes32 randomness, bytes32 nextPublicKey, bytes32 message, bytes32[] calldata signature)
        external
        returns (bytes32 publicKey, uint64 signatureIndex)
    {
        require(nextPublicKey != bytes32(0), InvalidPublicKey());

        publicKey = $publicKey;
        $publicKey = nextPublicKey;
        signatureIndex = $count++;
        $signedMessages[message] = publicKey;

        WOTSp.Context memory wots = WOTSp.Context({w: W, seed: SEED, adrs: Address.make(0, signatureIndex)});
        bytes32 signingMessage = getSigningMessage(randomness, nextPublicKey, signatureIndex, message);
        bytes32 signer = wots.recover(signingMessage, signature);
        require(signer == publicKey, NotAuthenticated());

        emit SignedMessage(publicKey, signatureIndex, message);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 digest, bytes calldata signature) public view returns (bytes4 magicValue) {
        return _isValidSignature(IERC1271.isValidSignature.selector, digest, signature);
    }

    /// @inheritdoc ILegacyERC1271
    function isValidSignature(bytes memory data, bytes calldata signature) external view returns (bytes4 magicValue) {
        return _isValidSignature(ILegacyERC1271.isValidSignature.selector, keccak256(data), signature);
    }

    /// @dev Checks a signature and returns the provided magic value if valid.
    function _isValidSignature(bytes4 validMagicValue, bytes32 digest, bytes calldata signature)
        private
        view
        returns (bytes4 magicValue)
    {
        require(signature.length == 0, InvalidSignature());
        bytes32 publicKey = $signedMessages[digest];
        return publicKey != bytes32(0) ? validMagicValue : bytes4(0xffffffff);
    }
}
