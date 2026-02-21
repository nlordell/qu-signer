// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

import {IERC1271, ILegacyERC1271} from "@/interfaces/IERC1271.sol";

/// @title Quantum-Secure Signer
/// @dev This signer implements a rolling Lamport signature scheme.
contract QuSigner is IERC1271, ILegacyERC1271 {
    /// @notice The current public key digest.
    /// @dev This signer implements a rolling signature scheme, where the public
    ///      key changes after every signature. This is because the Lamport
    ///      signing scheme used by the contract only supports one-time
    ///      signatures, meaning that a new private key needs to be used for
    ///      every new signed message.
    // forge-lint: disable-next-line(mixed-case-variable)
    bytes32 private $publicKeyDigest;

    /// @notice The signed messages.
    /// @dev This mapping stores the hash of the public key that last signed a
    ///      particular message.
    // forge-lint: disable-next-line(mixed-case-variable)
    mapping(bytes32 message => bytes32) private $signedMessages;

    /// @notice Event emitted that a signature was signed.
    event Signed(bytes32 message);

    /// @notice An invalid signature encoding.
    error InvalidSignatureEncoding();

    /// @notice The signature could not be authenticated against the public key
    ///         digest.
    error NotAuthenticated();

    /// @param publicKeyDigest The initial hash of the first public key used by
    ///                        the rolling signer.
    constructor(bytes32 publicKeyDigest) {
        $publicKeyDigest = publicKeyDigest;
    }

    /// @notice Gets the current public key digest.
    /// @return result The current public key digest.
    function getPublicKeyDigest() external view returns (bytes32 result) {
        return $publicKeyDigest;
    }

    /// @notice Sign a message with the current one-time signature key and roll
    ///         over to a new key.
    /// @dev The Lamport signature is not over the message itself, but the hash
    ///      of the message with the next public key. This ensures that only
    ///      authorized rollovers are possible (the _signing message_).
    ///
    ///      Additionally, the Lamport signature is encoded weaved with the
    ///      the public key, in order to allow the contract to verify the public
    ///      key matches the stored digest. For each bit with position `i` of
    ///      the signing message, starting with the most significant bit,
    ///      concatenate `sk_i,0; pk_i,1` if the bit is `0` or `pk_i,0; sk_i,1`
    ///      if the bit is `1`, where `sk_i,j` is one of the 512 secret 256-bit
    ///      values for bit position `i` and bit value `j`, and `pk_i,j` is
    ///      just the `keccak256(sk_i,j)`. This encoding allows the contract to
    ///      reconstruct the public key in-place and verify it against the
    ///      stored public key digest.
    /// @param message The message to sign.
    /// @param nextPublicKeyDigest The public key digest to roll over to.
    /// @param signature The Lamport signature over the hash of the message and
    ///                  the next public key.
    /// @return publicKeyDigest The public key digest used to sign the message.
    function sign(bytes32 message, bytes32 nextPublicKeyDigest, bytes memory signature)
        external
        returns (bytes32 publicKeyDigest)
    {
        require(signature.length == 0x4000, InvalidSignatureEncoding());

        publicKeyDigest = $publicKeyDigest;
        $publicKeyDigest = nextPublicKeyDigest;
        $signedMessages[message] = publicKeyDigest;

        assembly ("memory-safe") {
            // First, compute the signing message by hashing our message and the
            // next public key together.
            mstore(0x00, message)
            mstore(0x20, nextPublicKeyDigest)
            let signingMessage := keccak256(0x00, 0x40)

            // Convert all of the secret values to public values from our
            // interleaved Lamport signature. We work through the signature
            // backwards.
            for {
                let ptr := add(signature, 0x3FE0)
            } gt(ptr, signature) {
                ptr := sub(ptr, 0x40)
                signingMessage := shr(1, signingMessage)
            } {
                // `ptr` points to a bit pair, and so the interleaved secret is
                // either the first word if the bit is `0` or the second if the
                // bit is `1`. Compute the pointer to the secret and compute
                // its public value by hashing it.
                let skPtr := add(ptr, mul(and(signingMessage, 1), 0x20))
                mstore(skPtr, keccak256(skPtr, 0x20))
            }
        }

        require(keccak256(signature) == publicKeyDigest, NotAuthenticated());
        emit Signed(message);
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
        require(signature.length == 0, InvalidSignatureEncoding());
        bytes32 publicKeyHash = $signedMessages[digest];
        return publicKeyHash != bytes32(0) ? validMagicValue : bytes4(0xffffffff);
    }
}
