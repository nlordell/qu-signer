// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

library Lamport {
    type Key is bytes32;

    function fromPassword(string memory password) internal pure returns (Key result) {
        // TODO(nlordell): This key derivation function is not suitable for
        // cryptographic purposes and used **only for testing!**
        return Key.wrap(keccak256(bytes(password)));
    }

    function secretKey(Key self, uint256 sequence) internal pure returns (bytes memory result) {
        result = new bytes(0x4000);
        // TODO(nlordell): This key stretching function is not suitable for
        // cryptographic purposes and used **only for testing!**
        assembly ("memory-safe") {
            mstore(0x00, sequence)
            mstore(0x20, self)
            mstore(0x02, keccak256(0x00, 0x40))
            for {
                let i := 0
                let ptr := add(result, 0x20)
            } lt(i, 256) {
                i := add(i, 1)
            } {
                mstore8(0x00, i)
                mstore8(0x01, 0)
                mstore(ptr, keccak256(0, 0x22))
                ptr := add(ptr, 0x20)
                mstore8(0x01, 1)
                mstore(ptr, keccak256(0, 0x22))
                ptr := add(ptr, 0x20)
            }
        }
    }

    function publicKey(Key self, uint256 sequence) internal pure returns (bytes memory result) {
        result = secretKey(self, sequence);
        assembly ("memory-safe") {
            for {
                let ptr := add(result, 0x20)
                let end := add(ptr, 0x4000)
            } lt(ptr, end) {
                ptr := add(ptr, 0x20)
            } {
                mstore(ptr, keccak256(ptr, 0x20))
            }
        }
    }

    function publicKeyDigest(Key self, uint256 sequence) internal pure returns (bytes32 result) {
        // In order to prevent growing `MEMSIZE` too much, we clear the
        // allocation after computing the public key hash.
        uint256 ptr;
        assembly ("memory-safe") {
            ptr := mload(0x40)
        }

        result = keccak256(publicKey(self, sequence));

        assembly ("memory-safe") {
            mstore(0x40, ptr)
        }
    }

    function sign(Key self, uint256 sequence, bytes32 message)
        internal
        pure
        returns (bytes32 next, bytes memory result)
    {
        next = publicKeyDigest(self, sequence + 1);
        result = secretKey(self, sequence);
        assembly ("memory-safe") {
            mstore(0x00, message)
            mstore(0x20, next)
            let signingMessage := keccak256(0x00, 0x40)

            for {
                let i := 0
            } lt(i, 256) {
                i := add(i, 1)
            } {
                let ptr := add(add(result, 0x20), mul(i, 0x40))

                // Compute the public value for the opposite bit from the
                // signing message, since the signature reveals secret values
                // for the message bit only.
                let bit := and(1, shr(sub(255, i), signingMessage))
                let pkPtr := add(ptr, mul(0x20, iszero(bit)))
                mstore(pkPtr, keccak256(pkPtr, 0x20))
            }
        }
    }
}
