// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

/// @title Hash Function Address Library
/// @dev Hash function addressing used for randomizing hash calls as specified
///      by RFC-8391.
library Address {
    /// @notice A hash function address.
    type T is bytes32;

    /// @notice The type of hash function address.
    enum Type {
        OTS,
        LTREE
    }

    /// @notice The zero address.
    function zero() internal pure returns (T result) {
        return T.wrap(bytes32(0));
    }

    /// @notice Construct a new hash address.
    function make(uint32 layerAddress, uint64 treeAddress) internal pure returns (T result) {
        unchecked {
            return T.wrap(bytes32((uint256(layerAddress) << 224) | (uint256(treeAddress) << 160)));
        }
    }

    function setType(T self, Type typ) internal pure returns (T result) {
        unchecked {
            return T.wrap(
                (T.unwrap(self) & 0xffffffffffffffffffffffff0000000000000000000000000000000000000000)
                    | bytes32(uint256(uint8(typ)) << 128)
            );
        }
    }

    /// @notice Sets the chain address for an OTS hash address.
    function setChainAddress(T self, uint32 chainAddress) internal pure returns (T result) {
        return _set4(self, chainAddress);
    }

    /// @notice Sets the chain address for an OTS hash address.
    function setTreeHeight(T self, uint32 treeHeight) internal pure returns (T result) {
        return _set4(self, treeHeight);
    }

    /// @dev Sets the address field at index 4.
    function _set4(T self, uint32 value) internal pure returns (T result) {
        unchecked {
            return T.wrap(
                (T.unwrap(self) & 0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000)
                    | bytes32(uint256(value) << 64)
            );
        }
    }

    /// @notice Sets the hash address for an OTS hash address.
    function setHashAddress(T self, uint32 hashAddress) internal pure returns (T result) {
        return _set5(self, hashAddress);
    }

    /// @notice Sets the hash address for an L-tree hash address.
    function setTreeIndex(T self, uint32 treeIndex) internal pure returns (T result) {
        return _set5(self, treeIndex);
    }

    /// @dev Sets the address field at index 5.
    function _set5(T self, uint32 value) private pure returns (T result) {
        unchecked {
            return T.wrap(
                (T.unwrap(self) & 0xffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000)
                    | bytes32(uint256(value) << 32)
            );
        }
    }

    /// @notice Sets the key and mask of a hash function address.
    function setKeyAndMask(T self, uint32 keyAndMask) internal pure returns (T result) {
        unchecked {
            return T.wrap(
                (T.unwrap(self) & 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000)
                    | bytes32(uint256(keyAndMask))
            );
        }
    }

    /// @notice A hash function address as a 32-byte value.
    function asBytes32(T self) internal pure returns (bytes32 result) {
        return T.unwrap(self);
    }
}
