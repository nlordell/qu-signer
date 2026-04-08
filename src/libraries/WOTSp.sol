// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

import {Address} from "@/libraries/Address.sol";

/// @title Winternitz One-Time Signature Plus Library
/// @dev This library provides an implementation of the WOTS+ signing scheme for
///      the SHA-256 construction as specified by RFC-8391.
library WOTSp {
    using Address for Address.T;

    /// @notice A WOTS+ context was used with an invalid Winternitz parameter.
    error InvalidWinternitzParameter();

    /// @notice Attempted to recover a WOTS+ public key using a signature with
    ///         an invalid length.
    error InvalidSignatureLength();

    /// @notice A WOTS+ one-time signature context.
    struct Context {
        uint256 w;
        bytes32 seed;
        Address.T adrs;
    }

    /// @notice Compute the public key for a given secret key.
    /// @dev This method takes a 32-byte secret key seed, expands it to a full
    ///      WOTS+ secret key, computes the corresponding public key, and then
    ///      computes its L-tree root hash.
    /// @param self The WOTS+ context.
    /// @param sk The secret key.
    /// @return pk The WOTS+ public key L-tree root hash.
    function pubkey(Context memory self, bytes32 sk) internal view returns (bytes32 pk) {
        bytes32[] memory pkw = new bytes32[](_len(self.w));

        uint256 s;
        unchecked {
            s = self.w - 1;
        }
        bytes32 seed = self.seed;
        Address.T adrs = self.adrs.setType(Address.Type.OTS);

        for (uint256 i = 0; i < pkw.length; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            adrs = adrs.setChainAddress(uint32(i));
            bytes32 k = _prfKeygen(sk, seed, adrs.asBytes32());
            _mwrite(pkw, i, _chain(k, 0, s, seed, adrs));
        }

        return _ltree(pkw, seed, adrs.setType(Address.Type.LTREE));
    }

    /// @notice Sign a message with a secret key.
    /// @param self The WOTS+ context.
    /// @param sk The secret key.
    /// @param m The message to sign.
    /// @return sig The WOTS+ signature.
    function sign(Context memory self, bytes32 sk, bytes32 m) internal view returns (bytes32[] memory sig) {
        bytes memory mw = _baseW(m, self.w);

        bytes32 seed = self.seed;
        Address.T adrs = self.adrs.setType(Address.Type.OTS);

        sig = new bytes32[](mw.length);
        for (uint256 i = 0; i < sig.length; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            adrs = adrs.setChainAddress(uint32(i));
            bytes32 k = _prfKeygen(sk, seed, adrs.asBytes32());
            _mwrite(sig, i, _chain(k, 0, _byte(mw, i), seed, adrs));
        }
    }

    /// @notice Recovers a public key from a message and signature.
    /// @param self The WOTS+ context.
    /// @param m The signed message.
    /// @param sig The WOTS+ signature.
    /// @return pk The recovered WOTS+ public key L-tree root hash.
    function recover(Context memory self, bytes32 m, bytes32[] calldata sig) internal view returns (bytes32 pk) {
        bytes memory mw = _baseW(m, self.w);
        require(sig.length == mw.length, InvalidSignatureLength());

        uint256 s;
        unchecked {
            s = self.w - 1;
        }
        bytes32 seed = self.seed;
        Address.T adrs = self.adrs.setType(Address.Type.OTS);

        bytes32[] memory pkw = new bytes32[](sig.length);
        for (uint256 i = 0; i < pkw.length; i++) {
            uint256 c = _byte(mw, i);
            unchecked {
                // forge-lint: disable-next-line(unsafe-typecast)
                _mwrite(pkw, i, _chain(_cread(sig, i), c, s - c, seed, adrs.setChainAddress(uint32(i))));
            }
        }

        return _ltree(pkw, seed, adrs.setType(Address.Type.LTREE));
    }

    /// @dev The number of 32-byte string elements in a WOTS+ private key,
    ///      public key, and signature.
    function _len(uint256 w) private pure returns (uint256 result) {
        if (w == 16) {
            return 67;
        } else if (w == 4) {
            return 133;
        } else {
            revert InvalidWinternitzParameter();
        }
    }

    /// @dev The base-w encoding of a message.
    function _baseW(bytes32 m, uint256 w) private pure returns (bytes memory result) {
        if (w == 16) {
            return _base16(m);
        } else if (w == 4) {
            return _base4(m);
        } else {
            revert InvalidWinternitzParameter();
        }
    }

    /// @dev Compute the hash chaining function for a given input.
    function _chain(bytes32 x, uint256 i, uint256 s, bytes32 seed, Address.T adrs)
        private
        view
        returns (bytes32 result)
    {
        result = x;
        for (uint256 j = 0; j < s; j++) {
            unchecked {
                // forge-lint: disable-next-line(unsafe-typecast)
                adrs = adrs.setHashAddress(uint32(i + j));
            }
            bytes32 key = _prf(seed, adrs.setKeyAndMask(0).asBytes32());
            bytes32 bm = _prf(seed, adrs.setKeyAndMask(1).asBytes32());
            result = _f(key, result ^ bm);
        }
    }

    /// @dev Randomized tree hash.
    function _randHash(bytes32 left, bytes32 right, bytes32 seed, Address.T adrs)
        private
        view
        returns (bytes32 result)
    {
        bytes32 key = _prf(seed, adrs.setKeyAndMask(0).asBytes32());
        bytes32 bm0 = _prf(seed, adrs.setKeyAndMask(1).asBytes32());
        bytes32 bm1 = _prf(seed, adrs.setKeyAndMask(2).asBytes32());
        return _h(key, left ^ bm0, right ^ bm1);
    }

    /// @dev Compute the L-tree root hash for a public key in place. Note that
    ///      the public key that is passed in gets overwritten.
    function _ltree(bytes32[] memory pkw, bytes32 seed, Address.T adrs) private view returns (bytes32 result) {
        uint256 len = pkw.length;
        uint256 height = 0;
        unchecked {
            while (len > 1) {
                // forge-lint: disable-next-line(unsafe-typecast)
                adrs = adrs.setTreeHeight(uint32(height++));
                for (uint256 j = 0; j < len; j += 2) {
                    uint256 i = j >> 1;
                    // forge-lint: disable-next-line(unsafe-typecast)
                    _mwrite(pkw, i, _randHash(_mread(pkw, j), _mread(pkw, j + 1), seed, adrs.setTreeIndex(uint32(i))));
                }
                if (len & 1 != 0) {
                    _mwrite(pkw, len >> 1, _mread(pkw, len - 1));
                }
                len = (len + 1) >> 1;
            }
        }
        return _mread(pkw, 0);
    }

    /// @dev The WOTS+ cryptographic hash function.
    function _f(bytes32 key, bytes32 m) private view returns (bytes32 result) {
        return _sha256(bytes32(uint256(0)), key, m);
    }

    /// @dev The WOTS+ tree hash function.
    function _h(bytes32 key, bytes32 m, bytes32 n) private view returns (bytes32 result) {
        return _sha256(bytes32(uint256(1)), key, m, n);
    }

    /// @dev The WOTS+ pseudo-random function.
    function _prf(bytes32 key, bytes32 m) private view returns (bytes32 result) {
        return _sha256(bytes32(uint256(3)), key, m);
    }

    /// @dev The WOTS+ pseudo-random function used for key expansion.
    function _prfKeygen(bytes32 key, bytes32 m, bytes32 n) private view returns (bytes32 result) {
        return _sha256(bytes32(uint256(4)), key, m, n);
    }

    /// @dev Specialized SHA-256 function for WOTS+ designed for small code
    ///      and reduced gas costs.
    function _sha256(bytes32 domain, bytes32 key, bytes32 m) private view returns (bytes32 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, domain)
            mstore(add(ptr, 0x20), key)
            mstore(add(ptr, 0x40), m)
            if iszero(staticcall(gas(), 0x2, ptr, 0x60, 0x00, 0x20)) { revert(0x00, 0x00) }
            result := mload(0x00)
        }
    }

    /// @dev Specialized SHA-256 function for WOTS+ designed for small code
    ///      and reduced gas costs.
    function _sha256(bytes32 domain, bytes32 key, bytes32 m, bytes32 n) private view returns (bytes32 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, domain)
            mstore(add(ptr, 0x20), key)
            mstore(add(ptr, 0x40), m)
            mstore(add(ptr, 0x60), n)
            if iszero(staticcall(gas(), 0x2, ptr, 0x80, 0x00, 0x20)) { revert(0x00, 0x00) }
            result := mload(0x00)
        }
    }

    /// @dev The base4 encoding of a message.
    function _base4(bytes32 m) private pure returns (bytes memory result) {
        // The base-4 encoding of a 32-byte message is split into 128 characters
        // (4 characters per byte). Furthermore, we need an additional 5
        // characters to encode the checksum (which has a maximum value of
        // `3 * 128 = 0b01_10_00_00_00`). We implement it in assembly with a
        // partially unrolled inner loop for efficiency.
        result = new bytes(133);
        assembly ("memory-safe") {
            let ptr := add(result, 0x20)
            let csum := 0
            for {
                let i := 0
            } lt(i, 32) {
                ptr := add(ptr, 0x04)
                i := add(i, 1)
            } {
                let b := byte(i, m)
                {
                    let c := shr(6, b)
                    mstore8(ptr, c)
                    csum := add(csum, sub(3, c))
                }
                {
                    let c := and(shr(4, b), 3)
                    mstore8(add(ptr, 0x01), c)
                    csum := add(csum, sub(3, c))
                }
                {
                    let c := and(shr(2, b), 3)
                    mstore8(add(ptr, 0x02), c)
                    csum := add(csum, sub(3, c))
                }
                {
                    let c := and(b, 3)
                    mstore8(add(ptr, 0x03), c)
                    csum := add(csum, sub(3, c))
                }
            }

            mstore8(ptr, shr(8, csum))
            mstore8(add(ptr, 0x01), and(shr(6, csum), 3))
            mstore8(add(ptr, 0x02), and(shr(4, csum), 3))
            mstore8(add(ptr, 0x03), and(shr(2, csum), 3))
            mstore8(add(ptr, 0x04), and(csum, 3))
        }
    }

    /// @dev The base16 encoding of a message.
    function _base16(bytes32 m) private pure returns (bytes memory result) {
        // The base-16 encoding of a 32-byte message is split into 64 characters
        // (2 characters per byte). Furthermore, we need an additional 3
        // characters to encode the checksum (which has a maximum value of
        // `15 * 64 = 0b0011_1100_0000`). We implement it in assembly with a
        // partially unrolled inner loop for efficiency.
        result = new bytes(67);
        assembly ("memory-safe") {
            let ptr := add(result, 0x20)
            let csum := 0
            for {
                let i := 0
            } lt(i, 32) {
                ptr := add(ptr, 0x02)
                i := add(i, 1)
            } {
                let b := byte(i, m)
                {
                    let c := shr(4, b)
                    mstore8(ptr, c)
                    csum := add(csum, sub(15, c))
                }
                {
                    let c := and(b, 15)
                    mstore8(add(ptr, 0x01), c)
                    csum := add(csum, sub(15, c))
                }
            }

            mstore8(ptr, shr(8, csum))
            mstore8(add(ptr, 0x01), and(shr(4, csum), 15))
            mstore8(add(ptr, 0x02), and(csum, 15))
        }
    }

    /// @dev Reads the byte at index `i`. It is the responsibility of the caller
    ///      to ensure that `0 <= i < b.length`.
    function _byte(bytes memory b, uint256 i) private pure returns (uint256 c) {
        assembly ("memory-safe") {
            c := byte(0, mload(add(b, add(0x20, i))))
        }
    }

    /// @dev Reads a word at index `i`. It is the responsibility of the caller
    ///      to ensure that `0 <= i < a.length`.
    function _cread(bytes32[] calldata a, uint256 i) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := calldataload(add(a.offset, shl(5, i)))
        }
    }

    /// @dev Reads a word at index `i`. It is the responsibility of the caller
    ///      to ensure that `0 <= i < a.length`.
    function _mread(bytes32[] memory a, uint256 i) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(a, add(0x20, shl(5, i))))
        }
    }

    /// @dev Writes a word at index `i`. It is the responsibility of the caller
    ///      to ensure that `0 <= i < a.length`.
    function _mwrite(bytes32[] memory a, uint256 i, bytes32 w) private pure {
        assembly ("memory-safe") {
            mstore(add(a, add(0x20, shl(5, i))), w)
        }
    }
}
