// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

/// @title Interface of the ERC-1271 Standard Signature Method for Contracts
/// @dev See <https://ercs.ethereum.org/ERCS/erc-1271>.
interface IERC1271 {
    /// @notice Returns whether or not the signature provided is valid for the
    ///         specified digest.
    /// @param digest The signed digest.
    /// @param signature The signature bytes to verify.
    /// @return magicValue The magic value if the signature is valid.
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4 magicValue);
}

/// @title Legacy Interface of the ERC-1271 Standard Signature Method for Contracts
/// @dev This is the interface supported by the Safe smart account prior to v1.5.0.
interface ILegacyERC1271 {
    /// @notice Returns whether or not the signature provided is valid for the
    ///         specified data.
    /// @param data The signed data.
    /// @param signature The signature bytes to verify.
    /// @return magicValue The magic value if the signature is valid.
    function isValidSignature(bytes calldata data, bytes calldata signature) external view returns (bytes4 magicValue);
}
