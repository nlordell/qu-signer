// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

import {Test} from "@forge-std/Test.sol";
import {QuSigner} from "@/QuSigner.sol";
import {IERC1271, ILegacyERC1271} from "@/interfaces/IERC1271.sol";
import {Lamport} from "@test/util/Lamport.sol";

contract QuSignerTest is Test {
    using Lamport for Lamport.Key;

    function test_Sign() public {
        Lamport.Key key = Lamport.fromPassword("my secret");
        bytes32 message = keccak256("something to sign");

        QuSigner signer = new QuSigner(key.publicKeyDigest(0));

        assertEq(signer.getPublicKeyDigest(), key.publicKeyDigest(0));
        assertNotEq(signer.isValidSignature(message, ""), IERC1271.isValidSignature.selector);
        assertNotEq(signer.isValidSignature(bytes("something to sign"), ""), ILegacyERC1271.isValidSignature.selector);

        (bytes32 next, bytes memory signature) = key.sign(0, message);
        assertEq(next, key.publicKeyDigest(1));
        bytes32 signed = signer.sign(message, key.publicKeyDigest(1), signature);
        assertEq(signed, key.publicKeyDigest(0));

        assertEq(signer.getPublicKeyDigest(), key.publicKeyDigest(1));
        assertEq(signer.isValidSignature(message, ""), IERC1271.isValidSignature.selector);
        assertEq(signer.isValidSignature(bytes("something to sign"), ""), ILegacyERC1271.isValidSignature.selector);
    }
}
