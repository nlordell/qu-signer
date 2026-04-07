// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

import {Test} from "@forge-std/Test.sol";
import {QuSigner} from "@/QuSigner.sol";
import {IERC1271, ILegacyERC1271} from "@/interfaces/IERC1271.sol";
import {Address} from "@/libraries/Address.sol";
import {WOTSp} from "@/libraries/WOTSp.sol";

contract QuSignerTest is Test {
    using WOTSp for WOTSp.Context;

    function test_Sign() public {
        bytes32 sk = keccak256("my secret");
        bytes32 seed = keccak256(abi.encodePacked("public seed", sk));

        uint256[2] memory ws = [uint256(4), 16];
        uint64 signatureCount = 4;
        for (uint256 i = 0; i < ws.length; i++) {
            WOTSp.Context memory wots = WOTSp.Context({w: ws[i], seed: seed, adrs: Address.zero()});
            QuSigner signer = new QuSigner(wots.w, wots.seed, wots.pubkey(sk));

            for (uint64 n = 0; n < signatureCount; n++) {
                bytes memory data = abi.encodePacked("something to sign", n);
                bytes32 message = keccak256(data);

                bytes32 r = bytes32(vm.randomUint());
                wots.adrs = Address.make(0, n + 1);
                bytes32 next = wots.pubkey(sk);
                bytes32 m = sha256(abi.encode(2, r, next, n, message));
                wots.adrs = Address.make(0, n);
                bytes32 pk = wots.pubkey(sk);
                bytes32[] memory sig = wots.sign(sk, m);

                assertEq(signer.getPublicKey(), pk);
                assertNotEq(signer.isValidSignature(message, ""), IERC1271.isValidSignature.selector);
                assertNotEq(signer.isValidSignature(data, ""), ILegacyERC1271.isValidSignature.selector);

                vm.expectEmit();
                emit QuSigner.SignedMessage(pk, n, message);
                (bytes32 rec, uint64 idx) = signer.sign(r, next, message, sig);
                assertEq(rec, pk);
                assertEq(idx, n);

                assertEq(signer.getPublicKey(), next);
                assertEq(signer.isValidSignature(message, ""), IERC1271.isValidSignature.selector);
                assertEq(signer.isValidSignature(data, ""), ILegacyERC1271.isValidSignature.selector);
            }
        }
    }
}
