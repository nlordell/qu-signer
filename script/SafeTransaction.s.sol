// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

import {Script, console} from "@forge-std/Script.sol";
import {QuSigner} from "@/QuSigner.sol";
import {Address} from "@/libraries/Address.sol";
import {WOTSp} from "@/libraries/WOTSp.sol";
import {ISafe, ISafeProxyFactory, IMultiSend} from "@script/util/ISafe.sol";

contract SafeTransactionScript is Script {
    using WOTSp for WOTSp.Context;

    function args() public view returns (string memory password, uint256 w, bytes32 seed) {
        password = vm.envString("QUSIGNER_PASSWORD");
        w = vm.envOr("QUSIGNER_W", uint256(16));
        seed = vm.envOr("QUSIGNER_SEED", keccak256(abi.encodePacked("seed:", password)));
    }

    function run() public {
        (string memory password, uint256 w, bytes32 seed) = args();

        // This key derivation is UNSAFE and included only as an example.
        bytes32 sk = keccak256(abi.encodePacked("password:", password));
        WOTSp.Context memory wots = WOTSp.Context({w: w, seed: seed, adrs: Address.zero()});

        QuSigner signer;
        {
            signer = QuSigner(
                vm.computeCreate2Address(
                    bytes32(0),
                    keccak256(abi.encodePacked(type(QuSigner).creationCode, w, seed, wots.pubkey(sk))),
                    0x4e59b44847b379578588920cA78FbF26c0B4956C
                )
            );
            if (address(signer).code.length == 0) {
                bytes32 publicKey = wots.pubkey(sk);
                vm.broadcast();
                new QuSigner{salt: bytes32(0)}(w, seed, publicKey);
            }
        }

        ISafe safe;
        {
            ISafeProxyFactory factory = ISafeProxyFactory(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67);
            ISafe singleton = ISafe(0x29fcB43b46531BcA003ddC8FCB67FFE91900C762);

            address[] memory owners = new address[](1);
            owners[0] = address(signer);
            bytes memory setup =
                abi.encodeCall(ISafe.setup, (owners, 1, address(0), "", address(0), address(0), 0, address(0)));

            safe = ISafe(
                vm.computeCreate2Address(
                    keccak256(abi.encodePacked(keccak256(setup), uint256(0))),
                    keccak256(abi.encodePacked(factory.proxyCreationCode(), abi.encode(singleton))),
                    address(factory)
                )
            );
            if (address(safe).code.length == 0) {
                vm.broadcast();
                factory.createProxyWithNonce(address(singleton), setup, 0);
            }
        }

        bytes32 safeTxHash = safe.getTransactionHash(
            address(safe), 0, "", ISafe.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        bytes memory signCallData;
        {
            bytes32 randomness = bytes32(vm.randomUint());
            uint64 signatureIndex = signer.getSignatureCount();
            wots.adrs = Address.make(0, signatureIndex + 1);
            bytes32 nextPublicKey = wots.pubkey(sk);
            wots.adrs = Address.make(0, signatureIndex);
            bytes32[] memory signature =
                wots.sign(sk, signer.getSigningMessage(randomness, nextPublicKey, signatureIndex, safeTxHash));
            signCallData = abi.encodeCall(signer.sign, (randomness, nextPublicKey, safeTxHash, signature));
        }
        bytes memory execCallData = abi.encodeCall(
            safe.execTransaction,
            (
                address(safe),
                0,
                "",
                ISafe.Operation.Call,
                0,
                0,
                0,
                address(0),
                address(0),
                abi.encodePacked(uint256(uint160(address(signer))), uint256(65), uint8(0), uint256(0))
            )
        );

        bytes memory transactions = abi.encodePacked(
            // signer.sign(...)
            ISafe.Operation.Call,
            signer,
            uint256(0),
            signCallData.length,
            signCallData,
            // safe.execTransaction(...)
            ISafe.Operation.Call,
            safe,
            uint256(0),
            execCallData.length,
            execCallData
        );

        vm.broadcast();
        IMultiSend(0x9641d764fc13c8B624c04430C7356C1C7C8102e2).multiSend(transactions);

        console.log("using signer:         ", address(signer));
        console.log("using safe:           ", address(safe));
        console.log("executing transaction:", vm.toString(safeTxHash));
    }
}
