// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.34;

import {Script, console} from "@forge-std/Script.sol";
import {QuSigner} from "@/QuSigner.sol";
import {ISafe, ISafeProxyFactory, IMultiSend} from "@script/util/ISafe.sol";
import {Lamport} from "@test/util/Lamport.sol";

contract SafeTransactionScript is Script {
    using Lamport for Lamport.Key;

    function args() public view returns (string memory password, uint256 sequence) {
        password = vm.envString("PASSWORD");
        sequence = vm.envUint("SEQUENCE");
    }

    function run() public {
        (string memory password, uint256 sequence) = args();

        Lamport.Key key = Lamport.fromPassword(password);

        QuSigner signer;
        {
            signer = QuSigner(
                vm.computeCreate2Address(
                    bytes32(0),
                    keccak256(abi.encodePacked(type(QuSigner).creationCode, key.publicKeyDigest(0))),
                    0x4e59b44847b379578588920cA78FbF26c0B4956C
                )
            );
            if (address(signer).code.length == 0) {
                vm.broadcast();
                new QuSigner{salt: bytes32(0)}(key.publicKeyDigest(0));
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
        (bytes32 next, bytes memory signature) = key.sign(sequence, safeTxHash);
        bytes memory signatures = abi.encodePacked(uint256(uint160(address(signer))), uint256(65), uint8(0), uint256(0));

        bytes memory transactions;
        {
            bytes memory signCallData = abi.encodeCall(signer.sign, (safeTxHash, next, signature));
            bytes memory execCallData = abi.encodeCall(
                safe.execTransaction,
                (address(safe), 0, "", ISafe.Operation.Call, 0, 0, 0, address(0), address(0), signatures)
            );
            transactions = abi.encodePacked(
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
        }

        vm.broadcast();
        IMultiSend(0x9641d764fc13c8B624c04430C7356C1C7C8102e2).multiSend(transactions);

        console.log("using signer:         ", address(signer));
        console.log("using safe:           ", address(safe));
        console.log("executing transaction:", vm.toString(safeTxHash));
    }
}
