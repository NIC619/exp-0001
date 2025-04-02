// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import { console } from "forge-std/console.sol";
import { Script } from "forge-std/Script.sol";

import { ExperimentDelegation } from "../src/ExperimentDelegation.sol";
import { ECDSA } from "../src/utils/ECDSA.sol";

import { Callee } from "../test/ExperimentDelegation.t.sol";

contract DemoSepolia is Script {
    uint256 eoaPrivateKey = 55667788;
    address eoa = vm.rememberKey(eoaPrivateKey);

    function run() external {
        require(eoa != address(0), "EOA private key is not provided");
        console.log("EOA:", eoa);

        vm.startBroadcast(eoa);

        // 1. Deploy or get deployed delegation implementation
        ExperimentDelegation delegationImplementation = new ExperimentDelegation();
        // ExperimentDelegation delegationImplementation = ExperimentDelegation(payable(0x30A83F5e57Fa28a89b559850E586e08549eCbBc1));

        // 2. Sign and attach delegation
        vm.signAndAttachDelegation(address(delegationImplementation), eoaPrivateKey);
        bytes memory eoaCode = address(eoa).code;
        console.logBytes(eoaCode);
        ExperimentDelegation delegator = ExperimentDelegation(payable(eoa));

        // 3. Authorize a new P256 key
        uint256 p256PrivateKey = 100366595829038452957523597440756290436854445761208339940577349703440345778405;
        {
            (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);
            ECDSA.PublicKey memory publicKey = ECDSA.PublicKey(x, y);

            uint256 expiry = 0;
            uint256 nonce = delegator.nonce();
            bytes32 digest = keccak256(
                abi.encodePacked(nonce, publicKey.x, publicKey.y, expiry)
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaPrivateKey, digest);
            delegator.authorize(publicKey, expiry, ECDSA.RecoveredSignature(uint256(r), uint256(s), v == 27 ? 0 : 1));
        }

        (
            bool authorized,
            uint256 _expiry,
            ECDSA.PublicKey memory authorizedPublicKey
        ) = delegator.keys(0);
        console.log(authorized);
        console.log(authorizedPublicKey.x);
        console.log(authorizedPublicKey.y);
        console.log(_expiry);

        // 4. Execute a batch of calls
        {
            Callee callee = Callee(0x30A83F5e57Fa28a89b559850E586e08549eCbBc1);
            bytes memory data = abi.encodeWithSelector(Callee.increment.selector);
            bytes memory calls;
            calls = abi.encodePacked(
                uint8(0),
                address(callee),
                uint256(0.001 ether),
                data.length,
                data
            );
            calls = abi.encodePacked(
                calls,
                uint8(0),
                address(callee),
                uint256(0.001 ether),
                data.length,
                data
            );
            calls = abi.encodePacked(
                calls,
                uint8(0),
                address(callee),
                uint256(0.001 ether),
                data.length,
                data
            );

            bytes32 hash = keccak256(
                abi.encodePacked(delegator.nonce(), calls)
            );
            (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, hash);

            delegator.execute(
                calls,
                ECDSA.Signature(uint256(r), uint256(s)),
                0,
                false
            );
        }

        vm.stopBroadcast();
    }
}
