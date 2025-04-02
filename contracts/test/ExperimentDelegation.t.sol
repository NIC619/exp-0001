// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {ExperimentDelegation} from "../src/ExperimentDelegation.sol";
import {P256} from "../src/utils/P256.sol";
import {ECDSA} from "../src/utils/ECDSA.sol";

contract Callee {
    error UnexpectedSender(address expected, address actual);

    mapping(address => uint256) public counter;
    mapping(address => uint256) public values;

    function increment() public payable {
        counter[msg.sender] += 1;
        values[msg.sender] += msg.value;
    }

    function expectSender(address expected) public payable {
        if (msg.sender != expected) {
            revert UnexpectedSender(expected, msg.sender);
        }
    }
}

contract ExperimentDelegationTest is Test {
    ExperimentDelegation public delegator;
    uint256 public eoaPrivateKey = 123;
    address public eoa = vm.rememberKey(eoaPrivateKey);
    uint256 public p256PrivateKey;
    Callee public callee;

    function setUp() public {
        callee = new Callee();
        ExperimentDelegation delegationImplementation = new ExperimentDelegation();

        vm.signAndAttachDelegation(address(delegationImplementation), eoaPrivateKey);
        bytes memory eoaCode = address(eoa).code;
        console2.logBytes(eoaCode);
        delegator = ExperimentDelegation(payable(eoa));

        p256PrivateKey = 100366595829038452957523597440756290436854445761208339940577349703440345778405;
        vm.deal(address(delegator), 1.5 ether);
    }

    function test_authorize() public {
        vm.pauseGasMetering();

        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);
        ECDSA.PublicKey memory publicKey = ECDSA.PublicKey(x, y);

        vm.expectRevert();
        delegator.keys(0);

        vm.prank(address(delegator));
        vm.resumeGasMetering();
        delegator.authorize(publicKey, 0);
        vm.pauseGasMetering();

        (
            bool authorized,
            uint256 expiry,
            ECDSA.PublicKey memory authorizedPublicKey
        ) = delegator.keys(0);
        assertEq(authorized, true);
        assertEq(authorizedPublicKey.x, x);
        assertEq(authorizedPublicKey.y, y);
        assertEq(expiry, 0);
    }

    function test_authorize_with_signature() public {
        vm.pauseGasMetering();

        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);
        ECDSA.PublicKey memory publicKey = ECDSA.PublicKey(x, y);

        vm.expectRevert();
        delegator.keys(0);

        uint256 expiry = 0;
        uint256 nonce = delegator.nonce();
        bytes32 digest = keccak256(
            abi.encodePacked(nonce, publicKey.x, publicKey.y, expiry)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaPrivateKey, digest);

        vm.resumeGasMetering();
        delegator.authorize(publicKey, expiry, ECDSA.RecoveredSignature(uint256(r), uint256(s), v == 27 ? 0 : 1));
        vm.pauseGasMetering();

        (
            bool authorized,
            uint256 _expiry,
            ECDSA.PublicKey memory authorizedPublicKey
        ) = delegator.keys(0);
        assertEq(authorized, true);
        assertEq(authorizedPublicKey.x, x);
        assertEq(authorizedPublicKey.y, y);
        assertEq(_expiry, expiry);
    }

    function test_authorize_revertInvalidAuthority() public {
        vm.pauseGasMetering();
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);
        ECDSA.PublicKey memory publicKey = ECDSA.PublicKey(x, y);

        vm.expectRevert();
        delegator.keys(0);

        vm.resumeGasMetering();
        vm.expectRevert(ExperimentDelegation.InvalidAuthority.selector);
        delegator.authorize(publicKey, 0);
    }

    function test_revoke() public {
        vm.pauseGasMetering();

        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);
        ECDSA.PublicKey memory publicKey = ECDSA.PublicKey(x, y);

        vm.prank(address(delegator));
        delegator.authorize(publicKey, 0);

        delegator.keys(0);

        vm.prank(address(delegator));
        vm.resumeGasMetering();
        delegator.revoke(0);
        vm.pauseGasMetering();

        (
            bool authorized,
            uint256 expiry,
            ECDSA.PublicKey memory authorizedPublicKey
        ) = delegator.keys(0);
        assertEq(authorized, false);
    }

    function test_execute() public {
        vm.pauseGasMetering();

        assertEq(address(delegator).balance, 1.5 ether);
        assertEq(address(callee).balance, 0 ether);

        bytes memory data = abi.encodeWithSelector(Callee.increment.selector);
        bytes memory calls;
        calls = abi.encodePacked(
            uint8(0),
            address(callee),
            uint256(0.5 ether),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            uint8(0),
            address(callee),
            uint256(0.5 ether),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            uint8(0),
            address(callee),
            uint256(0.5 ether),
            data.length,
            data
        );

        bytes32 hash = keccak256(
            abi.encodePacked(delegator.nonce(), calls)
        );
        (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, hash);
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);

        vm.prank(address(delegator));
        delegator.authorize(
            ECDSA.PublicKey(x, y),
            0
        );

        vm.resumeGasMetering();
        delegator.execute(
            calls,
            ECDSA.Signature(uint256(r), uint256(s)),
            0,
            false
        );
        vm.pauseGasMetering();

        assertEq(callee.counter(address(delegator)), 3);
        assertEq(callee.values(address(delegator)), 1.5 ether);
        assertEq(address(delegator).balance, 0 ether);
        assertEq(address(callee).balance, 1.5 ether);
    }

    function test_execute_revertRevoke() public {
        vm.pauseGasMetering();

        bytes memory data = abi.encodeWithSelector(Callee.increment.selector);
        bytes memory calls;
        calls = abi.encodePacked(
            uint8(0),
            address(callee),
            uint256(0),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            uint8(0),
            address(callee),
            uint256(0),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            uint8(0),
            address(callee),
            uint256(0),
            data.length,
            data
        );

        bytes32 hash = keccak256(
            abi.encodePacked(delegator.nonce(), calls)
        );
        (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, hash);
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);

        vm.prank(address(delegator));
        delegator.authorize(
            ECDSA.PublicKey(x, y),
            0
        );

        vm.prank(address(delegator));
        vm.resumeGasMetering();
        delegator.revoke(0);
        vm.pauseGasMetering();

        vm.expectRevert(ExperimentDelegation.KeyNotAuthorized.selector);
        delegator.execute(
            calls,
            ECDSA.Signature(uint256(r), uint256(s)),
            0,
            false
        );
    }

    function test_execute_revertExpired() public {
        vm.pauseGasMetering();

        bytes memory data = abi.encodeWithSelector(Callee.increment.selector);
        bytes memory calls;
        calls = abi.encodePacked(
            uint8(0),
            address(callee),
            uint256(0),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            uint8(0),
            address(callee),
            uint256(0),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            uint8(0),
            address(callee),
            uint256(0),
            data.length,
            data
        );

        bytes32 hash = keccak256(
            abi.encodePacked(delegator.nonce(), calls)
        );
        (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, hash);
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);

        vm.prank(address(delegator));
        delegator.authorize(
            ECDSA.PublicKey(x, y),
            block.timestamp
        );

        vm.warp(block.timestamp + 1);

        vm.expectRevert(ExperimentDelegation.KeyExpired.selector);
        delegator.execute(
            calls,
            ECDSA.Signature(uint256(r), uint256(s)),
            0,
            false
        );
    }

    function test_revertReplay() public {
        vm.pauseGasMetering();

        bytes memory data = abi.encodeWithSelector(Callee.increment.selector);
        bytes memory calls;
        calls = abi.encodePacked(
            uint8(0),
            address(callee),
            uint256(0),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            uint8(0),
            address(callee),
            uint256(0),
            data.length,
            data
        );
        calls = abi.encodePacked(
            calls,
            uint8(0),
            address(callee),
            uint256(0),
            data.length,
            data
        );

        bytes32 hash = keccak256(
            abi.encodePacked(delegator.nonce(), calls)
        );
        (bytes32 r, bytes32 s) = vm.signP256(p256PrivateKey, hash);
        (uint256 x, uint256 y) = vm.publicKeyP256(p256PrivateKey);

        vm.prank(address(delegator));
        delegator.authorize(
            ECDSA.PublicKey(x, y),
            0
        );

        vm.resumeGasMetering();
        delegator.execute(
            calls,
            ECDSA.Signature(uint256(r), uint256(s)),
            0,
            false
        );
        vm.pauseGasMetering();

        vm.expectRevert(ExperimentDelegation.InvalidSignature.selector);
        delegator.execute(
            calls,
            ECDSA.Signature(uint256(r), uint256(s)),
            0,
            false
        );
    }
}
