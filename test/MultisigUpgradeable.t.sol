// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./mocks/MultisigUpgradeableMock.sol";

contract MultisigUpgradeableTest is Test {
    MultisigUpgradeableMock multisig;

    function setUp() public {
        multisig = new MultisigUpgradeableMock();
        multisig.__MultisigUpgradeableMock_init();
    }

    /**
     * MultisigUpgradeableMock.checkSigners
     */

    function test_RevertWhen_DeadlineExceeded() public {
        vm.expectRevert("Multisig: execution expired");

        // set block.timestamp to 100
        vm.warp(100);
        uint256 deadline = block.timestamp - 1;

        multisig.execute(bytes(""), deadline, new bytes[](0));
    }

    function test_RevertWhen_SignersNotSorted() public {
        (address signer0, uint256 signer0Pk) = makeAddrAndKey("signer0");
        (address signer1, uint256 signer1Pk) = makeAddrAndKey("signer1");

        assertTrue(signer0 < signer1);

        bytes memory execution = abi.encodeWithSelector(
            MultisigUpgradeableMock.checkSigners.selector,
            signer0,
            signer1
        );
        uint256 deadline = block.timestamp + 100;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = sign(
            signer1Pk,
            multisig.digest(deadline, execution, address(1))
        );
        signatures[1] = sign(
            signer0Pk,
            multisig.digest(deadline, execution, address(1))
        );

        vm.expectRevert("Multisig: unsorted signers");
        vm.prank(address(1));
        multisig.execute(execution, deadline, signatures);
    }

    function test_RevertWhen_MethodCalledDirectly() public {
        vm.expectRevert("Multisig: required");

        multisig.checkSigners(address(0), address(1));
    }

    function test_RevertWhen_MethodCalledWithoutEnoughSignatures() public {
        vm.expectRevert("Multisig: not enough signers");

        bytes memory execution = abi.encodeWithSelector(
            MultisigUpgradeableMock.checkSigners.selector,
            address(0),
            address(1)
        );
        uint256 deadline = block.timestamp + 100;

        multisig.execute(execution, deadline, new bytes[](0));
    }

    function test_ChecksSigners() public {
        (address signer0, uint256 signer0Pk) = makeAddrAndKey("signer0");
        (address signer1, uint256 signer1Pk) = makeAddrAndKey("signer1");

        assertTrue(signer0 < signer1);

        bytes memory execution = abi.encodeWithSelector(
            MultisigUpgradeableMock.checkSigners.selector,
            signer0,
            signer1
        );
        uint256 deadline = block.timestamp + 100;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = sign(
            signer0Pk,
            multisig.digest(deadline, execution, address(1))
        );
        signatures[1] = sign(
            signer1Pk,
            multisig.digest(deadline, execution, address(1))
        );

        vm.prank(address(1));
        bytes memory value = multisig.execute(execution, deadline, signatures);

        assertTrue(abi.decode(value, (bool)));
    }

    /**
     * MultisigUpgradeableMock.checkExecutor
     */

    function test_RevertWhen_MethodCalledThroughExecute() public {
        vm.expectRevert("Multisig: disabled");

        bytes memory execution = abi.encodeWithSelector(
            MultisigUpgradeableMock.checkExecutor.selector,
            address(0)
        );
        uint256 deadline = block.timestamp + 100;

        multisig.execute(execution, deadline, new bytes[](0));
    }

    function test_ChecksExecutor() public view {
        bool result = multisig.checkExecutor(address(this));
        assertTrue(result);
    }

    function sign(
        uint256 signer,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer, digest);
        return abi.encodePacked(r, s, v);
    }
}
