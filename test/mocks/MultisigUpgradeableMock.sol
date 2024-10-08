// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../contracts/utils/MultisigUpgradeable.sol";

contract MultisigUpgradeableMock is MultisigUpgradeable {
    function __MultisigUpgradeableMock_init() external initializer {
        __MultisigUpgradeable_init("MultisigUpgradeableMock");
    }

    function checkSigners(
        address signer0,
        address signer1
    ) public view requireSignatures(2) returns (bool) {
        return signers(0) == signer0 && signers(1) == signer1;
    }

    function checkExecutor(
        address executor
    ) external view disableMultisig returns (bool) {
        return executor == _msgSender();
    }

    function digest(
        uint256 deadline,
        bytes memory execution,
        address executor
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                _EXECUTION_TYPEHASH,
                keccak256(execution),
                executor,
                nonces(executor),
                deadline
            )
        );

        return _hashTypedDataV4(structHash);
    }
}
