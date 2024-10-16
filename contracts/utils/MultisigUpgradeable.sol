// SPDX-License-Identifier: MIT
// ClosedZeppelin Contracts (utils/MultisigUpgradeable.sol)

pragma solidity ^0.8.20;

import "openzeppelin-contracts/contracts/utils/Address.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts-upgradeable/contracts/utils/ContextUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/contracts/utils/NoncesUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";

abstract contract MultisigUpgradeable is
    ContextUpgradeable,
    EIP712Upgradeable,
    NoncesUpgradeable,
    ReentrancyGuardUpgradeable
{
    bytes32 internal immutable _EXECUTION_TYPEHASH =
        keccak256(
            "Execute(bytes32 call,address sender,uint256 nonce,uint256 deadline)"
        );

    /**
     * @dev Signers accessibility to allow contracts called by using multisig to perform data checks
     *      The data is cleaned after the execution to prevent reentrancy and to receive gas refunds
     */
    address[] private _signers;

    /**
     * @dev Modifier that requires a certain number of signatures to have been provided.
     *      This modifier can only be used within the context of a multisig call.
     * @param min The minimum number of signatures required.
     */
    modifier requireSignatures(uint256 min) {
        require(_reentrancyGuardEntered(), "Multisig: required");
        require(_signers.length >= min, "Multisig: not enough signers");
        _;
    }

    /**
     * @dev Modifier to disable multisig execution for a function.
     */
    modifier disableMultisig() {
        require(!_reentrancyGuardEntered(), "Multisig: disabled");
        _;
    }

    /**
     * @dev Constructor function that sets up the EIP712 version.
     * @param name The name of the contract.
     */
    function __Multisig_init(string memory name) internal onlyInitializing {
        __EIP712_init(name, "1");
    }

    /**
     * @dev Executes a multisig operation.
     * @param execution The execution data to be executed.
     * @param deadline The deadline by which the operation must be executed.
     * @param signatures The signatures authorizing the operation.
     * @return The result of the execution.
     */
    function execute(
        bytes calldata execution,
        uint256 deadline,
        bytes[] memory signatures
    ) public nonReentrant cleanSigners returns (bytes memory) {
        require(block.timestamp <= deadline, "Multisig: execution expired");

        bytes32 structHash = keccak256(
            abi.encode(
                _EXECUTION_TYPEHASH,
                keccak256(execution),
                _msgSender(),
                _useNonce(_msgSender()),
                deadline
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);

        _signers = new address[](signatures.length);
        for (uint256 i = 0; i < _signers.length; i++) {
            _signers[i] = ECDSA.recover(digest, signatures[i]);
            require(
                i == 0 || _signers[i - 1] < _signers[i],
                "Multisig: unsorted signers"
            ); // avoid repeated signatures
        }

        return Address.functionDelegateCall(address(this), execution);
    }

    /**
     * @dev Internal function that returns an array of addresses representing the signers of the multisig.
     * @return address[] representing the signers.
     */
    function signers() internal view returns (address[] memory) {
        return _signers;
    }

    /**
     * @dev Internal function that returns the address of a signer in the multisig at a specific index.
     * @param index uint256 representing the index of the signer to retrieve.
     * @return address representing the signer at the given index.
     */
    function signers(uint256 index) internal view returns (address) {
        return _signers[index];
    }

    /**
     * @dev Modifier to clean the signers array after the function is executed.
     */
    modifier cleanSigners() {
        _;
        delete _signers;
    }
}
