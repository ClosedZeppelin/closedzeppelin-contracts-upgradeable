// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {console2} from "forge-std/console2.sol";

contract StorageLocation {
    function run() external pure {
        console2.log("AccessControl");
        console2.logBytes32(
            keccak256(
                abi.encode(
                    uint256(keccak256("closedzeppelin.storage.AccessControl")) -
                        1
                )
            ) & ~bytes32(uint256(0xff))
        );
    }
}
