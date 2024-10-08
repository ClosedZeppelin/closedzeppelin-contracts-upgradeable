// SPDX-License-Identifier: MIT
// ClosedZeppelin Contracts (access/AccessControlUpgradeable.sol)

pragma solidity ^0.8.20;

import {IAccessControl} from "closedzeppelin-contracts/access/IAccessControl.sol";
import {ContextUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/ContextUpgradeable.sol";

contract AccessControlUpgradeable is ContextUpgradeable, IAccessControl {
    uint64 public constant DEFAULT_ADMIN_ROLE = 0x01;

    /// @custom:storage-location erc7201:closedzeppelin.storage.AccessControl
    struct AccessControlStorage {
        mapping(uint64 => uint64) _adminRoles;
        mapping(address => uint64) _members;
    }

    // keccak256(abi.encode(uint256(keccak256("closedzeppelin.storage.AccessControl")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant AccessControlStorageLocation =
        0x9e0c04d0e65cfbca09c5de6cfa0b9ca4ec2195d5907319b28da0d61b12773a00;

    function _getAccessControlStorage() private pure returns (AccessControlStorage storage $) {
        assembly {
            $.slot := AccessControlStorageLocation
        }
    }

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with a standardized message including the required role.
     *
     * The format of the revert reason is given by the following regular expression:
     *
     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/
     *
     * _Available since v4.1._
     */
    modifier onlyRole(uint64 role) {
        _checkRole(role);
        _;
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(
        uint64 role,
        address account
    ) public view virtual override returns (bool) {
        return _getAccessControlStorage()._members[account] & role > 0;
    }

    /**
     * @dev Revert with a standard message if `_msgSender()` is missing `role`.
     * Overriding this function changes the behavior of the {onlyRole} modifier.
     *
     * Format of the revert message is described in {_checkRole}.
     *
     * _Available since v4.6._
     */
    function _checkRole(uint64 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Revert with a standard message if `account` is missing `role`.
     *
     * The format of the revert reason is given by the following regular expression:
     *
     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/
     */
    function _checkRole(uint64 role, address account) internal view virtual {
        require(
            hasRole(role, account),
            "AccessControl: account is missing role"
        );
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(
        uint64 role
    ) public view virtual override returns (uint64) {
        return _getAccessControlStorage()._adminRoles[role];
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(
        uint64 role,
        address account
    ) public virtual override onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(
        uint64 role,
        address account
    ) public virtual override onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `account`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(
        uint64 role,
        address account
    ) public virtual override {
        require(
            account == _msgSender(),
            "AccessControl: can only renounce roles for self"
        );

        _revokeRole(role, account);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(uint64 role, uint64 adminRole) internal virtual {
        uint64 previousAdminRole = getRoleAdmin(role);
        _getAccessControlStorage()._adminRoles[role] = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(uint64 role, address account) internal virtual {
        _getAccessControlStorage()._members[account] |= role;
        emit RoleGranted(role, account, _msgSender());
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(uint64 role, address account) internal virtual {
        _getAccessControlStorage()._members[account] ^= role;
        emit RoleRevoked(role, account, _msgSender());
    }
}
