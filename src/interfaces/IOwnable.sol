// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IOwnable {
    function admin() external view returns (address);

    function owner() external view returns (address);

    function transferOwnership(address newOwner) external;
}
