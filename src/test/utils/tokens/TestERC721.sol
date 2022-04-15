// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title TestERC721
/// @notice FOR TEST PURPOSES ONLY.
contract TestERC721 is ERC721, Ownable {
    constructor() ERC721("TestERC721", "TEST") {}

    function mint(address to, uint256 tokenId) public {
        _safeMint(to, tokenId);
    }
}
