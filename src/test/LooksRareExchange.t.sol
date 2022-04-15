// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "ds-test/test.sol";

import {LooksRareExchange} from "../LooksRareExchange.sol";
import {CurrencyManager} from "../CurrencyManager.sol";
import {ExecutionManager} from "../ExecutionManager.sol";
import {RoyaltyFeeManager} from "../RoyaltyFeeManager.sol";
import {RoyaltyFeeRegistry} from "../RoyaltyFeeRegistry.sol";
import {StrategyStandardSaleForFixedPrice} from "../StrategyStandardSaleForFixedPrice.sol";
import {TransferSelectorNFT} from "../TransferSelectorNFT.sol";
import {TransferManagerERC721} from "../TransferManagerERC721.sol";
import {TransferManagerERC1155} from "../TransferManagerERC1155.sol";
import {OrderTypes} from "../libraries/OrderTypes.sol";

import {TestERC721} from "./utils/tokens/TestERC721.sol";
import {WETH} from "./utils/tokens/WETH.sol";
import {CheatCodes} from "./utils/CheatCodes.sol";

contract LooksRareExchangeTest is DSTest {
    address private seller;
    address private buyer;
    // @dev standard hardhat addresses
    address private constant protocolFeeRecipient =
        0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address private constant royaltyFeeReceiver =
        0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    // 5%
    uint256 private constant royaltyFeeLimit = 500;
    uint256 private constant minPercentageAsk = 9350;

    CurrencyManager private currencyManager;
    StrategyStandardSaleForFixedPrice private strategy;
    ExecutionManager private executionManager;
    RoyaltyFeeManager private royaltyFeeManager;
    RoyaltyFeeRegistry private royaltyFeeRegistry;
    LooksRareExchange private exchange;
    TransferManagerERC721 private transferManagerERC721;
    TransferManagerERC1155 private transferManagerERC1155;

    CheatCodes private cheats;

    TestERC721 private testErc721;
    WETH private weth;

    function setUp() public {
        weth = new WETH();

        currencyManager = new CurrencyManager();
        executionManager = new ExecutionManager();
        royaltyFeeRegistry = new RoyaltyFeeRegistry(royaltyFeeLimit);
        royaltyFeeManager = new RoyaltyFeeManager(address(royaltyFeeRegistry));
        exchange = new LooksRareExchange(
            address(currencyManager),
            address(executionManager),
            address(royaltyFeeManager),
            address(weth),
            protocolFeeRecipient
        );

        transferManagerERC721 = new TransferManagerERC721(address(exchange));
        transferManagerERC1155 = new TransferManagerERC1155(address(exchange));

        TransferSelectorNFT transferSelectorNFT = new TransferSelectorNFT(
            address(transferManagerERC721),
            address(transferManagerERC1155)
        );
        exchange.updateTransferSelectorNFT(address(transferSelectorNFT));

        // Support WETH
        currencyManager.addCurrency(address(weth));

        strategy = new StrategyStandardSaleForFixedPrice(500);
        executionManager.addStrategy(address(strategy));

        cheats = CheatCodes(HEVM_ADDRESS);

        seller = cheats.addr(1);
        buyer = cheats.addr(2);
        cheats.deal(buyer, 1 ether);
        cheats.prank(buyer);
        weth.deposit{value: 1 ether}();

        testErc721 = new TestERC721();
        testErc721.mint(seller, 0);

        // Set royalty for NFT
        // TODO: also test ERC-2981 in the future
        royaltyFeeRegistry.updateRoyaltyInfoForCollection(
            address(testErc721),
            address(this),
            royaltyFeeReceiver,
            150
        );
    }

    function makerOrderHash(OrderTypes.MakerOrder memory makerOrder)
        public
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    0x40261ade532fa1d2c7293df30aaadb9b3c616fae525a0b56d3d411c841a85028,
                    makerOrder.isOrderAsk,
                    makerOrder.signer,
                    makerOrder.collection,
                    makerOrder.price,
                    makerOrder.tokenId,
                    makerOrder.amount,
                    makerOrder.strategy,
                    makerOrder.currency,
                    makerOrder.nonce,
                    makerOrder.startTime,
                    makerOrder.endTime,
                    makerOrder.minPercentageToAsk,
                    keccak256(makerOrder.params)
                )
            );
    }

    function testMakerAsk() public {
        assertEq(testErc721.ownerOf(0), seller);
        assertEq(weth.balanceOf(seller), 0);
        assertEq(weth.balanceOf(buyer), 1 ether);
        assertEq(weth.balanceOf(protocolFeeRecipient), 0);
        assertEq(weth.balanceOf(royaltyFeeReceiver), 0);

        OrderTypes.MakerOrder memory makerAsk = OrderTypes.MakerOrder(
            true,
            seller,
            address(testErc721),
            1 ether,
            0,
            1,
            address(strategy),
            address(weth),
            0,
            block.timestamp,
            block.timestamp + 86400,
            minPercentageAsk,
            "",
            0,
            "",
            ""
        );
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                exchange.DOMAIN_SEPARATOR(),
                makerOrderHash(makerAsk)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = cheats.sign(1, digest);
        makerAsk.v = v;
        makerAsk.r = r;
        makerAsk.s = s;

        OrderTypes.TakerOrder memory takerBid = OrderTypes.TakerOrder(
            false,
            buyer,
            1 ether,
            0,
            minPercentageAsk,
            ""
        );

        cheats.prank(seller);
        testErc721.approve(address(transferManagerERC721), 0);

        cheats.startPrank(buyer);
        weth.approve(address(exchange), 1 ether);
        exchange.matchAskWithTakerBid(takerBid, makerAsk);
        cheats.stopPrank();

        assertEq(testErc721.ownerOf(0), buyer);
        assertEq(weth.balanceOf(seller), 0.935 ether);
        assertEq(weth.balanceOf(buyer), 0);
        assertEq(weth.balanceOf(protocolFeeRecipient), 0.05 ether);
        assertEq(weth.balanceOf(royaltyFeeReceiver), 0.015 ether);
    }
}