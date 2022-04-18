// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import "ds-test/test.sol";

import {LooksRareExchange} from "../LooksRareExchange.sol";
import {CurrencyManager} from "../CurrencyManager.sol";
import {ExecutionManager} from "../ExecutionManager.sol";
import {RoyaltyFeeManager} from "../RoyaltyFeeManager.sol";
import {RoyaltyFeeRegistry} from "../RoyaltyFeeRegistry.sol";
import {StrategyAnyItemFromCollectionForFixedPrice} from "../StrategyAnyItemFromCollectionForFixedPrice.sol";
import {TransferSelectorNFT} from "../TransferSelectorNFT.sol";
import {TransferManagerERC721} from "../TransferManagerERC721.sol";
import {TransferManagerERC1155} from "../TransferManagerERC1155.sol";
import {OrderTypes} from "../libraries/OrderTypes.sol";

import {TestERC721} from "./utils/tokens/TestERC721.sol";
import {WETH} from "./utils/tokens/WETH.sol";
import {CheatCodes} from "./utils/CheatCodes.sol";

contract LooksRareExchangeStrategyAnyItemFromCollectionForFixedPriceTest is
    DSTest
{
    address private seller;
    address private buyer;
    // @dev standard hardhat addresses
    address private constant protocolFeeRecipient =
        0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address private constant royaltyFeeReceiver =
        0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    // 5%
    uint256 private constant royaltyFeeLimit = 500;
    uint256 private constant minPercentageToAsk = 9350;

    CurrencyManager private currencyManager;
    StrategyAnyItemFromCollectionForFixedPrice private strategy;
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

        strategy = new StrategyAnyItemFromCollectionForFixedPrice(500);
        executionManager.addStrategy(address(strategy));

        cheats = CheatCodes(HEVM_ADDRESS);

        seller = cheats.addr(1);
        buyer = cheats.addr(2);

        cheats.deal(buyer, 1 ether);
        cheats.startPrank(buyer);
        weth.deposit{value: 1 ether}();
        weth.approve(address(exchange), 1 ether);
        cheats.stopPrank();

        testErc721 = new TestERC721();
        testErc721.mint(seller, 0);
        testErc721.mint(seller, 1);

        // Set royalty for NFT
        // TODO: also test ERC-2981 in the future
        royaltyFeeRegistry.updateRoyaltyInfoForCollection(
            address(testErc721),
            address(this),
            royaltyFeeReceiver,
            150
        );

        cheats.prank(seller);
        // NOTE: bid token ID is 0, match with token ID 1 only to verify
        // that any token ID in the collection can match with the bid
        testErc721.approve(address(transferManagerERC721), 1);
    }

    function makerOrderStruct(bool isOrderAsk, address signer)
        private
        returns (OrderTypes.MakerOrder memory makerOrder)
    {
        makerOrder = OrderTypes.MakerOrder(
            isOrderAsk,
            signer,
            address(testErc721),
            1 ether,
            0,
            1,
            address(strategy),
            address(weth),
            0,
            block.timestamp,
            block.timestamp + 86400,
            minPercentageToAsk,
            "",
            0,
            "",
            ""
        );
    }

    function takerOrderStruct(bool isOrderAsk, address signer)
        private
        returns (OrderTypes.TakerOrder memory takerOrder)
    {
        takerOrder = OrderTypes.TakerOrder(
            isOrderAsk,
            signer,
            1 ether,
            1,
            minPercentageToAsk,
            ""
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

    function signOrder(
        OrderTypes.MakerOrder memory makerOrder,
        uint256 privateKey
    ) private {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                exchange.DOMAIN_SEPARATOR(),
                makerOrderHash(makerOrder)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = cheats.sign(privateKey, digest);
        makerOrder.v = v;
        makerOrder.r = r;
        makerOrder.s = s;
    }

    function invalidDomainSeparator() private returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                    0xda9101ba92939daf4bb2e18cd5f942363b9297fbc3232c9dd964abb1fb70ed71,
                    0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6,
                    80001, // invalid chain ID
                    address(exchange)
                )
            );
    }

    function initialAssertions() private {
        assertEq(testErc721.ownerOf(0), seller);
        assertEq(testErc721.ownerOf(1), seller);
        assertEq(weth.balanceOf(seller), 0);
        assertEq(weth.balanceOf(buyer), 1 ether);
        assertEq(weth.balanceOf(protocolFeeRecipient), 0);
        assertEq(weth.balanceOf(royaltyFeeReceiver), 0);
    }

    function noChangeAssertions() private {
        initialAssertions();
    }

    function assetsChangedHandsAssertions() private {
        assertEq(testErc721.ownerOf(0), seller);
        assertEq(testErc721.ownerOf(1), buyer);
        assertEq(weth.balanceOf(seller), 0.935 ether);
        assertEq(weth.balanceOf(buyer), 0);
        assertEq(weth.balanceOf(protocolFeeRecipient), 0.05 ether);
        assertEq(weth.balanceOf(royaltyFeeReceiver), 0.015 ether);
    }

    function testTakerAskSuccess() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        signOrder(makerBid, 2);

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);

        cheats.prank(seller);
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        assetsChangedHandsAssertions();
    }

    function testTakerAskCancelled() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        signOrder(makerBid, 2);

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);

        cheats.prank(buyer);
        uint256[] memory orderNonces = new uint256[](1);
        orderNonces[0] = 0;
        exchange.cancelMultipleMakerOrders(orderNonces);

        cheats.prank(seller);
        cheats.expectRevert(bytes("Order: Matching order expired"));
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        noChangeAssertions();
    }

    function testTakerAskExpired() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        signOrder(makerBid, 2);

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);

        cheats.warp(block.timestamp + 86401);

        cheats.prank(seller);
        cheats.expectRevert(bytes("Strategy: Execution invalid"));
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        noChangeAssertions();
    }

    function testTakerAskNotStarted() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        makerBid.startTime = block.timestamp + 1;
        signOrder(makerBid, 2);

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);

        cheats.prank(seller);
        cheats.expectRevert(bytes("Strategy: Execution invalid"));
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        noChangeAssertions();
    }

    function testTakerAskBidTooLow() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        signOrder(makerBid, 2);

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);
        takerAsk.price = 0.99 ether;

        cheats.prank(seller);
        cheats.expectRevert(bytes("Strategy: Execution invalid"));
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        noChangeAssertions();
    }

    function testTakerAsk0Signer() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        makerBid.signer = address(0);
        signOrder(makerBid, 2);

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);

        cheats.prank(seller);
        cheats.expectRevert(bytes("Order: Invalid signer"));
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        noChangeAssertions();
    }

    function testTakerAskInvalidSignature() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                invalidDomainSeparator(),
                makerOrderHash(makerBid)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = cheats.sign(2, digest);
        makerBid.v = v;
        makerBid.r = r;
        makerBid.s = s;

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);

        cheats.prank(seller);
        cheats.expectRevert(bytes("Signature: Invalid"));
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        noChangeAssertions();
    }

    function testTakerAsk0Amount() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        makerBid.amount = 0;
        signOrder(makerBid, 2);

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);

        cheats.prank(seller);
        cheats.expectRevert(bytes("Order: Amount cannot be 0"));
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        noChangeAssertions();
    }

    function testTakerAskFeesHigherThanExpected() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        signOrder(makerBid, 2);

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);
        takerAsk.minPercentageToAsk = 9500;

        cheats.prank(seller);
        cheats.expectRevert(bytes("Fees: Higher than expected"));
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        noChangeAssertions();
    }

    function testTakerAskInvalidTaker() public {
        initialAssertions();

        OrderTypes.MakerOrder memory makerBid = makerOrderStruct(false, buyer);
        signOrder(makerBid, 2);

        OrderTypes.TakerOrder memory takerAsk = takerOrderStruct(true, seller);

        cheats.prank(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
        cheats.expectRevert(bytes("Order: Taker must be the sender"));
        exchange.matchBidWithTakerAsk(takerAsk, makerBid);

        noChangeAssertions();
    }
}
