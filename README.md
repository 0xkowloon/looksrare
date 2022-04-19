## Basic introduction

### Creating a maker ask

In order to sell an NFT, an NFT owner has to do 2 things. First, approve LooksRare’s `TransferManagerERC721` to be the NFT’s operator so that it can transfer the NFT to the buyer when an order is matched. The transfer manager allows the seller to only approve once per NFT on LooksRare. Second, sign a `MakerOrder` that can later be submitted on chain by the buyer to match with his bid.

```solidity
struct MakerOrder {
    bool isOrderAsk; // true --> ask / false --> bid
    address signer; // signer of the maker order
    address collection; // collection address
    uint256 price; // price (used as )
    uint256 tokenId; // id of the token
    uint256 amount; // amount of tokens to sell/purchase (must be 1 for ERC721, 1+ for ERC1155)
    address strategy; // strategy for trade execution (e.g., DutchAuction, StandardSaleForFixedPrice)
    address currency; // currency (e.g., WETH)
    uint256 nonce; // order nonce (must be unique unless new maker order is meant to override existing one e.g., lower ask price)
    uint256 startTime; // startTime in timestamp
    uint256 endTime; // endTime in timestamp
    uint256 minPercentageToAsk; // slippage protection (9000 --> 90% of the final price must return to ask)
    bytes params; // additional parameters
    uint8 v; // v: parameter (27 or 28)
    bytes32 r; // r: parameter
    bytes32 s; // s: parameter
}
```

There are currently 3 order matching strategies (fixed price on specific token IDs, bidding on the whole collection, selling to a specific address), each of which is its own contract. v (recovery identifier), r and s (ECDSA signature outputs) are the values of the transaction’s signatures.

#### MakerOrder signature

A seller has to sign an EIP-712 signature of the order’s hash. An EIP-712 signature allows signers to see exactly what they are signing in a client wallet as the signed data is split into different fields and prevents the reuse of signature. It is achieved by having a domain separator in the signature. The domain separator includes the chain ID and `LooksRareExchange`’s address, preventing the reuse of signature in another contract/chain (unless there is a fork).

```solidity
DOMAIN_SEPARATOR = keccak256(
    abi.encode(
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f, // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
        0xda9101ba92939daf4bb2e18cd5f942363b9297fbc3232c9dd964abb1fb70ed71, // keccak256("LooksRareExchange")
        0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6, // keccak256(bytes("1")) for versionId = 1
        block.chainid,
        address(this)
    )
);
```

A MakerOrder hash contains all its attributes except the signature values.

```solidity
function hash(MakerOrder memory makerOrder) internal pure returns (bytes32) {
    return
        keccak256(
            abi.encode(
                MAKER_ORDER_HASH,
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
```

EIP-712’s standard encoding prefix is `\x19\x01`, so the final digest is

```solidity
bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, hash));
```

and the `SignatureChecker` can call Solidity’s recover function to verify the signer is the same as the maker order’s signer address when the buyer submits the signature on chain.

```solidity
recover(digest, v, r, s) == signer;
```

### Bidding on a maker ask

The signature created by the seller is stored in a centralized database and can be retrieved by the website through an API. A seller who sees this pending order can make a bid by calling the function `LooksRareExchange#matchAskWithTakerBid`. This function takes the maker ask struct and the taker bid struct as arguments and run the selected order matching logic on them. There is no need to store a signature for the TakerOrder as it is submitted on chain.

```solidity
struct TakerOrder {
    bool isOrderAsk; // true --> ask / false --> bid
    address taker; // msg.sender
    uint256 price; // final price for the purchase
    uint256 tokenId;
    uint256 minPercentageToAsk; // // slippage protection (9000 --> 90% of the final price must return to ask)
    bytes params; // other params (e.g., tokenId)
}
```

#### Order validation

The function performs the following checks on the orders.

1.  Only 1 of the order is an ask.
    
    ```solidity
    require(
        (makerAsk.isOrderAsk) && (!takerBid.isOrderAsk),
        "Order: Wrong sides"
    );
    ```
    
2.  `msg.sender` cannot bid for another address.
    
    ```solidity
    require(
        msg.sender == takerBid.taker,
        "Order: Taker must be the sender"
    );
    ```
    
3.  The maker order must not have been executed/cancelled or the signer’s max cancelled nonce must not be greater than the maker order’s nonce. An order can be cancelled by explicitly setting the signer’s nonce at `_isUserOrderNonceExecutedOrCancelled` or setting the minimum order nonce at `userMinOrderNonce` such that any signature with a nonce less than it are rendered invalid.
    
    ```solidity
    require(
        (
            !_isUserOrderNonceExecutedOrCancelled[makerOrder.signer][
                makerOrder.nonce
            ]
        ) && (makerOrder.nonce >= userMinOrderNonce[makerOrder.signer]),
        "Order: Matching order expired"
    );
    ```
    
4.  Signer must be present and order amount must not be 0.
    
    ```solidity
    require(makerOrder.signer != address(0), "Order: Invalid signer");
    
    require(makerOrder.amount > 0, "Order: Amount cannot be 0");
    ```
    
5.  The maker order signature must be valid (as mentioned above).
    
    ```solidity
    require(
        SignatureChecker.verify(
            orderHash,
            makerOrder.signer,
            makerOrder.v,
            makerOrder.r,
            makerOrder.s,
            DOMAIN_SEPARATOR
        ),
        "Signature: Invalid"
    );
    ```
    
6.  The transaction currency and execution strategies are whitelisted by the contract owner at the `ExecutionManager/CurrencyManager` contract.
    
    ```solidity
    require(
        currencyManager.isCurrencyWhitelisted(makerOrder.currency),
        "Currency: Not whitelisted"
    );
    
    
    require(
         
    executionManager.isStrategyWhitelisted(makerOrder.strategy),
        "Strategy: Not whitelisted"
    );
    ```
    

#### Order matching execution

If the orders pass the validations, it will try to match the orders using the strategy selected by the maker.

```solidity
(
    bool isExecutionValid,
    uint256 tokenId,
    uint256 amount
) = IExecutionStrategy(makerAsk.strategy).canExecuteTakerBid(
        takerBid,
        makerAsk
    );

require(isExecutionValid, "Strategy: Execution invalid");
```

The strategy `StrategyStandardSaleForFixedPrice` checks that the maker order is currently active and the taker is actually bidding on the right token ID with the right price.

```solidity
((makerBid.price == takerAsk.price) &&
    (makerBid.tokenId == takerAsk.tokenId) &&
    (makerBid.startTime <= block.timestamp) &&
    (makerBid.endTime >= block.timestamp)),
```

If the strategy is able to match the orders, it will mark the order nonce as executed, transfer the sale amount to the seller, and transfer the NFT to the buyer. The protocol takes a cut from the sale and royalty is also taken from the sale if the NFT supports [EIP-2981](https://eips.ethereum.org/EIPS/eip-2981) or if the royalty amount is set in the protocol’s `RoyaltyFeeRegistry`.

```solidity
_isUserOrderNonceExecutedOrCancelled[makerAsk.signer][
    makerAsk.nonce
] = true;
```

#### Protocol fee and royalty fee transfers

```solidity
{
    uint256 protocolFeeAmount = _calculateProtocolFee(strategy, amount);

    // Check if the protocol fee is different than 0 for this strategy
    if (
        (protocolFeeRecipient != address(0)) && (protocolFeeAmount != 0)
    ) {
        IERC20(WETH).safeTransfer(
            protocolFeeRecipient,
            protocolFeeAmount
        );
        finalSellerAmount -= protocolFeeAmount;
    }
}
```

```solidity
{
    (
        address royaltyFeeRecipient,
        uint256 royaltyFeeAmount
    ) = royaltyFeeManager.calculateRoyaltyFeeAndGetRecipient(
            collection,
            tokenId,
            amount
        );

    // Check if there is a royalty fee and that it is different to 0
    if (
        (royaltyFeeRecipient != address(0)) && (royaltyFeeAmount != 0)
    ) {
        IERC20(WETH).safeTransfer(
            royaltyFeeRecipient,
            royaltyFeeAmount
        );
        finalSellerAmount -= royaltyFeeAmount;

    }
}
```

#### Slippage protection  

The protocol has a mechanism to prevent the sudden change of protocol fees and royalty fees from wrecking sellers. Sellers can set `minPercentageToAsk` in their orders to guarantee a minimum sale percentage to receive for the executed order.

```solidity
require(
    (finalSellerAmount * 10000) >= (minPercentageToAsk * amount),
    "Fees: Higher than expected"
);
```

#### NFT transfer

LooksRare supports both ERC-721 and ERC-1155 collections, so it cannot assume the token to be transferred is an ERC-721 token and converts the NFT address to an `IERC721`. The exchange uses a module called `TransferSelectorNFT` to check whether a collection supports the ERC-721 or the ERC-1155 interface (via EIP-165), then it uses the corresponding transfer manager to make the ERC-721/ERC-1155 transfers to the buyer.

```solidity
if (IERC165(collection).supportsInterface(INTERFACE_ID_ERC721)) {
    transferManager = TRANSFER_MANAGER_ERC721;
} else if (
    IERC165(collection).supportsInterface(INTERFACE_ID_ERC1155)
) {
    transferManager = TRANSFER_MANAGER_ERC1155;
}
```

```solidity
ITransferManagerNFT(transferManager).transferNonFungibleToken(
    collection,
    from,
    to,
    tokenId,
    amount
);
```
