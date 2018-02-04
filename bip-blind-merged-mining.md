    Drivechain Documentation -- Blind Merged Mining BIP
    Paul Sztorc
    November 17, 2017
    Document 3 of 3
    v4.1


Header
=======

    BIP: ????
    Layer: Consensus (soft fork)
    Title: Blind Merged Mining (Consensus layer)
    Author: Paul Sztorc <truthcoin@gmail.com>
            CryptAxe <cryptaxe@gmail.com>
            Chris Stewart <chris@suredbits.com>
    Comments-Summary: No comments yet.
    Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-???????
    Status: Draft
    Type: Standards Track
    Created: 2017-10-24
    License: BSD-2-Clause


Abstract
==========

Blind Merged Mining (BMM) is a way of mining special extension blocks, ie "sidechains". It produces strong guarantees that the block is valid, for *any* arbitrary set of rules; and yet it does so without requiring miners to actually do any validation on the block whatsoever.

BMM actually is a process that spans two or more chains. For an explanation of the "whole picture", please see [this post](http://www.truthcoin.info/blog/blind-merged-mining/). Here we focus on the modifications to mainchain Bitcoin.

To support BMM, the mainchain is asked to accomplish two goals:
1. Track a set of ordered hashes (the merged-mining).
2. Allow miners to "sell" the act of finding a sidechain block (through the use of a new extended serialization transaction type).

These goals are accomplished by forcing nodes to validate two new messages (M7, M8), and track data in one new database (D3).


Motivation
============

Regular "Merged-Mining" (MM) allows miners to reuse their hashing work to secure other chains (for example, as in Namecoin). However, traditional MM has two drawbacks:

1. Miners must run a full node of the other chain. (This is because [while miners can effortlessly create the block] miners will not create a valid payment to themselves, unless the block that they MM is a valid one. Therefore, miners must assemble a *valid* block first, then MM it.)
2. Miners are paid on the other chain, not on the regular BTC mainchain. For example, miners who MM Namecoin will earn NMC (and they will need to sell the NMC for BTC, before selling the BTC in order to pay for electricity).

Blind Merged-Mining (BMM) attempts to address those shortcomings.


Specification
============

Note: This document uses the notation side:\* and main:\* in front of otherwise-ambiguous words (such as "block", "node", or "chain"), to distinguish the mainchain version from its sidechain counterpart.

As stated above, we have two goals: [1] create and monitor an alt-chain (defined only by a deterministic list of hashes), and [2] allow miners to "sell" the act of finding a sidechain block (through the use of a new extended serialization transaction type).

### Sidechain Critical Data ("Sidechain Mini-Header")

Specifically, per side:block per side:chain, we track the following 35 bytes of information:

    1-byte   - ChainIndex (known as "Account Number" in hashrate-escrows.md , or as "Sidechain Number")
    32-bytes - sideHeaderHash (also known as "h*" / hashCritical, the hash of the sidechain block)
    2-bytes  - prevBlockRef (an index which points to this side:block's parent side:block)

The **ChainIndex** indicates which sidechain this critical data is relevant to. As we may eventually have more than one sidechain, this serves as an identifier similar to the Bitcoin network's magic bytes (0xF9BEB4D9). Drivechains however only need to use 1 byte for the identifier (there is a hard limit of 256 sidechains identified as 0-255). The **sideHeaderHash** is the hash of a side:block which will receive PoW via BMM. It serves a similar function to Bitcoin's "hashMerkleRoot", in that it contains the data for its blockchain. The **prevBlockRef** forms the set of headers into a blockchain structure by making each headers refer to one parent header. It is most similar to Bitcoin's hashPrevBlock.

Where does this data come from, and how does it get around?

#### Creating / Broadcasting This Data

##### Creation

By the time Blind Merged Mining can take place, the ChainIndex is globally known (it is the "Account Number" in D1 [see previous BIP], and "nSidechain" in the code). Each sidechain, when activated by soft fork, will take one of the 0-255 available indexes.

The other two items, sideHeaderHash and prevBlockRef, are created by sidechain nodes. sideHeaderHash is quite straightforward -- side:nodes build side:blocks, and take the hash of these.

The final item, prevBlockRef, is a little more complicated. It is an integer that counts the number of "skips" one must take in the side:chain in order to find the current side:block's parent block. In practice, this value will usually be zero. It will only be a value other than zero, in cases where invalid sidechain blocks have been mined, or when a side:node intentionally wants to orphan some side:blocks (if a side:node wants to orphan the most-recent N blocks, the value of the current block will be equal to N ; in the block after that it will be back to zero).

![dots-image](/bip-blind-merged-mining/bmm-dots-examples.png?raw=true)

Since the hashes themselves are already ordered by the mainchain, tracing the blockchain's path by index (prevBlockRef) will be the same as tracing it by identifying a list of hashes. In other words, the ordering given via each side:block's "prevBlockRef" will be isomorphic to an ordering given by each side:block's "prevSideHeaderHash" ... if "prevSideHeaderHash is defined to be the sidechain's equivalent of the mainchain's "prevBlockHash". It will be possible to freely convert from one to the other. See M8 to learn more about how these hashes are requested by sidechain block creators to be included in the mainchain.

Now that we know what our critical data is, and how it is made, how is this data broadcast and stored?

##### Broadcast

Mainchain nodes are going to need this data later, so it must be easy to find. We will put it into the coinbase via OP RETURN.

#### M7 -- "Blind-Mine the Sidechain(s)"

Thus, (for n sidechains) we have a coinbase output with:

    1-byte - OP_RETURN (0x6a)
    1-byte - Push the following (4+(n*35)) bytes (0x??)
    4-byte - Message header (0xD3407053)
    (n*(32+5))-byte - A sequence of bytes, of the three Mini-Header items (h*, prevBlockRef, ChainIndex).

( We assume that 5 bytes are used for the Critical Data bytes (non h* parts of the Sidechain Mini-Header). For 256 sidechains, a total of 9,478 bytes [1+1+4+256\*(32+5)] are required, conveniently just below the 10 KB scriptPubKey size limit.)

This data is parsed by laying it in sequential 37-byte chunks (any remaining data --ie, some final chunk that is less than 37 bytes in length-- has no consensus meaning). 

Each 37-byte chunk is then parsed to obtain the data outlined above (in "Description"). If two 35-byte chunks being with the same "Sidechain number" (ie, if the two chunks have the same first byte), then only the first chunk has consensus meaning.

We are left with, at most, one (h*, prevBlockRef) pair per sidechain per block. This data is added directly to D3, a new database.

#### D3 -- "RecentSidechains_DB"

To suit our purposes, the mainchain full nodes will need to keep track of the most recent 8000 (h\*, prevBlockRef) pairs.

( This 8,000 figure is a tradeoff between decentralization (costs of running the main:node) and sidechain security -- it requires attackers to merged-mine 8,000 invalid blocks consecutively, in order to cause the sidechain to fail. The mainchain burden is minimal, so this figure might be raised to 12,000 or higher. )

Therefore, D3 would look something like this:


           BlockHeight  CB_Index    SC_1   Blks_Atop_1   SC 2   Blks_Atop_2   SC 3   Blks_Atop_3
            ---------    ------    ------   ---------   ------   ---------   ------   ---------
       1.    401,005        2      (h*, 0)     7985     (h*, 0)        1     (h*, 0)        0
       2.    401,006        4      (h*, 0)     7984     (h*, 0)        0     (h*, 1)     7801
       3.    401,007        2      (h*, 0)     7983     (h*, 5)     2027     (h*, 0)        0
       4.    401,008        2      (h*, 0)     7982     (h*, 0)     2028     (h*, 1)     7800
      ...     ...                                                                  )
    7999.    409,003        3      (h*, 0)        1     (h*, 0)        0     (h*, 0)        1
    8000.    409,004        2      (h*, 0)        0     (h*, 1)        0     (h*, 0)        0


When new sidechains (or "hashrate escrows") are soft-forked into existence, a new column is added to D3 (to contain any BMMing that might be done on it).

For each sidechain we also track the field "Blocks Atop". This is the number of side:blocks that are "on top" of the specified side:block. These might be regarded as "side:confirmations" (pseudo-confirmations that are specific to each sidechain).

D3 also contains a column (not shown) for each sidechain containing "prevSideBlockHash". This value is is either derived from prevBlockRef; or else it is given explicitly (in which case it is the converse: prevBlockRef is derived from prevSideBlockHash).


#### Coinbase Cache

As mentioned above, M7s cause data to be added to D3. Recent D3 data is tracked by all mainchain nodes for a period of time.

To efficiently keep track of the above data, without having to constantly load and process entire blocks from disk, we temporarily cache enough coinbases in the chain index to maintain D3.


### M8 -- Paying miners to include BMM data in their coinbase outputs

This section introduces a new type of transaction, which allows sidechain block creators to request, and pay for, a critical hash to be included in a specific block by mainchain miners. See [the Blind Merged Mining spec](http://www.truthcoin.info/blog/blind-merged-mining/). This txn allows miners to "sell" the act of mining a sidechain block. By taking advantage of this option, miners earn tx fees for mining sidechains...truly "for free". They do not even need to run sidechain nodes, and the tx-fees they earn are in mainchain BTC. As a result, sidechains affect all miners equally and do not affect the mining ecosystem.

M8 will ultimately come in two versions. The second version will be specialized for use in the Lightning Network and must use the full 32-byte prevBlockHash (ironically, this larger transaction is cheaper for the Bitcoin network to process, as it is completely off-chain). The first version of M8, in contrast, cannot be used inside the Lightning Network, but is slightly more space-efficient (using the 2 prevBlockRef bytes to maintain chain order). It is important to make both options available to the user, because some side:nodes may be unwilling or unable to open a payment channels with each main:miner. However, in the long run we expect the lightning version to be preferred.

#### Setup

We define **"Mary"** as a mainchain miner, and **"Simon"** as a sidechain node.

The goal is to construct a payment from Simon to Mary, such that:

1. If the critical data conditions are met, **Mary** can claim the outputs of the transaction with finality.
2. If the critical data conditions are not met, the outputs become immediately available again to **Simon**.


#### Goals (this is rather philosophical, and skippable)

##### Immediate Expiration ("Fill-or-Kill")

We would like to make special guarantees to the counterparties of this transaction. Specifically, instead of Simon making a "payment" to Mary, we prefer that Simon give Mary an "offer" (which she can either accept or decline).

Crucially, we want Simon to safely make many offers to several different Mary's, in realtime (ie, quickly and off-chain). However, we ultimately want only one offer to be accepted, at most. In other words, we want Simon's offers to *immediately expire*. If only one offer can become a bona fide transaction, then Simon will feel comfortable making offers all day long. Because all of the Simons are making many offers, the Marys collectively gain access to a large set of offers to choose from.

##### Forward Progress (The Need for a "Ratchet")

The "ratchet" concept is an attempt to harmonize incentives among the main and side chain(s).
We need to ensure that a sidechain is making "forward progress", without tracking too much about the sidechain such that we burden Bitcoin (see [1] and [2]) all while still allowing the sidechain to reorganize [3].

* [1] https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-July/014789.html
* [2] http://www.drivechain.info/faq/index.html#what-is-the-difference-between-drivechain-and-extension-blocks
* [3] http://www.truthcoin.info/blog/blind-merged-mining/#handling-reorganizations

The ratchet system must keep track of sidechain "mini-headers" (see Sidechain Critical Data ("Sidechain Mini-Header")) and count the "blocks atop" maturity of the related side:blocks.

Simon's offer to Mary to include a critical hash in exchange for payment must be *atomic*. The "ratchet" concept helps to construct a very tight connection between two things:

1. The sidechain-block-generator "Simon" paying himself the side:block's side:tx-fees (which he receives in 100 sidechain blocks (blocks atop) hence).
2. "Simon" making a mainchain main:btc payment to a mainchain miner "Mary".

Either both of the two should succeed, or else both should jointly fail.

However, absent our intervention, there are cases in which [2, the payment to Mary] succeeds but [1, side:tx-fees] fails. One such case is when a side:block contains unusually high side:tx-fees. Here, there will be many requests to include a critical hash in exchange for payment submitted to Mary, but only one can be included in each main:block per sidechain. Without an incentive to make "forward progress", Mary is likely to include one of the highest paying requests in the next main:block (and the main:block after that, and so on). Mary will "blindly" include high-paying requests for *older* blocks, unless something prevents her from doing so.

To address these potential issues, we utilize the concept of "Blocks_Atop" (the "side:confirmations") that we mentioned earlier. As previously mentioned, Mary will not be able to spend Simon's M8 payment until satisfying the critical data requirements as well as the blocks atop (side:confirmations) requirement.


#### M8 -- The two forms of M8 transactions

As previously mentioned, M8 can take two forms. The first does not require the Lightning Network, but it does have new requirements for Immediate Expiration (see above). The second inherits Immediate Expiration from the Lightning Network itself, but requires extra preparation and a different/larger message.

Both forms require that certain Critical Data will be committed to within the coinbase of the block that the transaction is included in. For the non Lightning version, we have created a new extended serialization transaction type (very similar to how segwit handles witness data (the witness stack)).

##### M8_V1 - No Lightning Network

M8_V1 does not require the Lightning network but does have new requirements for validation.

A M8_V1 TxOut is expected to contain:

    1-byte - OP_RETURN (0x6a)
    1-byte - Push the following 36 bytes (0x24)
    4-byte - Message header (0xD1617368)
    32-bytes  - h* side:block hash
    5~7-bytes - BMM request identifying bytes (0x00bf00) + prevBlockRef & ChainIndex (sidechain mini-header)
    

In the first version of M8, we need to introduce the concept of Immediate Expiration (see above). In other words, we need a way for Simon to construct many payments to multiple Marys, such that only one of these is ever included; and only then if Simon's txn is expected to coincide with the finding of Simon's side:block.

We do this by imposing validity-rules on the txn itself:

1. The txn's content, when examined, must match part of the main:block's content. Specifically, the (ChainIndex, h\*) pair of the txn, must match one of the (ChainIndex, h\*) pairs in the M7 of this main:block.
2. Only one payment per sidechain per main:block is valid. In other words, if 400 people all try to bm-mine the sidechain with ChainIndex==4, then not only is it the case that only one side_4:block can be found, but it is also the case that only the corresponding M8 txn can be included (out of all of the 400 M8s which are for ChainIndex==4).
3. Simon's txns must only be valid for the current block; afterward, they immediately expire. This is because Simon's intended prevBlockRef & side:block contents will most likely change from one main:block to the next.

To impose new requirements on the transaction level (not the block level nor the TxOutput level), we borrow the "flag" trick from SegWit style transactions. If the flag is present, the transaction is examined for extra data, and if this data does not pass certain requirements, the transaction is invalid. With SegWit, this extra data is the signatures, and the extra requirements are the signatures' locations and validity. In the BMM-transactions, the extra data is the (ChainIndex, h\*) pair, which must meet the first two requirements (above) as well as the main:blocknumber, which must meet the third requirement (above).

To impose new requirements at the transaction level, we borrow the dummy vin & "flag" trick from SegWit style transactions. If the flag is set to 2 (0010), the transaction contains Critical Data and requires that our new validation rules be met in order for the txn to be valid in a block. Unless all of the requirements for sidechain critical data transactions are met by the block it is included in, the transaction is invalid. With SegWit, this extra data is the segwit signature stack, and the extra requirements are the signatures' locations and validity. In the sidechain BMM critical data transactions, the extra data is the (ChainIndex, h\*) pair, which must meet the first two requirements (above) as well as the main:blocknumber, which must meet the third requirement (above). Note The main:blocknumber does not take up any additional space compared to a normal txn, as we reuse the locktime field for our purposes.




![extra-data-image](/bip-blind-merged-mining/witness-vs-critical.png?raw=true)

This txn structure conserves main:blockspace, because it is the easiest way to refer to a previous sidechain block in 4 bytes, (prevBlockRef + FoK_nLockTime). Instead, we would need to use at least 32 bytes (prevSideBlockHash).

These types of transactions have slightly different mempool behavior, and should probably be kept in a second mempool. These txns are received, checked immediately, and if valid they are evaluated for inclusion in a block. If they are not able to be included in the specific requested block (if the block height requested has been surpassed by the chain tip), they are discarded. In fact, after any main:block is found, everything in this "second mempool" can be discarded as new payments will be created immediately for the next block height. (This includes cases where the blockchain reorganizes.) There is no re-evaluation of the txns in this mempool ever -- they are evaluated once and then either included or discarded. To be clear, when the transaction is received we are able to evaluate its validity, and do not need to rescan these transactions again.

Interestingly, these payments (M8) will *always* be directed to miners from non-miners. Therefore, non-mining nodes do not need to keep them in any mempool at all. Non-miner nodes can just wait for a block to be found, and check the txn then. These transactions more resemble a stock market's pit trades (in contrast, regular Bitcoin txns remind me more of paper checks).

##### M8_V2 With Lightning

M8_V2 requires having a LN-channel open with a miner. This may not always be practical (or even possible), especially today.

A M8_V1 TxOut is expected to contain:

    1-byte - OP_RETURN (0x6a)
    1-byte - Push the following 68 bytes (0x44)
    4-byte - Message header (0xD0520C6E)
    32-bytes  - h* side:block hash
    32-bytes  - prevSideBlockHash
    5~7-bytes - BMM request identifying bytes (0x00bf00) + prevBlockRef & ChainIndex (sidechain mini-header)
    

Notice that, in M8_V1, Simon could reuse the same h\* all he wanted, because only one M8_V1 could be included per main:block per sidechain. However, on the LN no such rule can be enforced, as the goal is to push everything off-chain and include *zero* M8s. So, we will never know what the M8s were or how many had an effect on anything.

Therefore, Simon will need to ensure that he **gives each Mary a different h\***. Simon can easily do this, as he controls the side:block's contents and can simply increment a nonce -- this changes the side:block, and changes its hash (ie, changes h\*).

With a unique h\* per Mary, and at most 1 h\* making it into a block (per sidechain), we can guarantee that only one of the M8_V2's critical data can be committed to in a single main:block. By giving each miner (who Simon has a payment channel open with) a different h*, Simon can figure out which miner followed through with the commit, and know that only one such commit went through. Furthermore, if this Simon's requested critical data is not found in a block, none of the M8_V2 payments will be spendable by the Mary(s), because none of the h\* in question have ever made it into D3 (which is always on-chain) and no blocks atop will be accumulated.

That's probably confusing, so here is an example, in which: Simon starts with 13 BTC, Mary starts with 40 BTC, the side:block's tx-fees currently total 7.1 BTC, and Simon is keeping 0.1 BTC for himself and paying 7 BTC to Mary.

We start with (I):

    Simon 13 in, Mary 40 in ; 53 in total
        Simon's version [signed by Mary]
            13 ; to Simon if TimeLock=over; OR to Mary if SimonSig
            40 ; to Mary
        Mary's version [signed by Simon]
            40 ; to me if TimeLock=over; OR to Simon if MarySig
            13 ; to Simon


And both parties move, from there to "M8_V2" (II):

    Simon 13 in, Mary 40 in ; 53 in total
        Simon's version [signed by Mary]
            6 ; to Simon if TimeLock=over; OR to Mary if SimonSig
            40 ; to Mary
            7 ; to Mary if critical data requirements met; OR to Simon if LongTimeLock=over
        Mary's version [signed by Simon]
            40 ; to Mary if TimeLock=over; OR to Simon if MarySig
            6 ; to Simon
            7 ; to Mary if critical data requirements met; OR to Simon if LongTimeLock=over

From here, if the h\* side:block in question is BMMed, they can proceed to (III):

    Simon 13 in, Mary 40 in ; 53 in total
        Simon's version [signed by Mary]
            6 ; to Simon if TimeLock=over; OR to Mary if SimonSig
            47 ; to Mary
        Mary's version [signed by Simon]
            47 ; to me if TimeLock=over; OR to Simon if MarySig
            6 ; to Simon

Although, if Simon proceeds immediately, he removes the protection of the 'ratchet'. Ie, Simon removes Mary's incentive to care about blocks being built on this side:block. If Simon's side:block is orphaned, he loses his 7 BTC. Simon can either play it safe, and wait the full 100 side:blocks before moving on (ie, moving on to the third LN txn, above); or else Simon can take the risk if he feels comfortable with it.

If the h\* side:block is not found, then (II) and (III) are basically equivalent to each other. Simon and Mary could jointly reconstruct (I) and go back there, or they could proceed to a new version of II (with a different h\*, trying again with new side:block in the next main:block).




Deployment
===========

This BIP will be deployed by "version bits" BIP9 with the name "blindmm" and using bit 4.

```
// Deployment of Drivechains (BIPX, BIPY)
consensus.vDeployments[Consensus::DEPLOYMENT_DRIVECHAINS].bit = 4;
consensus.vDeployments[Consensus::DEPLOYMENT_DRIVECHAINS].nStartTime = 1515974401; // January 15th, 2018.
consensus.vDeployments[Consensus::DEPLOYMENT_DRIVECHAINS].nTimeout = 1547510401; // January 15th, 2019.
```

Reference Implementation
==========================

See: https://github.com/drivechain-project/bitcoin/tree/mainchainBMM

Also, for interest, see an example sidechain here: https://github.com/drivechain-project/bitcoin/tree/sidechainBMM


References
============

* http://www.drivechain.info/literature/index.html
* http://www.truthcoin.info/blog/blind-merged-mining/
* https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-July/014789.html
* http://www.truthcoin.info/images/bmm-outline.txt


Thanks
=========

Thanks to everyone who contributed to the discussion, especially: ZmnSCPxj, Adam Back, Peter Todd, Dan Anderson, Sergio Demian Lerner, Matt Corallo, Sjors Provoost, Tier Nolan, Erik Aronesty, Jason Dreyzehner, Joe Miyamoto, Ben Goldhaber.


Copyright
==========

This BIP is licensed under the BSD 2-clause license.
