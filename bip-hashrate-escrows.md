
Header
=======

    BIP: ????
    Layer: Consensus (soft fork)
    Title: Hashrate Escrows (Consensus layer)
    Author: Paul Sztorc <truthcoin@gmail.com>
            CryptAxe <cryptaxe@gmail.com>
    Comments-Summary: No comments yet.
    Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-???????
    Status: Draft
    Type: Standards Track
    Created: 2017-08-14
    License: BSD-2-Clause
    Post-History: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-May/014364.html


Abstract
==========

A "Hashrate Escrow" is a clearer term for the concept of "locked to an SPV Proof", which is itself a restatement of the phrase "within a sidechain" as described in [a famous Oct 2014 paper](https://blockstream.com/sidechains.pdf) written partially by some Blockstream co-founders.

A Hashrate Escrow resembles a 2-of-3 multisig escrow, where the 3rd party (who will arbitrate any disputes) is a decentralized group of people: the dynamic-membership set of Bitcoin Miners. However, the 3rd party does not sign escrow-withdrawal transactions with a private key. Instead, these are "signed" by directing hashpower over them for a period of time.

This project has [a website](http://www.drivechain.info/) which includes [a FAQ](http://www.drivechain.info/faq/index.html).


Motivation
============

In practice these escrows are likely to be "asymmetric sidechains" of Bitcoin (such as [Rootstock](http://www.rsk.co/)) or "virtual chains" within Bitcoin (such as [proposed by Blockstack](https://github.com/blockstack/virtualchain) in mid-2016).

Sidechains have many potential benefits, including:

1. Protect Bitcoin from competition from altcoins and spinoffs. Safely allow competing implementations (of *sidechains*).
2. Protect Bitcoin from hard fork campaigns. (Such campaigns represent an existential threat to Bitcoin, as well as an avenue for developer corruption.)
3. Help with review, by making it much easier for reviewers to ignore bad ideas.
4. Provide an avenue for good-but-confusing ideas to prove their value safely.



Specification
==============


#### Components

Hashrate Escrows are built of two types of component: [1] new databases, and [2] new message-interpretations.

##### 1. New Databases

* D1. "Escrow_DB" -- a database of "accounts" and their attributes.
* D2. "Withdrawal_DB" -- a database of pending withdrawals from these accounts, and their statuses.

Please note that these structures (D1 and D2) will not literally exist anywhere in the blockchain. Instead they are constructed from messages...these messages, in contrast, *will* exist in the blockchain (with the exception of M4). 

##### 2. New Messages

* M1. "Propose New Escrow"
* M2. "ACK Escrow Proposal"
* M3. "Propose Withdrawal"
* M4. (implied) "ACK Withdrawal"
* M5. "Execute Deposit"   -- a transfer of BTC from-main-to-side
* M6. "Execute Withdrawal" -- a transfer of BTC from-side-to-main


#### On the Resource Requirements of New Databases

The "new" databases are simply reinterpretations of data that are already contained elsewhere in the blockchain. Specifically, M1 M2 and M3 are all located in the block's coinbase txn, and M5 and M6 might be found in any regular txn. M4 is a special case and does not actually need to be included anywhere, so it is not. If you like, you can imagine that the M4s reside in an optional extension block.

In other words, we just rearrange what is already there. Because of this, even though "new databases" are created and stored in memory, the existing bandwidth and storage limits are respected (although, see "M4" below).




### Adding Sidechains and Tracking Them (D1, M1, M2)

#### D1 -- "Escrow_DB"

The table below enumerates the new database fields, their size in bytes, and their purpose. In general, an escrow designer (for example, a sidechain-designer), is free to choose any value for these.

Note: Fields 6 through 9 have been intentionally removed. Previously, this section allowed miners to set and commit to voting/waiting periods. However, I have since standardized the periods: withdrawals expire after 6 months (26298 blocks), and they succeed if they ever achieve an ACK score of 13140 or higher. I have removed the waiting period, because anyone who adopts a policy of ignoring all withdrawals with fewer than 400 ACKs will automatically gain all of the benefits of the waiting period. The justification for this change is that it strongly implies that an attack on any one sidechain is an attack on all of them (in a sense, this change makes the "victimhood" of each sidechain "fungible").

Field No. | Label | Bytes | Type | Description / Purpose
----------|-------|------|------|--------
1 | Escrow Number | 1 | uInt | A number assigned to the entire escrow. Used to make it easy to refer to each escrow.
2 | Active\* | 2 | uInt | This counter starts at zero when a new entry is added, and increments as a new entry is supported by "M2". The entry either reaches the max value of 4032 (at which point the counter freezes), or else the entry is removed. This enforces the requirement "a soft fork is required to add a new escrow".
3 | Escrow Name/Description | 120 | string | A human-readable name and description of the sidechain. More than enough space to hold a 32 byte hash. Helps prevent destructive interference among sidechains (see below).
4 | Critical Private Key | 32 | hex | This is the Double-SHA256 of the binary release of the reference software. It ties the sidechain to a specific software release, and doubles as a way of signing withdrawals (see below).
5 | Critical Address\* | 32 | string | This is derived by taking f(x) = ImportPrivateKey(HexToBase58Check(x)) of field #3. It is intentionally in the human-readable format {{although it could be 25 bytes of binary}}.
10 | "CTIP" -- Part 1 "TxID"\* | 32 | hex | The CTIP, or "Critical (TxID, Index) Pair" is a variable for keeping track of where the escrow's money is (ie, which member of the UTXO set).
11 | "CTIP" -- Part 2 "Index"\* | 4 | hex | Of the CTIP, this is second element of the pair: the Index. See #10 above.


\* Denotes a "convenience field", the entry for this field is derived from other fields, or from the blockchain-state itself. The escrow-creator does not need to provide these values in M1 (or anywhere).

Escrow_DB requires 223 bytes [1+120+32+32+2+32+4] for each escrow in the main blockchain. Of these, 70 bytes [2+32+32+4] are merely for convenience. Therefore, a sidechain is defined (see "M1") by 153 bytes of information.

#### Notes on D1

1. D1 will always exist.
2. D1 will always have a unique sort (first by "Escrow Number" (field #1), and second by "Active" (field #2)). There is only ever one (escrow number, Active) pair. 
3. D1 is updated according to M1 and M2 (below).
4. If a new entry is added to D1 with an "Escrow Number" that is already in use, then this entry will either eventually be removed (because it was not supported with an M2), or it will eventually overwrite the old entry (if it *was* supported via M2).


#### Notes on D1

##### Obligations Placed on Miners

Miners have always upgraded their software according to criteria that are known only to them (in other words, "whenever they want").

However, this soft fork imposes two new criteria upon them. First: miners should only upgrade their software, if any modification to the portfolio of sidechains [that are added/removed in the upgrade] can be expected to increase miner wealth. Trivially, this implies that miners should make sure that the upgrade doesn't overwrite (and destroy) an existing sidechain that they like! But, more seriously, it implies that miners should take an interest in what the sidechain is doing to the mainchain and other sidechains (see below).

##### Destructive Sidechain Interference

People frequently emphasize that miners should have "as little control" as possible. It is a very safe claim to make, and a very easy sentence to write. Much harder is to determine exactly what this minimum value is, and how to achieve it. Harder still is to untie the knot of who is actually controlling what, in a decentralized, interacting system.

Certainly, miners can not have "zero control" -- for that is the same as to just remove them from the system altogether. Some rules are enforced "on miners by nodes" (such as the infamous blocksize limit); other rules are enforced by nodes but are narrowly-controlled by miners (such as the proof-of-work itself, or the block's timestamp). Thirdly, some rules are enforced by both against each other (such as the rule against including invalid txns or double-spent txns), for mutual benefit.

Some pause should be given, after one considers that the sidechain design goal is literally a piece of software that can do *anything*. Anything includes a great many things, many of which I demonstrate to be undesirable. Bitcoin itself does not allow "anything" -- it allows any person to transact, but, in contrast, it does not permit any person to double-spend. This is because "allowing anyone to do anything" is not viable in a world that contains undesirable interactions (what a libertarian might call "aggression") -- in the case of money, these are theft and counterfeiting.

I have produced a comprehensive quantity of written material [1], presentations [2], etc [3] on exactly what the level of miner-control should be, and why. Specifically, I claim that **miners should be aware of the purpose of the sidechain, and they should reject sidechains which have an unclear purpose or which have a purpose that will lead to decrease in miner-wealth** (where wealth measured explicitly as: the estimated present value of the purchasing power of the blockchain's coinbase txns). I claim that this criterion is necessary because, just Original Bitcoin filters unwanted interactions among different BTC txns, so too much "Sidechain Bitcoin" filter out unwanted interactions among sidechain.

* [1] http://www.truthcoin.info/blog/wise-contracts/
* [2] https://www.youtube.com/watch?v=xGu0o8HH10U&index=1&list=PLw8-6ARlyVciMH79ZyLOpImsMug3LgNc4
* [3] http://www.drivechain.info/literature/index.html

Call it a "sidechain non-aggression principle", if you want.

To the best of my knowledge, everyone who *has* reviewed this information as found the arguments to be acceptable. It has, also, changed a few minds (from "unacceptable" to "acceptable").


##### ISSUE: "Signing" BTC Txns

Currently, we use a process which may be suboptimal. It is that we *literally sign* a txn with a globally and publicly known private key. But this is for convenience purposes -- the signature that is produced is not doing anything, and is therefore wasteful. Instead we may use OP_TRUE, but this might interfere with how we detect the sidechain's balance. I'm not sure what the best way is. Someone needs to investigate how to do this -- removing OP_CheckSig, etc. This is a TODO for sure, and an opportunity for someone to help.



(The following messages were modeled on SegWit -- https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#commitment-structure )



#### M1 -- "Propose New Sidechain"

    1-byte - OP_RETURN (0x6a)
    1-byte - Push the following 157 bytes (0x9d)
    4-byte - Commitment header (0x53707243)
    153-byte - the critical bytes mentioned above (fields #1, #3, and #4, to populate a new D1 entry)


#### New Block Validation Rules

1. If the network detects a properly-formatted M1, it must add an entry to D1, into the very next block, with the following initial values:
* Field #5 will be calculated as per [version 1 Bitcoin addresses](https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses), but with a prefix of "4" instead of "1".
* Field #9 will be derived from #7 and #8 using math.
* The initial values of Fields #10, #11, and #12 are set to zero.
2. Only one M1 (of any kind) can be added into a block at a time.

#### Notes on M1

The escrow will "reuse" the same address over and over. But notice that there is no privacy loss due to address reuse, because the address in question does not "belong" to any specific individual. Furthermore, the transactions in question could already be linked by just watching the Hashrate Escrow for deposits ...this, in fact, is exactly what a sidechain must do in order to make main-to-side transfers.


#### M2 -- "ACK Sidechain Proposal"

    1-byte - OP_RETURN (0x6a)
    1-byte - Push the following 29 bytes (0x1D)
    4-byte - Commitment header (0x53616343)
    25-byte - Commitment hash: RIPMD-160 of Sha256 of a given M1 (above)

#### New Block Validation Rules

1. An entry will be removed from D1, unless that block contains an M2 supporting it (this will increment field #2), or the entry has accumulated 4032 M2s. Therefore, each entry needs to have 4032 *consecutive* M2s supporting it, else it will be removed from D1 and must start over. This requires all miners to agree to "soft fork" the sidechain into existence. This makes it easier to curate the list of active sidechains, and prevents destructive interference (see above) among contradictory sidechains.
2. Once the entry has 4032 M2s, then a miner must make a 0 btc payment to the Critical Address, thus activating the chain. This payment becomes the first "critical (TxID, index) pair" (or "CTIP").
3. It is possible to "overwrite" a D1 slot -- this destroys the sidechain that is there, and replaces it with a new one. This is defined as requiring 6 months (26298 blocks) of M2s, instead of 4 weeks (4032). This possibility does not change the security assumptions, because we already assume that users have access to "magically true" bandwidth at a rate of 1 bit per ACK-cycle. (This is why the voting cycles should be large, 1 month Waiting, 2+ months Voting).



### Adding Withdrawal-Attempts and Tracking Their Success (D2, M3, M4)

#### D2 -- "Withdrawal_DB"

The table below enumerates the database fields, their size (in bytes), type and purpose.


Field No. | Label | Bytes | Type | Description / Purpose
----------|-------|------|------|-----------------------
1 | Escrow Number | 1 | uInt | Links the withdrawal-request to a specific escrow.
2 | WT^ | 32 | hex | This is a "blinded transaction id" (ie, the double-Sha256 of a txn that has had two fields zeroed out, see M6) of a withdrawal-attempt.
3 | ACKs\* | 2 | uInt | The current total number of "votes", this starts at 0 and remains there throughout the waiting period.
4 | Age\* | 3 | uInt | Total duration of time, in blocks, that this WT^ has been inside of D2.
5 | Waiting Period\* | 2 | uInt | Total duration of time, in blocks, that this entry must sit idle, before it can begin to accumulate ACKs/NACKs. Pulled from D1's field #6.
6 | Max Age\* | 3 | uInt | Determined by summing (D1's field #6) and (D1's field #7).
7 | Threshold\* | 2 | uInt | Total ACKs needed, this is pulled from D1's field #9.
8 | Approved\* | 1 | boolean | True while ACKs > Threshold, False otherwise.

\* Denotes a "convenience field" (see above).

Withdrawal_DB requires 46 bytes [1+32+2+3+2+3+2+1] per entry. Of these, 13 bytes ([2+3+2+3+2+1], all fields except #1 and #2) can be generated locally, leaving 33 critical bytes [1+32].

#### New Block Validation Rules for D2

1. In each block, a hash commitment to D2 must always exist (even if D2 is blank).
2. D2 must always be sorted first by field #1 (Escrow Number) and second by field #4 (Age). This imposes a unique sort.
3. From one block to the next, every entry's "Age" field must increase by exactly 1.
4. From one block to the next, entries are only removed from D2 (in the very next block) if:
* * "Age" = "MaxAge".
* * If the block contains a txn who's blinded txID matches WT^. {{ This might be unnecessary, and a lot of work. }}
5. In addition, there are special rules for the allowed values in the "ACKs" field (field #3). See M4 below.

#### M3 -- "Propose Withdrawal"

    1-byte - OP_RETURN (0x6a)
    1-byte - Push the following 37 bytes (0x25)
    4-byte - Commitment header (0xD45AA943)
    33-byte - the critical bytes mentioned above (fields #1 and #2, to populate a new D2 entry)


#### New Block Validation Rules for M3

1. If the network detects a properly-formatted M3, it must add an entry to D2 in the very next block. The starting values of fields #3 and #4 are zero, and #5 is pulled over by extracting the relevant value from D1.
2. Each block can only contain one M3 per sidechain.


#### M4 -- "ACK Withdrawal"

#### Very Little Info, Probably Calculable in Advance

M4 is exceptional (in comparison to the other M's) in a few ways. First, its content is not stored anywhere, only the *hash* of its *effect* is stored (in a leaf of a merkle tree who's root is inserted into a mainchain coinbase). M4 alters the contents of D2 -- the *contents* of D2 are consensus critical, but M4 (the process by which nodes reach a new valid D2) can be anything.

In fact, M4 can also be *nothing*. In other words, it may be optional. This is precisely because, from one block to the next, we have constrained D2 such that it is only allowed to change in a few ways. Therefore, the exhaustive set of "candidate D2s" can be precomputed by full nodes in advance.

#### Two Withdrawals at Once

In general, only one withdrawal (per sidechain) can make progress (toward being included in a block) at a time. In other words, as WT^s are proposed, only one can make progress toward the finish line. As a result, a given side-to-main transfer will always take between 3 and 6 months. Instead, with more simultaneous withdrawals, the worst-case transfer duration would improve.

![dots-image](/bip-hashrate-escrows/two-groups.png?raw=true)

The worst-case withdrawal time obeys f(n)=3+(3/n) months, where n is the number of simultaneous withdrawals.

N=2 is the most desirable choice for several reasons. First, it delievers the greatest marginal benefit (of 1.5 months). Later choices only deliver 0.5 and 0.25 marginal months.

Second, n=2 can be implemented in a clever way: by allowing a withdrawal to freely advance, if and only if has an ACK-score of 6575 or greater, and if it also has the largest ACK score. In other words, the withdrawal that is furthest along can advance (or retreat) for free, if it has already made it at least halfway to the finish line. With this change, our new M4, is either an "abstain" for the sidechain (in which case nothing happens to any ACK scores), or else it will be in one of two cases: old_M4 + "the largest advances", or new_M4 + "the largest retreats". As a result the number of M4 possibilities (of which the next section is concerned) only increases by a factor of two (instead of exponentially).

It is possible to troll this rule, by getting two (or even three) withdrawals to have 6575+ ACK scores, and then getting them to *tie* for first place. So, if there are any ties, the ability to "bonus move" is disabled until all ties are broken.

#### How Hard is it to Guess M4?

If there are n Escrows and m Withdrawals-per-escrow<sup>1</sup>, then there are (m+2)^n total candidates for the next D2. This is because, [per block per escrow], one of three things can happen: (1) one of the m withdrawal-candidates can be "ACK"ed (or "upvoted" or "promoted"), which automatically downvotes the others; or (2) all withdrawal-candidates can be downvoted, or finally (3) the miners can abstain from voting on the escrow's withdrawals altogether, leaving the tallies the same.

First, for nodes which validate all sidechains (assuming these escrows are sidechains), this simplifies to 2^n -- these nodes only have to choose between the single honest choice (on one hand) or an abstention (on the other). Second, even for nodes that don't validate any sidechains, the number of candidates might be reduced from m^n to 3^n, by making a simplifying assumption: whichever withdrawal was most recently added/upvoted, is likely to be the one which is upvoted next.

Of course, that is still O(k^n) for n sidechains, which isn't great<sup>2</sup>. If the "D2 update" cannot be guessed, it must be transmitted in some way.

#### Giving Up and Getting M4 the Old Fashioned Way

Two examples for transmitting it are below:

"Short Form" (Assumes there are no more than 254 active withdrawal-attempts per account)

    4-byte - Message identifier (0x????????)
    1-byte - Version of this message
    N-byte - N is the total number of active accounts ("sidechains"), each byte specifies the position of the single WT that was "upvoted". A value of 0 indicates "downvote everything", a value of 255 indicates abstention.

"Long Form" (Makes no assumptions about anything)

    4-byte - Message identifier (0x????????)
    1-byte - Version of this message
    1-byte - Length (in bytes) of this message; total number of withdrawal attempts; y = ceiling( sum_i(m_i +2)/8 ). Nodes should already know what length to expect, because they know the sequence of M3s and therefore the vector of WT^s.
    Y-byte - stream of bits (not bytes), with a 1 indicating the position of the chosen action [downvote all, abstain, upvote1, upvote2, ...]


If the message is very very large, then nodes may not want to broadcast it. This opens up an "exhaustion attack"<sup>2</sup>, in which many miners create bad WT^s, vote on these randomly, and then refuse to broadcast their votes. Fortunately, even for a worst-case scenario of 200 sidechains and 1,000 withdrawal-attempts per sidechain, honest nodes can communicate a long form M4 with each other by using just 25,056 bytes per block [4+1+1+(200\*(1000+1+1)/8)].

Today's pre-drivechain miners can already carry out a similar attack, by creating and including txns and then not broadcasting that part of the block to anyone. This is often characterized as a  ["block publication incentive"](https://petertodd.org/2016/block-publication-incentives-for-miners), because in that case the prospect of exhaustively computing all possible transactions (to uncover the missing ones) is completely out of the question.

However, message M4 is different from a withheld-txn, because M4 operates outside of the block's mandated information-processing limits (ie, outside the infamous 1 MB nonwitness blocksize limit). So we should examine the conditions under which M4 grows and shrinks, to ensure that we are not smuggling in a tremendous burden on full nodes.

Under adversarial conditions, to lengthen a long-form M4 by one bit per block, for C blocks, the attacker must pay 312 bits (39 bytes) one time (to embed a new M3 message). The value C is the length of the sidechain's voting period, which varies but which I expect to be approximately 8,064 (and which could theoretically be as high as 65,536). Thus the attacker can burden nodes disproportionately, if (s)he wishes.

Fortunately, the attack in question has no motivation (as far as I can tell). If the miner's goal is to trick rivals into mining on top of invalid blocks, he can already do this much more effectively with the unpublished-txn method (above). If instead he is just trying to harass nodes, then nodes may freely "downgrade" to earlier versions of the protocol, and simply ignore all drivechain-related messages. It seems that the attack could best be used in order to: make a large D2, make D2 confusing, sneak in votes for evil WT^ lurking in D2. Thus, the attack disables the transparency of the drivechain system, to some extent. The cost of the attack is forgone transaction fees, due to block space wasted on useless M3s.

In practice, n is already capped, and miners may impose [on each other] a "soft cap" on m for their mutual protection. Thus, n and m might never get above 10 and 30, respectfully. In this case, the [Short Form, this time] M4 can never require more than 15 bytes per block, no matter what the attacker tries.

In practice, m should always be 1 or 2, else something fishy is going on; and m can only inch up by 1 unit per block. So the system as a whole is still quite transparent, in that users are warned appropriately and well in advance. Attackers must invest upfront and they face an uphill climb, in order to eventually make things more expensive for a few others; defenders can wait-and-see if the attack looks like it will ever amount to anything before lifting a finger.


##### New Block Validation Rules (for D2 and, by implication, M4)

From one block to the next, D2 can only be edited in a few strict ways:

* Entries can only be added/removed from D2 if they meet the criteria above (in M3, and implicitly M1 and M2).
* The ACK-counter of any individual entry can only change by (-1,0,+1) relative to its previous entry.
* Within a sidechain group, upvoting one withdrawal (ACK=ACK+1) requires you to downvote all other withdrawals in that group. However, the minimum ACK value is zero (and, therefore, downvotes cannot reduce it below zero).

##### Footnotes for M4

<sup>1</sup> This represents the worst-case scenario is one where all the Withdrawals are spread evenly over each Sidechain. Under normal operations, there is no reason to expect the all sidechains will have the same number of withdrawals at any given time. In fact, under normal operations, the very *concept* of counting the withdrawals-per-sidechain should be a purposeless one, because there should only be *one* withdrawal at a time. Nonetheless we consider the worst case scenario here.

<sup>2</sup> Guessing becomes more computationally intensive in a highly adversarial situation where the "limited range" is intentionally expanded. In such a scenario, [a] there are many sidechains, and [b] miners voluntarily sacrifice their scarce block-space by creating a high number of (mutually-exclusive, and hence ultimately invalid) withdrawal attempts and putting these into coinbase transactions; and then agree to all [c] vote on these randomly (guaranteeing that all withdrawals fail, including any true withdrawals) and [d] successfully withhold their random voting strategies from nodes (even including spy-miner-nodes). Under this bizarre scenario, nodes may require computing resources which increase near-exponentially with the number of withdrawals, and it may take a long time for an ignorant node to exhaustively work out the underlying state of Withdrawal_DB. In this case, nodes may decide to temporarily stop validating such transactions (as if they had not yet upgraded to support this soft fork).



### Depositing and Withdrawing (M5, M6)


Both M5 and M6 are regular Bitcoin txns. They are identified by meeting an important criteria: they select a one of the Critical TxID-index Pairs (a "CTIP") as one of their inputs. Deposits ("M5") are distinguished from withdrawals ("M6") by simply checking to see if money is "going in", or "out". In other words, we compare the BTC value of the original CTIP to that of new CTIP. If original <= new it is a deposit, if original > new then it is a withdrawal.

The code that identifies sidechain withdrawal / deposit txns (by calculating how much value is being put into or taken out of a sidechain) can be seen here: https://github.com/drivechain-project/bitcoin/blob/mainchainBMM/src/validation.cpp#L351-L386

Such txns are forced (by consensus) to obey two additional criteria:

1. They must contain an output paying "to" the Critical Address [probably in TxOut0].
2. They must be accompanied by an update to this sidechain's Critical TxID-index Pair (CTIP). The new CTIP must be "this" txn itself.

These criteria are enforced here https://github.com/drivechain-project/bitcoin/blob/mainchainBMM/src/validation.cpp#L440-L473 by checking that a deposit is paying back to the sidechain more than it is taking out, and completely rejecting any withdrawal from the mempool. And here https://github.com/drivechain-project/bitcoin/blob/mainchainBMM/src/validation.cpp#L1747-L1757 we allow for a withdrawal only once it has attained sufficient work score (ACKs).

The purpose of this is to have all of the escrow's money (ie all of the sidechain's money) in one TxID, so that depositors immediately undo any UTXO bloat they may cause. This simplifies the withdrawal process, as there is no need to worry about cleaning up "dust deposits" (...and such cleaning can often result in headaches, for example where a withdrawal-txn is larger than 1MB in size, or else may only withdraw an arbitrarily limited amount of BTC). Notice that, unless we assume that an account will last forever, all utxos which are deposited must eventually be withdrawn by someone. Therefore, the relevant design criterion is not "efficiency" (total network cost) but rather "who should pay" (allocation of costs).

#### M5. "Make a Deposit" -- a transfer of BTC from-main-to-side

As far as mainchain consensus is concerned, there are no additional requirements.

However, in practice there *are* additional mainchain requirements...specified by the escrow account, (ie specified by the "sidechain" or "virtual chain"). These requirements are not part of mainchain consensus and are allowed to be anything. In other words, the sidechain is free to invent any way to credit depositor's money -- M5 is fully customizable.

One method, is for mainchain depositors to append a zero-value OP Return to a Deposit txn, so that the sidechain knows how to credit funds. Mainchain users must upgrade their wallet software, of course, (on an individual basis) in order to become aware of and take advantage of new deposit-methods.

##### Inconvenient Race Condition

The requirement that each hashrate escrow be linked to a single TxID does create an interesting inconvenience for depositors. If a user is slow to sign a txn after constructing it (perhaps because the user employs an air-gapped computer, etc), then the signed txn may no longer be valid. This is because the input it selects, may no longer be the Critical TxID (as "the" Critical TxID changes with each deposit). **Only one user can deposit at a time** (although many can deposit per block). As a result, the transaction must fail, and the user would need to be prompted to remake and resign the txn. If this is problem is too frustrating, users can always make main-to-side transfers using atomic cross chain swaps (or, the LN, if they already have a channel open on both chains).

Fortunately, it is already a part of mainchain consensus that no two txns can spend the same TxID. The only new issue here is the confusion it might create for the user (hence the need for error messages and alternative deposit-methods).


#### M6. "Execute Withdrawal" -- a transfer of BTC from-side-to-main

We come, finally, to the critical matter: where users can take their money *out* of the escrow account, and return it to the "regular" UTXO set. As previously mentioned, this txn is one which (a) spends from a CTIP and (b) reduces the quantity of BTC in an account's CTIP. Most of the work has already been done by D1, M3, M4, and D2. Furthermore, existing Bitcoin tx-rules prevent the sidechain from ever withdrawing more money than has been placed into it.

From there, we merely introduce two final concepts:

1. In each block, an entry in D2 is considered an "approved candidate" if the "ACKs" value is above 13140.
2. A "blinded TxID" is way of hashing the txn, in which we first overwrite some parts of the txn with zeros. Specifically, the first 36 bytes of "TxIn0" (the first input, including TxOutHash and TxOutIndex), as well as the first 8 bytes of "TxOut0" (the first output).

Blinding is necessary because we allow each sidechain only one UTXO at a time.

of our restriction of the account to a single UTXO-member. Because of this, during the ACKing process the withdrawal-txn (which is currently being ACKed) may change in two ways: the CTIP (which changes with each deposit), and the total quantity of BTC stored in the account (which arbitrarily increases with each new deposit). In other words, a withdrawal-attempt is created via M3, but this takes place many blocks before the withdrawal is actually included via M6. During this time, a single new deposit to the account would change its CTIP and its value. So, what do we ACK? Well, we ACK a "blinded" version of the withdrawal. This blinded version is stable because the dynamic parts are always overwritten with zeros.

While we ACK a blinded WT^, what is actually included in the blockchain ("M6") is an unblinded WT^. Since each blinded WT^ could correspond to many different unblinded WT^s, we need to impose further restrictions on those unblinded WT^s that are finally included. First, we will force the final unblinded WT^ to spend the entire sidechain balance (by forcing sum(input_values) to equal sum(output_values)). To avoid withdrawing the entire sidechain balance with every withdrawal, we will, secondly, force the unblinded WT^ to create a new output which is itself a deposit to the sidechain it withdrew from (which nodes can check using D1's CTIP field). Unfortunately, these requirements eliminate the possibility of including a transaction fee, as traditionally calculated. So, finally, to compensate for *that*, txn fees are encoded explicitly as a withdrawal to OP_TRUE (which the main:block's miner can immediately claim).

With all of this in place, the only requirements for inclusion in a block are these:

1. "Be ACKed" -- The "blinded TxID" of this txn must be member of the "approved candidate" set in the D2 of this block.
2. "Return Change to Account" -- TxOut0 must pay to the "critical account" (see D1) that corresponds to the CTIP that was selected as a TxIn.
3. "Return *all* Change to Account" -- Sum of inputs must equal the sum of outputs. No traditional tx fee is possible.

Finally, don't forget that M6 inherits the requirement (common to both M5 and M6) that the CTIP be selected as an input, and that the CTIP then be updated. In this case, we know that the critical index will be zero, so the new CTIP will be ("this TxID" (NOT blinded), 0). The TxID is NOT blinded because blinding is only for accumulating ACKs.

As a result of these requirements, every single withdrawal-attempt will fail, unless an entry has been added to D2 and "ACKed" a sufficient number of times.



Backward compatibility
========================

As a soft fork, older software will continue to operate without modification. Non-upgraded nodes will see a number of phenomena that they don't understand -- coinbase txns with non-txn data, value accumulating in anyone-can-spend UTXOs for months at a time, and then random amounts leaving the UTXO in single, infrequent bursts. However, this phenomena doesn't affect them or the validity of the money that they receive.

( As a nice bonus, note that the sidechains themselves inherit a resistance to hard forks. The only way to guarantee that the WT^s reported by different clients will continue to match identically, is to upgrade sidechains via soft forks of themselves. )


Deployment
===========

This BIP will be deployed by "version bits" BIP9 with the name "hrescrow" and using bit 4.

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

See http://www.drivechain.info/literature/index.html


Credits
=========

Thanks to everyone who contributed to the discussion, especially: ZmnSCPxj, Adam Back, Peter Todd, Dan Anderson, Sergio Demian Lerner, Chris Stewart, Matt Corallo, Sjors Provoost, Tier Nolan, Erik Aronesty, Jason Dreyzehner, Joe Miyamoto, Ben Goldhaber.



Copyright
==========

This BIP is licensed under the BSD 2-clause license.
