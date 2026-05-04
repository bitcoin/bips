```
  BIP: ?
  Layer: Applications
  Title: SwiftSync initial block download
  Authors: Robert Netzke <bips@2140.dev>, Ruben Somsen <bips@2140.dev>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-3-Clause
  Requires: BIP ?, BIP ?
```
# Abstract

_SwiftSync_ is a protocol to accelerate initial block download (IBD) using existing cryptographic primitives and minimal state. The protocol is comprised of hash aggregate for a set of elements and a "hintsfile" to indicate the spent-ness of outputs in the chain history. Using these hints, clients may perform IBD in parallel, which maximizes the use of existing system resources and shifts the performance limitations to internet quality.
# Motivation

Initial block download is the first user experience when using Bitcoin software, and, moreover, is a bootstrapping cost for second layer protocols. Improvements to this process benefit end-users and scaling protocols alike. IBD faces two limitations. First, although the lifetime of coins demonstrates an empirical distribution, cache misses occur for coins that are deleted. This creates unnecessary disk I/O and database compaction. Secondly, given the structure of a block, coins that are spent are indexed by their outpoint. This creates a requirement for clients to maintain a cache to fetch coin metadata associated with an outpoint. _SwiftSync_ alleviates both of these limitations, allowing for IBD in as fast as a client can download blocks and verify signatures.
# Specification

## Definitions

- $H$: A hashing function
- $Hintsfile_{n}$: Defined in BIP ???
- $UTXO_{n}$: Unspent outputs at block height $n$

_SwiftSync_ builds on a common observation in cryptography, that _verification_ is often orders of magnitude more performant than _computation_. What a client seeks to verify when performing _SwiftSync_ is that a unspent transaction output (UTXO) set indeed corresponds to the chain history downloaded from peers.

A key invariant is that a UTXO set state at height $n$ is equivalent to all of the outputs created in the chain history, less all of the inputs:

$Outputs - UTXO_{n} = Inputs$

Given this relationship between the two sets, a client uses hints to $UTXO_{n}$ to verify the chain history they have received is correct. This document describes the fully-validating client, however this protocol may be easily extended to assume-valid assumptions.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.
## Aggregation

A client must compare $Outputs - UTXO_{n}$ with $Inputs$ in a succinct way. Rather than say, comparing the lists, a client may compute two aggregates, and compare the values at the end of the protocol. The _aggregate_ is defined over the data structure of the elements and a hashing function. It is recommended, but not strictly required, that a client uses the typical SHA-256 hash, with an additional randomly generated salt value[^2]. The elements of the set a client compares are _coins_, which are defined as the following:

$Coin = Creation Height + Coinbase Flag + Output Script + Amount + Outpoint$

To add an element to an aggregate, a client computes the $H(Coin)$ and interprets that number as an unsigned 256-bit integer. To update the state of the aggregate, a client simply adds this element to the previous state, modulo 256 bits. Thus, for a set of $Coin$, the _aggregate_ is defined as:

$Agg = H(Coin_{0}) + ... + H(Coin_{i})\mod2^{256}$

## Protocol

Block validation when performing _SwiftSync_ is nearly the same, only with a few additional steps. First, a client requires a $Hintsfile_{n}$ and two aggregates, one for block inputs $Agg_{inputs}$, one for block outputs $Agg_{outputs}$

When downloading blocks, _SwiftSync_ clients will do the following:
1. Download the required block undo data defined in BIP ???
2. Using the undo data, validate the block. A non-exhaustive but explicit list of steps include:
	1. Check the coinbase does not over-claim the block subsidy
	2. Check the number of signature operations
	3. Validate all script executions succeed
	4. Validate non-contextual checks like merkle roots and timestamps
	5. If the block is invalid, disconnect the peer. If the block is valid, continue
3. For all inputs, except the coinbase, add them to $Agg_{inputs}$
4. For all outputs:
	1. If the output is _unspendable_, continue
	2. Add the output to $UTXO_{n}$ if the output is in $Hintsfile_{n}$ and continue
	3. Otherwise, add the output to $Agg_{outputs}$

Notice here that a client does not have to download blocks in any particular order, and may download blocks from multiple peers at a time. A client then verifies $Agg_{outputs} = Agg_{inputs}$ once they have arrived at height $n$[^1]. If the verification succeeds, the client accepts $UTXO_{n}$ as valid. In the failure case, the client rejects $UTXO_{n}$ and attempts to recover using a reindex in the usual serial case.
# Rationale

While there are hash functions, such as siphash, that may offer a performance improvement compared to SHA-256, consensus is already dependent on the cryptographic assumptions of SHA. Thus, SHA-256 is recommended to circumvent adding new cryptographic assumptions to IBD. On griefing, a malicious peer may construct undo data that is valid for the given block, yet it is not spending the correct coins in the history for the chain of most work. Take, for example, a trivially spendable output. The malicious peer may use any script when serving the block inputs, which will alter the output of $H_{salt}(Coin)$, ultimately causing the final verification to fail. To mitigate this, it is encouraged to commit to the hashes of the block inputs, either within the binary or file from a semi-trusted source.
# Note on BIP-30 and BIP-34

During the period between the genesis block and BIP-34 activation, a _SwiftSync_ client must check for duplicate coinbase outputs. A cache of these outputs is modest in memory footprint, and may be easily added and queried for the fixed block range. More information on this caveat is detailed in [this article](https://gist.github.com/RubenSomsen/a02b9071bf81b922dcc9edea7d810b7c).
# Extension to Assume Valid

The protocol may be easily extended, and rather simplified, with similar assumptions to _assume valid_. Rather than hashing the entirety of coin data, a client may take $H(Outpoint)$ and add these results to the aggregates. This removes the need to download block undo data from peers, and is compatible with the current peer-to-peer protocol.

There are, however, a number of drawbacks with this valid approach. At the end of the protocol, the client must also check the total monetary value introduced in the system is less than the expected value for the height $n$. An equivalency check is not possible, as there are instances where coinbase subsidies were under-claimed. Further, the number of signature operations cannot be checked for input scripts, and the order of transactions cannot be checked as well.

Finally, the undo data for the block cannot be computed locally with this approach. This poses a data availability problem, as fully-validating SwiftSync clients will need their connections to serve undo-data.
# Reference Implementation
- [`swiftsync`](https://github.com/2140-dev/swiftsync) Rust implementation
# Acknowledgements

Kudos to my colleague Ruben Somsen for creating the protocol described in this specification
# References
- [Original proposal](https://gist.github.com/RubenSomsen/a61a37d14182ccd78760e477c78133cd)

[^1]: For the aggregate construction, one may observe that, rather than using two aggregates, adding H(Coin) when it is created and subtracting the coin hash when it was spent should result in an aggregate state of $0$ at the end of the protocol. While this is certainly more elegant, the subtractions require computing a field inverse over the field of 256 bits. This small performance cost is unnecessary, as checking for equivalence is sufficient.
[^2]: Any hash function that is resistant to targeted collision attacks is suitable. MuHash serves as another example.
