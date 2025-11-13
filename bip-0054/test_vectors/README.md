## BIP54 test vectors

This folder contains a set of test vectors for each mitigation introduced in the BIP. This document
presents them in more detail.

The code used to generate half of the test vectors is included with the implementation and available
[here][other-vectors]. The other half requires mining mainnet blocks and is [published
separately][bip54-miner]. In both cases it is implemented as a regular Bitcoin Core unit test, and
the test vectors are persisted as a JSON file if the `UPDATE_JSON_TESTS` preprocessor directive is
set (off by default).

To compile the [header][header-miner] and [block][block-miner] miners you may have to link to
libatomic explicitly. This can be achieved like so:
```
cmake -B atomicbuild -DAPPEND_LDFLAGS="-latomic"
cmake --build atomicbuild/ -j $(nproc)
```

[Premined headers][premined-headers] are also provided along with the header miner to allow changing
some of the last headers without having to re-generate the whole chain.


### Difficulty adjustment exploits

The [`timestamps.json`](./timestamps.json) test vectors exercise the two constraints on block header
timestamps introduced by BIP54 to mitigate the Timewarp and Murch-Zawy attacks. Each test case
features a chain of mainnet headers starting from the genesis block, and whether this header chain
is valid by BIP54 rules. Each test case also contains a comment describing why this particular chain
is (in)valid according to BIP54.  All test cases are valid according to current Bitcoin consensus
rules. It is intended to be used to test a BIP54 implementation by feeding the header chain to a
Bitcoin node implementation, enforcing the BIP54 rules on this chain from genesis.

The test vector file features a JSON array of JSON objects, each corresponding to a test case. Each
JSON object features the following entries:
- `header_chain`: a JSON array of strings. An ordered list of hex-encoded mainnet block headers.
- `valid`: a JSON boolean. Whether this chain of headers is valid according to BIP54.
- `comment`: a JSON string. Description of the test case.

For the purpose of testing a Timewarp fix, a Timewarp attack was included early on in the history of
testnet3. An implementer of BIP54 may want to ensure that syncing testnet3 by enforcing BIP54 since
genesis will treat block `00000000118da1e2165a19307b86f87eba814845e8a0f99734dce279ca3fb029` as
invalid.


### Long block validation time

The [`sigops.json`](sigops.json) file contains test vectors for the limit on the number of
potentially-executed legacy signature operations in a single transaction, introduced by BIP54 in
order to mitigate long block validation times. Each test case represents a transaction and whether a
block containing it would be valid according to BIP54. The test cases feature an extensive set of
combinations of inputs and output types, ways to run into the limit, historical violations and some
pathological transactions exhibiting the specific implementation details. All test cases but those
belonging to this last category feature transactions that are valid under current Bitcoin consensus
rules. Each test case also features a comment describing why the transaction is (in)valid according
to BIP54.

The test vector file features a JSON array of JSON objects, each corresponding to a test case. Each
JSON object features the following entries:
- `spent_outputs`: a JSON array of strings. An ordered list of hex-encoded Bitcoin-serialized
  transaction outputs spent by each input of this test case's transaction.
- `tx`: a JSON string. A hex-encoded Bitcoin-serialized transaction to be evaluated.
- `valid`: a JSON boolean. Whether this transaction is valid according to current consensus rules
  supplemented by BIP54.
- `comment`: a JSON string. Description of the test case.


### Merkle tree malleability with 64-byte transactions

The [`txsize.json`](./txsize.json) file contains test cases exercising the new constraint on
non-witness transaction size introduced in BIP54. Each test case contains a transaction and whether
it would be valid according to BIP54, as well as a comment describing why it is (in)valid. All test
cases are otherwise valid according to current Bitcoin consensus rules.

The test vector file features a JSON array of JSON objects, each corresponding to a test case. Each
JSON object features the following entries:
- `tx`: a JSON string. A hex-encoded Bitcoin-serialized transaction to be evaluated.
- `valid`: a JSON boolean. Whether this transaction is valid according to BIP54.
- `comment`: a JSON string. Description of the test case.


### Possibility of duplicate coinbase transactions

The [`coinbases.json`](./coinbases.json) file contains test cases exercising the new restrictions on
coinbase transactions introduced in BIP54 to prevent duplicate coinbase transactions without
resorting to BIP30 validation. Each test case contains a chain of mainnet blocks (including the
genesis block), and whether this block chain is valid according to BIP54. All test cases are valid
according to current Bitcoin's consensus rules, except one that features a block containing a
coinbase transaction timelocked to a future block height.

The test vector file features a JSON array of JSON objects, each corresponding to a test case. Each
JSON object features the following entries:
- `block_chain`: a JSON array of strings. An ordered list of hex-encoded mainnet blocks.
- `valid`: a JSON boolean. Whether this block chain is valid according to current Bitcoin consensus
  rules supplemented by BIP54.
- `comment`: a JSON string. Description of the test case.


[bip54-miner]: https://github.com/darosior/bitcoin/blob/bip54_miner/commits
[header-miner]: https://github.com/darosior/bitcoin/blob/bip54_miner/src/test/bip54_header_miner.cpp
[block-miner]: https://github.com/darosior/bitcoin/blob/bip54_miner/src/test/bip54_block_miner.cpp
[other-vectors]: https://github.com/darosior/bitcoin/blob/2509_inquisition_consensus_cleanup/src/test/bip54_tests.cpp
[premined-headers]: https://github.com/darosior/bitcoin/blob/bip54_miner/src/test/bip54_premined_headers.h
