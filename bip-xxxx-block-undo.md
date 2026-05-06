```
  BIP: ?
  Layer: Peer Services
  Title: Peer sharing of block spent coins
  Authors: Robert Netzke <bips@2140.dev>
  Deputies: Ruben Somsen <bips@2140.dev>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-3-Clause
```

# Abstract

Inputs of a Bitcoin block are referenced by the outpoint data structure. This poses a limitation during initial block download (IBD), such that a client must process blocks sequentially to validate the chain history. The SwiftSync protocol allows blocks to be evaluated in arbitrary order, however additional data is required that must be served over the peer-to-peer network. Namely, the creation height, coinbase flag, input script, and amount for each spent coin must be accessible to fully validate a block in a state-less manner. This data cannot be trusted by a peer under usual conditions, however SwiftSync allows a client performing IBD to validate the correctness of this data.
# Motivation

A current limitation of IBD is that it must be done sequentially. This is a result of the height, coinbase flag, input script, and amount of the block inputs being omitted from the data committed to by proof of work in the current block, and, thus, this data cannot be trusted if received over the wire naively. Using the SwiftSync protocol, a client is able to verify the correctness of this data, even if served by a potentially untrusted party. This is a property of the SwiftSync hash aggregate, which commits to the height, coinbase flag, script, and amount when creating and deleting coins.
# Specification

In Bitcoin Core, to roll-back the chain state in the event of a block reorganization, the height, coinbase flag, script and amount metadata for each input of a block are stored in a data structure known colloquially as "undo data". This terminology stems from its use to "undo" the effect of a block by repopulating the UTXO set with the coins that were spent by the reorganized block. To remain general in language, this data will be referred as "spent coins."

Bitcoin Core full archival nodes store spent coins for all blocks. This is useful in the context of SwiftSync, as no additional index must be created or maintained to serve this data to peers. There are, however, some discrepancies between how this data is serialized on disk in Bitcoin core and how this proposal seeks to serialize this data over the peer-to-peer protocol, which are detailed in the rationale section.

This section defines how to request and serve block spent coins over the peer-to-peer protocol, as well as signaling support of this feature to peers.
## Definitions

- `[]byte`: arbitrary byte vector
- `<N bytes>`: size `N` byte vector
- `vector<Foo>`: arbitrary sized vector of `Foo`
- `CompactSize`: encoding of unsigned integers defined in peer-to-peer messages
- `CompressAmount`: defined in the Function Appendix section

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.
## Data structures
#### Height Code

The height and coinbase flag are encoded as a 32 bit integer. To encode the height and flag, binary left shift the height one bit, treat the boolean as a bit, insert it into the newly opened bit position. To decode the height, binary right shift the code. To decode the coinbase flag, mask the first bit position of the header code and interpret the bit as a boolean.

Take, for example, a height with binary encoding `0010 0111`. To encode a coinbase output at this height, one begins with a left shift: `0100 1110`, and places the coinbase flag in the least significant bit: `0100 1111`.

#### Reconstructable Script Format

| Prefix | Script   | Format                                | Expansion                                                    |
| :------ | :-------- | :------------------------------------- | :------------------------------------------------------------ |
| `0x00` | Unknown  | `CompactSize(Len([]bytes)) + []bytes` | `[]bytes`                                                    |
| `0x01` | `P2PKH`  | `<20 bytes>`                          | `OP_DUP OP_HASH160 20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG` |
| `0x02` | `P2PK`   | `<32 byte 0x02 parity public key>`    | `33 0x02 <32 byte public key> OP_CHECKSIG`                   |
| `0x03` | `P2PK`   | `<32 byte 0x03 parity public key>`    | `33 0x03 <32 byte public key> OP_CHECKSIG`                   |
| `0x04` | `P2PK`   | `<64 byte public key>`                | `65 0x04 <64 byte public key> OP_CHECKSIG`                   |
| `0x05` | `P2SH`   | `<20 bytes>`                          | `OP_HASH160 20 <20 bytes> OP_EQUAL`                          |
| `0x06` | `P2WSH`  | `<32 bytes>`                          | `OP_0 32 <32 bytes>`                                         |
| `0x07` | `P2WPKH` | `<20 bytes>`                          | `OP_0 20 <20 bytes>`                                         |
| `0x08` | `P2TR`   | `<32 byte X-only public key>`         | `OP_1 32 <32 bytes>`                                         |

Scripts are serialized in this format by concatenating the `Prefix` and `Format` fields.
#### Amount Format

The 64 bit unsigned integers representing amounts are compressed by first using the `CompressAmount` function defined below, and serializing the result with `CompactSize`.
#### Coin

| Field                    | Type                          | Serialization | Description                                                                                                       |
| :----------------------- | :---------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------- |
| Input index              | 32 bit unsigned integer       | Little endian | The index in the block inputs for which this coin corresponds. The coinbase inputs are _excluded_ from this index |
| Height and coinbase flag | Height code                   | Little endian |                                                                                                                   |
| Script                   | Reconstructable script format | Defined above |                                                                                                                   |
| Amount                   | 64 bit unsigned integer       | Defined above | Satoshi denominated value                                                                                         |
## Messages

#### MSG_GET_SPENT_COINS

`MSG_GET_SPENT_COINS` defines a request for the inputs of a block.

Define `cmdString` as `getbspent`. Define BIP-324 message type as ???.

| Field       | Type                    | Description                                                               |
| :---------- | :---------------------- | ------------------------------------------------------------------------- |
| `version`   | `byte`                  | Version of the expected serialization in the response                     |
| `blockhash` | 32 byte vector          | Hash of the block for which inputs are requested                          |
| `cutoff`    | 32 bit unsigned integer | If set greater than zero, only include coins created _before_ this height |

#### MSG_SPENT_COINS

`MSG_SPENT_COINS` defines the data structure for inputs of a block.

Define `cmdString` as `bspent`. Define BIP-324 message type as ???.

| Field       | Type                              | Description                                                    |
| :---------- | :-------------------------------- | -------------------------------------------------------------- |
| `blockhash` | 32 byte vector                    | Block hash these coins are spent from                          |
| `len`       | `CompactSize(Len(vector<Coins>))` | The length of the coins vector                                 |
| `coins`     | `vector<Coin>`                    | Coins that were spent, after filtering on the request `cutoff` |

A client supporting the `bspent` MUST include coins created _before_ the `cutoff` field in `getbspent` requests. A client receiving a `bspent` message with un-requested or missing coins MUST disconnect from the serving peer. A client supporting `bspent` MUST adhere to the format of `Coin` specified in the `verion` of the request.

## Signaling

Support for serving historical block undo data is advertised by a service bit. 

| Field             | Value      |
| :----------------- | :---------- |
| `NODE_BLOCK_UNDO` | `1 << ???` |

A client advertising this service bit SHOULD respond to `getbspent` messages, subject to rate-limiting and bandwidth limiting.
# Rationale

The lifetime, or interval between creation and spending height, of the coins on the Bitcoin blockchain demonstrate an empirical phenomena that the majority of coins are spent within 100 blocks. In fact, approximately 41 percent of coins are spent within 10 blocks at the time of writing[^1]. Clients may leverage this to reduce the bandwidth required to fetch undo data by using an in-memory cache. For example, a client may store coins that were created in a 5 block window, and request only coins that are older than this height via the `cutoff` filter. This results in a significant bandwidth reduction at the cost of a cache that can be set dynamically by the client depending on available memory.

Beyond the use of a dynamic coin height filter, there are additional reasons to not simply read the undo data from disk and send it over the wire. Legacy fields (`nVersion`) are set to `0x00` when writing and reading this data to maintain compatibility of disk format with old clients. Furthermore, using the amount compression specified above, an 11gb reduction in bandwidth is achieved. The application of `VARINT` as opposed to `CompactSize` offers a further reduction of 4gb, however the `VARINT` primitive is currently a Bitcoin Core implementation detail. Reusing existing network primitives results in the majority of savings, so this specification opts to lower implementation burden for clients. With respect to reconstructable script, utilizing this format results in a savings of around 12gb. The scheme is loss-less, and may be upgradable by appending script variants. For reference, the naive encoding of block undo data is 118gb as of block 930,000[^1][^2][^3].
# Function Appendix

Bitcoin Core utilizes a technique to remove trailing zeros from the representation of amounts. This technique offers a significant size reduction in amount serialization. These functions are duplicated from the [test framework](https://github.com/bitcoin/bitcoin/blob/master/test/functional/test_framework/compressor.py).
## Compress Amount

```python
def compress_amount(n):
    if n == 0:
        return 0
    e = 0
    while ((n % 10) == 0) and (e < 9):
        n //= 10
        e += 1
    if e < 9:
        d = n % 10
        assert (d >= 1 and d <= 9)
        n //= 10
        return 1 + (n*9 + d - 1)*10 + e
    else:
        return 1 + (n - 1)*10 + 9
```
## Decompress Amount

```python
def decompress_amount(x):
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    n = 0
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n
```
# Compatibility

Clients seeking to perform fully-validating SwiftSync require peers that serve undo data. Serving data requires no additional index and may be enabled via the service bit.
# Reference Implementation and Test Vectors
## Reference Implementation
- [Bitcoin Core](https://github.com/rustaceanrob/bitcoin/tree/bip-block-undo)

## Test Vectors
- [Reconstructable script](test_vectors/block_undo/reconstructable_script.json)
- [Compressed Amount](test_vectors/block_undo/compressed_amount.json)

In order: `P2PKH, P2SH, P2TR, P2WPKH, P2WSH, P2PK (odd), P2PK (even), P2PK (uncompressed), OP_RETURN (unspendable/unknown)`

# Footnotes
[^1]: Relevant statistics may be generated via binaries in the [`swiftsync-research`](https://github.com/rustaceanrob/swiftsync-research) repository
[^2]: Reconstructable scripts are borrowed from [UTREEXO](https://github.com/bitcoin/bips/pull/1923) which is subsequently borrowed from Cory Field's UHS proposal
[^3]: Astute readers may notice uncompressed public keys may be compressed before they are sent and decompressed by the receiving client. Although this would slightly reduce bandwidth, it would increase the complexity of client code, as a `secp256k1` context would be required to decode the message, which is not currently a requirement. As of height 936,212 the number of uncompressed public keys spent in blocks is 853,515. This represents a very modest savings in bandwidth, around 30MB. As such, this technique is omitted for implementation simplicity.

