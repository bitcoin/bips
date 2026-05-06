```
  BIP: ?
  Layer: Peer Services
  Title: Hints for unspent coins
  Authors: Robert Netzke <bips@2140.dev>
  Deputies: Ruben Somsen <bips@2140.dev>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-3-Clause
```

# Abstract

The SwiftSync protocol requires a client to have foresight, or "hints", into the UTXO set at a state at a particular height, which is verified at the end of the protocol. This document describes a concise representation of the UTXO set. Clients performing SwiftSync may use this file of hints to perform IBD and verify the UTXO set they arrive at is correct.
# Motivation

SwiftSync can improve the user experience by accelerating IBD, however the protocol requires the client verify a UTXO set corresponds to the blockchain history they received. Rather than simply encoding and distributing the UTXO set, a far smaller representation may be computed and shared. Intuitively, just as how it is cheap for programs to share pointers to objects in memory, we define a "hintsfile" that encodes pointers to unspent outputs.
# Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

Our goal is to indicate which outputs in a block, or set of blocks, will remain unspent at a particular chain height. There are many ways to do so, however an intuitive representation is a [bitset](https://en.cppreference.com/w/cpp/utility/bitset.html). Each output in a block is assigned a bit, with a `0` bit denoting the output will be spent, and a `1` to denote the output is unspent. For a block of 8 outputs, we may arrive at a bitset of `1000 0010`, which conveys the 0th and 6th index are UTXOs.

Empirically, this representation does poorly, as the vast majority of outputs are spent. In fact, simply recording the indices within the block that will be unspent is a more optimal approach than the bitset. For our example above, that would be recording the numbers `0, 6`. To efficiently represent this data, we may formulate the problem as the following: what is the most efficient way to represent $n$ random, monotonically increasing indices less than or equal to size $m$? In other words, for a block with $n$ unspent outputs, what is an efficient representation?

This formulation has a known theoretical optimum of $\log_2 \binom{m}{n}$ bits. _Elias-Fano_ developed a representation that is reasonably close to this optimum in a concise and maintainable format.
## Elias-Fano Encoding

Suppose we would like to encode $n$ monotonically increasing elements ${ i_{0}, ..., i_{n - 1} }$ where $i_{n - 1} = m$. _Elias-Fano_ builds on the intuition that numbers may share bits in their binary representation. Consider the integers 6 and 7. The binary representation of 6 is `0110` while the binary representation of 7 is `0111`, differing by only one bit. This observation may be used to efficiently store elements. For the lowest bits of the elements, we will represent them in a bitset, and for the highest bits, we will represent the difference in bits as unary.

We define the following:
- Let ${ i_{0}, ..., i_{n-1} }$ be a list of $n$ elements where $i_{n-1} = m$
- Let $\ell(m, n)$ be the function that determines the number of low bits to use: $\ell(m, n) = \left\lfloor \log_2 \ \left(\frac{m+1}{n}\right) \right\rfloor$
- Let $\text{unary}(q)$ be the following function: $\text{unary}(q) = \underbrace{0\cdots0}_{q}1$

We start by determining $\ell$ for a given $n$ and $m$. For each $i$, take the $\ell$ least significant bits and append them, most significant bit ordering, to a bitset $L$. Next, iterate over each element and take the remaining most significant bits, then record the difference between the last element's high bits and the current element's high bits. Record that number using the $\text unary$ function, and append the unary to a vector $H$. The final representation is $m$, $n$, $L$, $H$.
## Worked Example

Suppose $S = [3, 7, 12]$. Then $n=3$ and $m=12$.
### 1. Compute the number of lower bits to use

We start by computing $\ell$:

$\ell = \left\lfloor \log_2\left(\frac{m+1}{n}\right) \right\rfloor = \left\lfloor \log_2\left(\frac{13}{3}\right) \right\rfloor = \lfloor \log_2(4.33) \rfloor = \lfloor 2.11 \rfloor = 2$

| Element | Binary | Upper (top 2 bits) = `value >> 2` | Lower (bottom 2 bits) = `value & 0b11` |
| ------- | ------ | --------------------------------- | -------------------------------------- |
| 3       | `0011` | `00` → 0                          | `11` → 3                               |
| 7       | `0111` | `01` → 1                          | `11` → 3                               |
| 12      | `1100` | `11` → 3                          | `00` → 0                               |

### 2. Encode the low bits

Next, we will build $L$ by concatenating the lower bits. In the example, we have `11 11 00`, which corresponds to $L = 111100$.

### 3. Encode the high bits

The upper values are $0, 1, 3$. We encode the gaps between consecutive upper values in unary. Note that the first element does not have a previous upper value to compare to, so $0$ is used.

| Element | Upper value | Gap from previous | Unary |
|---------|-------------|-------------------|-------|
| 3       | 0           | 0 (from start)    | `1`   |
| 7       | 1           | 1                 | `01`  |
| 12      | 3           | 2                 | `001` |

Then we will build $H$ by concatenating the unary. In the example, we have `1 01 001`, which corresponds to $H = 101001$.
### 4. Fetching an element

Now we would like to recover an element from the encoding. Supposed we are fetching $S[2] = 12$. We may use a combination of bit shifts and bitwise _OR_ to recover our element.

- To get the lower bits, we read $\ell$ bits from $L$ with offset $2\ell$. In our case,  $L = 111100$, so we read $00$.
- To get the upper bits, we find the position of the third termination bit `1`. In our example , $H = 101001$, and we see that the third `1` is at position 5. To retrieve the high bits we stored, we may take the position and subtract the index, so $5 - 2 = 3$. The position minus the index is equivalent to counting the numbers of $0$. Indeed, this is the value for the high bits of $12$.
- Finally, we combine the low bits and high bits with a bitwise _OR_ and left shift operation: $S[2] = 3 << \ell \mid 0 = 3 << 2 \mid 0 = 12 + 0 = 12$
## Hintsfile

Using _Elias-Fano_ as a primitive, we may now define the _hintsfile_ that will encode which outputs are unspent in a block. A _hintsfile_ is comprised of the following:

| Field   | Value                            | Description                            |
| ------- | -------------------------------- | -------------------------------------- |
| Magic   | `0x55, 0x54, 0x58, 0x4f`         | File identifier                        |
| Version | `0x00`                           | File version                           |
| Height  | 4 byte vector                    | Height, represented in little endian   |
| Hints   | Vector of _Elias Fano_ encodings | The indices that are unspent per block |

The serialization of an _Elias Fano_ representation is:

| Field | Value                   | Serialization | Description                                      |
| ----- | ----------------------- | ------------- | ------------------------------------------------ |
| `N`   | 32 bit unsigned integer | `CompactSize` | The number of indices that are unspent           |
| `M`   | 32 bit unsigned integer | `CompactSize` | Maximum index                                    |
| `L`   | `vector<byte>`          |               | Bitset representing the low bits of the elements |
| `H`   | `vector<byte>`          |               | Unary encoding of the high bits                  |

With the exception that, for `N = 0x00`, the serialization is `0x00`.
### Deserialization

To recover the $L$ and $H$, the client decodes $n$ and $m$, then computes the number of low bits $\ell$. The number of bytes to interpret as $L$ is $\left\lceil \frac{n \cdot \ell}{8} \right\rceil$ and the number of bytes to interpret as $H$ is $\left\lceil \frac{n + \lfloor m / 2^\ell \rfloor}{8} \right\rceil$.
### Constructing the Hintsfile

An _unspendable output_ is defined as:
- An output with script length over 10,000 OR
- An output beginning with `OP_RETURN` OR
- A BIP-30 unspendable coinbase output

The simplest way for a server to construct a hintsfile is to:
1. Read the next block
2. Initialize an empty vector
3. Set the current index to `0`
4. While outputs remain:
	1. If the output is _unspendable_, continue
	2. Query the UTXO set. If the output is not in the UTXO set, increment the current index. Otherwise, write the current index to the vector and go back to step 3.
5. Write the Elias-Fano encoding of the vector to file.

### Interpreting the Hintsfile

After deserializing the hints from file as described above, a client may find the indices of interest by recovering integers $i_{0}, .., i_{n-1}$ using the fetch algorithm. Once the block is received, the client may then iterate over the outputs, adding the outputs with a matching index to the UTXO set, ignoring _unspendable outputs_.

A client interpreting the hintsfile MUST fail decoding if the number of hints does not match the height recorded in the file header. When iterating over the block outputs, a client MUST ignore _unspendable outputs_.
# Rationale

The _Elias Fano_ encoding was selected as it is was the most efficient encoding explored during the research process, yet the implementation is concise and does not require dependencies on third party libraries. As of block height 930,000, the UTXO set may be represented in 119mb with this method, which is well within the 450mb `dbcache` requirement in Bitcoin Core, and reasonable for most clients to hold directly in memory. This encoding represents elements in $2n + n \lceil \log_2(m/n) \rceil$ bits, which is within a reasonable bound of the theoretical optimum.

Partitioning the hints by block is an intuitive choice, and allows for efficient random access of hints. Groupings of multiple blocks were explored, however these had no effect on the file size. Thus, this format opts for simplicity. The removal intrablock spends results in a size reduction of ~4mb for the reference height. While non-trivial, removing these outputs from the index counter would increase the complexity of client code. In particular, portions of the program that are concerned with _adding_ coins must also be aware of when they are _spent_. This implementation complexity would be particularly problematic, for instance, in Bitcoin Core's `AddCoin` method.
# Distribution

A malicious hintsfile distributor cannot lead a client to accepting an invalid UTXO set state, but they can expend time and resources of a client attempting to perform IBD with SwiftSync. Clients SHOULD obtain a hintsfile from a party that has a moral, financial, or otherwise incentive-aligned reason to provide truthful data. Examples of such a party include local community leaders or meetup organizers that have a direct social incentive to provide a useful hintsfile to users.
# Auxiliary Use Cases

Although this file is intended for use with the _SwiftSync_ protocol, it may be possible to accelerate initial block download with a hintsfile alone. The client may use the file to determine if an output should remain in memory or written straight to disk, which is currently a non-trivial design consideration when performing IBD.
# Reference Implementation and Test Vectors

## Reference Implementation(s)
- [Bitcoin Core](https://github.com/rustaceanrob/bitcoin/tree/hintsfile-v1)
- [`hintsfile crate`](https://github.com/rustaceanrob/hintsfile/tree/master)
## Test Vectors
 - [Elias-Fano encoding](test_vectors/hinstfile/elias_fano.json)
# Acknowledgements

Thank you to l0rinc for challenging and reviewing the many iterations of this file, and thank you to Eliam for exploring alternatives and giving insights.
# References
- [Research repository](https://github.com/rustaceanrob/swiftsync-research) 
- [Explanatory article](https://t.holmium.no/dia/elias-fano/#_representation_1_fixed_size_compact_encoding)
- [Paper](https://drops.dagstuhl.de/storage/00lipics/lipics-vol078-cpm2017/LIPIcs.CPM.2017.30/LIPIcs.CPM.2017.30.pdf?utm_source=ppq.ai)
