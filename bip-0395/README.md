# BIP 395: Unspendable internal keys reference implementation

Requires Python 3.10 or later. All dependencies are included or part of the
Python standard library; no package installation is needed.

Implements BIP 395 draft version 0.2.0. The commitment uses sorted, unique
65-byte records containing each referenced compressed public key and chain code.
The preimage is the CompactSize record count followed by the records, hashed
with the tag `WalletPolicy/NUMS/2`. An empty record set has the preimage `00`.

This implementation is for demonstration and interoperability testing, not
production use. Construction acceptance does not establish Miniscript typing,
safety, spendability, wallet-policy validity, or consensus validity. The
implementation does not compile scripts, aggregate MuSig keys, or sign transactions.

## API and modules

[reference.py](reference.py) implements record collection and internal-key construction.

| Function | Result |
| --- | --- |
| `prepare_policy(template, keys_info)` | Validated internal derivation path and sorted, unique records. |
| `construct_root(policy)` | Commitment preimage and chain code, with a method to serialize the synthetic root. |
| `derive_internal_key(policy, expansion, index)` | 32-byte x-only internal key. |
| `export_policy(template, keys_info, network)` | Replacement template, augmented key-information vector, and checksumless descriptor. |

`prepare_policy` returns a `PreparedPolicy` with two fields. `internal_path`
contains child indexes, tuples of multipath alternatives, and a final `None`
for the wildcard. `records` contains the sorted commitment records. Export uses
the supplied template and key information to preserve script key occurrences
and spending conditions.

The network argument is `mainnet` or `testnet`; testnet version bytes also serve
signet and regtest. Export selects the synthetic root's version bytes, assigns it
`@0`, and renumbers the other placeholders by first appearance. Supplied
key-information items are preserved, with unreferenced items placed last.

[policy.py](policy.py) validates the construction grammar and collects key references
and the internal path. [bip32.py](bip32.py) handles public BIP 32 keys, and
[encoding.py](encoding.py) provides Base58Check and CompactSize encoding.
Curve arithmetic and tagged hashing use an unchanged subset of
secp256k1lab 1.0.0; see [UPSTREAM](secp256k1lab/UPSTREAM) for its pinned revision and
source details, and [COPYING](secp256k1lab/COPYING) for its MIT license.

The recursive parser may raise `RecursionError` on deeply nested inputs.

## Test vectors

[vectors.json](vectors.json) contains fixed inputs, intermediate values, and expected
results. Its `version` field identifies the vector format, currently 2, and its `tag`
field identifies the commitment hash tag. Binary values use lowercase hexadecimal.

- Each `valid` case contains `given` inputs, `intermediary` sorted records,
  preimages and chain codes, and `expected` synthetic xpubs, derived
  internal keys, and exports.
- The `equivalent` and `distinct` groups identify cases whose commitments must agree
  or differ. Equal commitments can accompany different internal-key paths and scripts.
  Each case records its own derived internal keys and exported descriptor.
- The `invalid` cases identify the construction stage that must fail. The `prepare`
  stage covers template, path, and referenced-key validation. The `derive` stage
  covers the selected expansion and wildcard index.

These are construction vectors, not a classification of safe wallet policies.
[gen_vectors.py](gen_vectors.py) prints candidate vectors to standard output for
review before replacing the fixed vectors.

Wallets adopting this construction for an existing policy must retain their original
descriptors to watch and spend coins received under the original convention. See the BIP's
[backward compatibility section](../bip-0395.mediawiki#backward-compatibility).

## Running the checks

Run the [offline tests](tests.py) from the repository root:

```sh
python3 -B bip-0395/tests.py
```

The runner reads the fixed vectors without rewriting them. It also checks published
BIP 32 derivations, manually specified commitment preimages, CompactSize boundaries,
and injected invalid-child failures.

The optional [Bitcoin Core cross-check](check_core.py) compares exported xpub
derivation with explicit internal keys for selected descriptors. It also checks
that policies with the same internal key and different spending conditions produce
different addresses.

```sh
python3 -B bip-0395/check_core.py
```

This requires `bitcoind` and `bitcoin-cli` on the executable search path. It starts a
temporary regtest node with peer networking disabled and prints a JSON report. It
does not connect to an existing node or use the user's Bitcoin configuration. See
the [recorded results](core-checks.json).
