# Unspendable internal keys: reference implementation

Requires Python 3.10 or later. All dependencies are included or part of the
Python standard library; no package installation is needed.

This implementation is for demonstration and interoperability testing, not
production use. Construction acceptance does not establish Miniscript typing,
safety, spendability, wallet-policy validity, or consensus validity. The
implementation does not compile scripts, aggregate MuSig keys, or sign transactions.

## API and modules

[reference.py](reference.py) implements this BIP's normalization and construction:

| Function | Result |
| --- | --- |
| `normalize_policy(template, keys_info)` | Normalized template and ordered records. |
| `construct_root(policy)` | Commitment preimage and chain code, with a method to serialize the synthetic root. |
| `derive_internal_key(policy, expansion, index)` | 32-byte x-only internal key. |
| `export_policy(template, keys_info, network)` | Replacement template, augmented key-information vector, and checksumless descriptor. |

The network argument is `mainnet` or `testnet`; testnet version bytes also serve
signet and regtest. Export selects the synthetic root's version bytes, assigns it
`@0`, and renumbers the other placeholders by first appearance. Supplied
key-information items are preserved, with unreferenced items placed last.

[policy.py](policy.py) provides parsing and printing, [bip32.py](bip32.py) handles
public BIP 32 keys, and [encoding.py](encoding.py) provides Base58Check and CompactSize
encoding. Curve arithmetic and tagged hashing use an unchanged subset of
secp256k1lab 1.0.0; see [UPSTREAM](secp256k1lab/UPSTREAM) for its pinned revision and
source details, and [COPYING](secp256k1lab/COPYING) for its MIT license.

The recursive parser and normalizer may raise `RecursionError` on deeply nested inputs.

## Test vectors

[vectors.json](vectors.json) contains fixed inputs, intermediate values, and expected
results. Its `version` field identifies the vector format. Binary values use lowercase
hexadecimal.

- Each `valid` case contains `given` inputs, `intermediary` normalized templates,
  records, preimages, and chain codes, and `expected` synthetic xpubs, derived
  internal keys, and exports.
- The `equivalent` and `distinct` groups identify cases whose commitments must agree
  or differ.
- The `invalid` cases identify the construction stage that must fail.

These are construction vectors, not a classification of safe wallet policies.
[gen_vectors.py](gen_vectors.py) prints candidate vectors to standard output for
review before replacing the fixed vectors.

## Running the checks

Run the [offline tests](tests.py) from the repository root:

```sh
python3 -B bip-unspendable-internal-keys/tests.py
```

The runner reads the fixed vectors without rewriting them. It also checks published
BIP 32 derivations, manually specified commitment preimages, CompactSize boundaries,
and injected invalid-child failures.

The optional [Bitcoin Core cross-check](check_core.py) compares exported xpub
derivation with explicit internal keys for selected descriptors:

```sh
python3 -B bip-unspendable-internal-keys/check_core.py
```

This requires `bitcoind` and `bitcoin-cli` on the executable search path. It starts a
temporary regtest node with peer networking disabled and prints a JSON report. It
does not connect to an existing node or use the user's Bitcoin configuration. See
the [recorded results](core-checks.json).
