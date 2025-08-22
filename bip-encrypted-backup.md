```
BIP: ?
Title: Compact encryption scheme for non-seed wallet data
Author: Pyth <pyth@pythcoiner.dev>
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-xxxx
Status: Draft
Type: Specification
Created: 2025-08-22
License: BSD-2-Clause
Post-History: https://delvingbitcoin.org/t/a-simple-backup-scheme-for-wallet-accounts/1607/31
              https://groups.google.com/g/bitcoindev/c/5NgJbpVDgEc
```

## Introduction

### Abstract

This BIP defines a compact encryption scheme for **wallet descriptors** (BIP-0380),
**wallet policies** (BIP-0388), **labels** (BIP-0329), and **wallet backup metadata** (json).
The payload must not contain any private key material.

Users can store encrypted backups on untrusted media or cloud services without leaking
addresses, script structures, or cosigner counts. The encryption key derives from the
lexicographically-sorted public keys in the descriptor, allowing any keyholder to decrypt
without additional secrets.

Though designed for descriptors and policies, the scheme works equally well for labels
and backup metadata.

### Copyright

This BIP is licensed under the BSD 2-Clause License.  
Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the above copyright notice and this permission notice appear
in all copies.

### Motivation

Losing the **wallet descriptor** (or **wallet policy**) is just as catastrophic as
losing the seed itself. The seed lets you sign, but the descriptor maps you to your coins.
For multisig or miniscript wallets, keys alone won't help—without the descriptor, you
can't reconstruct the script.

Offline storage of descriptors has two practical obstacles:

1. **Descriptors are hard to store offline.**  
   Descriptors can be much longer than a 12/24-word seed. Paper and steel backups
   become impractical or error-prone.

2. **Online redundancy carries privacy risk.**  
   USB drives, phones, and cloud storage solve the length problem but expose your
   wallet structure. Plaintext descriptors leak your pubkeys and script details.
   Cloud storage is often unencrypted, and even cloud encryption could be compromised,
   depending on (often opaque) implementation details. Its security also reduces to
   that of the weakest device with cloud access. Each copy increases the attack surface.

This BIP therefore proposes an **encrypted**, and compact backup format that:

* can be **safely stored in multiple places**, including untrusted on-line services,  
* can be **decrypted only by intended holders** of specified public keys,

See the original [Delving post](https://delvingbitcoin.org/t/a-simple-backup-scheme-for-wallet-accounts/1607/31)
for more background.

### Expected properties

* **Encrypted**: safe to store with untrusted cloud providers or backup services  
* **Access controlled**: only designated cosigners can decrypt  
* **Easy to implement**: it should not require any sophisticated tools/libraries.  
* **Vendor-neutral**: works with any hardware signer

### Scope

This proposal targets wallet descriptors (BIP-0380) and policies (BIP-0388), but the
scheme also works for labels (BIP-0329) and other wallet metadata like
[wallet backup](https://github.com/pythcoiner/wallet_backup).

Private key material MUST be removed before encrypting any payload.

## Specification

Note: in the followings sections, the operator ⊕  refers to the bitwise XOR operation.

### Secret generation

- Let $p_1, p_2, \dots, p_n$, be the public keys in the descriptor/wallet policy, in
  increasing lexicographical order
- Let $s$ = sha256("BIP_XXXX_DECRYPTION_SECRET" | $p_1$ | $p_2$ | ... | $p_n$)
- Let $s_i$ = sha256("BIP_XXXX_INDIVIDUAL_SECRET" | $p_i$)
- Let $c_i$ = $s$ ⊕  $s_i$

**Note:** To prevent attackers from decrypting the backup using publicly known
keys, explicitly exclude any public keys with x coordinate
`50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` (the BIP341 NUMS
point, used as a taproot internal key in some applications). Additionally, exclude any
other publicly known keys.

Applications that exclude additional keys SHOULD document this, although decryption
using these keys will simply fail. This does not affect decryption with the remaining
keys.

### Key Normalization

Before computing the encryption secret, all public keys in the descriptor/wallet policy
MUST be normalized to **32-byte x-only public key format**.[^x-only]

[^x-only]: **Why x-only keys?**
    X-only public keys are 32 bytes, a natural size for cryptographic operations.
    This format is also used in BIP340 (Schnorr signatures) and BIP341 (Taproot).

The normalization process depends on the key type:

#### Extended Public Keys (xpubs)

For extended public keys (including those with origin information and/or multipaths):
- Extract the root extended public key
- Extract the **x-coordinate** from its public key (32 bytes)
- Ignore derivation paths, origin information, and multipath specifiers

#### Compressed Public Keys

For 33-byte compressed public keys (0x02 or 0x03 prefix):
- Remove the prefix byte
- Result is 32 bytes (x-coordinate only)

#### X-only Public Keys

Already in the correct format—use as-is (32 bytes).

#### Uncompressed Public Keys

For 65-byte uncompressed public keys (0x04 prefix):
- Extract the x-coordinate (bytes 1-32)
- Result is 32 bytes

See [keys_types.json](./bip-encrypted-backup/test_vectors/keys_types.json) for
normalization test vectors.

### Encryption

The format uses CHACHA20_POLY1305 (RFC 8439) as the default encryption algorithm,
with a 96-bit random nonce and a 128-bit authentication tag to provide confidentiality
and integrity. AES_256_GCM is also supported as an alternative.[^chacha-default]

[^chacha-default]: **Why CHACHA20-POLY1305 as default?**
    ChaCha20-Poly1305 is already used in Bitcoin Core (e.g., BIP324) and is widely
    available in cryptographic libraries. It performs well in software without
    hardware acceleration, making it suitable for hardware wallets and embedded devices.

* let $nonce$ = random(96 bits)
* let $ciphertext$ = encrypt($payload$, $secret$, $nonce$)

### Decryption

In order to decrypt the payload of a backup, the owner of a certain public key p
computes:

* let $s_i$ = sha256("BIP_XXXX_INDIVIDUAL_SECRET" ‖ $p$)
* for each `individual_secret_i` generate `reconstructed_secret_i` =
`individual_secret_i` ⊕ `si`
* for each `reconstructed_secret_i` process $payload$ =
decrypt($ciphertext$, $secret$, $nonce$)

Decryption will succeed if and only if **p** was one of the keys in the
descriptor/wallet policy.

### Encoding

The encrypted backup must be encoded as follows:

`MAGIC` `VERSION` `DERIVATION_PATHS` `INDIVIDUAL_SECRETS` `ENCRYPTION`
`ENCRYPTED_PAYLOAD`

#### Magic

`MAGIC`: 6 bytes which are ASCII/UTF-8 representation of **BIPXXX** (TBD).

#### Version

`VERSION`: 1 byte unsigned integer representing the format version. The current
specification defines version `0x01`.

#### Derivation Paths

Note: the derivation-path vector should not contain duplicates.
Derivation paths are optional; they can be useful to simplify the recovery process
if one has used a non-common derivation path to derive his key.[^derivation-optional]

[^derivation-optional]: **Why are derivation paths optional?**
    When standard derivation paths are used, they are easily discoverable, making
    them straightforward to brute-force. Omitting them enhances privacy by reducing
    the information shared publicly about the descriptor scheme.

`DERIVATION_PATH` follows this format:

`COUNT`  
`CHILD_COUNT` `CHILD` `...` `CHILD`  
`...`  
`CHILD_COUNT` `CHILD` `...` `CHILD`

`COUNT`: 1-byte unsigned integer (0–255) indicating how many derivation paths are
included.  
`CHILD_COUNT`: 1-byte unsigned integer (1–255) indicating how many children are in
the current path.  
`CHILD`: 4-byte big-endian unsigned integer representing a child index per BIP-32.

#### Individual Secrets

At least one individual secret must be supplied.[^no-fingerprints]

[^no-fingerprints]: **Why no fingerprints in plaintext encoding?**
    Including fingerprints would leak direct information about the descriptor
    participants, which compromises privacy.

The `INDIVIDUAL_SECRETS` section follows this format:

`COUNT`  
`INDIVIDUAL_SECRET`  
`INDIVIDUAL_SECRET`

`COUNT`: 1-byte unsigned integer (1–255) indicating how many secrets are included.  
`INDIVIDUAL_SECRET`: 32-byte serialization of the derived individual secret.

Note: the individual secrets vector should not contain duplicates. Implementations
MAY deduplicate secrets during encoding or parsing.

#### Encryption

`ENCRYPTION`: 1-byte unsigned integer identifying the encryption algorithm.

| Value  | Definition                             |
|:-------|:---------------------------------------|
| 0x00   | Reserved                               |
| 0x01   | CHACHA20_POLY1305 (default)            |
| 0x02   | AES_256_GCM                            |

#### Payload Size Limits

CHACHA20_POLY1305 (per RFC 8439) supports plaintext up to 2^38 - 64 bytes.
AES_256_GCM (per RFC 5116) supports plaintext up to 2^36 - 31 bytes.
Implementations MAY impose stricter limits based on platform constraints
(e.g., limiting to 2^32 - 1 bytes on 32-bit architectures).

Implementations MUST reject empty payloads.

#### Ciphertext

`CIPHERTEXT` is the encrypted data resulting from encryption of `PAYLOAD` with algorithm
defined in `ENCRYPTION` where `PAYLOAD` is encoded following this format:

`CONTENT` `PLAINTEXT`

#### Integer Encodings

All variable-length integers are encoded as
[compact size](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer).

#### Content

`CONTENT` is a variable length field defining the type of `PLAINTEXT` being encrypted,
it follows this format:

`TYPE` (`LENGTH`) `DATA`

`TYPE`: 1-byte unsigned integer identifying how to interpret `DATA`.

| Value  | Definition                             |
|:-------|:---------------------------------------|
| 0x00   | Reserved                               |
| 0x01   | BIP Number (big-endian uint16)         |
| 0x02   | Vendor-Specific Opaque Tag             |

`LENGTH`: variable-length integer representing the length of `DATA` in bytes.

For all `TYPE` values except `0x01`, `LENGTH` MUST be present.

`DATA`: variable-length field whose encoding depends on `TYPE`.

For `TYPE` values defined above:
- 0x00: parsers MUST reject the payload.
- 0x01: `LENGTH` MUST be omitted and `DATA` is a 2-byte big-endian unsigned integer
  representing the BIP number that defines it.
- 0x02: `DATA` MUST be `LENGTH` bytes of opaque, vendor-specific data.

For all `TYPE` values except `0x01`, parsers MUST reject `CONTENT` if `LENGTH` exceeds
the remaining payload bytes.

Parsers MUST skip unknown `TYPE` values less than `0x80`, by consuming `LENGTH` bytes
of `DATA`.

For unknown `TYPE` values greater than or equal to `0x80`, parsers MUST stop parsing
`CONTENT`.[^type-upgrade]

[^type-upgrade]: **Why the 0x80 threshold?**
    The `TYPE >= 0x80` rule means we're not stuck with the current TLV encoding.
    It has a nice upgrade property: you can still encode backward compatible stuff
    at the start.

#### Encrypted Payload

`ENCRYPTED_PAYLOAD` follows this format:

`NONCE` `LENGTH` `CIPHERTEXT`

`NONCE`: 12-byte (96-bit) nonce.
`LENGTH`: variable-length integer representing ciphertext length.
`CIPHERTEXT`: variable-length ciphertext.

Note: `CIPHERTEXT` is followed by the end of the `ENCRYPTED_PAYLOAD` section.  
Compliant parsers MUST stop reading after consuming `LENGTH` bytes of ciphertext;
additional trailing bytes are reserved for vendor-specific extensions and MUST
be ignored.

### Text Representation

Implementations SHOULD encode and decode the backup using Base64 (RFC 4648).[^psbt-base64]

[^psbt-base64]: **Why Base64?**
    PSBT (BIP174) is commonly exchanged as a Base64 string, so wallet software
    likely already supports this representation.

## Rationale

See footnotes throughout the specification for design rationale.

### Future Extensions

The version field enables possible future enhancements:

- Additional encryption algorithms
- Support for threshold-based decryption
- Hiding number of participants
- bech32m export

### Implementation

- Rust [implementation](https://github.com/pythcoiner/bitcoin-encrypted-backup)

### Test Vectors

[key_types.json](./bip-encrypted-backup/test_vectors/keys_types.json) contains test
vectors for key serialisations.  
[content_type.json](./bip-encrypted-backup/test_vectors/content_type.json) contains test
vectors for contents types serialisations.  
[derivation_path.json](./bip-encrypted-backup/test_vectors/derivation_path.json) contains
test vectors for derivation paths serialisations.  
[individual_secrets.json](./bip-encrypted-backup/test_vectors/individual_secrets.json)
contains test vectors for individual secrets serialization.  
[encryption_secret.json](./bip-encrypted-backup/test_vectors/encryption_secret.json)
contains test vectors for generation of encryption secret.  
[chacha20poly1305_encryption.json](./bip-encrypted-backup/test_vectors/chacha20poly1305_encryption.json)
contains test vectors for ciphertexts generated using CHACHA20-POLY1305.
[aesgcm256_encryption.json](./bip-encrypted-backup/test_vectors/aesgcm256_encryption.json)
contains test vectors for ciphertexts generated using AES-GCM256.
[encrypted_backup.json](./bip-encrypted-backup/test_vectors/encrypted_backup.json)
contains test vectors for generation of complete encrypted backup.  

## Acknowledgements

// TBD
