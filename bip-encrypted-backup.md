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
   Cloud encryption doesn't help against subpoenas or provider breaches, and each
   copy increases attack surface.  

These constraints lead to an acute need for an **encrypted**, and
ideally compact backup format that:

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

- Let $p_1, p_2, \dots, p_n$, be the public keys in the descriptor/wallet policy, in increasing lexicographical order
- Let $s$ = sha256("BEB_BACKUP_DECRYPTION_SECRET" | $p_1$ | $p_2$ | ... | $p_n$)
- Let $s_i$ = sha256("BEB_BACKUP_INDIVIDUAL_SECRET" | $p_i$)
- Let $c_i$ = $s$ ⊕  $s_i$

**Note:** To prevent attackers from decrypting the backup using publicly known
keys, explicitly exclude any public keys with x coordinate
`50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` (the BIP341 NUMS
point, used as a taproot internal key in some applications). Additionally, exclude any
other publicly known keys. In some cases, it may be possible to exclude certain keys
from this process for customs applications or user needs, it is recommended to document
such decision.

### Key Normalization

Before computing the encryption secret, all public keys in the descriptor/wallet policy MUST be normalized to **33-byte compressed public key format** (SEC format with 0x02 or 0x03 prefix).

The normalization process depends on the key type:

#### Extended Public Keys (xpubs)

For extended public keys (including those with origin information and/or multipaths):
- Extract the root extended public key
- Use its **compressed public key** (33 bytes)
- Ignore derivation paths, origin information, and multipath specifiers

#### Compressed Public Keys

Already in the correct format—use as-is (33 bytes).

#### X-only Public Keys

For 32-byte x-only public keys:
- Prepend 0x02 (assuming even y-coordinate)
- Result is 33 bytes

#### Uncompressed Public Keys

For 65-byte uncompressed public keys (0x04 prefix):
- Compress to SEC format using the y-coordinate parity
- If y is even: prefix with 0x02
- If y is odd: prefix with 0x03
- Result is 33 bytes (prefix + x-coordinate)

See [keys_types.json](./bip-encrypted-backup/test_vectors/keys_types.json) for normalization test vectors.

### AES-GCM Encryption

* let $nonce$ = random()  
* let $ciphertext$ = aes_gcm_256_encrypt($payload$, $secret$, $nonce$)

### AES-GCM Decryption

In order to decrypt the payload of a backup, the owner of a certain public key p
computes:

* let $s_i$ = sha256("BEB_BACKUP_INDIVIDUAL_SECRET" ‖ $p$)  
* for each `individual_secret_i` generate `reconstructed_secret_i` =
`individual_secret_i` ⊕ `si`  
* for each `reconstructed_secret_i` process $payload$ =
aes_gcm_256_decrypt($ciphertext$, $secret$, $nonce$)

Decryption will succeed if and only if **p** was one of the keys in the
descriptor/wallet policy.

### Encoding

The encrypted backup must be encoded as follows:

`MAGIC` `VERSION` `DERIVATION_PATHS` `INDIVIDUAL_SECRETS` `ENCRYPTION`
`ENCRYPTED_PAYLOAD`

#### Magic

`MAGIC`: 3 bytes which are ASCII/UTF-8 representation of **BEB** (`0x42, 0x45,
0x42`).

#### Version

`VERSION`: 1 byte unsigned integer representing the format version. The current
specification defines version `0x01`.

#### Derivation Paths

 Note: the derivation-path vector should not contain duplicates.  
 Derivation paths are optional; they can be useful to simplify the recovery process
if one has used a non-common derivation path to derive his key.

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

At least one individual secret must be supplied.

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
| 0x00   | Undefined                              |
| 0x01   | AES-GCM-256                            |

#### Payload Size Limits

AES-GCM-256 (per RFC5116) supports plaintext up to 2^36 - 31 bytes.  
Implementations MAY impose stricter limits based on platform constraints
(e.g., limiting to 2^32 - 1 bytes on 32-bit architectures).  

Implementations MUST reject empty payloads.

#### Ciphertext

`CIPHERTEXT` is the encrypted data resulting encryption of `PAYLOAD` with algorithm
defined in `ENCRYPTION` where `PAYLOAD` is encoded following this format:

`CONTENT` `PLAINTEXT`

#### Content

`CONTENT` is a variable length field defining the type of `PLAINTEXT` being encrypted,
it follows this format:

`LENGTH` `VARIANT`

`LENGTH`: 1-byte unsigned integer representing the length of `VARIANT` content.  
`VARIANT`: there is 3 variants:  
 - if `LENGTH` == 0, it represent undefined content, no `VARIANT` follow.  
 - if `LENGTH` == 2, `VARIANT` is 2-byte big-endian unsigned integer representing
 the related BIP number that defines the exact content category.  
 - if 2 < `LENGTH` < 0xFF, `VARIANT` is `LENGTH` additional bytes carrying opaque,
 vendor-specific data.  

Note: `LENGTH` = 0xFF is reserved for future extensions. Parsers MUST reject
payloads with `LENGTH` = 0xFF by returning an error.  

#### Encrypted Payload

`ENCRYPTED_PAYLOAD` follows this format:

`NONCE` `LENGTH` `CIPHERTEXT`


`NONCE`: 12-byte nonce for AES-GCM-256.  
`LENGTH`: [compact
size](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer)
integer representing ciphertext length.  
`CIPHERTEXT`: variable-length ciphertext.

Note: `CIPHERTEXT` is followed by the end of the `ENCRYPTED_PAYLOAD` section.  
Compliant parsers MUST stop reading after consuming `LENGTH` bytes of ciphertext;  
additional trailing bytes are reserved for vendor-specific extensions and MUST
be ignored.

## Rationale

 - Why derivation paths are optional: When standard derivation paths are used, they are
 easily discoverable, making them straightforward to brute-force. Omitting them
 enhances privacy by reducing the information shared publicly about the descriptor
 scheme.

- Why avoid including fingerprints in plaintext encoding: Including fingerprints leaks
direct information about the descriptor participants, which compromises privacy.


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
[aesgcm256_encryption.json](./bip-encrypted-backup/test_vectors/aesgcm256_encryption.json)
contains test vectors for ciphertexts generated using AES-GCM256.  
[encrypted_backup.json](./bip-encrypted-backup/test_vectors/encrypted_backup.json)
contains test vectors for generation of complete encrypted backup.  

## Acknowledgements

// TBD
