```
BIP: ?  
Layer: Applications  
Title: Compact encryption scheme for non-seed wallet data  
Author: // TBD  
Comments-Summary: No comments yet.  
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-????  
Status: Draft  
Type: Informational  
Created: 2025-08-22  
License: BSD-2-Clause  
```

## Introduction

### Abstract

This BIP defines a compact encryption scheme for **wallet descriptors** (BIP-0380),
**wallet policies** (BIP-0388), **labels** (BIP-0329), and
**wallet backup metadata** (json). The payload must not contains any private key material.
This scheme enables users to outsource long‑term storage to untrusted media or cloud
services without revealing which addresses, scripts, or number of cosigners are involved.
Encryption keys are derived from the lexicographically‑sorted public keys inside the
descriptor or policy, so any party who already holds one of those keys can later decrypt
the backup without extra secrets or round‑trips. The format uses AES-GCM-256 with a 96‑bit
random nonce and a 128‑bit authentication tag to provide confidentiality and integrity.
While initially designed for descriptors and policies, the same scheme encrypts labels
and backup metadata, allowing a uniform, vendor‑neutral, and future‑extensible backup format.

### Copyright

This BIP is licensed under the BSD 2-Clause License.  
Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the above copyright notice and this permission notice appear
in all copies.

### Motivation

In practice, losing the **wallet descriptor** (or **wallet policy**) is often **as
catastrophic as losing the wallet’s seed** itself.  While the seed grants the
ability to sign, the descriptor grants a map to the coins.  In multisig or
miniscript contexts, keys alone are **not sufficient** for recovery: without the
original descriptor the wallet cannot reconstruct the script.

Offline storage of descriptors has two practical obstacles:

1. **Descriptors are hard to store offline.**  
   Descriptor string representation can be far longer than a 12/24-word seed phrase.  
Paper, steel, and other long-term analog media quickly become impractical for such
lengths, or error-prone to transcribe.

2. **Online redundancy carries privacy risk.**  
   Keeping backups on USB thumb-drives, computers, phones, or (worst) cloud drives
avoids the first problem but amplifies surveillance risk: anyone who gains these
**plaintext descriptors** learns the wallet’s public keys, script structure,
etc...  Even with encryption at the cloud provider, an attacker or a subpoena can
compel access, and each extra copy multiplies the attack surface.

These constraints lead to an acute need for an **encrypted**, and
ideally compact backup format that:

* can be **safely stored in multiple places**, including untrusted on-line services,  
* can be **decrypted only by intended holders** of specified public keys,  

See the original [Delving post](https://delvingbitcoin.org/t/a-simple-backup-scheme-for-wallet-accounts/1607/31)
for more background.

### Expected properties

* **Encrypted**: this allows users to outsource its storage to untrusted parties,
for example, cloud providers, specialized services, etc.  
* **Has access control**: decrypting it should only be available to the desired
parties (typically, a subset of the cosigners).  
* **Easy to implement**: it should not require any sophisticated tools.  
* **Vendor-independent**: it should be easy to implement using any hardware signing
device.  

### Scope

The primary motivation of this proposal is to store a wallet descriptor(BIP-0380) or a
wallet policy(BIP-0388), but it seems valuable enough to also use this scheme to encrypt
payload containing others wallet-related metadata, like Labels(BIP-0329) or
[wallet backup](https://github.com/pythcoiner/wallet_backup).

Note: For any kind of payload intented to be encrypted with this scheme, private key
material MUST be removed before encryption.

## Specification

Note: in the followings sections, the operator ⊕  refers to the bitwise XOR operation.

### Secret generation

- Let $p_1, p_2, \dots, p_n$, be the public keys in the descriptor/wallet policy, in increasing lexicographical order
- Let $s =$ sha256("BEB_DECRYPTION_SECRET" $\| p_1 \| p_2 \| \dots \| p_n)$
- Let $s_i =$ sha256("BEB_INDIVIDUAL_SECRET" $\| p_i)$
- Let $c_i = s \oplus s_i $

### AES-GCM Encryption

* let `nonce` = random()  
* let `ciphertext` = aes_gcm_256_encrypt(`payload`, `secret`, `nonce`)

### AES-GCM Decryption

In order to decrypt the payload of a backup, the owner of a certain public key p
computes:

* let `si` = sha256("BEB_INDIVIDUAL_SECRET" ‖ `p`)  
* for each `individual_secret_i` generate `reconstructed_secret_i` =
`individual_secret_i` ⊕ `si`  
* for each `reconstructed_secret_i` process `payload` =
aes_gcm_256_decrypt(`ciphertext`, `secret`, `nonce`)

Decryption will succeed if and only if **p** was one of the keys in the
descriptor/wallet policy.

### Encoding

The encrypted backup must be encoded as follows:

`MAGIC` `VERSION` `DERIVATION_PATHS` `INDIVIDUAL_SECRETS` `CONTENT` `ENCRYPTION`
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

#### Content

`CONTENT`: 1-byte unsigned integer identifying what has been encrypted.

| Value  | Definition                             |
|:-------|:---------------------------------------|
| 0x00   | Undefined                              |
| 0x01   | BIP-0380 Descriptor (string)           |
| 0x02   | BIP-0388 Wallet policy (string)        |
| 0x03   | BIP-0329 Labels (JSONL)                |
| 0x04   | Wallet backup (JSON)                   |

#### Encrypted Payload

`ENCRYPTED_PAYLOAD` follows this format:

`TYPE` `NONCE` `LENGTH` `CIPHERTEXT`

`TYPE`: 1-byte unsigned integer identifying the encryption algorithm.  

| Value  | Definition                             |
|:-------|:---------------------------------------|
| 0x00   | Undefined                              |
| 0x01   | AES-GCM-256                            |

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

### Implementation

- rust [implementation](https://github.com/pythcoiner/encrypted_backup)

### Test Vectors

See rust implementation [tests](https://github.com/pythcoiner/encrypted_backup/blob/3280f6f9706497671f08d9365414315159080a84/src/ll.rs#L511)

## Acknowledgements

// TBD
