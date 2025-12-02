```
BIP: ?
Layer: Applications
Title: Wallet Metadata Backup Format
Authors: Pyth <pythcoiner@wizardsardine.com>
Status: Draft
Type: Specification
Assigned: ?
License: BSD-2-Clause
Discussion: https://groups.google.com/g/bitcoindev/c/ylPeOnEIhO8
```

## Abstract

This document specifies a format for exporting wallet backup data, including accounts,
descriptors, associated keys, labels, transactions, and partially signed Bitcoin
transactions (PSBTs).
The format aims to standardize wallet backup and restore operations across different
Bitcoin wallet implementations by providing a common structure and field naming
conventions.
All fields are optional except for the base structure, which must include at least one
account entry.

## Copyright

This BIP is licensed under the BSD 2-clause license.

## Motivation

Bitcoin software wallets store various forms of metadata beyond just private keys,
including account structures, descriptors, labels, and transaction history.  
While [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
and [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) provide
standardized mechanisms for key recovery, they do not preserve additional wallet-specific
metadata necessary for seamless migration between wallets.

A standardized wallet backup format ensures that users can migrate wallets without losing
critical metadata, reducing vendor lock-in and enabling more robust recovery options.
This BIP serves as a central repository where wallet developers can document their usage
of the global format, improving interoperability without forcing a specific
implementation.

## Rationale

Several wallet implementations store backup data in proprietary formats, making migration
difficult.  
This proposal introduces a structured, human-readable format, leveraging JSON to store
wallet metadata in a portable way.  
The format is flexible and extensible, allowing wallet developers to include as much or
as little information as they think necessary.  

By making all fields optional except for the base structure with at least one account,
this standard accommodates diverse use cases and preferences.  
Wallet developers can include only the fields relevant to their application while
maintaining structural integrity.  

## Specification

A wallet backup is a UTF-8 encoded text file containing a single valid JSON object
representing the backup structure.  
This object includes wallet-level metadata, multiple accounts, and associated key data.  

### version

This BIP defines version 1 of this specification.  

### Wallet Backup Structure

The top-level JSON object must contain at least one account in the `accounts` array.  
All other fields are optional.  

- `version`: Optional integer version of the backup format.  
- `bip`: Optional integer value representing the number of this BIP.  
- `name`: Optional string wallet name.  
  NOTE: `alias` is an alias of `name`.  
- `description`: Optional string wallet description.  
- `accounts`: Mandatory array of account objects.  
  Must contain at least one account.  
  See [Account Object Structure](#account-object-structure).  
- `network`: Optional string network identifier.  
  Valid values are `bitcoin` (mainnet), `testnet3`, `testnet4`, `signet`, and `regtest`.  
- `last_height`: Optional integer representing the last block height the exporter had
  processed.  
- `proprietary`: Optional JSON object storing application-specific metadata.  

### Account Object Structure

Each account object in the `accounts` array represents a single account within the wallet.
All fields are optional, allowing wallets to include only the metadata they support.

- `name`: Optional string account name.  
  NOTE: `alias` is an alias of `name`.  
- `description`: Optional string account description.  
- `active`: Optional boolean field indicating if the account is active.  
- `type`: Optional string describing the account type.  
  Possible values include `bip_380` (output descriptor), `bip_388` (wallet policies),
  `bip_392` (silent payments), or any arbitrary string representing metadata needed to
  find and spend coins for an account.  
- `output_type`: Optional string describing the output category of the account.  
  Values used by bitcoin core are `legacy`, `p2sh-segwit`, `bech32`, and `bech32m`.  
- `descriptor`: Optional string or object representing the account structure as
  defined by the value in `type`.  
- `change_descriptor`: Optional string or object representing an explicit change-side
  descriptor, paired with `descriptor`. Intended for wallets that do not use BIP-389
  multipath descriptors (e.g. Bitcoin Core).  
- `descriptor_id`: Optional string containing a stable hexadecimal identifier for the
  receive `descriptor`. Its construction is implementation-defined, but it MUST be stable
  across exports of the same descriptor.  
- `change_descriptor_id`: Optional string. Same semantics as `descriptor_id`, for
  `change_descriptor`.  
- `receive_index`: Optional integer representing the maximum receive index for generated
  receive addresses.  
- `change_index`: Optional integer representing the maximum change index for generated
  change addresses.  
- `range_start`: Optional integer representing the cached keypool range start of the
  receive `descriptor`. Present only for ranged descriptors.  
- `range_end`: Optional integer representing the cached keypool range end of the receive
  `descriptor`. Present only for ranged descriptors.  
- `change_range_start`: Optional integer representing the cached keypool range start of
  the `change_descriptor`. Present only for ranged descriptors.  
- `change_range_end`: Optional integer representing the cached keypool range end of the
  `change_descriptor`. Present only for ranged descriptors.  
- `timestamp`: Optional integer Unix timestamp representing account creation time in
  seconds.  
- `iso_8601_datetime`: optional string representing account creation time in ISO 8601
  format.  
- `block_height`: Optional integer representing account creation time in bitcoin block
  height unit.  
- `last_height`: Optional integer representing the last seen block height.  
- `bip352_labels`: Optional array of silent payments labels (`[0,1,2]`), or range (`{0-10}`).  
- `keys`: Optional object mapping descriptor key fingerprints to key metadata objects.
  See [Key Object Structure](#key-object-structure).  
- `bip329_labels`: Optional array containing label structures for transactions, addresses, and
  keys following [BIP-0329](https://github.com/bitcoin/bips/blob/master/bip-0329.mediawiki).  
  NOTE: `labels` is an alias of `bip329_labels`.  
- `transactions`: Optional array containing transactions.  
  Wallets may include only transactions spending coins controlled by the account, only
  transactions funding controlled coins, or only their corresponding outpoints.  
  See [Transaction Object Structure](#transaction-object-structure).  
- `bip352_outputs`: Optional array of
  [Silent Payment Owned Output Object Structure](#silent-payment-owned-output-object-structure).  
- `bip174_psbts`: Optional array containing unspent but partially signed transactions as defined
  by [BIP-0174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki).  
- `bip370_psbts`: Optional array containing unspent but partially signed transactions as defined
  by [BIP-0370](https://github.com/bitcoin/bips/blob/master/bip-370.mediawiki).  
- `psbts`: Optinnal array than can contains both BIP-0174 & BIP-0370 PSBTs.  
- `bip39_mnemonic`: Optional string containing mnemonic words following BIP39.  
  Since backups may be stored online, storing mainnet mnemonics is strongly discouraged.  
- `proprietary`: Optional JSON object storing account-specific metadata.  

### Key Object Structure

Keys in the `keys` dictionary are indexed by their
[BIP32 fingerprint](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers).
Each key object contains metadata about the key.

- `key`: Optional string representing the public key fingerprint in hexadecimal form.  
- `alias`: Optional string user-defined alias for the key.  
- `role`: Optional string role of the key in wallet operations.  
  See [Key Roles](#key-roles).  
- `key_type`: Optional string describing ownership of the key.  
  See [Key Types](#key-types).  
- `key_status`: Optional string describing the status of the key.  
  See [Key Status](#key-status).  
- `bip85_derivation_path`: Optional string describing the
  [BIP-0085](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) derivation
  path used to derive this key from the master key.  

### Key Roles

The `role` field may contain one of the following values.  

- `main`: Key used for normal spending conditions.  
- `recovery`: Key designated for recovery scenarios.  
- `inheritance`: Key to inherit funds if the primary user disappears.  
- `cosigning`: Key designated for policy-enforcing cosigning.  

### Key Types

The `key_type` field may contain one of the following values.  

- `internal`: Main user-owned key.  
- `external`: Key held by heirs or trusted individuals.  
- `third_party`: Key held by a service provider.  

### Key Status

The `key_status` field may contain one of the following values.  

- `active`: The key is actively used.  
- `inactive`: The key is not yet actively used.  
- `revoked`: The key has been revoked and MUST NOT be used anymore.  

### Transaction Object Structure

Each entry in the `transactions` array is a JSON object describing a single transaction
relevant to the account. All fields are optional except `txid`.

- `txid`: Optional string containing the transaction id (hex).  
- `wtxid`: Optional string containing the witness transaction id (hex). Segwit only.  
- `hex`: Optional string containing the raw transaction (hex).  
- `time`: Optional integer representing the best-known transaction time in unix
  seconds. Block time when confirmed, otherwise first-seen time.  
- `time_received`: Optional integer representing when the exporting wallet first
  observed the transaction, in unix seconds. MAY be earlier than `time`.  
- `blockhash`: Optional string containing the confirming block hash (hex).  
- `blockheight`: Optional integer containing the confirming block height.  
- `blockindex`: Optional integer containing the position of the transaction in the
  confirming block.  
- `abandoned`: Optional boolean representing user-driven abandoned state, separate
  from mempool eviction.  

### Silent Payment Owned Output Object Structure

- `outpoint`: Optional string representing the outpoint in the form `<txid>:<vout>`.  
- `block_height`: Optional integer representing the height of the block containing
  the transaction.  
  NOTE: if `block_height` value is `null`, it means the outpoints belongs to an
  unconfirmed transaction at the time of backup.  
- `tweak`: Optional hexadecimal string representing the tweak.  
- `amount`: Optional integer representing the output amount value in sats.  
- `script`: Optional hexadecimal string representing the spending script for this
  outpoint.  
- `label`: Optional string representing a label attached to this output, similar to
  BIP-0329 label.  
- `spend_status`: Optional string describing the spend status of the output.  
  See [Spend status](#spend-status).  

### Spend Status

The `spend_status` field may contain one of the following values.  

- `unconfirmed`: The transaction is broadcast but not yet confirmed in a block.
- `replaced`: The transaction has been replaced by a transaction confirmed in a block.
- `unspent`: The transaction has been confirmed in a block and the output is unspent.
- `spent`: The transaction has been confirmed in a block and the output is spent.

## Importing

When importing a wallet backup follow these guidelines.  

* Importing wallets should preserve all metadata they support and discard unsupported
  fields.  
* Wallets should warn users if essential data cannot be restored.  
* Wallets should ensure that key roles and types are properly mapped to their internal
  structures if used.  
* Wallets may truncate labels or other string fields if necessary, but should warn users
  when truncation occurs.  
* Wallets should validate the structure and ensure at least one account is present before
  attempting import.  

## Encryption

This format can be encrypted following [BIP-XXXX](https://github.com/bitcoin/bips/pull/1951).

## Security Considerations

* The backup format should not include private keys to avoid unintended key exposure.  
* Backups should be encrypted to prevent unauthorized access.  
* Care should be taken to ensure that proprietary metadata does not contain sensitive
  information.  
* Since backups may be stored online or in cloud storage, storing mainnet mnemonics or
  private keys is strongly discouraged.  

## Backwards Compatibility

This format is extensible and allows future additions without breaking compatibility.  
Wallets may ignore fields they do not recognize while maintaining the structural
integrity of the backup.  
Future revisions may add fields, and wallets should gracefully handle unknown entries by
ignoring them.  

## Reference Implementation

TBD

## References

* [BIP-0032: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
* [BIP-0039: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
* [BIP-0174: Partially Signed Bitcoin Transaction Format](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
* [BIP-0329: Wallet Labels Export Format](https://github.com/bitcoin/bips/blob/master/bip-0329.mediawiki)
* [BIP-0380: Output Script Descriptors](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
* [BIP-0085: Deterministic Entropy From BIP32 Keychains](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
