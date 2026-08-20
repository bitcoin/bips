# BIP-0139 Field Registry

This file is the central repository of fields for the
[BIP-0139](../bip-0139.md) wallet backup format.  
New fields are registered by opening a pull request editing only this file, following
the process described in the
[Field Registry](../bip-0139.md#field-registry) section of BIP-0139.  

## Wallet Fields

Fields of the top-level wallet backup object.  
The mandatory `version` and `accounts` fields are defined in BIP-0139; all fields below
are optional.

- `name`: Optional string wallet name.  
- `note`: Optional string note about this backup, written by the user when the backup is
  made.  
- `network`: Optional string network identifier.  
  Valid values are `bitcoin` (mainnet), `testnet3`, `testnet4`, `signet`, and `regtest`.  
- `last_height`: Optional integer representing the last block height the exporter had
  processed.  
- `proprietary`: Optional JSON object storing application-specific metadata.  

## Account Fields

Fields of the [account object](../bip-0139.md#account-object-structure).  
The mandatory `type` and `descriptor` fields are defined in BIP-0139; all fields below
are optional.

- `name`: Optional string account name.  
- `description`: Optional string account description.  
- `active`: Optional boolean field indicating if the account is active.  
- `output_type`: Optional string describing the output category of the account.  
  Values used by Bitcoin Core are `legacy`, `p2sh-segwit`, `bech32`, and `bech32m`.  
- `change_descriptor`: Optional string representing an explicit change-side
  descriptor, paired with `descriptor`. Intended for wallets that do not use BIP-389
  multipath descriptors (as e.g. Bitcoin Core does).  
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
- `birth_block`: Optional integer representing the account creation time as a bitcoin
  block height.  
- `last_height`: Optional integer representing the last seen block height.  
- `bip352_labels`: Optional array of silent payments labels (`[0,1,2]`), or range (`{0-10}`).  
- `keys`: Optional object mapping descriptor key fingerprints to key metadata objects.
  See [Key Object Structure](../bip-0139.md#key-object-structure).  
- `labels`: Optional array containing label structures for transactions, addresses, and
  keys following [BIP-0329](https://github.com/bitcoin/bips/blob/master/bip-0329.mediawiki).  
- `transactions`: Optional array containing transactions.  
  Wallets may include only transactions spending coins controlled by the account, only
  transactions funding controlled coins, or only their corresponding outpoints.  
  See [Transaction Object Structure](../bip-0139.md#transaction-object-structure).  
- `bip352_outputs`: Optional array of
  [Silent Payment Owned Output Object Structure](../bip-0139.md#silent-payment-owned-output-object-structure).  
- `psbts`: Optional array containing unspent but partially signed transactions, as defined
  by [BIP-0174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) or
  [BIP-0370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki).  
- `bip39_mnemonic`: Optional string containing mnemonic words following BIP39.  
  Since backups may be stored online, this field is intended for test networks only
  (`testnet3`, `testnet4`, `signet`, `regtest`); it MUST NOT be used to store mainnet mnemonics.  
- `proprietary`: Optional JSON object storing account-specific metadata.  

## Key Fields

Fields of the [key object](../bip-0139.md#key-object-structure).  
The mandatory `key` field is defined in BIP-0139; all fields below are optional.

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

## Transaction Fields

Fields of the [transaction object](../bip-0139.md#transaction-object-structure).  
The mandatory `txid` field is defined in BIP-0139; all fields below are optional.

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

## Silent Payment Owned Output Fields

Fields of the
[silent payment owned output object](../bip-0139.md#silent-payment-owned-output-object-structure).  
The mandatory `outpoint` and `tweak` fields are defined in BIP-0139; all fields below are
optional.

- `block_height`: Optional integer representing the height of the block containing
  the transaction.  
  NOTE: if `block_height` value is `null`, it means the outpoints belongs to an
  unconfirmed transaction at the time of backup.  
- `amount`: Optional integer representing the output amount value in sats.  
- `script`: Optional hexadecimal string representing the spending script for this
  outpoint.  
- `label`: Optional string representing a label attached to this output, similar to
  BIP-0329 label.  
- `spend_status`: Optional string describing the spend status of the output.  
  See [Spend Status](#spend-status).  

### Spend Status

The `spend_status` field may contain one of the following values.  

- `unconfirmed`: The transaction is broadcast but not yet confirmed in a block.
- `replaced`: The transaction has been replaced by a transaction confirmed in a block.
- `unspent`: The transaction has been confirmed in a block and the output is unspent.
- `spent`: The transaction has been confirmed in a block and the output is spent.
