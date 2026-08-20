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
- `date`: Optional timestamp recording when the backup was made.  
- `network`: Optional string network identifier.  
  Valid values are `bitcoin` (mainnet), `testnet3`, `testnet4`, `signet`, `mutinynet`
  and `regtest`.  
  A backup covers a single network. A wallet holding accounts on more than one writes one
  backup per network.  
  A signet is defined by its challenge script, so this list names only the well-known
  ones. Any other signet uses `signet`, and a wallet needing to tell two of them apart
  records the challenge in `proprietary`.  
- `transactions`: Optional object mapping a transaction id to a transaction object.  
  See [Transaction Object Structure](../bip-0139.md#transaction-object-structure).  
  Transactions live here rather than on the account so that one touching several
  accounts is stored once, and so that a wallet that cannot attribute a transaction to
  an account can still carry it.  
- `psbts`: Optional object mapping a transaction id to a partially signed transaction, as
  defined by [BIP-0174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) or
  [BIP-0370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki).  
  The key is the txid of the PSBT's unsigned transaction. That value is stable for the
  whole signing process, whereas the txid of the finished transaction changes as legacy
  inputs are signed.  
  PSBTs live here rather than on the account so that one spending inputs from several
  accounts is stored once, and so that a wallet holding PSBTs it cannot attribute to an
  account can still carry them.  
- `signers`: Optional array of signer objects.  
  See [Signer Object Structure](../bip-0139.md#signer-object-structure).  
- `proprietary`: Optional JSON object storing application-specific metadata.  

## Account Fields

Fields of the [account object](../bip-0139.md#account-object-structure).  
The mandatory `type` and `descriptor` fields are defined in BIP-0139; all fields below
are optional.

- `name`: Optional string account name.  
- `description`: Optional string account description.  
- `status`: Optional string describing where the account is in its lifecycle.  
  See [Account Status](#account-status).  
- `hidden`: Optional boolean recording that the account is suppressed in the exporting
  wallet's interface. This is independent of `status`: a hidden account may still be
  active.  
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
- `gap_limit`: Optional integer number of consecutive unused addresses an importer must
  scan past the last used one before concluding there are no more.  
  A single value covers both the receive and change sides. An exporter holding a distinct
  limit per side should emit the larger, since a limit that is too high only costs
  scanning work while one that is too low misses addresses.  
- `birth_block`: Optional integer representing the account creation time as a bitcoin
  block height. An importer may start scanning at this height instead of the genesis
  block.  
  Most wallets record a creation date rather than a height. An exporter holding only a
  date SHOULD convert it against a chain source.  
  If it cannot, it MAY estimate the height, and the estimate MUST be at or before the true
  height, never after. The error is asymmetric: too early only costs scanning time, while
  too late silently misses transactions and the funds in them. An estimate from a date
  should therefore subtract a margin covering the drift of a fixed block interval, on the
  order of a difficulty period.  
  An exporter that can do neither SHOULD omit the field. An absent `birth_block` means a
  full scan, which is slow but correct.  
- `last_height`: Optional integer height this account has been synced to.  
  A wallet that tracks one sync point for the whole backup writes that same height into
  every account. Accounts that sync independently, such as a separately scanned silent
  payments account, carry their own.  
- `bip352_labels`: Optional list of the silent payment label indices in use.  
  Either an array of integers (`[0, 1, 2]`) or an object with `start` and `end` members
  (`{"start": 0, "end": 10}`), where `end` is exclusive, matching `range_start` and
  `range_end`.  
  An importer that does not know which labels were issued cannot detect outputs paid to
  them, so omitting a label in use loses the funds received on it.  
- `keys`: Optional object mapping descriptor key fingerprints to key metadata objects.
  See [Key Object Structure](../bip-0139.md#key-object-structure).  
- `labels`: Optional array containing label structures for transactions, addresses, and
  keys following [BIP-0329](https://github.com/bitcoin/bips/blob/master/bip-0329.mediawiki).  
- `transactions`: Optional array of transaction ids referencing entries in the wallet's
  `transactions` map, listing the transactions that involve this account.  
  Present only where the wallet can attribute a transaction to an account. A wallet may
  reference only transactions spending coins controlled by the account, only those funding
  controlled coins, or both.  
- `coins`: Optional array of outputs owned by the account.  
  See [Coin Object Structure](../bip-0139.md#coin-object-structure).  
- `bip352_outputs`: Optional array of
  [Silent Payment Owned Output Object Structure](../bip-0139.md#silent-payment-owned-output-object-structure).  
- `psbts`: Optional array of transaction ids referencing entries in the wallet's `psbts`
  map, listing the partially signed transactions that involve this account.  
  Present only where the wallet can attribute a PSBT to an account. A PSBT carried in the
  wallet map need not be referenced by any account.  
- `bip39_mnemonic`: Optional string containing mnemonic words following BIP39.  
  Since backups may be stored online, this field is intended for test networks only
  (`testnet3`, `testnet4`, `signet`, `regtest`); it MUST NOT be used to store mainnet mnemonics.  
- `proprietary`: Optional JSON object storing account-specific metadata.  

### Account Status

The `status` field may contain one of the following values.  

- `active`: The account still derives new addresses.  
- `superseded`: The account no longer derives new addresses, having been replaced by
  another, but must still be watched because it may hold coins.  
- `archived`: The user retired the account.  

## Signer Fields

Fields of the [signer object](../bip-0139.md#signer-object-structure).  
The mandatory `fingerprints` field is defined in BIP-0139; all fields below are optional.

- `key_status`: Optional string describing the status of the signer's keys.  
  See [Key Status](#key-status).  
- `bip85_derivation_path`: Optional string describing the
  [BIP-0085](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) derivation
  path used to derive this signer's key from a master key.  
- `bip85_application`: Optional string naming the BIP-0085 application the key was derived
  for. Needed alongside `bip85_derivation_path` when the derived secret is not itself a
  BIP32 key.  
- `bip85_index`: Optional integer index used in the BIP-0085 derivation.  
- `modality`: Optional string describing where the key material lives.  
  Either `dedicated` (a device whose only job is signing) or `general` (software on a
  general-purpose or network-connected device, including a remote service).  
  The value can only degrade over a key's lifetime: material that has been on a general
  device never becomes dedicated again. An importer that reads a value more dedicated than
  the one it recorded MUST treat it as suspect, and MUST NOT silently promote it.  
- `devices`: Optional array of records describing how this signer can be reached.  
  Each entry may contain `vendor` and `model` strings naming the product, a `transports`
  array of strings such as `usb`, `qr`, `nfc`, `sd` or `service`, a `registration` string
  holding an opaque blob proving a descriptor was registered on that device, and a
  `last_health_check` timestamp recording when signing through it was last
  proven to work.  
  The whole array is advisory. It is a cache of how the signer was last reached, not a
  statement that the key belongs to a device, and a key may be moved to other hardware at
  any time. An importer MAY ignore it and MUST fall back to asking the user.  
  `registration` is the one member that does not degrade gracefully: a blob produced on one
  device is meaningless on another, so an importer MUST re-verify it rather than trust it.  

### Key Status

The `key_status` field may contain one of the following values.  

- `active`: The key is actively used.  
- `inactive`: The key is not yet actively used.  
- `revoked`: The key has been revoked and MUST NOT be used anymore.  

## Key Fields

Fields of the [key object](../bip-0139.md#key-object-structure).  
The mandatory `key` field is defined in BIP-0139; all fields below are optional.

- `alias`: Optional string user-defined alias for the key.  
- `role`: Optional string role of the key in wallet operations.  
  See [Key Roles](#key-roles).  
- `key_type`: Optional string describing ownership of the key.  
  See [Key Types](#key-types).  

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

## Transaction Fields

Fields of the [transaction object](../bip-0139.md#transaction-object-structure).  
The transaction id is the key of the wallet's `transactions` map, not a field; all fields
below are optional.

- `wtxid`: Optional string containing the witness transaction id (hex). Segwit only.  
- `hex`: Optional string containing the raw transaction (hex).  
- `block_time`: Optional timestamp of the block confirming the transaction. Absent while
  the transaction is unconfirmed.  
- `time_received`: Optional timestamp of when the exporting wallet first observed the
  transaction. MAY be earlier than `block_time`.  
  These two are separate measurements and neither substitutes for the other. An exporter
  emits whichever it holds and omits the other; wallets commonly keep only one. A consumer
  wanting a single best-known time derives it, preferring `block_time` and falling back to
  `time_received`.  
- `blockhash`: Optional string containing the confirming block hash (hex).  
- `blockheight`: Optional integer containing the confirming block height.  
- `blockindex`: Optional integer containing the position of the transaction in the
  confirming block.  
- `abandoned`: Optional boolean representing user-driven abandoned state, separate
  from mempool eviction.  

## Coin Fields

Fields of the [coin object](../bip-0139.md#coin-object-structure).  
The mandatory `outpoint` field is defined in BIP-0139; all fields below are optional.

- `amount`: Optional integer representing the output amount value in sats.  
- `address`: Optional string containing the address the output pays to.  
- `script`: Optional hexadecimal string containing the output script.  
- `block_height`: Optional integer height of the block containing the funding
  transaction. If `null`, the funding transaction was unconfirmed at backup time.  
- `is_change`: Optional boolean indicating the output was paid to the change keychain.  
- `derivation_index`: Optional integer index the output's address was derived at.  
- `is_immature`: Optional boolean indicating the output is an immature coinbase output.  
- `is_from_self`: Optional boolean indicating the funding transaction was made by this
  wallet.  
- `frozen`: Optional boolean recording that the user marked this output do-not-spend.  
  This is user intent and cannot be recovered from the chain, so it is lost unless it is
  backed up.  
- `spend_status`: Optional string describing the spend status of the output.  
  See [Spend Status](#spend-status).  

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
