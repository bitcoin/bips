# BIP-0139 Field Registry

This file is the central repository of fields for the
[BIP-0139](../bip-0139.md) wallet backup format.  
New fields are registered by opening a pull request editing only this file, following
the process described in the [Field Registry](../bip-0139.md#field-registry) section of the
specification.  

## Wallet Fields

Optional fields of the top-level wallet backup object. Its mandatory fields, `version`,
`network` and `accounts`, are specified with the object itself.

```
| field        | type      | description                                                           |
|--------------|-----------|-----------------------------------------------------------------------|
| name         | string    | Wallet name.                                                          |
|--------------|-----------|-----------------------------------------------------------------------|
| note         | string    | Note about this backup, written by the user when the backup is made.  |
|--------------|-----------|-----------------------------------------------------------------------|
| date         | timestamp | When the backup was made.                                             |
|--------------|-----------|-----------------------------------------------------------------------|
| transactions | object    | Maps a transaction id to a transaction object. Transactions are keyed |
|              |           | here rather than held on the account so that one touching several     |
|              |           | accounts is stored once, and so that a wallet that cannot attribute a |
|              |           | transaction to an account can still carry it. Accounts reference them |
|              |           | by transaction id.                                                    |
|--------------|-----------|-----------------------------------------------------------------------|
| psbts        | object    | Maps a transaction id to a partially signed transaction, as defined   |
|              |           | by BIP-0174 or BIP-0370. The key is the transaction id of the PSBT's  |
|              |           | *unsigned* transaction, which stays stable for the whole signing      |
|              |           | process, whereas the id of the finished transaction changes as legacy |
|              |           | inputs are signed. Kept at wallet level for the same reason as        |
|              |           | transactions.                                                         |
|--------------|-----------|-----------------------------------------------------------------------|
| signers      | array     | Signer objects.                                                       |
|--------------|-----------|-----------------------------------------------------------------------|
| proprietary  | object    | Application-specific metadata.                                        |
|--------------|-----------|-----------------------------------------------------------------------|
```

## Account Fields

Optional fields of the [account object][accountobj]. Its mandatory fields, `type` and
`descriptor`, are specified with the object itself.

```
| field              | type            | description                                               |
|--------------------|-----------------|-----------------------------------------------------------|
| name               | string          | Account name.                                             |
|--------------------|-----------------|-----------------------------------------------------------|
| description        | string          | Account description.                                      |
|--------------------|-----------------|-----------------------------------------------------------|
| status             | enum            | Where the account is in its lifecycle. See Account        |
|                    |                 | Status.                                                   |
|--------------------|-----------------|-----------------------------------------------------------|
| hidden             | boolean         | The account is suppressed in the exporting wallet's       |
|                    |                 | interface. Independent of status: a hidden account may    |
|                    |                 | still be active.                                          |
|--------------------|-----------------|-----------------------------------------------------------|
| change_descriptor  | string          | Explicit change-side descriptor, paired with descriptor.  |
|                    |                 | For wallets that do not use BIP-389 multipath             |
|                    |                 | descriptors, as e.g. Bitcoin Core does.                   |
|--------------------|-----------------|-----------------------------------------------------------|
| receive_index      | integer         | Maximum receive index for generated receive addresses.    |
|--------------------|-----------------|-----------------------------------------------------------|
| change_index       | integer         | Maximum change index for generated change addresses.      |
|--------------------|-----------------|-----------------------------------------------------------|
| range_start        | integer         | Cached keypool range start of the receive descriptor.     |
|                    |                 | Ranged descriptors only.                                  |
|--------------------|-----------------|-----------------------------------------------------------|
| range_end          | integer         | Cached keypool range end of the receive descriptor.       |
|                    |                 | Ranged descriptors only.                                  |
|--------------------|-----------------|-----------------------------------------------------------|
| change_range_start | integer         | Cached keypool range start of the change_descriptor.      |
|                    |                 | Ranged descriptors only.                                  |
|--------------------|-----------------|-----------------------------------------------------------|
| change_range_end   | integer         | Cached keypool range end of the change_descriptor. Ranged |
|                    |                 | descriptors only.                                         |
|--------------------|-----------------|-----------------------------------------------------------|
| gap_limit          | integer         | Consecutive unused addresses an importer must scan past   |
|                    |                 | the last used one before concluding there are no more. A  |
|                    |                 | single value covers both the receive and change sides. An |
|                    |                 | exporter holding a distinct limit per side should emit    |
|                    |                 | the larger, since a limit that is too high only costs     |
|                    |                 | scanning work while one that is too low misses addresses. |
|--------------------|-----------------|-----------------------------------------------------------|
| birth_block        | integer         | Account creation time as a block height. An importer may  |
|                    |                 | start scanning here instead of at genesis. Most wallets   |
|                    |                 | record a creation date rather than a height. An exporter  |
|                    |                 | holding only a date SHOULD convert it against a chain     |
|                    |                 | source. If it cannot, it MAY estimate the height, and the |
|                    |                 | estimate MUST be at or before the true height, never      |
|                    |                 | after: too early only costs scanning time, while too late |
|                    |                 | silently misses transactions and the funds in them. An    |
|                    |                 | estimate from a date should subtract a margin covering    |
|                    |                 | the drift of a fixed block interval, on the order of a    |
|                    |                 | difficulty period. An exporter that can do neither SHOULD |
|                    |                 | omit the field; an absent birth_block means a full scan,  |
|                    |                 | which is slow but correct.                                |
|--------------------|-----------------|-----------------------------------------------------------|
| last_height        | integer         | Height this account has been synced to. A wallet that     |
|                    |                 | tracks one sync point for the whole backup writes that    |
|                    |                 | same height into every account. Accounts that sync        |
|                    |                 | independently, such as a separately scanned silent        |
|                    |                 | payments account, carry their own.                        |
|--------------------|-----------------|-----------------------------------------------------------|
| bip352_labels      | array or object | The silent payment label indices in use. Either an array  |
|                    |                 | of integers ([0, 1, 2]) or an object with start and end   |
|                    |                 | members ({"start": 0, "end": 10}), where end is           |
|                    |                 | exclusive, matching range_start and range_end. An         |
|                    |                 | importer that does not know which labels were issued      |
|                    |                 | cannot detect outputs paid to them, so omitting a label   |
|                    |                 | in use loses the funds received on it.                    |
|--------------------|-----------------|-----------------------------------------------------------|
| keys               | object          | Maps a key fingerprint to a key object.                   |
|--------------------|-----------------|-----------------------------------------------------------|
| labels             | array           | Label structures for transactions, addresses and keys,    |
|                    |                 | following BIP-0329.                                       |
|--------------------|-----------------|-----------------------------------------------------------|
| transactions       | array           | Transaction ids referencing the wallet's transactions     |
|                    |                 | map, for transactions involving this account. Present     |
|                    |                 | only where the wallet can attribute a transaction to an   |
|                    |                 | account; an entry in the wallet map need not be           |
|                    |                 | referenced by any account.                                |
|--------------------|-----------------|-----------------------------------------------------------|
| coins              | array           | Coin objects owned by the account.                        |
|--------------------|-----------------|-----------------------------------------------------------|
| bip352_outputs     | array           | Silent payment owned output objects.                      |
|--------------------|-----------------|-----------------------------------------------------------|
| psbts              | array           | Transaction ids referencing the wallet's psbts map, for   |
|                    |                 | PSBTs involving this account. Present only where the      |
|                    |                 | wallet can attribute a PSBT to an account.                |
|--------------------|-----------------|-----------------------------------------------------------|
| bip39_mnemonic     | string          | Mnemonic words following BIP-39. Since backups may be     |
|                    |                 | stored online, this field is intended for test networks   |
|                    |                 | only (testnet3, testnet4, signet, regtest); it MUST NOT   |
|                    |                 | be used to store mainnet mnemonics.                       |
|--------------------|-----------------|-----------------------------------------------------------|
| proprietary        | object          | Application-specific metadata.                            |
|--------------------|-----------------|-----------------------------------------------------------|
```

### Account Status

The `status` field may contain one of the following values.  

- `active`: The account still derives new addresses.  
- `superseded`: The account no longer derives new addresses, having been replaced by
  another, but must still be watched because it may hold coins.  
- `archived`: The user retired the account.  

## Signer Fields

Optional fields of the [signer object][signerobj]. Its mandatory field, `fingerprints`,
is specified with the object itself.

```
| field                 | type    | description                                                    |
|-----------------------|---------|----------------------------------------------------------------|
| key_status            | enum    | Status of the signer's keys. See Key Status.                   |
|-----------------------|---------|----------------------------------------------------------------|
| bip85_derivation_path | string  | BIP-0085 derivation path used to derive this signer's key from |
|                       |         | a master key.                                                  |
|-----------------------|---------|----------------------------------------------------------------|
| bip85_application     | string  | The BIP-0085 application the key was derived for. Needed       |
|                       |         | alongside bip85_derivation_path when the derived secret is not |
|                       |         | itself a BIP32 key.                                            |
|-----------------------|---------|----------------------------------------------------------------|
| bip85_index           | integer | Index used in the BIP-0085 derivation.                         |
|-----------------------|---------|----------------------------------------------------------------|
| modality              | enum    | Where the key material lives: dedicated (a device whose only   |
|                       |         | job is signing) or general (software on a general-purpose or   |
|                       |         | network- connected device, including a remote service). The    |
|                       |         | value can only degrade over a key's lifetime: material that    |
|                       |         | has been on a general device never becomes dedicated again. An |
|                       |         | importer that reads a value more dedicated than the one it     |
|                       |         | recorded MUST treat it as suspect, and MUST NOT silently       |
|                       |         | promote it.                                                    |
|-----------------------|---------|----------------------------------------------------------------|
| devices               | array   | Records of how this signer can be reached. Each entry may      |
|                       |         | contain vendor and model strings naming the product, a         |
|                       |         | transports array of strings such as usb, qr, nfc, sd or        |
|                       |         | service, a registration string holding an opaque blob proving  |
|                       |         | a descriptor was registered on that device, and a              |
|                       |         | last_health_check timestamp recording when signing through it  |
|                       |         | was last proven to work. The array is advisory: it caches how  |
|                       |         | the signer was last reached, not a claim that the key belongs  |
|                       |         | to a device, and a key may be moved to other hardware at any   |
|                       |         | time. An importer MAY ignore it and MUST fall back to asking   |
|                       |         | the user. registration is the one member that does not degrade |
|                       |         | gracefully, since a blob produced on one device is meaningless |
|                       |         | on another, so an importer MUST re-verify it rather than trust |
|                       |         | it.                                                            |
|-----------------------|---------|----------------------------------------------------------------|
```

### Key Status

The `key_status` field may contain one of the following values.  

- `active`: The key is actively used.  
- `inactive`: The key is not yet actively used.  
- `revoked`: The key has been revoked and MUST NOT be used anymore.  

## Key Fields

Optional fields of the [key object][keyobj]. Its mandatory field, `key`, is specified
with the object itself.

```
| field    | type   | description                                                                  |
|----------|--------|------------------------------------------------------------------------------|
| alias    | string | User-defined alias for the key.                                              |
|----------|--------|------------------------------------------------------------------------------|
| role     | enum   | Role of the key in wallet operations. See Key Roles.                         |
|----------|--------|------------------------------------------------------------------------------|
| key_type | enum   | Ownership of the key. See Key Types.                                         |
|----------|--------|------------------------------------------------------------------------------|
```

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

Optional fields of the [transaction object][txobj]. The transaction id is the key of the
wallet's `transactions` map, not a field.

```
| field         | type      | description                                                          |
|---------------|-----------|----------------------------------------------------------------------|
| wtxid         | string    | Witness transaction id (hex). Segwit only.                           |
|---------------|-----------|----------------------------------------------------------------------|
| hex           | string    | Raw transaction (hex).                                               |
|---------------|-----------|----------------------------------------------------------------------|
| block_time    | timestamp | Time of the block confirming the transaction. Absent while           |
|               |           | unconfirmed. This and time_received are separate measurements and    |
|               |           | neither substitutes for the other; an exporter emits whichever it    |
|               |           | holds.                                                               |
|---------------|-----------|----------------------------------------------------------------------|
| time_received | timestamp | When the exporting wallet first observed the transaction. MAY be     |
|               |           | earlier than block_time. A consumer wanting a single best-known time |
|               |           | derives it, preferring block_time and falling back to this.          |
|---------------|-----------|----------------------------------------------------------------------|
| blockhash     | string    | Confirming block hash (hex).                                         |
|---------------|-----------|----------------------------------------------------------------------|
| blockheight   | integer   | Confirming block height.                                             |
|---------------|-----------|----------------------------------------------------------------------|
| blockindex    | integer   | Position of the transaction in the confirming block.                 |
|---------------|-----------|----------------------------------------------------------------------|
| abandoned     | boolean   | User-driven abandoned state, separate from mempool eviction.         |
|---------------|-----------|----------------------------------------------------------------------|
```

## Coin Fields

Optional fields of the [coin object][coinobj]. Its mandatory field, `outpoint`, is
specified with the object itself.

```
| field            | type    | description                                                         |
|------------------|---------|---------------------------------------------------------------------|
| amount           | integer | Output amount in sats.                                              |
|------------------|---------|---------------------------------------------------------------------|
| address          | string  | Address the output pays to.                                         |
|------------------|---------|---------------------------------------------------------------------|
| script           | string  | Output script (hex).                                                |
|------------------|---------|---------------------------------------------------------------------|
| block_height     | integer | Height of the block containing the funding transaction. If null,    |
|                  |         | that transaction was unconfirmed at backup time.                    |
|------------------|---------|---------------------------------------------------------------------|
| is_change        | boolean | The output was paid to the change keychain.                         |
|------------------|---------|---------------------------------------------------------------------|
| derivation_index | integer | Index the output's address was derived at.                          |
|------------------|---------|---------------------------------------------------------------------|
| is_immature      | boolean | The output is an immature coinbase output.                          |
|------------------|---------|---------------------------------------------------------------------|
| is_from_self     | boolean | The funding transaction was made by this wallet.                    |
|------------------|---------|---------------------------------------------------------------------|
| frozen           | boolean | The user marked this output do-not-spend. This is user intent and   |
|                  |         | cannot be recovered from the chain, so it is lost unless it is      |
|                  |         | backed up.                                                          |
|------------------|---------|---------------------------------------------------------------------|
| spend_status     | enum    | Spend status of the output. See Spend Status.                       |
|------------------|---------|---------------------------------------------------------------------|
```

## Silent Payment Owned Output Fields

Optional fields of the [silent payment owned output object][spobj]. Its mandatory fields,
`outpoint` and `tweak`, are specified with the object itself.

```
| field        | type    | description                                                             |
|--------------|---------|-------------------------------------------------------------------------|
| block_height | integer | Height of the block containing the transaction. If null, the outpoint   |
|              |         | belongs to a transaction that was unconfirmed at backup time.           |
|--------------|---------|-------------------------------------------------------------------------|
| amount       | integer | Output amount in sats.                                                  |
|--------------|---------|-------------------------------------------------------------------------|
| script       | string  | Spending script for this outpoint (hex).                                |
|--------------|---------|-------------------------------------------------------------------------|
| label        | string  | Label attached to this output, similar to a BIP-0329 label.             |
|--------------|---------|-------------------------------------------------------------------------|
| spend_status | enum    | Spend status of the output. See Spend Status.                           |
|--------------|---------|-------------------------------------------------------------------------|
```

### Spend Status

The `spend_status` field may contain one of the following values.  

- `unconfirmed`: The transaction is broadcast but not yet confirmed in a block.
- `replaced`: The transaction has been replaced by a transaction confirmed in a block.
- `unspent`: The transaction has been confirmed in a block and the output is unspent.
- `spent`: The transaction has been confirmed in a block and the output is spent.

[txobj]: ../bip-0139.md#transaction-object-structure
[signerobj]: ../bip-0139.md#signer-object-structure
[keyobj]: ../bip-0139.md#key-object-structure
[coinobj]: ../bip-0139.md#coin-object-structure
[spobj]: ../bip-0139.md#silent-payment-owned-output-object-structure
[accountobj]: ../bip-0139.md#account-object-structure
