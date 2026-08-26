# BIP-0139 Field Registry

This file is the central repository of fields for the
[BIP-0139](../bip-0139.md) wallet metadata export format.  
The `optional` column marks the optional fields, a blank means the field is mandatory.
Mandatory fields are fixed by BIP-0139, so a pull request against this file may add or
change optional fields only.  

## Wallet Fields

Fields of the top-level wallet object.

```
| field        | optional | type      | description                                                |
|--------------|----------|-----------|------------------------------------------------------------|
| version      |          | string    | Export format and version. See Wallet Object Structure for |
|              |          |           | the required value.                                        |
|--------------|----------|-----------|------------------------------------------------------------|
| network      |          | string    | Network of the wallet. See Wallet Object Structure for the |
|              |          |           | permitted values.                                          |
|--------------|----------|-----------|------------------------------------------------------------|
| accounts     |          | array     | Account objects. Must not be empty.                        |
|--------------|----------|-----------|------------------------------------------------------------|
| name         | optional | string    | Wallet name or alias.                                      |
|--------------|----------|-----------|------------------------------------------------------------|
| note         | optional | string    | Note about this export, written by the user when the       |
|              |          |           | export is made.                                            |
|--------------|----------|-----------|------------------------------------------------------------|
| date         | optional | timestamp | When the export was made.                                  |
|--------------|----------|-----------|------------------------------------------------------------|
| transactions | optional | object    | Maps a transaction id to a transaction object.             |
|              |          |           | Transactions are recorded here rather than in the          |
|              |          |           | `account` object so a transaction related to several       |
|              |          |           | accounts is stored only once. Accounts reference them by   |
|              |          |           | transaction id.                                            |
|--------------|----------|-----------|------------------------------------------------------------|
| psbts        | optional | object    | Maps a transaction id to a PSBT, as defined by BIP-0174 or |
|              |          |           | BIP-0370. The key is the transaction id of the PSBT's      |
|              |          |           | *unsigned* transaction, which stays stable for the whole   |
|              |          |           | signing process, whereas the id of the finalized           |
|              |          |           | transaction changes as legacy inputs are signed. Kept at   |
|              |          |           | wallet level for the same reason as transactions.          |
|--------------|----------|-----------|------------------------------------------------------------|
| signers      | optional | array     | Signer objects.                                            |
|--------------|----------|-----------|------------------------------------------------------------|
| proprietary  | optional | object    | Application-specific metadata.                             |
```

## Account Fields

Fields of the [account object][accountobj].

```
| field              | optional | type            | description                                    |
|--------------------|----------|-----------------|------------------------------------------------|
| type               |          | string          | Type of account descriptor. See Account Object |
|                    |          |                 | Structure for the permitted values.            |
|--------------------|----------|-----------------|------------------------------------------------|
| descriptor         |          | string/array    | Account descriptor. Its structure is defined   |
|                    |          |                 | by `type`. See Account Object Structure.       |
|--------------------|----------|-----------------|------------------------------------------------|
| name               | optional | string          | Account name/alias.                            |
|--------------------|----------|-----------------|------------------------------------------------|
| description        | optional | string          | Account description.                           |
|--------------------|----------|-----------------|------------------------------------------------|
| status             | optional | enum            | Where the account is in its lifecycle. See     |
|                    |          |                 | Account Status.                                |
|--------------------|----------|-----------------|------------------------------------------------|
| hidden             | optional | boolean         | Whether the account is hidden in the wallet's  |
|                    |          |                 | interface. Independent of status: a hidden     |
|                    |          |                 | account may still be active.                   |
|--------------------|----------|-----------------|------------------------------------------------|
| change_descriptor  | optional | string          | Explicit change-side descriptor, paired with   |
|                    |          |                 | descriptor. For wallets that keep receive and  |
|                    |          |                 | change descriptors separate, such as Bitcoin   |
|                    |          |                 | Core.                                          |
|--------------------|----------|-----------------|------------------------------------------------|
| receive_index      | optional | integer         | Maximum generated receive index for receive    |
|                    |          |                 | addresses.                                     |
|--------------------|----------|-----------------|------------------------------------------------|
| change_index       | optional | integer         | Maximum generated change index for change      |
|                    |          |                 | addresses.                                     |
|--------------------|----------|-----------------|------------------------------------------------|
| range_start        | optional | integer         | Cached keypool range start of the receive      |
|                    |          |                 | descriptor. Ranged descriptors only.           |
|--------------------|----------|-----------------|------------------------------------------------|
| range_end          | optional | integer         | Cached keypool range end of the receive        |
|                    |          |                 | descriptor. Ranged descriptors only.           |
|--------------------|----------|-----------------|------------------------------------------------|
| change_range_start | optional | integer         | Cached keypool range start of the              |
|                    |          |                 | change_descriptor. Ranged descriptors only.    |
|--------------------|----------|-----------------|------------------------------------------------|
| change_range_end   | optional | integer         | Cached keypool range end of the                |
|                    |          |                 | change_descriptor. Ranged descriptors only.    |
|--------------------|----------|-----------------|------------------------------------------------|
| gap_limit          | optional | integer         | Consecutive unused addresses a wallet must     |
|                    |          |                 | scan past the last used one before concluding  |
|                    |          |                 | there are no more. A single value covers both  |
|                    |          |                 | the receive and change sides.                  |
|--------------------|----------|-----------------|------------------------------------------------|
| birth_block        | optional | integer         | Account creation time as a block height. An    |
|                    |          |                 | importer may start scanning here instead of at |
|                    |          |                 | genesis. Many wallets record a creation date   |
|                    |          |                 | rather than a block height. An exporter        |
|                    |          |                 | holding only a date SHOULD convert it against  |
|                    |          |                 | a chain source. If it cannot, it MAY estimate  |
|                    |          |                 | the height as (date - genesis_block_time) /    |
|                    |          |                 | 600, anchored at the network's genesis block   |
|                    |          |                 | and never at the chain tip: the chain has      |
|                    |          |                 | historically run slightly ahead of the         |
|                    |          |                 | ten-minute target, so extrapolating forward    |
|                    |          |                 | from genesis should land below the true height |
|                    |          |                 | while counting back from the tip lands above   |
|                    |          |                 | it. The estimate MUST be at or before the true |
|                    |          |                 | height, never after, because too early only    |
|                    |          |                 | costs scanning time while too late silently    |
|                    |          |                 | misses transactions. An exporter that can do   |
|                    |          |                 | neither SHOULD omit this field.                |
|--------------------|----------|-----------------|------------------------------------------------|
| last_height        | optional | integer         | Height this account has been synced to. A      |
|                    |          |                 | wallet that tracks one sync point for the      |
|                    |          |                 | whole export writes that same height into      |
|                    |          |                 | every account.                                 |
|--------------------|----------|-----------------|------------------------------------------------|
| bip352_labels      | optional | array or object | The silent payment label indices in use.       |
|                    |          |                 | Either an array of integers ([0, 1, 2]) or an  |
|                    |          |                 | object with start and end members ({"start":   |
|                    |          |                 | 0, "end": 10}), where end is exclusive.        |
|--------------------|----------|-----------------|------------------------------------------------|
| keys               | optional | object          | Maps a key fingerprint to a key object.        |
|--------------------|----------|-----------------|------------------------------------------------|
| labels             | optional | array           | Label structures for transactions, addresses   |
|                    |          |                 | and keys, following BIP-0329.                  |
|--------------------|----------|-----------------|------------------------------------------------|
| transactions       | optional | array           | Transaction ids referencing the wallet's       |
|                    |          |                 | transactions map, for transactions related to  |
|                    |          |                 | this account.                                  |
|--------------------|----------|-----------------|------------------------------------------------|
| coins              | optional | array           | Coin objects owned by the account, silent      |
|                    |          |                 | payment outputs included.                      |
|--------------------|----------|-----------------|------------------------------------------------|
| psbts              | optional | array           | Transaction ids referencing the wallet's psbts |
|                    |          |                 | map, for PSBTs related to this account.        |
|--------------------|----------|-----------------|------------------------------------------------|
| bip39_mnemonic     | optional | string          | Mnemonic words following BIP-0039. Since       |
|                    |          |                 | exports may be stored online, this field is    |
|                    |          |                 | intended for test networks only (testnet3,     |
|                    |          |                 | testnet4, signet, regtest); it MUST NOT be     |
|                    |          |                 | used to store mainnet mnemonics. The field     |
|                    |          |                 | carries the words alone. A seed protected by a |
|                    |          |                 | BIP-39 passphrase MUST NOT use it.             |
|--------------------|----------|-----------------|------------------------------------------------|
| proprietary        | optional | object          | Application-specific metadata.                 |
```

### Account Status

The `status` field may contain one of the following values.  

- `active`: The account can derive new addresses.  
- `superseded`: The account no longer derives new addresses, but must still be
  watched because it may hold or receive coins.  
- `archived`: The user retired the account, it is no longer watched.

## Signer Fields

Fields of the [signer object][signerobj].

```
| field                 | optional | type    | description                                         |
|-----------------------|----------|---------|-----------------------------------------------------|
| fingerprints          |          | array   | BIP32 fingerprints of keys held by this signer.     |
|-----------------------|----------|---------|-----------------------------------------------------|
| key_status            | optional | enum    | Status of the signer's keys. See Key Status.        |
|-----------------------|----------|---------|-----------------------------------------------------|
| bip85_derivation_path | optional | string  | BIP-0085 derivation path used to derive this        |
|                       |          |         | signer's key from a master key, if one was used.    |
|-----------------------|----------|---------|-----------------------------------------------------|
| key_storage           | optional | enum    | Whether the signer's key is `hot` or `cold`.        |
|-----------------------|----------|---------|-----------------------------------------------------|
| devices               | optional | array   | Metadata and connection preferences for the last    |
|                       |          |         | seen devices holding this key. Entries may include  |
|                       |          |         | vendor, model, transports, registration and         |
|                       |          |         | last_health_check.                                  |
```

### Key Status

The `key_status` field may contain one of the following values.  

- `inactive`: The key is not yet actively used.  
- `active`: The key is actively used.  
- `revoked`: The key has been revoked and MUST NOT be used anymore.  

## Key Fields

Fields of the [key object][keyobj].

```
| field    | optional | type   | description                                                       |
|----------|----------|--------|-------------------------------------------------------------------|
| key      |          | string | BIP-0032 public key fingerprint.                                  |
|----------|----------|--------|-------------------------------------------------------------------|
| alias    | optional | string | User-defined alias for the key.                                   |
|----------|----------|--------|-------------------------------------------------------------------|
| role     | optional | enum   | Role of the key in wallet operations. See Key Roles.              |
|----------|----------|--------|-------------------------------------------------------------------|
| key_type | optional | enum   | Ownership of the key. See Key Types.                              |
```

### Key Roles

The `role` field may contain one of the following values.  

- `main`: Key used for normal spending conditions.  
- `recovery`: Key designated for recovery scenarios.  
- `inheritance`: Key to inherit funds if the primary user disappears.  
- `cosigning`: Key designated for policy-enforcing cosigning.  

### Key Types

The `key_type` field may contain one of the following values.  

- `internal`: User-owned key.  
- `external`: Key held by heirs or trusted individuals.  
- `third_party`: Key held by a service provider.  

## Transaction Fields

Fields of the [transaction object][txobj]. The transaction id is the key of the
wallet's `transactions` map, not a field.

```
| field         | optional | type      | description                                               |
|---------------|----------|-----------|-----------------------------------------------------------|
| wtxid         | optional | string    | Witness transaction id (hex). Segwit only.                |
|---------------|----------|-----------|-----------------------------------------------------------|
| hex           | optional | string    | Raw transaction (hex).                                    |
|---------------|----------|-----------|-----------------------------------------------------------|
| fee           | optional | integer   | Transaction fee in sats.                                  |
|---------------|----------|-----------|-----------------------------------------------------------|
| block_time    | optional | timestamp | Time of the block confirming the transaction. Absent      |
|               |          |           | while unconfirmed. This and time_received are separate    |
|               |          |           | measurements and neither substitutes for the other, an    |
|               |          |           | exporter emits whichever it holds.                        |
|---------------|----------|-----------|-----------------------------------------------------------|
| time_received | optional | timestamp | When the exporting wallet first observed the transaction. |
|               |          |           | MAY be earlier than block_time.                           |
|---------------|----------|-----------|-----------------------------------------------------------|
| blockhash     | optional | string    | Confirming block hash (hex).                              |
|---------------|----------|-----------|-----------------------------------------------------------|
| blockheight   | optional | integer   | Confirming block height.                                  |
|---------------|----------|-----------|-----------------------------------------------------------|
| blockindex    | optional | integer   | Position of the transaction in the confirming block.      |
|---------------|----------|-----------|-----------------------------------------------------------|
| abandoned     | optional | boolean   | Whether the user decided to abandon this transaction.     |
```

## Coin Fields

Fields of the [coin object][coinobj]. Silent payment outputs are coins and use this object
too, with `tweak` set.

```
| field            | optional | type    | description                                              |
|------------------|----------|---------|----------------------------------------------------------|
| outpoint         |          | string  | The outpoint, in the form `<txid>:<vout>`.               |
|------------------|----------|---------|----------------------------------------------------------|
| amount           | optional | integer | Output amount in sats.                                   |
|------------------|----------|---------|----------------------------------------------------------|
| script           | optional | string  | Output script (hex).                                     |
|------------------|----------|---------|----------------------------------------------------------|
| block_height     | optional | integer | Height of the block containing the funding transaction.  |
|                  |          |         | If null, that transaction was unconfirmed at export.     |
|------------------|----------|---------|----------------------------------------------------------|
| is_change        | optional | boolean | Whether the output was paid to a change address.         |
|------------------|----------|---------|----------------------------------------------------------|
| derivation_index | optional | integer | Index the output's address was derived at.               |
|------------------|----------|---------|----------------------------------------------------------|
| is_immature      | optional | boolean | The output is an immature coinbase output.               |
|------------------|----------|---------|----------------------------------------------------------|
| is_from_self     | optional | boolean | The funding transaction was made by this wallet.         |
|------------------|----------|---------|----------------------------------------------------------|
| frozen           | optional | boolean | The user marked this output as do-not-spend.             |
|------------------|----------|---------|----------------------------------------------------------|
| spend_status     | optional | enum    | Spend status of the output. See Spend Status.            |
|------------------|----------|---------|----------------------------------------------------------|
| tweak            | optional | string  | Silent payment outputs only: the tweak needed to derive  |
|                  |          |         | the output, as defined by BIP-0352. Absent for ordinary  |
|                  |          |         | outputs.                                                 |
|------------------|----------|---------|----------------------------------------------------------|
| sp_label         | optional | string  | Silent payment outputs only: the BIP-0352 label scalar   |
|                  |          |         | of the labelled address the output was paid to, in       |
|                  |          |         | hexadecimal. Absent for the unlabelled address. This is  |
|                  |          |         | protocol data, not an annotation.                        |
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
[accountobj]: ../bip-0139.md#account-object-structure
