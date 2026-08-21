# BIP-0139 Field Registry

This file is the central repository of fields for the
[BIP-0139](../bip-0139.md) wallet metadata export format.  
New fields are registered by opening a pull request editing only this file, following
the process described in the [Field Registry](../bip-0139.md#field-registry) section of the
specification.  
The `optional` column marks the optional fields; a blank means the field is mandatory.
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
| network      |          | string    | Network the export covers. See Wallet Object Structure for |
|              |          |           | the permitted values.                                      |
|--------------|----------|-----------|------------------------------------------------------------|
| accounts     |          | array     | Account objects. Must contain at least one.                |
|--------------|----------|-----------|------------------------------------------------------------|
| name         | optional | string    | Wallet name.                                               |
|--------------|----------|-----------|------------------------------------------------------------|
| note         | optional | string    | Note about this export, written by the user when the       |
|              |          |           | export is made.                                            |
|--------------|----------|-----------|------------------------------------------------------------|
| date         | optional | timestamp | When the export was made.                                  |
|--------------|----------|-----------|------------------------------------------------------------|
| transactions | optional | object    | Maps a transaction id to a transaction object.             |
|              |          |           | Transactions are keyed here rather than held on the        |
|              |          |           | account so that one touching several accounts is stored    |
|              |          |           | once, and so that a wallet that cannot attribute a         |
|              |          |           | transaction to an account can still carry it. Accounts     |
|              |          |           | reference them by transaction id.                          |
|--------------|----------|-----------|------------------------------------------------------------|
| psbts        | optional | object    | Maps a transaction id to a partially signed transaction,   |
|              |          |           | as defined by BIP-0174 or BIP-0370. The key is the         |
|              |          |           | transaction id of the PSBT's *unsigned* transaction, which |
|              |          |           | stays stable for the whole signing process, whereas the id |
|              |          |           | of the finished transaction changes as legacy inputs are   |
|              |          |           | signed. Kept at wallet level for the same reason as        |
|              |          |           | transactions.                                              |
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
| type               |          | string          | Language `descriptor` is written in. See       |
|                    |          |                 | Account Object Structure for the permitted     |
|                    |          |                 | values.                                        |
|--------------------|----------|-----------------|------------------------------------------------|
| descriptor         |          | string/array    | The account structure, written in the language |
|                    |          |                 | named by `type`. See Account Object Structure. |
|--------------------|----------|-----------------|------------------------------------------------|
| name               | optional | string          | Account name.                                  |
|--------------------|----------|-----------------|------------------------------------------------|
| description        | optional | string          | Account description.                           |
|--------------------|----------|-----------------|------------------------------------------------|
| status             | optional | enum            | Where the account is in its lifecycle. See     |
|                    |          |                 | Account Status.                                |
|--------------------|----------|-----------------|------------------------------------------------|
| hidden             | optional | boolean         | The account is suppressed in the exporting     |
|                    |          |                 | wallet's interface. Independent of status: a   |
|                    |          |                 | hidden account may still be active.            |
|--------------------|----------|-----------------|------------------------------------------------|
| change_descriptor  | optional | string          | Explicit change-side descriptor, paired with   |
|                    |          |                 | descriptor. For wallets that do not use        |
|                    |          |                 | BIP-389 multipath descriptors, as e.g. Bitcoin |
|                    |          |                 | Core does.                                     |
|--------------------|----------|-----------------|------------------------------------------------|
| receive_index      | optional | integer         | Maximum receive index for generated receive    |
|                    |          |                 | addresses.                                     |
|--------------------|----------|-----------------|------------------------------------------------|
| change_index       | optional | integer         | Maximum change index for generated change      |
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
| gap_limit          | optional | integer         | Consecutive unused addresses an importer must  |
|                    |          |                 | scan past the last used one before concluding  |
|                    |          |                 | there are no more. A single value covers both  |
|                    |          |                 | the receive and change sides. An exporter      |
|                    |          |                 | holding a distinct limit per side should emit  |
|                    |          |                 | the larger, since a limit that is too high     |
|                    |          |                 | only costs scanning work while one that is too |
|                    |          |                 | low misses addresses.                          |
|--------------------|----------|-----------------|------------------------------------------------|
| birth_block        | optional | integer         | Account creation time as a block height. An    |
|                    |          |                 | importer may start scanning here instead of at |
|                    |          |                 | genesis. Most wallets record a creation date   |
|                    |          |                 | rather than a height. An exporter holding only |
|                    |          |                 | a date SHOULD convert it against a chain       |
|                    |          |                 | source. If it cannot, it MAY estimate the      |
|                    |          |                 | height as (date - genesis block time) / 600,   |
|                    |          |                 | anchored at the network's genesis block and    |
|                    |          |                 | never at the chain tip: the chain has          |
|                    |          |                 | historically run slightly ahead of the ten-    |
|                    |          |                 | minute target, so extrapolating forward from   |
|                    |          |                 | genesis lands below the true height while      |
|                    |          |                 | counting back from the tip lands above it. The |
|                    |          |                 | estimate MUST be at or before the true height, |
|                    |          |                 | never after, because too early only costs      |
|                    |          |                 | scanning time while too late silently misses   |
|                    |          |                 | transactions and the funds in them. An         |
|                    |          |                 | exporter that can do neither SHOULD omit the   |
|                    |          |                 | field; an absent birth_block means a full      |
|                    |          |                 | scan, which is slow but correct.               |
|--------------------|----------|-----------------|------------------------------------------------|
| last_height        | optional | integer         | Height this account has been synced to. A      |
|                    |          |                 | wallet that tracks one sync point for the      |
|                    |          |                 | whole export writes that same height into      |
|                    |          |                 | every account. Accounts that sync              |
|                    |          |                 | independently, such as a separately scanned    |
|                    |          |                 | silent payments account, carry their own.      |
|--------------------|----------|-----------------|------------------------------------------------|
| bip352_labels      | optional | array or object | The silent payment label indices in use.       |
|                    |          |                 | Either an array of integers ([0, 1, 2]) or an  |
|                    |          |                 | object with start and end members ({"start":   |
|                    |          |                 | 0, "end": 10}), where end is exclusive,        |
|                    |          |                 | matching range_start and range_end. An         |
|                    |          |                 | importer that does not know which labels were  |
|                    |          |                 | issued cannot detect outputs paid to them, so  |
|                    |          |                 | omitting a label in use loses the funds        |
|                    |          |                 | received on it.                                |
|--------------------|----------|-----------------|------------------------------------------------|
| keys               | optional | object          | Maps a key fingerprint to a key object.        |
|--------------------|----------|-----------------|------------------------------------------------|
| labels             | optional | array           | Label structures for transactions, addresses   |
|                    |          |                 | and keys, following BIP-0329.                  |
|--------------------|----------|-----------------|------------------------------------------------|
| transactions       | optional | array           | Transaction ids referencing the wallet's       |
|                    |          |                 | transactions map, for transactions involving   |
|                    |          |                 | this account. Present only where the wallet    |
|                    |          |                 | can attribute a transaction to an account; an  |
|                    |          |                 | entry in the wallet map need not be referenced |
|                    |          |                 | by any account.                                |
|--------------------|----------|-----------------|------------------------------------------------|
| coins              | optional | array           | Coin objects owned by the account, including   |
|                    |          |                 | silent payment outputs.                        |
|--------------------|----------|-----------------|------------------------------------------------|
| psbts              | optional | array           | Transaction ids referencing the wallet's psbts |
|                    |          |                 | map, for PSBTs involving this account. Present |
|                    |          |                 | only where the wallet can attribute a PSBT to  |
|                    |          |                 | an account.                                    |
|--------------------|----------|-----------------|------------------------------------------------|
| bip39_mnemonic     | optional | string          | Mnemonic words following BIP-39. Since exports |
|                    |          |                 | may be stored online, this field is intended   |
|                    |          |                 | for test networks only (testnet3, testnet4,    |
|                    |          |                 | signet, regtest); it MUST NOT be used to store |
|                    |          |                 | mainnet mnemonics. The field carries the words |
|                    |          |                 | alone. A seed protected by a BIP-39 passphrase |
|                    |          |                 | MUST NOT use it, since the words without the   |
|                    |          |                 | passphrase restore a different wallet and give |
|                    |          |                 | no sign that anything is wrong.                |
|--------------------|----------|-----------------|------------------------------------------------|
| proprietary        | optional | object          | Application-specific metadata.                 |
```

### Account Status

The `status` field may contain one of the following values.  

- `active`: The account still derives new addresses.  
- `superseded`: The account no longer derives new addresses, having been replaced by
  another, but must still be watched because it may hold coins.  
- `archived`: The user retired the account.  

## Signer Fields

Fields of the [signer object][signerobj].

```
| field                 | optional | type    | description                                         |
|-----------------------|----------|---------|-----------------------------------------------------|
| fingerprints          |          | array   | BIP32 fingerprints held by this signer, in          |
|                       |          |         | hexadecimal form.                                   |
|-----------------------|----------|---------|-----------------------------------------------------|
| key_status            | optional | enum    | Status of the signer's keys. See Key Status.        |
|-----------------------|----------|---------|-----------------------------------------------------|
| bip85_derivation_path | optional | string  | BIP-0085 derivation path used to derive this        |
|                       |          |         | signer's key from a master key.                     |
|-----------------------|----------|---------|-----------------------------------------------------|
| bip85_application     | optional | string  | The BIP-0085 application the key was derived for.   |
|                       |          |         | Needed alongside bip85_derivation_path when the     |
|                       |          |         | derived secret is not itself a BIP32 key.           |
|-----------------------|----------|---------|-----------------------------------------------------|
| bip85_index           | optional | integer | Index used in the BIP-0085 derivation.              |
|-----------------------|----------|---------|-----------------------------------------------------|
| modality              | optional | enum    | Where the key material lives: dedicated (a device   |
|                       |          |         | whose only job is signing) or general (software on  |
|                       |          |         | a general- purpose or network- connected device,    |
|                       |          |         | including a remote service). The value can only     |
|                       |          |         | degrade over a key's lifetime: material that has    |
|                       |          |         | been on a general device never becomes dedicated    |
|                       |          |         | again. An importer that reads a value more          |
|                       |          |         | dedicated than the one it recorded MUST treat it as |
|                       |          |         | suspect, and MUST NOT silently promote it.          |
|-----------------------|----------|---------|-----------------------------------------------------|
| devices               | optional | array   | Records of how this signer can be reached. Each     |
|                       |          |         | entry may contain vendor and model strings naming   |
|                       |          |         | the product, a transports array of strings such as  |
|                       |          |         | usb, qr, nfc, sd or service, a registration string  |
|                       |          |         | holding an opaque blob proving a descriptor was     |
|                       |          |         | registered on that device, and a last_health_check  |
|                       |          |         | timestamp recording when signing through it was     |
|                       |          |         | last proven to work. The array is advisory: it      |
|                       |          |         | caches how the signer was last reached, not a claim |
|                       |          |         | that the key belongs to a device, and a key may be  |
|                       |          |         | moved to other hardware at any time. An importer    |
|                       |          |         | MAY ignore it and MUST fall back to asking the      |
|                       |          |         | user. registration is the one member that does not  |
|                       |          |         | degrade gracefully, since a blob produced on one    |
|                       |          |         | device is meaningless on another, so an importer    |
|                       |          |         | MUST re-verify it rather than trust it.             |
```

### Key Status

The `key_status` field may contain one of the following values.  

- `active`: The key is actively used.  
- `inactive`: The key is not yet actively used.  
- `revoked`: The key has been revoked and MUST NOT be used anymore.  

## Key Fields

Fields of the [key object][keyobj].

```
| field    | optional | type   | description                                                       |
|----------|----------|--------|-------------------------------------------------------------------|
| key      |          | string | Public key fingerprint in hexadecimal form.                       |
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

- `internal`: Main user-owned key.  
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
| fee           | optional | integer   | Transaction fee in sats. Computing it needs the funding   |
|               |          |           | transaction of every input, which a wallet may no longer  |
|               |          |           | have after restoring from this export.                    |
|---------------|----------|-----------|-----------------------------------------------------------|
| block_time    | optional | timestamp | Time of the block confirming the transaction. Absent      |
|               |          |           | while unconfirmed. This and time_received are separate    |
|               |          |           | measurements and neither substitutes for the other; an    |
|               |          |           | exporter emits whichever it holds.                        |
|---------------|----------|-----------|-----------------------------------------------------------|
| time_received | optional | timestamp | When the exporting wallet first observed the transaction. |
|               |          |           | MAY be earlier than block_time. A consumer wanting a      |
|               |          |           | single best- known time derives it, preferring block_time |
|               |          |           | and falling back to this.                                 |
|---------------|----------|-----------|-----------------------------------------------------------|
| blockhash     | optional | string    | Confirming block hash (hex).                              |
|---------------|----------|-----------|-----------------------------------------------------------|
| blockheight   | optional | integer   | Confirming block height.                                  |
|---------------|----------|-----------|-----------------------------------------------------------|
| blockindex    | optional | integer   | Position of the transaction in the confirming block.      |
|---------------|----------|-----------|-----------------------------------------------------------|
| abandoned     | optional | boolean   | User-driven abandoned state, separate from mempool        |
|               |          |           | eviction.                                                 |
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
|                  |          |         | If null, that transaction was unconfirmed at export      |
|                  |          |         | time.                                                    |
|------------------|----------|---------|----------------------------------------------------------|
| is_change        | optional | boolean | The output was paid to the change keychain.              |
|------------------|----------|---------|----------------------------------------------------------|
| derivation_index | optional | integer | Index the output's address was derived at.               |
|------------------|----------|---------|----------------------------------------------------------|
| is_immature      | optional | boolean | The output is an immature coinbase output.               |
|------------------|----------|---------|----------------------------------------------------------|
| is_from_self     | optional | boolean | The funding transaction was made by this wallet.         |
|------------------|----------|---------|----------------------------------------------------------|
| frozen           | optional | boolean | The user marked this output do-not-spend. This is user   |
|                  |          |         | intent and cannot be recovered from the chain, so it is  |
|                  |          |         | lost unless it is backed up.                             |
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
|                  |          |         | protocol data, not an annotation; a human label goes in  |
|                  |          |         | the account labels with type output.                     |
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
