# BIP-139 wallet survey

Can each wallet fill each BIP-139 field?

    ✓   it can
    -   it cannot, or has no such concept

A wallet holding more than a field can carry still scores ✓; the loss is listed under
missing fields. A value computed on demand, stored under another name, or not emitted by
current export code is ✓ - the question is what the wallet can produce.

## Revisions read

| Wallet         | Commit                            |
|----------------|-----------------------------------|
| Bitcoin Core   | `1e7ff0fe`                        |
| Liana          | `6ef57fb6`                        |
| Sparrow        | `194bd70`                         |
| Bull Bitcoin   | `ce0add466` / `6f0709b`           |
| Nunchuk        | `a1d485a` / `025aba7` / `e091ed8` |
| Bitcoin Keeper | `3a7b53c` / `f960b1f`             |
| Bitcoin Safe   | `4ce099e`                         |
| Electrum       | `3d41451f2`                       |
| Green          | `71b90dd` / `08464d6`             |
| Specter        | `b8679a4`                         |
| Dana           | `2b8ba6d`                         |
| Wasabi         | `bbc25a3`                         |
| Bitkey         | `1c0858d09`                       |

## The matrix

```
Core = Bitcoin Core     Keep = Bitcoin Keeper   Dana = Dana
Lian = Liana            BSaf = Bitcoin Safe     Wasb = Wasabi
Sprw = Sparrow          Elec = Electrum         Bitk = Bitkey
Bull = Bull Bitcoin     Grn = Green
Nunc = Nunchuk          Spec = Specter

field                       | Core | Lian | Sprw | Bull | Nunc | Keep | BSaf | Elec | Grn  | Spec | Dana | Wasb | Bitk |  ✓
----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
wallet.version              |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  ✓   |   7
wallet.network              |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
wallet.accounts             |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
wallet.name                 |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  -   |  ✓   |  -   |   8
wallet.note                 |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |   2
wallet.date                 |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
wallet.transactions         |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
wallet.psbts                |  -   |  ✓   |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  -   |   7
wallet.signers              |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  ✓   |  11
wallet.proprietary          |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |   9
----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
account.type                |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
account.descriptor          |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
account.name                |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |   8
account.description         |  -   |  -   |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |   3
account.status              |  ✓   |  -   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  -   |  -   |  -   |  ✓   |   6
account.hidden              |  -   |  -   |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |   3
account.change_descriptor   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |   8
account.receive_index       |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  11
account.change_index        |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  11
account.range_start         |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |   2
account.range_end           |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |   5
account.change_range_start  |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |   2
account.change_range_end    |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |   5
account.gap_limit           |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  -   |   8
account.birth_block         |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |   8
account.last_height         |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
account.bip352_labels       |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |   1
account.keys                |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
account.labels              |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  12
account.transactions        |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
account.coins               |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
account.psbts               |  -   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  -   |   5
account.bip39_mnemonic      |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  -   |  ✓   |   8
account.proprietary         |  -   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  ✓   |   7
----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
signer.fingerprints         |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  12
signer.key_status           |  -   |  -   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |   4
signer.bip85_derivation_path|  -   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |   3
signer.bip85_application    |  -   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |   3
signer.bip85_index          |  -   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |   3
signer.modality             |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  11
signer.devices              |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  11
----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
key.key                     |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
key.alias                   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |   9
key.role                    |  -   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |   6
key.key_type                |  -   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |   9
----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
transaction.wtxid           |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |  -   |   6
transaction.hex             |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  10
transaction.fee             |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
transaction.block_time      |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
transaction.time_received   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |   5
transaction.blockhash       |  ✓   |  -   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |   8
transaction.blockheight     |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
transaction.blockindex      |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  ✓   |  -   |   3
transaction.abandoned       |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |   2
----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
coin.outpoint               |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
coin.amount                 |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
coin.script                 |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
coin.block_height           |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
coin.is_change              |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
coin.derivation_index       |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  12
coin.is_immature            |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  ✓   |   8
coin.is_from_self           |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  ✓   |  10
coin.frozen                 |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |   8
coin.spend_status           |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  13
coin.tweak                  |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  ✓   |  -   |   4
coin.sp_label               |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |   2
```
