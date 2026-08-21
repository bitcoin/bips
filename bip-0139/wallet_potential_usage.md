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


## Missing fields

Ranked by how many wallets want them.

| Missing field                           | Wanted by | Evidence                                                                                                                                                                                                                                                         |
|-----------------------------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **gap limit**                           | 5         | Nunchuk `DbKeys::GAP_LIMIT`; Sparrow `wallet.gapLimit`; Bitcoin Safe `Wallet.gap` (=20); Electrum `gap_limit`/`gap_limit_for_change`; Wasabi `MinGapLimit`/`AbsoluteMinGapLimit`=21 - **decision: add**                                                          |
| **frozen / do-not-spend UTXO flag**     | 6         | Nunchuk `COININFO.LOCKED`; Sparrow `Status.FROZEN`; Electrum `set_frozen_state_of_addresses`; Keeper `isManualOverride`/`dustReason`; Specter `wallet.frozen_utxo`; Bull Bitcoin `FrozenUtxos` table                                                             |
| **a general (non-SP) UTXO/coin object** | 5         | Liana `Coin`; Wasabi `SmartCoin`; Sparrow `BlockTransactionHashIndex`; Nunchuk `UnspentOutput`; Green tx-list outputs. The only outpoint-level object in BIP-139 is `bip352_outputs`, which is silent-payments-only                                              |
| **hardware signer device identity**     | 5         | Sparrow `keystore.deviceRegistration`; Keeper `Signer.type`; Bitcoin Safe `KeyStore.hardware_signer_id`; Nunchuk `SignerType`; Specter `Device.device_type`. All lose which device a key lives on                                                                |
| **coin tags / categories**              | 2         | Nunchuk `TAGS`/`COLLECTIONS` tables; Bitcoin Safe `Label.category`, currently smuggled into the label string with a `" #"` separator on export                                                                                                                   |
| **per-branch key role association**     | 2         | Nunchuk `Timelock`/`ScriptNode`; Keeper `MiniscriptElements` Phase/Path with per-path thresholds and timelocks. BIP-139's flat `keys{}` dict cannot say which spending branch a key belongs to                                                                   |
| **descriptor cache (cached xpubs)**     | 1         | Core `DescriptorCache`. Without it a watch-only restore cannot top up hardened-derivation descriptors without re-consulting the signer                                                                                                                           |
| **BIP-39 passphrase**                   | 1         | Bull Bitcoin `MnemonicSeedModel.passphrase`                                                                                                                                                                                                                      |
| **BIP-85 application + index**          | 1         | Bull Bitcoin derives non-key secrets; `bip85_derivation_path` alone does not round-trip them                                                                                                                                                                     |
| **SP label index as protocol data**     | 2         | Dana persists the raw 32-byte BIP-352 label scalar in `owned_outputs.label`; Bull Bitcoin the same. BIP-139's `sp_output.label` is documented as "similar to a BIP-0329 label" (human text). Same name, different semantics - a false friend                     |
| **CoinJoin / anonymity state**          | 1         | Wasabi. Per-address `AnonymitySet`, `AnonScoreTarget`, `AutoCoinJoin`, `PlebStopThreshold`, `ExcludedCoinsFromCoinJoin`, and `PrisonedCoins.json`. A round-trip preserves keys and history but strips every signal driving the wallet's actual privacy behaviour |
| **Liquid / asset support**              | 2         | Green (confidential amounts, blinders, SLIP-77 master blinding key, asset IDs); Nunchuk `LIQUID` wallet type. decision: out of scope, carried in `proprietary` (see 1b)                                                                                          |
| **payment requests / invoices**         | 1         | Electrum `invoices.py`                                                                                                                                                                                                                                           |
| **contacts / address book**             | 2         | Electrum `contacts.py`; Dana `contacts` table                                                                                                                                                                                                                    |
| **Lightning channel state**             | 1         | Electrum, entire `lnworker`/`lnchannel` plus `export_channel_backup`                                                                                                                                                                                             |
| **backup verification state**           | 1         | Bull Bitcoin `isEncryptedVaultTested`/`isPhysicalBackupTested`                                                                                                                                                                                                   |
| **signer health-check timestamp**       | 2         | Nunchuk `last_health_check`; Keeper `HealthCheckDetails[]`                                                                                                                                                                                                       |

## Liana legacy compatibility

Does the current draft break Liana's shipping backup format
(`liana-gui/src/backup.rs`)? Six breaking changes and one lossy one. Three earlier entries
were resolved by changes this survey prompted.

| Liana today                                                       | BIP-139 now                                         | Verdict                                                 |
|-------------------------------------------------------------------|-----------------------------------------------------|---------------------------------------------------------|
| `version: u32`, serde default `0`                                 | mandatory string `BIP139-1`                         | **BREAKING**, type                                      |
| `Account.timestamp`, unix time                                    | `birth_block`, a height                             | **BREAKING**, unit                                      |
| `Account.transactions: Vec<String>` hex                           | `wallet.transactions` map of objects + account refs | **BREAKING**, shape                                     |
| `Account.psbts: Vec<String>` base64                               | `wallet.psbts` map keyed by txid + account refs     | **BREAKING**, shape                                     |
| no `type` field                                                   | `type` mandatory                                    | **BREAKING**                                            |
| `KeyRole`/`KeyType` serialise PascalCase                          | registry values are lowercase                       | **BREAKING**, silent                                    |
| `network: Network` mandatory                                      | mandatory                                           | resolved by this survey                                 |
| `Backup.alias`                                                    | no wallet-level alias                               | LOSSY                                                   |
| `Account.chain_tip{height, hash}`                                 | `last_height`, an integer                           | lossy in principle; `block_hash` is always `None` today |
| `Backup.date`                                                     | `wallet.date`                                       | resolved by this survey                                 |
| `Account.coins: BTreeMap<String, Coin>`                           | the coin object                                     | resolved by this survey                                 |
| `Account.labels`, `Account.keys`, `Key.{key,alias,role,key_type}` | unchanged                                           | SAFE                                                    |

Notes:

- The `version` change is worse than a type change: the field is optional-with-default
  today, and `backup.rs:500-503` asserts a missing `version` reads as `0`. A
  `"BIP139-1"` string fails to deserialise the whole struct.
- `timestamp` drives rescan (`lianad/src/commands/mod.rs:335`), so a rename without the
  chain lookup silently corrupts it. The registry now states the conversion.
- `KeyRole`/`KeyType` have no `#[serde(rename_all)]`, so they emit `"Main"`, `"ThirdParty"`
  against the registry's `main`, `third_party`.
- Both transaction and PSBT changes are net wins: the daemon already holds
  `txid`/`height`/`time` (`daemon/model.rs:287,291-292`) that the hex-only export discards.
- `Coin` maps field for field, with two names corrected: `account` became `is_change`, and
  `is_coinbase` became `is_immature` to match what it actually holds.

## Per-wallet difficulty

| Wallet         | Verdict                                | Main blocker                                                                                                             |
|----------------|----------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| Bitcoin Core   | easy-moderate                          | Draft already exists. `keys{}`, BIP-85, BIP-39, BIP-352 are out of model                                                 |
| Liana          | moderate                               | Mandatory-field type changes; `coins`/`chain_tip`/`date` have no home                                                    |
| Sparrow        | moderate                               | One-account-per-file; descriptor reconstructed from policy+keystores; no role/status vocabulary                          |
| Bull Bitcoin   | moderate (app) / hard (SP)             | `tweak` and `script` persist in Rust but are not exposed over the FFI to Dart - a cross-repo change                      |
| Nunchuk        | moderate                               | `ExportBackup()` is already close to BIP-139 shape; `type` enum needs translation; Liquid fits nothing                   |
| Bitcoin Keeper | moderate                               | Label export and BSMS backup are ~80% there; tx cache and key roles are the gaps                                         |
| Bitcoin Safe   | moderate                               | Descriptor/label/tx plumbing is near-turnkey; `birth_block` does not exist at all                                        |
| Electrum       | moderate-hard                          | Mandatory `type`/`descriptor` unsatisfiable for imported-address and Old_KeyStore wallets                                |
| Green          | moderate (singlesig) / hard (multisig) | Multisig subaccounts have no descriptor representation whatsoever                                                        |
| Specter        | moderate                               | Closest structural match of any wallet; needs a top-level container to wrap N wallet files                               |
| Dana           | moderate-hard                          | No descriptor representation for a `bip392` account exists to build on                                                  |
| Wasabi         | hard                                   | No descriptors; one file holds 2-3 branches; core privacy state has no home                                              |
| Bitkey         | moderate                               | Three-key structure fits well, but descriptor, indices and tx cache are all synthesised from BDK live rather than stored |

## Prior art worth reading

Three wallets already ship something close to BIP-139:

- **Nunchuk** `ExportBackup()`/`SyncWithBackup()` (`storage/storage.cpp:1804-1947`) - a
  multi-wallet, multi-signer, cross-device JSON sync payload: `wallets[]` with descriptor
  plus `pending_signatures[]` holding PSBTs. The closest existing analogue to BIP-139.
- **Specter** `specter_backup_file()` (`specter.py:717-742`) - zips one JSON per wallet
  plus one per device; `WalletImporter` reads it back, plus Electrum and generic
  "account map" JSON (Fully Noded / Gordian / Sparrow style).
- **Keeper** - a BIP-329-shaped JSONL label export with explicit `txn`->`tx` renaming, a
  BSMS descriptor backup, and a full encrypted whole-wallet JSON backup to a relay server.

## Implementer traps found

- **Specter `last_block` is a block hash, not a height** (`wallet.py:547-558`, Core's
  `listsinceblock` cursor). A name-based mapping onto `last_height` corrupts the type.
- **Specter `Key.key_type` means output script purpose** (`wpkh`/`sh-wsh`/`wsh`/`tr`,
  `key.py:36`), not BIP-139's ownership axis. Copying by name produces garbage.
- **Specter `output_type` uses `"taproot"`** where Core and BIP-139 use `"bech32m"`.
- **`sp_output.label` is a false friend.** Dana and Bull Bitcoin both persist the raw
  BIP-352 label scalar under that name; BIP-139 documents it as human text.
- **Liana's `Coin.account` is not an account** - it is the keychain, `0` for receive and
  `1` for change. Its `is_coinbase` is populated from `is_immature`, not from whether the
  output is a coinbase.
- **Keeper's `lastSynched` is a timestamp**, not a height, despite the name.
- **Dana's `txid` is nullable** (`RecordedTransactionUnknownOutgoing`), conflicting with
  BIP-139's mandatory `txid`.
- **The Core draft is not current with the spec.** It emits `version` as integer `1` and
  checks it as `getInt<int>()`; it places `labels` and `transactions` at the **wallet
  root** rather than per-account (a structural, not naming, divergence); and it emits
  `receive_range_start`/`receive_range_end`, `bip329_labels`, and `block_height` where the
  spec now says `range_start`/`range_end`, `labels`, and `birth_block`.
