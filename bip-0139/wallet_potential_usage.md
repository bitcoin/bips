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
| Bull Bitcoin   | `ce0add466`                       |
| Nunchuk        | `a1d485a` / `025aba7` / `e091ed8` |
| Bitcoin Keeper | `3a7b53c` / `f960b1f`             |
| Bitcoin Safe   | `4ce099e`                         |
| Electrum       | `3d41451f2`                       |
| Green          | `71b90dd` / `08464d6`             |
| Specter        | `b8679a4`                         |
| Dana           | `2b8ba6d`                         |
| Wasabi         | `bbc25a3`                         |
| Bitkey         | `1c0858d09`                       |

Bitcoin Keeper's desktop companion is a pure HWI bridge with no database and no
persistence, so it contributes nothing to the matrix. Nunchuk and Green each keep their
data model in a shared core library (`libnunchuk` and `gdk`), which is what was read; the
platform applications were read for storage and export paths only. Bull Bitcoin was read on
its silent payments branch.

## The matrix

```
Core = Bitcoin Core     Keep = Bitcoin Keeper   Dana = Dana
Lian = Liana            BSaf = Bitcoin Safe     Wasb = Wasabi
Sprw = Sparrow          Elec = Electrum         Bitk = Bitkey
Bull = Bull Bitcoin     Grn = Green
Nunc = Nunchuk          Spec = Specter

field                        | Core | Lian | Sprw | Bull | Nunc | Keep | BSaf | Elec | Grn  | Spec | Dana | Wasb | Bitk |  ✓
-----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
wallet.version               |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  ✓   |  7
wallet.accounts              |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
wallet.name                  |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  -   |  ✓   |  -   |  8
wallet.note                  |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  2
wallet.network               |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
wallet.proprietary           |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  9
wallet.transactions          |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
wallet.psbts                 |  -   |  ✓   |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  -   |  7
-----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
account.type                 |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
account.descriptor           |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
account.name                 |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  8
account.description          |  -   |  -   |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  3
account.status               |  ✓   |  -   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  -   |  -   |  -   |  ✓   |  6
account.change_descriptor    |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  8
account.receive_index        |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   | 11
account.change_index         |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   | 11
account.range_start          |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  2
account.range_end            |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  5
account.change_range_start   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  2
account.change_range_end     |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  5
account.birth_block          |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  8
account.last_height          |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
account.bip352_labels        |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  1
account.keys                 |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
account.labels               |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   | 12
account.bip352_outputs       |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  3
account.bip39_mnemonic       |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  -   |  ✓   |  8
account.proprietary          |  -   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  ✓   |  7
-----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
signer.key_status            |  -   |  -   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  4
signer.bip85_derivation_path |  -   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  2
-----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
key.key                      |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
key.alias                    |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  -   |  ✓   |  9
key.role                     |  -   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |  6
key.key_type                 |  -   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  9
-----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
transaction.txid             |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
transaction.wtxid            |  ✓   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  6
transaction.hex              |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   | 10
transaction.block_time       |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
transaction.time_received    |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  5
transaction.blockhash        |  ✓   |  -   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  8
transaction.blockheight      |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   | 13
transaction.blockindex       |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  3
transaction.abandoned        |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  2
-----------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+-----
sp_output.outpoint           |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  3
sp_output.tweak              |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  3
sp_output.block_height       |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  3
sp_output.amount             |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  3
sp_output.script             |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  3
sp_output.label              |  -   |  -   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  1
sp_output.spend_status       |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  3
```

## Decisions taken from this survey

| Change                                                                                       | Evidence                                                                                          |
|----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| `type` names the descriptor language, not the kind of wallet; BIP-389 multipath is `bip_380` | 9 wallets had answered with their own taxonomy                                                    |
| added `multi_bip380`, an account whose `descriptor` is an array                              | one `addr()` account per address is degenerate for imported-address wallets                       |
| dropped `output_type`                                                                        | the mandatory descriptor already states it, more precisely                                        |
| dropped `wallet.last_height`, kept it on the account                                         | 7 wallets hold one sync point; the registry says write it into every account                      |
| `transaction.time` became `block_time`, absent while unconfirmed                             | no wallet stored the old "block time or first-seen" union                                         |
| `active` became `status` (active/superseded/archived), `hidden` split out                    | Keeper distinguishes archived from superseded in production; hidden is orthogonal                 |
| `birth_block` gained a derivation rule: convert, else estimate at or before, else omit       | 5 wallets hold a date, 3 a height                                                                 |
| added `gap_limit`, single value                                                              | 6 wallets store one; `range_*` does not carry the scanning policy                                 |
| added a coin object with `frozen`                                                            | 5 wallets hold UTXO state; frozen is user intent, unrecoverable from the chain                    |
| signers moved above the account, with `fingerprints[]`                                       | Specter, Nunchuk and Keeper all keep signers above accounts; one signer holds several master keys |
| added signer `modality`, `devices[]`, `bip85_application`/`index`                            | 6 wallets model how key material is held and how a signer is reached                              |
| `transactions` and `psbts` became wallet-level maps keyed by txid, referenced per account    | an entry touching two accounts was duplicated; two wallets cannot attribute one at all            |
| `wallet.description` became `wallet.note`, with `date`                                       | nothing had a wallet description; a note about the backup is a different thing                    |
| `bip352_labels` range encoded as `{start, end}`, end exclusive                               | `{0-10}` was not valid JSON                                                                       |
| mainnet mnemonics stay out of scope                                                          | 3 wallets hold them and must drop them on export                                                  |
| Liquid stays out of scope, carried in `proprietary`                                          | 2 wallets, and it needs an asset model the format does not have                                   |

Recommended and not yet applied: drop `sp_output.label` and register a field for the
BIP-352 label scalar. Only Sparrow fills it, and both silent-payment wallets need the name
for protocol data; BIP-329 already labels outputs through `account.labels`.

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

The question that prompted the survey: does the current draft break Liana's shipping
backup format (`liana-gui/src/backup.rs`)? Yes, in six ways.

| #  | Liana today                                               | BIP-139 now                         | Verdict                |
|----|-----------------------------------------------------------|-------------------------------------|------------------------|
| 1  | `version: u32`, serde default 0 (`backup.rs:60-66`)       | mandatory string `BIP139-1`         | **BREAKING**           |
| 2  | `Backup.alias` + `Key.alias` (`backup.rs:52,425`)         | aliases dropped                     | **BREAKING** (lossy)   |
| 3  | `Backup.date: Option<u64>` (`backup.rs:56,241`)           | no such field                       | LOSSY                  |
| 4  | `Account.timestamp` unix time (`backup.rs:352`)           | `birth_block`, a height             | **BREAKING** (unit)    |
| 5  | `Account.transactions: Vec<String>` hex (`backup.rs:358`) | array of tx objects                 | **BREAKING**           |
| 6  | `Account.coins: BTreeMap<String, Coin>` (`backup.rs:362`) | no such object                      | LOSSY                  |
| 7  | `Account.chain_tip{height,hash}` (`backup.rs:370-373`)    | `last_height` int                   | LOSSY (partial)        |
| 8  | no `type` field                                           | `type` mandatory enum               | **BREAKING**           |
| 9  | `network: Network` mandatory (`backup.rs:54`)             | optional                            | **BREAKING ON IMPORT** |
| 10 | `Account.labels: Option<bip329::Labels>`                  | `bip329_labels` renamed to `labels` | SAFE                   |
| 11 | `KeyRole`/`KeyType` serialise PascalCase                  | registry values are lowercase       | **BREAKING**           |
| 12 | `descriptor_id`, `bip`, `bip174_psbts`, `bip370_psbts`    | removed                             | N/A, never adopted     |

Details worth carrying forward:

- **Row 1 is worse than a type change.** The field is optional-with-default today; a unit
  test at `backup.rs:500-503` asserts a missing `version` defaults to `0`. A
  `"version":"BIP139-1"` string fails to deserialise the whole struct
  (`export.rs:1143`, `installer/decrypt.rs:153`).
- **Row 4 needs a chain lookup, not a cast.** `Account.timestamp` is a unix timestamp that
  drives rescan (`lianad/src/commands/mod.rs:335`). A naive rename silently corrupts
  rescan behaviour.
- **Row 5 is breaking but a net win.** The daemon already holds `txid`/`height`/`time`
  (`daemon/model.rs:287,291-292`) that the hex-only export throws away. Moving to
  transaction objects lets Liana capture more, not less.
- **Row 9 runs the opposite way from expected.** Liana's format is stricter for backups it
  *produces*, but a legal BIP-139 backup omitting `network` fails to deserialise into
  Liana at all - a unit test at `backup.rs:505-508` asserts this is a parse error.
- **Row 10 is a non-event.** Liana's field was *always* named `labels`, never
  `bip329_labels`. The rename aligns the spec with Liana rather than breaking it.
- **Row 11 was not previously noticed.** No `#[serde(rename_all)]` anywhere in
  `backup.rs`, so the enums serialise as `"Main"`, `"ThirdParty"` against the registry's
  `main`, `third_party`. Silent interop failure independent of the mandatory changes.
- **Row 6 is the significant one.** Liana's `Coin` (amount, outpoint, address,
  block_height, account, derivation_index, is_coinbase, is_from_self) has no home. This is
  the same gap five wallets hit - see "a general (non-SP) UTXO/coin object" above.

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
| Dana           | moderate-hard                          | No descriptor representation for a `bip_392` account exists to build on                                                  |
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
