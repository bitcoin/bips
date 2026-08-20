# BIP-139 wallet survey

Which wallets would have interest in exporting or importing each BIP-139 field, and how
hard the format would be to implement for each.

Scope: the 53 fields defined by `bip-0139.md` (8 mandatory) plus
`bip-0139/field-registry.md` (45 optional). The enum value lists (key roles, key
types, key status, spend status) are values, not fields, so they are not rows.

Cell values answer: would this wallet have interest in round-tripping this field?

    ✓   the wallet has the concept and would want it
    ~   only in some configurations, or a lossy/partial match to its model
    -   the wallet has no such concept

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

field                     | Core | Lian | Sprw | Bull | Nunc | Keep | BSaf | Elec | Grn  | Spec | Dana | Wasb | Bitk | ✓  ~  -
--------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+---------
wallet.version            |  ✓   |  ✓   |  -   |  -   |  ~   |  ✓   |  ✓   |  ~   |  -   |  -   |  -   |  -   |  ✓   | 5  2  6
wallet.accounts           |  ✓   |  ✓   |  ~   |  ✓   |  ✓   |  ✓   |  ✓   |  ~   |  ✓   |  ~   |  ✓   |  ✓   |  ✓   |10  3  0
wallet.name               |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ~   |  ~   |  -   |  ~   |  -   | 5  3  5
wallet.description        |  -   |  -   |  ~   |  -   |  -   |  -   |  -   |  -   |  -   |  ~   |  -   |  -   |  -   | 0  2 11
wallet.network            |  ✓   |  ✓   |  ✓   |  ~   |  ~   |  ~   |  ✓   |  ~   |  ~   |  ✓   |  ✓   |  ✓   |  ✓   | 8  5  0
wallet.last_height        |  ✓   |  ~   |  ✓   |  -   |  ✓   |  -   |  ✓   |  ✓   |  ~   |  ~   |  ✓   |  ✓   |  ~   | 7  4  2
wallet.proprietary        |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   | 9  0  4
--------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+---------
account.type              |  ✓   |  ~   |  ~   |  ✓   |  ~   |  ~   |  ~   |  ~   |  ~   |  ✓   |  ~   |  ~   |  ✓   | 4  9  0
account.descriptor        |  ✓   |  ✓   |  ~   |  ~   |  ✓   |  ✓   |  ✓   |  ~   |  ~   |  ✓   |  ~   |  ~   |  ✓   | 7  6  0
account.name              |  -   |  ✓   |  ~   |  ✓   |  ✓   |  ✓   |  ✓   |  ~   |  ✓   |  ✓   |  -   |  -   |  -   | 7  2  4
account.description       |  -   |  -   |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   | 3  0 10
account.active            |  ✓   |  -   |  -   |  ~   |  ~   |  ~   |  -   |  -   |  ~   |  -   |  -   |  -   |  ~   | 1  5  7
account.output_type       |  ✓   |  -   |  ~   |  ~   |  ✓   |  ~   |  ~   |  ✓   |  ~   |  ~   |  -   |  ~   |  ✓   | 4  7  2
account.change_descriptor |  ✓   |  -   |  ✓   |  ✓   |  ~   |  -   |  -   |  ~   |  ✓   |  ✓   |  ~   |  -   |  ✓   | 6  3  4
account.receive_index     |  ✓   |  ✓   |  ~   |  ✓   |  ~   |  ✓   |  ✓   |  ✓   |  ~   |  ✓   |  -   |  ~   |  -   | 7  4  2
account.change_index      |  ✓   |  ✓   |  ~   |  ~   |  ~   |  ✓   |  ✓   |  ✓   |  ~   |  ✓   |  -   |  ~   |  -   | 6  5  2
account.range_start       |  ✓   |  -   |  -   |  -   |  -   |  ~   |  -   |  -   |  -   |  ~   |  -   |  -   |  -   | 1  2 10
account.range_end         |  ✓   |  -   |  -   |  -   |  ~   |  ~   |  ~   |  -   |  -   |  ✓   |  -   |  ~   |  -   | 2  4  7
account.change_range_start|  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  ~   |  -   |  -   |  -   | 1  1 11
account.change_range_end  |  ✓   |  -   |  -   |  -   |  ~   |  -   |  ~   |  -   |  -   |  ✓   |  -   |  ~   |  -   | 2  3  8
account.birth_block       |  ~   |  ~   |  ~   |  ~   |  -   |  -   |  -   |  -   |  ~   |  ✓   |  ~   |  ✓   |  -   | 2  6  5
account.last_height       |  ~   |  ✓   |  ~   |  ~   |  ✓   |  ~   |  ✓   |  ✓   |  ~   |  ~   |  ✓   |  ✓   |  ~   | 6  7  0
account.bip352_labels     |  -   |  -   |  ~   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   |  -   | 0  1 12
account.keys              |  ~   |  ✓   |  ~   |  ~   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ~   |  ~   |  ~   | 7  6  0
account.labels            |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |12  0  1
account.transactions      |  ~   |  ~   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ~   |10  3  0
account.bip352_outputs    |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   | 3  0 10
account.psbts             |  -   |  ✓   |  -   |  -   |  ✓   |  ✓   |  ~   |  ~   |  -   |  ✓   |  -   |  ~   |  -   | 4  3  6
account.bip39_mnemonic    |  -   |  -   |  ~   |  ✓   |  ~   |  ✓   |  ~   |  ~   |  ~   |  -   |  ~   |  -   |  ~   | 2  7  4
account.proprietary       |  -   |  ✓   |  ~   |  -   |  ~   |  -   |  ~   |  -   |  ~   |  -   |  -   |  ✓   |  ✓   | 3  4  6
--------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+---------
key.key                   |  ~   |  ✓   |  ~   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ~   |  ✓   |  ✓   |10  3  0
key.alias                 |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ~   |  -   |  ~   |  -   |  -   |  ~   | 6  3  4
key.role                  |  -   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ~   |  ✓   |  -   |  -   |  -   |  ✓   | 5  1  7
key.key_type              |  -   |  ✓   |  ~   |  ~   |  ✓   |  ✓   |  ~   |  ~   |  ✓   |  -   |  ~   |  ~   |  ✓   | 5  6  2
key.key_status            |  -   |  -   |  -   |  ✓   |  ~   |  ~   |  -   |  -   |  -   |  -   |  -   |  -   |  ~   | 1  3  9
key.bip85_derivation_path |  -   |  -   |  -   |  ✓   |  -   |  ✓   |  -   |  -   |  ~   |  -   |  -   |  -   |  -   | 2  1 10
--------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+---------
transaction.txid          |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ~   |  ✓   |  ✓   |12  1  0
transaction.wtxid         |  ✓   |  ~   |  ~   |  -   |  -   |  -   |  ~   |  ✓   |  -   |  -   |  -   |  ~   |  -   | 2  4  7
transaction.hex           |  ✓   |  ✓   |  ✓   |  ~   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  ✓   |  -   |  ✓   |  -   | 9  1  3
transaction.time          |  ✓   |  ✓   |  ~   |  ✓   |  ~   |  ~   |  ✓   |  ✓   |  ✓   |  ~   |  ~   |  ~   |  ~   | 6  7  0
transaction.time_received |  ✓   |  -   |  -   |  -   |  -   |  -   |  ~   |  -   |  -   |  ✓   |  ~   |  ✓   |  ~   | 3  3  7
transaction.blockhash     |  ✓   |  -   |  ✓   |  ✓   |  -   |  -   |  ✓   |  ✓   |  -   |  ✓   |  ✓   |  ✓   |  -   | 8  0  5
transaction.blockheight   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ~   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |  ✓   |12  1  0
transaction.blockindex    |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   |  -   |  ✓   |  -   | 3  0 10
transaction.abandoned     |  ✓   |  -   |  -   |  -   |  ~   |  -   |  -   |  ~   |  -   |  -   |  -   |  -   |  -   | 1  2 10
--------------------------+------+------+------+------+------+------+------+------+------+------+------+------+------+---------
sp_output.outpoint        |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   | 3  0 10
sp_output.tweak           |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   | 3  0 10
sp_output.block_height    |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ~   |  -   |  -   | 2  1 10
sp_output.amount          |  -   |  -   |  ✓   |  ✓   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   | 3  0 10
sp_output.script          |  -   |  -   |  ~   |  ~   |  -   |  -   |  -   |  -   |  -   |  -   |  ✓   |  -   |  -   | 1  2 10
sp_output.label           |  -   |  -   |  ✓   |  ~   |  -   |  -   |  -   |  -   |  -   |  -   |  ~   |  -   |  -   | 1  2 10
sp_output.spend_status    |  -   |  -   |  ~   |  ~   |  -   |  -   |  -   |  -   |  ~   |  -   |  ~   |  -   |  -   | 0  4  9
```

## Headline findings

### 1. Mandatory `descriptor` is satisfiable everywhere, but at a cost

Five wallets have shipping wallet types with no descriptor in their own model: Electrum
watch-only imported-address wallets (`Imported_Wallet.is_watching_only()` when keystore is
None, `wallet.py:3876`; `get_script_descriptor_for_address` returns `None` for
`script_type in ('address','unknown')`, `wallet.py:2712-2716`); Electrum `Old_KeyStore`
wallets (pre-BIP32 stretched mpk, `keystore.py:749-800`); Green multisig subaccounts (docs
scope `core_descriptors` to "Singlesig only", `gdk-json.rst:392`); Wasabi (identity is
`ExtPubKey` + hardcoded BIP-84/86 paths, `KeyManager.cs`); and Dana (scan/spend keys as raw
secp256k1 scalars, `rust/src/api/wallet.rs:45-58`).

None of these is actually unrepresentable. The descriptor family already covers them:

- **`addr(ADDR)` and `raw(HEX)`** - BIP-385, Status **Deployed**. A bare address or script
  is a valid top-level descriptor, which covers Electrum's imported-address wallets.
- **`sp(KEY)` / `sp(KEY,KEY)`** - BIP-392, Status Draft, and precisely what the `type` value
  `bip_392` refers to. Dana's scan and spend keys have a standard representation; it simply
  has not implemented one.
- **`wsh(multi(...))`** for Green multisig, synthesisable at export time since the service
  xpub is derivable client-side from `network_parameters.cpp` constants plus `gait_path`.
- Wasabi already builds `wpkh([fp/84'/0'/0']xpub/<0;1>/*)` for its segwit branch
  (`WpkhOutputDescriptorHelper.cs`), just for hardware registration rather than for export;
  only the taproot branch lacks a builder.

So the objection to mandatory `descriptor` is not impossibility. What remains are two real
costs:

**One account per address.** Expressing an Electrum imported-address wallet means one
`addr()` account per address. A wallet with 200 imported addresses becomes 200 accounts,
each with its own mandatory `type`. That is valid but degenerate, and it interacts badly
with everything else the account object carries - 200 copies of `birth_block`,
`last_height` and a `keys` map, for one wallet.

A `multi_bip380` type fixes this: one account whose `descriptor` is an array of BIP-380
descriptors rather than a single string. The 200 addresses become one
account with 200 `addr()` entries, and everything account-scoped is written once.

Two consequences to settle if this is adopted:

- **`descriptor` becomes shape-dependent on `type`** - a string for the single-descriptor
  types, an array for the set type. That is consistent with how the field is already
  defined ("representing the account structure as defined by the value in `type`", so
  `type` is explicitly the discriminator), but it does partly reopen the string-only
  decision. The narrower reading is that the field is always *either* a descriptor string
  or a list of them, never an object.
- **The index and range fields stop applying.** `receive_index`, `change_index`,
  `range_start`/`range_end` and `change_descriptor` are meaningless for a bag of
  non-ranged `addr()` descriptors. The registry should say they are absent for this type
  rather than leaving an importer to guess.

**Loss of derivation for `Old_KeyStore`.** Already-derived addresses can be written as
`addr()`, but BIP-380 has no key expression for Electrum's legacy stretching algorithm, so
what survives the round trip is a **snapshot of used addresses, not a wallet**. The
importer can see history and balances but cannot generate the next address. This is the one
place where the format genuinely cannot carry what the wallet holds.

Note also that `addr()` and `raw()` descriptors are not solvable - Bitcoin Core's own
descriptor header says so explicitly ("true for all descriptors except ones that use `raw`
or `addr` constructions", `src/script/descriptor.h:114-116`) - so an account backed by one
is watch-only by construction. That is correct for the Electrum case but worth stating in
the spec, since a consumer cannot assume a descriptor implies spendability.

### 1b. Liquid is out of scope, carried in `proprietary`

Nunchuk and Green both ship Liquid wallets. Nunchuk builds `elwpkh(...)` Elements
descriptors (`descriptor.cpp:352-365`); Green treats `liquid`, `testnet-liquid` and
`localtest-liquid` as full peer networks with their own confidential-transaction model
(`network_parameters.cpp:170-256`). Neither `type` nor `network` has a value for them, and
Liquid additionally carries per-output `asset_id`, `amountblinder`/`assetblinder`/
`blinding_key`, and a SLIP-77 master blinding key (`gdk-json.rst:107-109,530-556`) without
which a restored wallet cannot unblind its own history.

**Decision: leave Liquid out of the format for now and carry it in `proprietary`.** Two of
twelve wallets is a thin mandate for adding an asset model, blinding keys and two enum
value sets to a Bitcoin BIP, and `proprietary` exists precisely so a wallet can round-trip
what the format does not model.

One consequence to be aware of: `network` is an enum with no Liquid value, so a Liquid
account cannot state what chain it belongs to. Since `network` is optional the account can
simply omit it rather than claim to be Bitcoin, but that means a Liquid backup is
identifiable only by whatever the exporter puts in `proprietary`. If that turns out to
matter, adding the `network` values alone is a cheap registry change that does not require
modelling assets or blinding at all.

### 2. The closed `type` enum does not fit

`account.type` scores 3 ✓ / 9 ~ / 0 - : nearly every wallet is a partial fit.

- Nunchuk `LIQUID` wallets (`elwpkh(...)`, `descriptor.cpp:352-365`) fit none of the three
  values. Green's Liquid networks likewise.
- Keeper's `VaultType` (`DEFAULT`/`COLLABORATIVE`/`CANARY`/`SINGE_SIG`/`MINISCRIPT`) is
  disjoint from the enum.
- Sparrow's `MULTI_HD` spans plain `sortedmulti` (bip_380) and arbitrary miniscript
  (arguably bip_388), so the correct value is not mechanically deducible.
- Electrum's `wallet_type` values `old` and watch-only `imported` have no home.
- For Core, Specter and Bitcoin Safe the value is always `bip_380`, so the enum carries
  zero information.
- No value exists for BIP-389 multipath, which Liana, Bitcoin Safe, Keeper and Nunchuk all
  use.

### 3. Fields no surveyed wallet would populate

One field scored zero ✓ across all thirteen wallets:

| Field                | Note                                                                     |
|----------------------|--------------------------------------------------------------------------|
| `wallet.description` | Zero support; decision: rename to `wallet.note` as backup-event metadata |

`account.bip352_labels` deserves emphasis. The expectation was that a silent-payments
donation wallet would use per-donor labels heavily. It does not: Dana has no
`add_label`/`Label::new` call anywhere, exposing exactly one static receive address plus
one change address. Bull Bitcoin uses only the reserved change label
(`Label::new(scan_sk, 0)`), and Sparrow only recognises label index 0 while scanning with
an empty label set (`net/ElectrumServer.java:1676`). The array-or-range shape has nothing
to represent in any surveyed wallet.

`key.role` scores 5 ✓ once the question is read as intended - does the wallet have the
concept and would it want it round-tripped - rather than as "does it populate the field
today". Nobody populates it today. But five wallets model spending-policy roles as a core
part of what they are:

- **Liana**: the role of any key is already derivable from the descriptor.
  `contains_fingerprint_in_primary_path` / `contains_fingerprint_in_recovery_path`
  (`liana/src/descriptors/mod.rs:235-247`) resolve a fingerprint against
  `policy().primary_path` and `policy().recovery_paths`, and
  `KeyRole{Main,Recovery,Inheritance,Cosigning}` is defined at `backup.rs:434-444`. Only
  the wiring is missing: `to_backup()` writes `role: None`
  (`app/settings/mod.rs:494,503`), `from_backup()` takes `_role` (`mod.rs:512`), and
  `KeySetting` has no role field (`mod.rs:481-485`).
- **Green**: the server cosigning key is a genuine `third_party` + `cosigning`
  (`network_parameters.cpp` `service_pubkey`, `xpub_hdkey.cpp` `green_pubkeys`), and the
  2-of-3 `recovery_xpub` a genuine `recovery`.
- **Bitcoin Keeper**: keys are assigned to inheritance and emergency miniscript paths at
  vault construction (`EnhancedVault.ts:65-66,90-115`); `INHERITANCE` matches BIP-139's
  value exactly.
- **Nunchuk**: multisig-first with miniscript and timelock vaults, plus a `SignerTag::
  INHERITANCE` (`nunchuk.h:218-229`) and server/platform signer types.
- **Bitkey**: a 2-of-3 where the three keys are distinct types in the code -
  `appKey: AppSpendingPublicKey`, `hardwareKey: HwSpendingPublicKey`,
  `serverKey: F8eSpendingKeyset` (`spending/SpendingKeyset.kt`). The mapping is
  unambiguous - app and hardware are `main`/`internal`, the Block-held server key is
  `cosigning`/`third_party` - but it is expressed as separate columns rather than an enum,
  so an exporter hard-codes it.

In all four the role is currently *implied by structure* rather than stored as an
attribute, which is precisely the information a flat `keys{}` dictionary loses on export.
That is an argument for the field, not against it.

But the four role values are not equally inferable, and this is why no wallet populates
the field today. Structure distinguishes only two of them:

| Value         | Inferable from structure?                                         |
|---------------|-------------------------------------------------------------------|
| `main`        | Yes - the key sits in the primary spending path                   |
| `recovery`    | Only as "not main" - it sits on a timelocked branch               |
| `inheritance` | **No** - identical structure to `recovery`                        |
| `cosigning`   | Partially - correlates with a third-party key in the primary path |

`recovery` and `inheritance` are structurally indistinguishable: both are keys on a
timelocked branch, and the difference is whether the holder is the user later or an heir.
Liana's own descriptor comment calls the timelocked branch "the heir"
(`liana/src/descriptors/mod.rs:99`), yet a Liana wallet cannot tell the two apart from the
descriptor alone. The same ambiguity applies to Keeper's inheritance and emergency paths
and to Nunchuk's timelocked vaults.

That makes `role` a **user-intent** field, not a derived one - and no surveyed wallet has
an input path for it. In Liana, `KeyRole` appears only in the enum definition
(`backup.rs:435`), the struct field (`backup.rs:427`), an import, and the ignored `_role`
parameter (`app/settings/mod.rs:512`); there is no setter and no UI. So the honest reading
of the 4 ✓ is: four wallets want the field and can partially populate it, but none can
fill it completely without asking the user a question they are not currently asked. An
importer should treat a missing `role` as normal rather than as data loss.

`key.key_type` (`internal` / `external` / `third_party`) tracks the same five wallets at
5 ✓, and for the same reason: each of them has at least one key it does not own, and the
classification is inferable without any new stored state.

- **Liana** already populates it - `Some(KeyType::ThirdParty)` for cosigning-provider keys
  (`app/settings/mod.rs:495`). The only wallet that writes this field today.
- **Green**: the server key is Blockstream-operated from a hardcoded `service_pubkey`
  (`network_parameters.cpp`), so `third_party`; the user key and the 2-of-3 recovery key
  are both `internal`.
- **Bitcoin Keeper**: `Signer.isExternal` (`vault.ts:115`) is set for Policy-Server keys
  (`src/hardware/index.ts:405`), which is exactly the `third_party` distinction.
- **Nunchuk**: `SignerType` includes `SERVER`, `PLATFORM` and `FOREIGN_SOFTWARE`
  (`nunchuk.h:196-207`), all of which are non-owned keys.

The caveat is that these vocabularies do not line up one-to-one - Keeper's
`SignerStorage{HOT,COLD,WARM}` and Nunchuk's `SignerType` are device-modality axes that
happen to carry ownership information, not ownership axes. Mapping them is a judgement
call per wallet, not a rename. But the information is there.

Where the vocabulary does not stretch - Keeper's `EMERGENCY`, Nunchuk's server/platform
keys - the enum can simply grow, and this is cheap by construction: **the role, key type,
key status and spend status value lists live in `field-registry.md`, so adding a value is
a registry pull request. `type`'s enum lives in `bip-0139.md` itself and is mandatory, so
extending it means amending the BIP.** Those two enums are not equally expensive to
change, which is worth keeping in mind when judging the `type` findings above.

### 4. `key_status` and `bip85_derivation_path` trace to one wallet

Bull Bitcoin's `Bip85Derivations` table
(`lib/core/storage/tables/bip85_derivations_table.dart`) is an exact match for four
BIP-139 key fields at once:

```dart
class Bip85Derivations extends Table {
  TextColumn get path            => text()();            // bip85_derivation_path
  TextColumn get xprvFingerprint => text()();            // key
  TextColumn get application     => textEnum<...>()();   // no BIP-139 field
  TextColumn get status          => textEnum<...>()();   // key_status
  TextColumn get alias           => text().nullable()(); // alias
}
enum Bip85StatusColumn { active, inactive, revoked }     // verbatim
```

This is the only wallet with `revoked`. Greps are empty in Sparrow, Nunchuk, Keeper,
Liana, Green and Specter; the hits in Bitcoin Safe and Electrum are false positives (a
plugin subscription and Lightning HTLC revocation respectively).

`bip85_derivation_path` has two takers: Bull Bitcoin and Keeper. But Bull Bitcoin also
shows the field is incomplete - it derives non-key secrets (an Ark seed) via BIP-85 and
needs `application` and `index` to reconstruct them. The path alone does not round-trip.

This also resolves where `account.active` came from. The Bull Bitcoin usage is real, but
it lives at **key** granularity as a three-state enum, not at **account** granularity as a
boolean. `account.active` has no match in bb-mobile; the nearest account-level concept is
`isDefault` (which wallet is primary per network), a different axis. Only Core scores ✓.

### 5. Mainnet mnemonics are out of scope

**Decision: mainnet mnemonics are out of scope. The field stays, and its test-network-only
restriction stands unchanged.**

The consequence is deliberate: a wallet holding a mainnet mnemonic must not put it in a
BIP-139 backup, even though several would like to. Backing up mainnet seed material is a
separate problem with different security requirements, and this format - plaintext metadata
by design, possibly stored in cloud storage - is the wrong carrier for it.

The survey evidence below is what the decision was weighed against.

#### What the restriction costs

BIP-139 says the field must not hold mainnet mnemonics. Four wallets are affected.

- **Sparrow** routinely stores an encrypted mainnet BIP-39 seed inside the wallet file
  (`seed.mnemonicString`, `sql/V1__Initial.sql`). A compliant export must drop it.
- **Keeper** stores mainnet mobile-key mnemonics (`WalletDerivationDetails.mnemonic`).
- **Dana** is a mainnet donation wallet whose mnemonic is exactly what users want backed up.
- **Bitcoin Safe agrees with the rule**: `KeyStoreImporterTypes.seed` is restricted to
  regtest/testnet/testnet4/signet (`keystore.py:116-122`).
- **Electrum cannot populate it in principle**: its native seed is not BIP-39, and when
  restored from a real BIP-39 phrase it derives the xprv and discards the words
  (`keystore.py:1069-1079`).
- **Wasabi cannot either, mathematically**: it stores only the password-encrypted master
  key, and mnemonic-to-seed is a one-way KDF.

Also missing: a **BIP-39 passphrase** field. Bull Bitcoin has
`MnemonicSeedModel.passphrase`; a 25th-word wallet cannot be restored without it.

### 6. Fields with the strongest support (keep, unchanged)

`transaction.txid` (11 ✓), `transaction.blockheight` (11 ✓), `account.transactions`
(10 ✓), `wallet.accounts` (9 ✓), `key.key` (9 ✓), `transaction.hex` (9 ✓),
`transaction.blockhash` (8 ✓), `wallet.network` / `wallet.last_height` /
`account.receive_index` / `account.name` / `account.keys` / `account.labels` (7 ✓ each).

`account.labels` is worth noting: seven wallets already implement BIP-329 natively -
Sparrow (its author wrote BIP-329), Liana (via the `bip329` crate), Nunchuk
(`ExportBIP329`/`ImportBIP329`), Keeper (JSONL with `txn`->`tx` renaming), Bitcoin Safe,
Bull Bitcoin, and Green (`client_blob::get_bip329()`).

## Proposed additions to the key object

The `key_type` caveat above is a symptom: wallets are being asked to squeeze several
independent axes into one field. Two of them look worth registering, one does not.

### Signer modality (worth adding)

Six wallets model how the key material is held, separately from who owns it: Keeper
`SignerStorage{HOT,COLD,WARM}`; Nunchuk `SignerType{HARDWARE,AIRGAP,SOFTWARE,NFC,SERVER}`
(`nunchuk.h:196-207`); Sparrow `KeystoreSource`; Bull Bitcoin
`SignerEntity{local,remote,none}`; Wasabi `IsWatchOnly`/`IsHardwareWallet`
(`KeyManager.cs:175-180`); Electrum's `Hardware_KeyStore` vs `BIP32_KeyStore` class split.
This is what implementers reach for when asked to fill `key_type`, and why that mapping is
lossy: `HOT`/`COLD` is not `internal`/`external`.

Two properties this field must document if it is added:

**It can only degrade.** A hot key never becomes cold. Once key material has touched a
general-purpose or network-connected device it stays that way, so the value is monotonic
over a key's lifetime. An importer that sees a *colder* value than it last recorded should
treat that as suspect rather than as an upgrade, and a wallet must never silently promote
a key's modality on import.

**Two values, not three.** Keeper's `WARM` means the app's own software keys plus the
server key - `MOBILE_KEY`, `MY_KEEPER` (a seed typed into the app), `POLICY_SERVER`
(`signerSetup.ts:125,173`, `SetupSigningServer.tsx:80`, `EnterSeedScreen.tsx:350`) - while
`COLD` is dedicated hardware (20 assignments). `SignerStorage.HOT` is **never assigned
anywhere in the codebase**. So the middle value is neither well defined nor exercised: a
key held by app software is simply hot, and calling it warm just blurs the one distinction
that matters. This field should be two-valued - the key material either lives on a
dedicated signing device or it does not.

### Signer records (worth adding, as a list)

Six wallets store what looks at first like device identity - Sparrow `WalletModel`, Keeper
`Signer.type`, Bitcoin Safe `hardware_signer_id`, Nunchuk `SignerType`, Specter
`Device.device_type`, Bull Bitcoin `signerDevice` - plus Sparrow's
`KeystoreSource{HW_USB,HW_AIRGAPPED,SW_SEED,SW_WATCH,SW_PAYMENT_CODE}`.

None of them uses it as identity. In all six it answers one runtime question: **how do I
sign with this key** - open a USB dialog, show a QR, prompt for an NFC tap, or call a
server API. Keeper additionally branches on it to pick the right PSBT signing path per
vendor. The rest is presentation, plus per-model quirk workarounds (Sparrow skips high
account numbers on BitBox02) and reconnecting to a signer after a restore, which is
Specter's stated reason for wanting it.

Nothing uses it to reconstruct the wallet. Restore, rescan and spend all work without ever
knowing which brand of device holds a key; you just get a worse signing experience until
the user says.

So the right framing is not identity but a **cached record of what the wallet knows about
reaching this key**, which resolves the objection that a key is not bound to a device. As a
cache, "this key was last reachable over USB on a Coldcard" stays true after the user
migrates hardware - it merely stops being useful. As identity, the same string becomes
false.

**Shape.** Four separate facts share one scope - the (key, device) pair - and they belong
in one nested structure rather than as four flat key fields:

    devices: [
      {
        vendor?, model?,          // which product instance holds the key
        transports: [...],        // USB, airgapped QR, NFC, SD card, server API
        registration?,            // opaque blob proving the descriptor is registered
        last_health_check?        // when this path was last proven to work
      },
      ...
    ]

Why nested rather than flat:

- **transport is a device capability, not a key property.** A Coldcard offers USB, QR and
  SD; a Tapsigner offers only NFC. A flat array of `(transport, vendor, model)` triples
  would repeat the vendor once per transport.
- **vendor/model identifies a product instance**, and a key can sit on more than one device
  when a seed has been restored twice - hence a list.
- **registration is device-specific by construction** (Sparrow `keystore.deviceRegistration`,
  Nunchuk `LedgerWalletHmac`, Keeper `RegisteredVaultInfo.hmac`). An hmac produced on one
  device is meaningless on another, so it has to hang off the device entry. Losing it means
  a restored multisig wallet silently falls back to blind signing.
- **health check is recorded per signer in both wallets that have it** - Nunchuk
  `SingleSigner::get_last_health_check()` (`nunchuk.h:480,515`), Keeper
  `HealthCheckDetails[]`/`lastHealthCheck`. What it establishes is that you can still reach
  and sign with the key, and you establish that *through* a device, so per-device is the
  honest granularity. For inheritance and multisig wallets where a key may sit untouched
  for years, it is exactly the metadata a restore wants to carry.

It degrades cleanly in both directions: a wallet that knows the transport but not the
product emits transports only, covering Sparrow's `KeystoreSource`; a wallet that knows the
product but not how it will be reached emits vendor and model with no transport list,
covering the other five.

The whole structure is **advisory**: an importer may ignore it, must not treat it as
authoritative, and must fall back to asking the user. Two wallets already treat it as soft
- Bitcoin Safe guesses the product from free text and defaults to `generic`
(`keystore.py:153,310`), and Keeper has an explicit unknown case for external keys
(`operations/index.ts:1916`). Specter goes further and rewrites the value on export,
turning `BitcoinCore` into `BitcoinCoreWatchOnly` (`specter.py:736-737`) because the
exported file no longer carries the hot key. An existing implementation already edits this
value to suit the context it exports into, which is the strongest argument for marking the
whole structure advisory.

One caveat worth writing into any registry entry: `registration` is the one member that
cannot degrade gracefully. A stale transport or vendor is merely unhelpful; a stale
registration blob is actively wrong, so an importer must re-verify it rather than trust it.

### Where all this belongs: signers and devices above the account

BIP-139 nests `keys{}` inside the account. The three wallets that model signers most
seriously all keep them **above** accounts:

- **Specter**: `DeviceManager` is separate from `WalletManager`, and the backup zips two
  parallel trees, `wallets/<alias>.json` and `devices/<alias>.json` (`specter.py:726,739`).
- **Nunchuk**: `signerdb.cpp` is a distinct store from `walletdb.cpp` - signers get their
  own database, not a section of the wallet's.
- **Keeper**: two schemas, `Signer` (the shared object) and `VaultSigner` (the per-vault
  reference to it).

Account-nested `keys{}` inherits their problem: a signer used in three accounts is written
three times, and because the copies are mutable they drift - a health check recorded in one
account leaves the other two silently stale. The BIP is a Draft, so the structure is still
open, and the shape the survey points to is:

    wallet
      signers: [ { fingerprints: [ <fingerprint>, ... ],   // the keys this signer holds
                   key_status?, modality?, bip85_*?,       // what it is
                   vendor?, model?, transports: [...],     // how you reach it
                   registration?, last_health_check? } ]
      accounts: [ { ..., keys: { <fingerprint>: { alias, role, key_type } } } ]

Two objects, not three. A signer and a device are the same thing: the holder of key
material, whether that is a hardware product, a phone app or a remote service. Every
wallet that models this seriously models it that way, with the signer owning a list of
keys:

- **Specter**: `Device` holds `self.keys: List[Key]` (`device.py:48`) and serialises
  `"keys": [...]` (`device.py:109`).
- **Keeper**: `Signer` carries a `masterFingerprint` plus `signerXpubs`.
- **Nunchuk**: `MasterSigner` produces many `SingleSigner`s, stored in a separate
  `signerdb.cpp`.

So `fingerprints[]` belongs on the signer, and vendor, model, transports, registration and
health check are simply metadata about that signer.

Note that the plural is not about derivation depth. Every account derived from one seed
shares that seed's master fingerprint, so derivation alone would need only a single value.
The reason the field must be a list is that **a signer can hold several master keys**: a
device with more than one seed loaded, or BIP-39 passphrase wallets, where each passphrase
produces a different master key and therefore a different fingerprint. Keying signers by a
single fingerprint would make those unrepresentable, forcing one physical signer to appear
as several unrelated entries with duplicated metadata.

(This is also why a `passphrase` field matters - see the missing-fields table. Bull Bitcoin
stores `MnemonicSeedModel.passphrase`, and without it a passphrase-derived fingerprint
cannot be reproduced on restore.)

The two scopes are then:

- **signer** (wallet-wide): what holds the key material and how you reach it - the set of
  fingerprints it carries, its lifecycle status, its modality, its BIP-85 origin, and the
  advisory vendor/model/transport/registration/health-check metadata.
- **account key** (per fingerprint per account): how *this account* uses the key -
  `alias`, `role` and `key_type`. All three describe a relationship between a key and a
  policy, and relationships are per-account: the same key can be named differently in two
  accounts, be main in one and recovery in another, and be a third-party cosigner in one
  policy while being your own key in another.

The relation stays many-to-many and this shape still expresses both directions: one signer
holding several keys is several entries in its `fingerprints[]`, and one key living on two
signers - a seed restored twice - is two signer entries listing the same fingerprint.

This is a change to the BIP rather than a registry addition, but BIP-139 is Draft, so
nothing here is locked.

### BIP-85 application and index

One wallet, but it makes an existing field usable. Bull Bitcoin derives non-key secrets via
BIP-85 (`Bip85DerivationEntity.application`, `.index`); `bip85_derivation_path` alone
cannot reconstruct them.

### Not covered at all: xpub and key origin

The key object carries no xpub or key origin. That is fine while `descriptor` is mandatory
and carries the origin info, but it means key metadata is stranded for exactly the wallets
that cannot produce a descriptor (finding 1) - Electrum imported-address wallets, Green
multisig, Wasabi. The two problems compound.

### Summary

| Proposal                   | Verdict | Wallets | Shape                                                                               |
|----------------------------|---------|---------|-------------------------------------------------------------------------------------|
| signer modality            | add     | 6       | single value, two variants, degrade-only                                            |
| signer records             | add     | 6       | list of signers: fingerprints, vendor/model, transports, registration, health check |
| BIP-85 application + index | add     | 1       | makes `bip85_derivation_path` usable                                                |

The first three are registry entries. The signer/device placement is a change to the
BIP's own structure - see the section above.

## Decision: keep `bip352_labels`, fix the range encoding

`account.bip352_labels` scored zero ✓, but for a narrower reason than the other
zero-support fields. All three silent-payments wallets use only the reserved change label
`m=0`: Dana has no `add_label`/`Label::new` call anywhere and exposes one static receive
address plus one change address; Bull Bitcoin uses `Label::new(scan_sk, 0)` only
(`bwk/sp/src/receiver/mod.rs:215`); Sparrow recognises index 0 while scanning with an
explicitly empty label set (`net/ElectrumServer.java:1676`). The expectation that a
donation wallet would use per-donor labels is refuted.

**Decision: keep the field.** Silent payments are evolving quickly, and unlike every other
zero-support field this one loses *funds* rather than metadata when absent: scanning for a
labelled output requires knowing the label was issued, so if a user handed out an address
at `m=5` and the backup does not record it, a restore scanning only `m=0` silently misses
those outputs.

**Decision: the range form uses `start` and `end`.** The current definition reads "array of
silent payments labels (`[0,1,2]`), or range (`{0-10}`)", and `{0-10}` is not valid JSON -
as written, an implementer has no way to emit the range form at all. It becomes an object
with `start` and `end` members.

**Decision: `end` is exclusive**, `[start, end)`, following Core's convention for
`range_start`/`range_end` (`walletutil.h:69-70`). The two range concepts in the format
therefore agree, which avoids an obvious off-by-one trap.

## Decision: `spend_status` stays as defined

`sp_output.spend_status` scored zero ✓ with four `~`, and no wallet has `replaced`. Bull
Bitcoin's core models `OutputSpendStatus{Unspent, Spent{txid,block_hash}, Mined(block_hash)}`
with a coarser `UnifiedCoinStatus{unconfirmed, unspent, spent}` at the FFI; Dana computes
the status from a join and has no RBF tracking; Sparrow tracks `spentBy` with no matching
enum. (Note that silent-payment scanning seeing only confirmed outputs is a current
implementation limit, not a property of the protocol.)

**Decision: keep the four values as they are.** For the record, the definitions flatten two
independent axes into one value - the state of the transaction that *created* the output
(unconfirmed / confirmed / replaced) and whether the output has been *spent* - so some
combinations cannot be expressed, such as an output from an unconfirmed transaction that
has already been spent in an unconfirmed chain. Accepted as-is.

## Decision: `labels` and `transactions` stay account-level

This is the one place the spec and its only implementation structurally disagree. BIP-139
defines both as account fields; the Core draft emits `bip329_labels` and `transactions` as
**wallet-root** arrays (`backup.cpp` `BuildLabelsArray`, `BuildTransactionsArray`). Not a
naming difference - the objects sit at different depths, so a strict BIP-139 consumer and
the Core draft cannot read each other's labels or history at all.

**Decision: account-level is correct; the Core draft is wrong and should move them.**

The placement comes from Liana, where both live inside `struct Account`
(`backup.rs:356,358`) alongside `psbts`, `coins` and `chain_tip`, with the wallet object
holding only `name`, `alias`, `accounts`, `network`, `date`, `proprietary` and `version`.

Worth noting for whoever fixes the Core draft: Liana is single-account by construction
(`Backup::account()` and `export.rs:1173-1185` reject anything but exactly one account), so
the placement was never tested against the case that makes it matter. The open detail is a
transaction moving funds between two accounts of the same wallet - account-level storage
means writing it under both, or choosing an owner. Core hits this immediately because one
transaction routinely touches several descriptors; a rule for it should be stated in the
spec rather than left to implementers.

## Decision: add `gap_limit`

Six wallets store it and the format has no field for it: Nunchuk `DbKeys::GAP_LIMIT`
(user-tunable, `walletdb.cpp:214-216`), Sparrow `wallet.gapLimit`, Bitcoin Safe
`Wallet.gap` (default 20, passed as `stop_gap` to `full_scan`, `wallet.py:750,1330`),
Electrum `gap_limit` and `gap_limit_for_change` (20/10, `wallet.py:4093-4094`), Wasabi
`MinGapLimit`/`AbsoluteMinGapLimit` = 21 (`KeyManager.cs:29,55`), Bitkey
`DEFAULT_STOP_GAP = 1000` (`BdkBlockchainProviderImpl.kt:165`, a build-time constant rather
than per-wallet state, but a real value an exporter can emit).

It is not covered by anything already present. `receive_index`/`change_index` record how far
derivation got; `range_start`/`range_end` record the cached keypool window. Neither states
how far past the last used address a wallet must keep scanning - that is the *policy*, and
it is what an importer needs to reproduce the same address discovery. Restoring a wallet
built with gap 20 into an importer defaulting to 5 silently loses addresses and the funds
on them.

It also matters most for the wallets that cannot use `range_*` at all: Sparrow, Electrum and
Nunchuk track concrete generated addresses rather than a descriptor range, so the gap limit
is the only scanning parameter they have to hand over.

**Decision: add it.**

**Decision: a single `gap_limit`, not a receive/change pair.** Electrum is the only wallet
that keeps two values (`gap_limit` 20 and `gap_limit_for_change` 10,
`wallet.py:4093-4094`); the other four have one. An Electrum export therefore has to pick a
value, and the safe choice is the larger of the two, since a gap limit that is too high
only costs scanning work while one that is too low loses addresses.

## Proposed: backup-event metadata

`wallet.description` scored zero across all twelve wallets, and the two `~` are misfits -
Sparrow's `wallet.label` is not used as a description in reachable UI code, and Specter's
is per-wallet where a Specter wallet *is* an account, so it maps to `account.description`.
No wallet has anything to say about a wallet as a whole that would not sit better on the
account or in `name`.

**Decision: rename it to `wallet.note`** - a free-text note the user writes when making the
backup. That changes what the field is for: not a description of the wallet, but an
annotation of the export itself ("before hardware migration", "pre-upgrade snapshot"). The
concept has no competitor in any wallet because none of them offer it, not because users
would not use it.

This puts it in a small cluster of **backup-event** metadata, distinct from wallet
metadata, and there is already a second member with evidence behind it: Liana's
`Backup.date` (`backup.rs:56,241`), set from `now()` at export and purely informational -
nothing reads it back. It was listed as lossy in the compat table because BIP-139 has no
counterpart. If `note` is added, `date` is its natural companion: both describe the act of
backing up rather than the wallet, and together they let a user tell two backup files apart
without opening them.

Note that `account.description` is a different field and should stay - it has 3 ✓ (Nunchuk,
Keeper, Specter all have a real per-account description).

## Proposed: a general coin object

The most-requested missing structure in the survey, wanted by five wallets, and already
present in the format BIP-139 grew out of. Liana ships it today as
`Account.coins: BTreeMap<String, Coin>` (`backup.rs:362`), keyed by outpoint and populated
from `daemon.list_coins()` (`backup.rs:225-228`):

    Coin { amount, outpoint, address, block_height,
           account,          // 0 = receive, 1 = change
           derivation_index, is_coinbase, is_from_self }

BIP-139 dropped it, and the only outpoint-level object left is `bip352_outputs`, which is
silent-payments-specific. The other four wallets have the same shape under other names:
Wasabi `SmartCoin` (outpoint, amount, script, spent, anonymity set), Sparrow
`BlockTransactionHashIndex` (outpoint, value, height, label, `spentBy`), Nunchuk
`UnspentOutput` + `COININFO`, Green's tx-list outputs.

Two naming traps carried over from Liana's version if it is reused directly:

- **`account` is not an account.** It is the keychain, computed as
  `if value.is_change { 1 } else { 0 }` (`backup.rs:387-400`). In BIP-139 that name would
  collide with the real account object; `is_change` or `keychain` says what it means.
- **`is_coinbase` is populated from `is_immature`**, not from whether the output is a
  coinbase. The field name does not match its content.

Note also that Liana's export filters on `[Unconfirmed, Confirmed, Spending]`
(`backup.rs:220-224`), so it is a UTXO snapshot rather than full coin history.

What justifies the object is the data that a descriptor plus a rescan cannot reproduce
cheaply: `is_from_self`, immaturity, and above all the **frozen / do-not-spend flag**,
which six wallets track (Nunchuk `COININFO.LOCKED`, Sparrow `Status.FROZEN`, Electrum
`set_frozen_state_of_addresses`, Keeper `isManualOverride`, Specter `frozen_utxo`, Bull
Bitcoin `FrozenUtxos`) and which is pure user intent - it cannot be derived from the chain
at all. It currently has nowhere to go.

**It does not replace `bip352_outputs`.** The two overlap on outpoint, amount, script and
block height, but they are different kinds of record: a coin object is wallet state -
what you own and what you have decided about it - whereas `bip352_outputs` carries
`tweak`, which is spend-critical key material without which the output cannot be swept at
all. Tracking data and key material should not share an object, so both stay.

## Bitkey validates the signer/device split

Bitkey is the clearest test of the `signers` restructuring, because its three keys differ
on exactly the axes the new object separates:

- the **app key** is software on a phone - `modality: general`
- the **hardware key** lives on a dedicated Bitkey device - `modality: dedicated`, with
  `devices[]` populated as vendor `Block`, model `W1`/`W3` (`account/HardwareType.kt`) and
  `transports: ["nfc"]`, since hardware signing is an NFC tap
- the **server key** is held by Block's f8e service - `modality: general`,
  `transports: ["service"]`

Its `appGlobalAuthKeyHwSignature` (`Keybox.sq`) is close in spirit to
`devices[].registration`: a proof that a specific app key was paired with a specific
hardware unit. It attests key-to-device binding rather than descriptor registration, but it
is the same category of per-(key, device) evidence the field exists to carry.

Two Bitkey-specific gaps remain that no proposed field covers:

- **Service identifiers.** `f8eEnvironment` and the server-issued `keysetId`
  (`f8e/F8eSpendingKeyset.kt`) are what a restored wallet needs to re-establish contact with
  the cosigning service. Without them a `third_party`/`cosigning` key is identified but
  unusable. Green has the same problem in a different form; both would land in
  `proprietary` today.
- **Key rotation history.** Bitkey keeps inactive keysets (`spendingKeysetEntity` rows with
  `isActive = 0`) that belong to the *same* account but describe an older descriptor.
  BIP-139 has no way to say "this account, earlier keyset", so each rotation would have to
  become its own account entry, losing the relationship. Worth noting as a general gap: any
  wallet that rotates keys has wallet history the format cannot express.

## Why fields score `~`

163 of the 689 cells are `~`, spread over 45 fields. The reason a cell is `~` matters more
than the count, because it says whether the *field* is wrong or the *wallet* simply has not
got there. Six recurring reasons, in descending order of what they imply for the spec.

### A. Wrong unit - the field cannot hold what the wallet has

The strongest signal, because no amount of implementation work fixes it.

- **`birth_block` (6 `~`).** The field is a block height. Six wallets store a **date**:
  Liana `Account.timestamp` (unix, drives rescan, `lianad/commands/mod.rs:335`), Sparrow
  `wallet.birthDate` (the user-facing field; `birthHeight` exists in the schema but nothing
  populates it), Bull Bitcoin `birthday: DateTime?`, Dana `_keyBirthday` (a timestamp,
  resolved to a height only transiently at sync), Core `WalletDescriptor::creation_time`,
  Green `earliest_key_creation_time`. Only Specter and Wasabi store a real height. Converting
  needs a chain lookup, so an offline exporter cannot comply at all. **This is the single
  clearest case in the survey of a field the wallets cannot fill as defined.**
- **`account.last_height` (7 `~`).** Not a unit problem but the same shape: Core, Sparrow,
  Bull Bitcoin, Keeper, Green, Specter and Bitkey all hold one **wallet-global** sync
  height, not one per account. Specter's nearest value is a block *hash*, not a height.

### B. Wrong granularity - the data exists one level away

- `account.last_height` again: duplicated at wallet and account level in the format, while
  wallets have it once.
- `wallet.name` (3 `~`): Green, Specter and Wasabi have per-account or filename-derived
  names, nothing at wallet level.
- `wallet.accounts` (3 `~`): Sparrow, Electrum and Specter are one-account-per-file, so the
  array is always length 1 and multi-account state lives in separate files.
- `account.bip39_mnemonic` (7 `~`): a mnemonic belongs to a signer shared across accounts,
  not to one account. Resolved by dropping the field.

### C. Vocabulary mismatch - the concept matches, the values do not

Cheap to fix, because these value lists live in the registry.

- **`account.type` (9 `~`)** - the largest single cluster. Every wallet has its own
  taxonomy: Nunchuk `WalletType` (5 values incl. `LIQUID`), Keeper `VaultType`
  (`DEFAULT`/`COLLABORATIVE`/`CANARY`/`MINISCRIPT`), Sparrow `PolicyType` serialising as
  `"SINGLE"`/`"MULTI"`, Electrum `wallet_type` strings, Green subaccount types. None maps
  onto three values.
- `account.output_type` (7 `~`): everyone has script types, spelled differently -
  `p2wpkh` vs `bech32`, Specter's `"taproot"` vs `bech32m`.
- `wallet.network` (5 `~`): no testnet3/testnet4 split in Nunchuk, Keeper, Bitkey or Bull
  Bitcoin; Liquid missing entirely.
- `key.key_type` (6 `~`): device modality offered where ownership was asked for. Addressed
  by the new `modality` field.
- `account.active` (5 `~`): wallets have `archived` (Nunchuk, Keeper), `hidden` (Green) or
  `isDefault` (Bull Bitcoin) - inverse polarity, or a different axis altogether.
- Liana's `KeyRole`/`KeyType` serialise PascalCase against the registry's lowercase, which
  would fail silently even where the concept matches exactly.

### D. Derivable but not stored - a wallet gap, not a field problem

These need work in the exporter and nothing in the spec.

- `account.descriptor` (6 `~`): Sparrow, Nunchuk, Keeper, Bitkey and Bitcoin Safe all
  **reconstruct** the descriptor on demand from policy plus keys rather than persisting it.
  Export is easy; import is harder, since a descriptor string must be parsed back into
  signer objects.
- `account.receive_index` / `change_index` (4-5 `~`): Sparrow, Nunchuk, Green and Wasabi
  derive the index from the stored address list rather than keeping a counter.
- `transaction.wtxid` (4 `~`): computable from the stored raw transaction everywhere.
- `key.key` (3 `~`): the fingerprint is present inside descriptor key origins, just not
  surfaced as its own record.

### E. False friends - same name, different meaning

The dangerous category, because a name-based mapping silently produces wrong data.

- **`transaction.time` (7 `~`)** - defined as "block time when confirmed, otherwise
  first-seen". No wallet stores that union: Nunchuk keeps only `blocktime`, Wasabi only
  `FirstSeen` (its UI shows first-seen even for confirmed transactions), Sparrow only the
  block date (null while unconfirmed), Specter the `min()` of three sources, Dana only
  `confirmation_timestamp`. Since `time_received` already exists for first-seen, `time`
  asking for either value makes the pair ambiguous - an importer cannot tell which meaning
  a given `time` carries.
- `sp_output.label` (2 `~`): Dana and Bull Bitcoin store the raw BIP-352 label **scalar**
  under this name; the registry documents it as BIP-329-style text.
- Specter's `key_type` means output script purpose; Specter's `last_block` is a hash.
- Liana's `Coin.account` means keychain, and its `is_coinbase` holds immaturity.

### F. Configuration-dependent - correct behaviour

- `account.change_descriptor` (3 `~`): absent for BIP-389 multipath wallets by design.
- `account.range_*` (2-4 `~`): meaningless for wallets that track concrete addresses.
- `account.psbts` (3 `~`): Bitcoin Safe and Electrum persist PSBTs outside the wallet
  record; Wasabi exports them one-shot to a file.

### What this implies

Categories D and F need nothing. C is a registry job, already in hand for `type` and
`key_type`. B is mostly resolved by moving signers above the account.

**A is the open one, and `birth_block` is the case to revisit.** Six wallets hold a
timestamp and two hold a height, so as defined the field is unfillable by the majority
without a chain lookup - and an offline exporter cannot do one at all.

## Labels: the gap belongs to BIP-329, not here

`account.labels` originally scored 5 `~`. All five are now ✓, and no BIP-139 change was
needed for any of them.

Seven wallets already implement BIP-329 natively - Sparrow (whose author wrote it), Liana
(the `bip329` crate), Nunchuk (`ExportBIP329`/`ImportBIP329`), Keeper, Bitcoin Safe, Bull
Bitcoin and Green. That is the strongest adoption of any standard this format delegates to.

The five `~` had two causes, both resolved:

- **Mechanical conversion.** Electrum keeps a flat `{key: text}` dict and infers the record
  type from the key's shape; Specter keeps `{label: [addresses]}`, address-only; Core's
  draft synthesises `type: "tx"` entries from address-book data and transaction comments;
  Dana has a per-transaction `user_note`. All are exporter work, nothing the spec must
  change. Core's two real problems - the `bip329_labels` name and wallet-root placement -
  are fixed separately.
- **Multiple labels per item.** Wasabi's `LabelsArray` is a *set* of labels per address or
  transaction feeding its cluster analysis; Nunchuk has `TAGS` and `COLLECTIONS` tables;
  Bitcoin Safe has `category` and works around the single-string limit by concatenating it
  into the label with a `" #"` separator. BIP-329 gives one `label` string per reference.

The second is a real limitation, but it is BIP-329's, and BIP-329 already has the mechanism
to fix it: an **Additional Fields** section (`bip-0329.mediawiki:142`) defining optional
per-record fields such as `height`, `time`, `fee`, `value`, `rate`, `fmv` and `keypath`.

A `tags` array of strings, valid on any record type, covers all three wallets:

    { "type": "output", "ref": "abc...:1", "label": "rent",
      "tags": ["kyc-free", "collection:cold-storage", "category:savings"] }

Bare strings are plain tags; an optional `ns:value` prefix carries a second axis, which is
what Nunchuk needs to keep tags and collections apart and what Bitcoin Safe needs for
`category`. Splitting on the first colon leaves tag text free to contain others. It
degrades cleanly: a wallet with only plain tags emits bare strings, and an importer that
does not recognise a namespace still sees a usable tag.

Adding this to BIP-139 instead would fork labelling into two mechanisms and undo the
benefit of delegating, so the proposal belongs upstream.

Separately, BIP-329's Additional Fields already cover something recorded below as missing:
`rate` and `fmv` are exactly Electrum's per-transaction fiat cost-basis data
(`set_fiat_value`), so that gap is closed upstream too.

## `proprietary` needs no change

The six `~` on `wallet.proprietary` were a scoring artefact. No wallet has a field named
`proprietary`, but every one has application-specific data and nowhere else to put it -
Core's wallet flags and node config, Sparrow's `walletConfig` and `walletTable`, Nunchuk's
`tapsigners`/`deleted_wallets`, Electrum's `db_metadata`, Green's settings and client blob.
All are ✓ on interest; the bucket is simply created at export time.

Two objections were considered and rejected:

- **That importers discard it.** The Importing section says to "discard unsupported
  fields", which drops another application's proprietary data on a round trip. This is
  intended: a backup is a snapshot written by one wallet, and a wallet that re-exports is
  writing its own backup, not editing someone else's.
- **That keys could collide without namespacing.** They cannot in practice. A backup file
  is not expected to be written or updated by two different applications, so the key space
  belongs to whichever wallet wrote the file.

Core's draft did introduce `wallet_flags` and `bitcoin_conf` as top-level keys rather than
nesting them under `proprietary`, which is worth noting as an implementation detail to
reconcile, but it does not indicate a problem with the field.

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
- **Dana's `txid` is nullable** (`RecordedTransactionUnknownOutgoing`), conflicting with
  BIP-139's mandatory `txid`.
- **The Core draft is not current with the spec.** It emits `version` as integer `1` and
  checks it as `getInt<int>()`; it places `labels` and `transactions` at the **wallet
  root** rather than per-account (a structural, not naming, divergence); and it emits
  `receive_range_start`/`receive_range_end`, `bip329_labels`, and `block_height` where the
  spec now says `range_start`/`range_end`, `labels`, and `birth_block`.
