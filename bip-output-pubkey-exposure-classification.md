```
  BIP: ?
  Layer: Applications
  Title: Output Public Key Exposure Classification
  Authors: duncan0k <duncan0k@cipherscope.io>
  Status: Draft
  Type: Informational
  Assigned: ?
  License: BSD-2-Clause OR CC0-1.0
  Discussion: 2026-09-03: https://delvingbitcoin.org/t/standardizing-an-exposure-classification-for-existing-outputs-pre-bip/2866
              2026-09-04: https://gnusha.org/pi/bitcoindev/010001a06dd4cdd9-b8082042-8750-4e9a-917e-2053c919e4c4-000000@email.amazonses.com/
  Version: 0.6.0
  Requires: 360
```

## Abstract

This document defines four exposure levels for Bitcoin outputs with respect to an adversary
holding a cryptographically relevant quantum computer (CRQC): `EXPOSED_AT_REST`,
`EXPOSED_ON_SPEND`, `NOT_EXPOSED` and `UNDETERMINED`. The first two are BIP 360's long exposure
and short exposure, applied to individual outputs. No deployed output type is `NOT_EXPOSED`.
Levels are derived from confirmed chain data only, so implementations that see the same chain
assign the same levels. When the data cannot distinguish two levels, the more exposed level is
assigned.

## Motivation

Published estimates of the supply exposed to a CRQC range from about 25% to over 34%. The
difference comes from definitional choices that are rarely stated:

- A reused script that has been spent from and still holds funds. Its key is on the chain, but
  some tools report it as exposed only when next spent.
- P2TR. The output key is a public key, but some tools treat the output as protected because the
  internal key is hidden.
- P2SH and P2WSH outputs whose script has not been revealed.
- Keys disclosed off-chain, for example through an xpub or a spend on a fork.
- P2MR. It is not exposed at rest, but spending through a leaf that requires a signature reveals
  its key in the mempool.

BIP 360 lists which output types are vulnerable to long exposure and notes that other types
become vulnerable once their script reveals a public key. It does not specify, for a given
output, what counts as revealed or what to report when the history is incomplete. A holder
checking an address, or a custodian deciding which outputs to move first, needs every tool to give
the same answer for the same output.

This document specifies those rules, with test vectors. It does not score risk or recommend when
to migrate. Appendix A gives an informative minimum action for each level.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and "MAY" in this document
are to be interpreted as described in RFC 2119.

### Terminology

* **Key material**: a secp256k1 public key, compressed, uncompressed, or x-only as defined in
  [BIP 340](bip-0340.mediawiki). An x-only key is key material; the point with even `y` is
  recoverable from it.
* **Published**: included in a confirmed transaction, in a `scriptPubKey`, a `scriptSig` or a
  witness.
* **Spending key set** of an output: the public keys whose signatures are required to spend it.
  For a script-committing output it cannot be determined from the output alone; the committed
  script is needed.
* **Disclosed**: an output is disclosed if it meets the structural or derived condition of
  `EXPOSED_AT_REST`.
* **Long exposure** and **short exposure**: the two attacks defined in
  [BIP 360](bip-0360.mediawiki), on key material that is on the chain and on key material that is
  in the mempool while a spend is unconfirmed.

Unconfirmed transactions MUST NOT be used to determine an exposure level. Mempool disclosure is
not a property of the chain and may never become one. Implementations MAY report it separately.

### Exposure Levels

Each output has exactly one level.

#### `EXPOSED_AT_REST`

An adversary can derive a private key offline and spend the output at any time, with no warning
to the owner. This is BIP 360's long exposure for a single output.

An output is `EXPOSED_AT_REST` if it is disclosed, that is, if either condition holds:

1. **Structural**: its `scriptPubKey` contains key material.
2. **Derived**: earlier transactions have published key material sufficient to spend it, together
   with any script or Merkle path needed to use that key material. For `m`-of-`n` multisig, any
   `m` of the `n` keys suffice. For P2MR this is a leaf script that requires a signature, its
   Merkle path and the keys it requires. This typically follows a spend from the same script or
   key.

An output that meets the derived condition MUST NOT be assigned a lower level than one that meets
the structural condition. Where history is partial, the aggregate-count floor also assigns this
level without establishing disclosure; see
[Classification Under Partial History](#classification-under-partial-history).

#### `EXPOSED_ON_SPEND`

The output is not disclosed, and spending it is assumed to publish key material. There is no
offline attack. The exposure window opens when a spending transaction is broadcast and closes when
that transaction is confirmed and buried. An adversary who derives the key within the window can
replace the transaction. This is BIP 360's short exposure.

Outputs that pay the same `scriptPubKey` share one window. It opens when a spend of any of them is
broadcast and closes when the spend of the last remaining one is confirmed and buried. Once a
confirmed spend has published key material that meets the derived condition, the other outputs
paying the script, and any paid to it later, are `EXPOSED_AT_REST`. Unconfirmed spends do not
change a level.

#### `NOT_EXPOSED`

The consensus rules of the output's type do not require secp256k1 key material to spend it, so
neither attack applies. This level is a property of the output type. It MUST NOT be inferred for a
hash-committed script from the absence of information about the script.

No deployed output type qualifies. P2MR ([BIP 360](bip-0360.mediawiki)) does not: an unrevealed
tree may contain a leaf that requires a secp256k1 signature. The level exists for future output
types built on post-quantum signature schemes.

#### `UNDETERMINED`

The implementation does not recognize the output's script semantics, and no sound statement about
its key material can be made. An output that cannot be classified MUST be assigned `UNDETERMINED`,
never `NOT_EXPOSED`. Outputs of types deployed after an implementation's release fall here.

### Conservative Assignment

Implementations MUST apply the **fail-closed rule**: where the available data cannot distinguish
two levels, the level indicating greater disclosure MUST be assigned. Under-reporting gives false
assurance; over-reporting costs an unneeded migration. The rule accepts the second error to avoid
the first.

Consequences:

* A script parse failure MUST NOT clear a level established by other evidence.
* Truncated or partial history MUST NOT yield `NOT_EXPOSED`; see
  [Classification Under Partial History](#classification-under-partial-history).
* Output types the implementation does not recognize MUST yield `UNDETERMINED`.
* `NOT_EXPOSED` is assigned by output type only. It MUST NOT be inferred from the contents of an
  unrevealed script.

### Classification by Output Type

The table gives the level of an output that no earlier transaction has disclosed. The derived
condition overrides every row.

| Output type | On-chain commitment | Level absent prior disclosure |
| --- | --- | --- |
| P2PK | public key, in full | `EXPOSED_AT_REST` |
| P2MS (bare multisig) | all `n` public keys, in full | `EXPOSED_AT_REST` |
| P2PKH | `HASH160` of the key | `EXPOSED_ON_SPEND` |
| P2WPKH | `HASH160` of the key | `EXPOSED_ON_SPEND` |
| P2SH | `HASH160` of the redeem script | `EXPOSED_ON_SPEND` |
| P2WSH | `SHA256` of the witness script | `EXPOSED_ON_SPEND` |
| P2TR | 32-byte x-only output key | `EXPOSED_AT_REST` |
| P2MR ([BIP 360](bip-0360.mediawiki)) | 32-byte script tree Merkle root | `EXPOSED_ON_SPEND` |
| Other witness versions / programs | undetermined | `UNDETERMINED` |
| Non-standard or unparsable | undetermined | `UNDETERMINED` |

**P2TR is `EXPOSED_AT_REST`, including script-path-only outputs.** The output key
`Q = P + H(P‖m)·G` is in the `scriptPubKey`. An adversary who computes the discrete logarithm of
`Q` can sign a key-path spend. Consensus does not check how `Q` was constructed, so a provably
unspendable (NUMS) internal key does not prevent this. `Q` alone does not reveal a BIP 341
output's internal key `P` or script tree, but neither limits key-path spending (see Rationale).
Implementations MAY report a holder-retained secret such as `P` as a separate attribute; they MUST
NOT let it lower the level.

**P2SH and P2WSH are `EXPOSED_ON_SPEND`.** The script is unknown until spent. A spend reveals it,
together with any key material its signatures require. A script that requires no signature would
be unexposed, but that cannot be observed before the spend and MUST NOT be assumed.

**P2MR is `EXPOSED_ON_SPEND`.** P2MR has no key path, so no key material is on the chain before a
spend: it is not exposed at rest. A script-path spend publishes the leaf script and its Merkle path
and, if the leaf requires a signature, a secp256k1 signature and the key it verifies against.
While the spend is unconfirmed, an adversary who derives the key can spend the same output through
the same leaf, as with P2WSH. BIP 360 states that P2MR resists long exposure, and that resistance
to short exposure requires post-quantum signatures. The leaves of an unspent tree cannot be
observed, so an implementation MUST NOT assume a leaf that requires no signature.

A confirmed spend through a leaf that requires a signature publishes that leaf's keys, script and
Merkle path, so every other output committing to the same tree is `EXPOSED_AT_REST` by the derived
condition. A published leaf key alone does not disclose a P2MR output, because spending it also
requires the leaf script and Merkle path.

Two cases are spendable by anyone, which is not exposure to a quantum adversary. Before BIP 360
activates, a witness version 2, 32-byte output can be spent without key material; its level
describes it as P2MR after activation. After activation, so can a P2MR output whose tree has depth
zero once its leaf script has been revealed, since BIP 360 skips script execution at depth zero.
Implementations SHOULD flag both cases separately, in addition to the level.

### Classification Under Partial History

These rules apply to types whose level depends on spend history, those that are otherwise
`EXPOSED_ON_SPEND`. Structural levels need no history: P2PK, P2MS and P2TR are `EXPOSED_AT_REST`
from the `scriptPubKey` alone, and an unrecognized type is `UNDETERMINED` whatever its history.

An implementation may be unable to retrieve a script's complete history, because of indexer
pagination, scan limits or pruning. An aggregate count of the script's confirmed spent outputs,
where available, is sufficient:

> If the count is greater than zero, at least one confirmed spend has occurred. For every type in
> the table other than `UNDETERMINED`, a spend publishes what the script commits to: the key, the
> full script and its keys, or for P2MR the executed leaf with its Merkle path and keys. All of
> its outputs are therefore `EXPOSED_AT_REST`. A count of zero establishes only that no output
> paying this `scriptPubKey` has a confirmed spend.

Implementations SHOULD use this inference as a floor that retrieved transactions do not lower, with
one exception. The floor over-approximates when no spend published key material, as with a
revealed script or leaf that requires no signature. An implementation that has retrieved every
spend of the script and finds that the derived condition does not hold SHOULD assign the level
from the table.

If neither complete history nor an aggregate count is available, the implementation MUST assign
`UNDETERMINED`.

### Indexer Blind Spots

Address-indexed data sources index outputs by the address encoded in their `scriptPubKey`. P2PK
and bare P2MS outputs have no address and are often missing from the history of the P2PKH address
for the same key. An implementation that relies on such a source can miss a P2PK disclosure and
report `EXPOSED_ON_SPEND` for a key that has been on the chain since 2009. Implementations SHOULD
also query by script hash where the source allows it, and MUST document the limitation where it
does not.

### Out-of-Band Disclosure

The following disclose key material without evidence on the Bitcoin chain and are outside this
classification:

* spends on a fork that shares Bitcoin's UTXO history;
* an extended public key given to a third party, which reveals every public key derivable from it,
  including keys of outputs never spent;
* reuse of the key on sidechains, bridges or other protocols;
* compromise or publication by anyone holding the key.

The levels describe only what the chain shows. Implementations MUST NOT present
`EXPOSED_ON_SPEND` or `NOT_EXPOSED` as evidence that no disclosure has occurred. Implementations
that learn of such disclosure by other means SHOULD report it as a separate signal, labelled as not
chain-derived.

### Test Vectors

Script-level vectors can be checked without network access. Each gives a `scriptPubKey` in hex and
the level required for an output paying to it with no prior disclosure. Every public key below is
a valid secp256k1 point. The P2WSH script hash and the P2MR Merkle root are arbitrary 32-byte
values.

```
# P2PK, uncompressed key (genesis coinbase output script)
4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac
=> EXPOSED_AT_REST

# P2PK, compressed key
2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac
=> EXPOSED_AT_REST

# P2PKH
76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac
=> EXPOSED_ON_SPEND

# P2MS, 1-of-2 bare multisig
5121022222222222222222222222222222222222222222222222222222222222222222
  21033333333333333333333333333333333333333333333333333333333333333333
  52ae
=> EXPOSED_AT_REST

# P2SH
a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87
=> EXPOSED_ON_SPEND

# P2WPKH (witness v0, 20-byte program)
001489abcdefabbaabbaabbaabbaabbaabbaabbaabba
=> EXPOSED_ON_SPEND

# P2WSH (witness v0, 32-byte program)
00201111111111111111111111111111111111111111111111111111111111111111
=> EXPOSED_ON_SPEND

# P2TR (witness v1, 32-byte program; output key is the generator's x-coordinate)
512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
=> EXPOSED_AT_REST

# P2MR (witness v2, 32-byte program, BIP 360)
52201111111111111111111111111111111111111111111111111111111111111111
=> EXPOSED_ON_SPEND

# Witness v2, 16-byte program — valid per BIP 350, semantics unassigned
5210751e76e8199196d454941c45d1b3a323
=> UNDETERMINED

# Witness v16, 40-byte program — valid per BIP 350, semantics unassigned
60285fbf4c95ba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1cba1c
=> UNDETERMINED
```

History-dependent vectors, which require chain state; every spend in them publishes key material:

| Condition | Required level |
| --- | --- |
| P2PKH script, one or more confirmed spends, balance remains | `EXPOSED_AT_REST` |
| P2WSH script, one or more confirmed spends, balance remains | `EXPOSED_AT_REST` |
| P2PKH script, no confirmed spend, retrieved history truncated | `EXPOSED_ON_SPEND` |
| P2PKH script, no confirmed spend, complete history available | `EXPOSED_ON_SPEND` |
| P2TR script, no transactions at all | `EXPOSED_AT_REST` |
| P2MR script, no confirmed spend, complete history available | `EXPOSED_ON_SPEND` |
| P2MR script, one or more confirmed spends, balance remains | `EXPOSED_AT_REST` |
| P2MR script, script-path spend occurred, revealed leaf key reused elsewhere | revealed key's other outputs become `EXPOSED_AT_REST` |
| Hash-committed script (e.g. P2PKH), aggregate statistics unavailable, history incomplete | `UNDETERMINED` |

## Rationale

**Four levels.** A single exposed/not-exposed split would merge a standing threat with a
spend-time race. The first calls for migration; the second for sweeping the script when it is
spent. `UNDETERMINED` is required by the fail-closed rule, not by a difference in risk.

**A level with no members.** `NOT_EXPOSED` has no member today. Defining it now fixes its meaning,
a property of consensus rules and never an inference about an unseen script, before an output type
that needs it exists.

**Disclosure mechanism does not change the level.** Structural and derived disclosure give the
adversary the same capability. Separate levels would suggest that a reused address is safer than
P2PK. Implementations that report the mechanism SHOULD do so as a separate attribute, not by
lowering the level.

**The name `EXPOSED_ON_SPEND`.** The level describes an output that is safe at rest: the holder
still knows something the adversary does not. Reviewers have read the name as "already exposed by
a spend". `EXPOSED_WHEN_SPENT` is the leading alternative. The name is kept stable while this is
discussed; implementations tracking this draft should treat the two spellings as synonyms until
the name is settled.

**Attacker-spendability, not holder-provability.** The classification describes what an adversary
can do under current consensus rules, which is observable. Whether the holder retains a secret the
adversary lacks, such as a P2TR internal key, is not: a tweaked `Q` cannot be distinguished
on-chain from a bare key. A classification based on it could not be deterministic, and a recovery
mechanism based on it would fail for an unknown fraction of P2TR outputs. Holder-provability
belongs in a rescue protocol specification.

**No scoring.** A risk score depends on balance, dormancy and CRQC timelines, which are contested
and not observable on-chain. Standardizing only the observable makes independent results
comparable.

**The aggregate-count floor.** A full history scan is unbounded for heavily used scripts and
unavailable to many light clients. The floor needs one counter and prevents a truncated scan from
under-reporting.

**Relationship to BIP 361.** BIP 361 defines its phases over output types, which consensus can
evaluate. This document answers a per-output question that consensus does not: whether the key of
a given output has already been published. Neither depends on the other.

**Relationship to BIP 360.** BIP 360 defines the two attacks and lists which output types are
vulnerable to long exposure; the table above starts from that list. BIP 360 also defines P2MR,
which is not exposed at rest and is `EXPOSED_ON_SPEND` because an unrevealed tree may contain a
secp256k1 leaf. This document requires BIP 360 for its terms and for P2MR. The rest applies if
BIP 360 is not activated.

## Appendix A: Holder Implications (Informative)

For each level, the table gives the minimum action a holder should be advised to take and a fixed
action key. Implementations MAY expose the key alongside the level so that wallets present the
same baseline. Implementations SHOULD NOT give advice that contradicts the floor. Wording,
reasons and urgency are left to them.

| Level | Action key | Floor |
| --- | --- | --- |
| `EXPOSED_AT_REST` | `MIGRATE` | Move the funds to an output type that is not exposed at rest as soon as one the holder trusts is available. Until then, do not add funds to the output. |
| `EXPOSED_ON_SPEND` | `SWEEP_WHEN_SPENDING` | No action while unspent. When spending, spend every output paying the same script in one transaction, and do not send change or new funds back to that script. |
| `NOT_EXPOSED` | `NONE` | No action. |
| `UNDETERMINED` | `TREAT_AS_MIGRATE` | Until the implementation can classify the output, advise as for `EXPOSED_AT_REST`. |

The `EXPOSED_AT_REST` floor names a property, not an output type. Hash-committed outputs with no
prior disclosure, including P2MR ([BIP 360](bip-0360.mediawiki)) once available, are not exposed at
rest. They are `EXPOSED_ON_SPEND`, and that floor then applies. Implementations SHOULD state which
destinations they consider available, and SHOULD NOT describe any of them as `NOT_EXPOSED`.

## Backward Compatibility

This document introduces no consensus, policy or peer-to-peer change. Software that reports
exposure under another taxonomy changes in three ways on adoption, all in the conservative
direction:

* reused scripts whose earlier spends published their keys, and that retain a balance, move to
  `EXPOSED_AT_REST`;
* unrecognized output types move to `UNDETERMINED`;
* for software that followed versions of this document before 0.5.0, P2MR outputs move from
  `NOT_EXPOSED` to `EXPOSED_ON_SPEND`.

Implementations SHOULD version their reports so that consumers can distinguish results produced
before and after adoption.

## Reference Implementation

A Python implementation that uses only the standard library is available at:

    https://github.com/duncan0k/pubkey-exposure-classification

It implements the level assignment, the fail-closed rule, the derived condition and the
aggregate-count floor, and runs every vector in this document. The vectors are also published
there as `test_vectors.json` under CC0-1.0.

## Changelog

* 0.6.0 — Condensed the text; test vector outcomes are unchanged. `EXPOSED_ON_SPEND` now covers
  outputs that pay the same script: the exposure window opens when a spend of any of them is
  broadcast and closes when the spend of the last of them is confirmed and buried. Removed the
  naming note from Specification; the discussion remains in Rationale. In Appendix A, the
  `SWEEP_WHEN_SPENDING` floor now says to spend every output paying the script in one transaction.
  Review by murch on the pull request. Also: stated the derived condition in terms of key material
  and defined "disclosed" by the two `EXPOSED_AT_REST` conditions, so a revealed script or leaf
  that requires no signature is not disclosure; the aggregate-count floor is now lowered only after
  every spend of the script has been retrieved; dropped the claim that every satisfiable P2MR leaf
  requires a secp256k1 signature; stated that a pre-activation witness version 2, 32-byte output
  carries the P2MR level and is flagged separately; and noted that a P2MR output with a depth-zero
  tree is spendable by anyone once its leaf script is revealed, which implementations SHOULD flag.
* 0.5.1 — Noted that a witness version 2, 32-byte output is spendable by anyone until BIP 360
  activates; implementations SHOULD flag it separately.
* 0.5.0 — Changed the type to Informational. Mapped the first two levels onto BIP 360's long and
  short exposure and cited it (review by murch on Delving Bitcoin). Corrected P2MR from
  `NOT_EXPOSED` to `EXPOSED_ON_SPEND`. Redefined `NOT_EXPOSED` as a property of an output type's
  consensus rules, which no deployed type has. Added P2MR vectors and extended the aggregate floor
  to P2MR.
* 0.4.0 — Rewrote the Abstract and Motivation. Added Appendix A, an action key and minimum action
  per level, requested by wallet developers on Delving Bitcoin.
* 0.3.0 — Distinguished attacker-spendability from holder-provability (review by conduition on
  the mailing list). Recorded the naming question for `EXPOSED_ON_SPEND`. Added the Discussion
  header.
* 0.2.0 — Clarified that the derived condition requires a complete spend recipe, including for
  P2MR. Limited the partial-history `UNDETERMINED` rule to history-dependent levels. Noted that the
  aggregate floor over-approximates for scripts that require no signature. Removed an impossible
  `NOT_EXPOSED` case from the indexer discussion.
* 0.1.0 — Initial draft.

## Copyright

This document is licensed under the BSD 2-Clause License and, at the recipient's option, under
CC0 1.0 Universal. The test vectors are additionally placed under CC0 1.0 Universal.
