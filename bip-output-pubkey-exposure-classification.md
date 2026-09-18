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
  Version: 0.5.1
  Requires: 360
```

## Abstract

This document defines four exposure levels for Bitcoin outputs. The level answers one
question: how much would an attacker holding a cryptographically relevant quantum computer
have to do to take the coins? For one level the answer is nothing but wait. For another,
win a race against a single transaction. For another, the attack does not apply; no output
type deployed today reaches it. For the last, nobody can say yet.

The first two levels are the long exposure and short exposure vulnerabilities that BIP 360
defines, stated for one output rather than for an output type. The levels are derived only
from what the block chain shows, so two implementations looking at the same chain state
must reach the same answer. An implementation that cannot
tell must say so rather than report the output as safe.

## Motivation

I maintain a tool that classifies mainnet addresses by exposure. For its first month in
production it labelled an address that had been spent from, and still held coins, as
"exposed on spend". That label was wrong. The public key had been on the chain since the
first spend, and an attacker does not need to wait for the next one. The address was in
the same position as a P2PK output, and the tool was telling users it was safer. Fixing
that made me look at how other tools and published figures define exposure, and they do
not agree with each other.

Published estimates of the exposed supply run from about 25% to over 34%. That spread is
not measurement noise. It comes from definitional choices that are usually not stated:

- A reused address that has been spent from and still holds a balance. Some tools treat it
  as exposed only when it is next spent. To the attacker it is exposed now.
- A P2TR output. Its 32-byte output key is a public key. Some tools count it as protected
  because the internal key is hidden; the attacker does not need the internal key.
- A P2SH or P2WSH output whose script has never been revealed. Nothing about its keys can
  be observed, and tools differ on what to report.
- Keys disclosed off-chain, through an xpub given to a service or a spend of the same
  output on a fork. Some counts include these; the chain cannot see them.
- A P2MR output, once BIP 360 activates. It resists long exposure, and that is easy to
  read as safe. A spend still puts the leaf key in the mempool. Four revisions of this
  document made that mistake.

One rule runs through everything that follows: when the data cannot distinguish two
levels, the classifier reports the more exposed one. A tool that under-reports hands
someone a false all-clear they may act on. A tool that over-reports costs a migration that
was not needed. Those two errors are not equal, and I would rather my tool make the second.

BIP 360 already draws the line this document builds on. Its motivation separates long
exposure attacks, on keys that sit on the chain, from short exposure attacks, on keys that
appear in the mempool while a spend confirms. It lists which output types are vulnerable to
the first, and notes that the others become vulnerable the moment their script reveals a
key. That list is a statement about output types. Every disagreement above lives under its
footnote: what counts as revealed, for which outputs, and what to report when the chain
cannot be read in full. BIP 361 proposes a schedule for retiring legacy signatures and would
ask that question at scale. Neither document answers it, and it is not their job to.

The cost of disagreement is not confusion. It is wrong decisions. A mining pool or a
custodian deciding which addresses to move, and in what order, takes that decision from
whatever tool it uses. Where tools disagree, some addresses that are already exposed stay
where they are, and effort goes into moving addresses that were fine. If a proposal like
BIP 361 activates, the same question is asked at scale, with money attached, by software
that has to agree with other software.

This document stops at the observable fact. It does not score risk and does not tell
anyone when to migrate. My own tooling does score, and that score depends on balance,
dormancy and assumptions about when a quantum computer arrives. Those are judgements, and
other people will make them differently. Standardizing the fact underneath means those
judgements at least get made over the same facts. An informative appendix maps each level
to a minimum recommended action, because wallet developers asked for one; it is a floor
for wording, not a risk model.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and "MAY" in this document
are to be interpreted as described in RFC 2119.

### Terminology

* **Key material** — a compressed or uncompressed secp256k1 public key, or an x-only public key
  as defined in [BIP 340](bip-0340.mediawiki). A 32-byte x-only key is key material: the full
  point is recoverable by selecting the even-`y` solution.
* **Published** — appearing in the block chain in any confirmed transaction, whether in a
  `scriptPubKey`, a `scriptSig`, or a witness stack.
* **Spending key set** of an output `O` — the set of public keys that must produce valid
  signatures in order to spend `O`. For script-based outputs, this set is not knowable from `O`
  alone before the script is revealed.
* **Disclosed** — an output `O` is disclosed if every member of a sufficient subset of its
  spending key set has been published. For an `m`-of-`n` multisig output, publication of any `m`
  of the `n` keys is sufficient.
* **Long exposure** and **short exposure** — the two attacks [BIP 360](bip-0360.mediawiki)
  defines: on key material that sits on the chain, and on key material that appears in the
  mempool while a spending transaction waits to confirm. `EXPOSED_AT_REST` is the first
  vulnerability stated for one output; `EXPOSED_ON_SPEND` marks an output subject only to the
  second.

Unconfirmed transactions MUST NOT be used to determine an exposure level. A transaction in the
mempool discloses key material to observers, but that disclosure is not yet a property of the
chain and may never become one. Implementations MAY report mempool disclosure separately; it is
outside this classification.

### Exposure Levels

Every output is assigned exactly one of four levels.

#### `EXPOSED_AT_REST`

The output is disclosed. A CRQC-equipped adversary can derive the spending key offline and spend
the output at a time of its choosing, without waiting for the legitimate owner to act. No
observable on-chain event gives the owner warning or an opportunity to react. This is BIP 360's
long exposure vulnerability, applied to a single output.

An output is `EXPOSED_AT_REST` if either condition holds:

1. **Structural** — its `scriptPubKey` contains key material directly.
2. **Derived** — key material sufficient to spend it was published by an earlier transaction,
   typically because the same key or script was previously used and spent from.

Both conditions produce the same adversarial capability and therefore the same level. An
implementation MUST NOT assign a lesser level to a reused, previously-spent script merely because
the key was disclosed by a spend rather than by the `scriptPubKey`.

#### `EXPOSED_ON_SPEND`

The output is not disclosed, but spending it will necessarily publish key material. The adversary
has no offline attack. The exposure window opens when a spending transaction is broadcast and
closes when it is confirmed and buried; within that window, an adversary capable of deriving the
key faster than the transaction confirms may replace it. This is BIP 360's short exposure
vulnerability. BIP 360 notes that Bitcoin outputs are generally subject to it; that includes
P2MR until a leaf can be satisfied without secp256k1 key material.

Note that this level describes an output that is *safe at rest*: the holder still knows something
the adversary does not. The name has been read as "already exposed" by at least one reviewer;
`EXPOSED_WHEN_SPENT` is under consideration as a clearer label (see Rationale).

#### `NOT_EXPOSED`

The output's consensus rules do not require secp256k1 key material to spend it, so neither attack
applies: nothing sits on the chain to attack at rest, and nothing appears in the mempool at spend
time. This level is a property of the output *type*, established by its consensus rules. It MUST
NOT be inferred for a hash-committed script from the absence of evidence about the script's
contents.

No output type deployed at the time of writing has this property. P2MR
([BIP 360](bip-0360.mediawiki)) does not: removing the key path is what keeps it from being
exposed at rest, but every leaf that can be satisfied today is satisfied with a secp256k1
signature. The level is defined now so that an output type built on a post-quantum signature
scheme has a level to go to when one exists.

#### `UNDETERMINED`

The output's script semantics are not recognized by the implementation, and no sound statement
about its key material can be made.

`UNDETERMINED` MUST be assigned rather than `NOT_EXPOSED` whenever an output cannot be classified.
An implementation that has not been updated for an output type deployed after its release will
encounter such outputs; reporting them as unexposed would state a safety property the
implementation has not established. This level exists so that the classification degrades
correctly rather than optimistically as the chain evolves.

### Conservative Assignment

Implementations MUST apply the **fail-closed rule**: where available data is insufficient to
distinguish between two levels, the level indicating greater disclosure MUST be assigned.

A classifier that reports an output as less exposed than the chain warrants provides false
assurance to a holder who may act on it. A classifier that errs toward greater exposure prompts
an unnecessary migration. These errors are not symmetric, and the specification is not neutral
between them.

Consequences that follow from this rule:

* Failure to parse a script MUST NOT clear an exposure level that has already been established by
  other evidence.
* Truncated or partial transaction history MUST NOT yield `NOT_EXPOSED`; see
  [Classification Under Partial History](#classification-under-partial-history).
* Output types not recognized by the implementation MUST yield `UNDETERMINED`.
* `NOT_EXPOSED` is assigned by output type only; it MUST NOT be inferred from the contents of a
  script that has not been revealed.

### Classification by Output Type

The following table gives the level of an output that has *not* been disclosed by any earlier
transaction. The derived condition of `EXPOSED_AT_REST` overrides every row: an output for which
*everything required to construct a valid spend* — sufficient keys, and for script-committing
types the script itself — has been published elsewhere is `EXPOSED_AT_REST` regardless of its
type.

| Output type | On-chain commitment | Level absent prior disclosure |
| --- | --- | --- |
| P2PK | public key, in full | `EXPOSED_AT_REST` |
| P2MS (bare multisig) | all `n` public keys, in full | `EXPOSED_AT_REST` |
| P2PKH | `HASH160` of the key | `EXPOSED_ON_SPEND` |
| P2WPKH | `HASH160` of the key | `EXPOSED_ON_SPEND` |
| P2SH | `HASH160` of the redeem script | `EXPOSED_ON_SPEND` |
| P2WSH | `SHA256` of the witness script | `EXPOSED_ON_SPEND` |
| P2TR | 32-byte x-only output key | `EXPOSED_AT_REST` |
| P2MR ([BIP 360](bip-0360.mediawiki)) | 32-byte `TapBranch` Merkle root | `EXPOSED_ON_SPEND` |
| Other witness versions / programs | undetermined | `UNDETERMINED` |
| Non-standard or unparsable | undetermined | `UNDETERMINED` |

Three rows warrant explicit statement.

**P2TR is `EXPOSED_AT_REST`, including script-path-only outputs.** A Taproot output commits the
tweaked output key `Q = P + H(P‖m)·G` in the clear. An adversary who solves the discrete logarithm
of `Q` obtains a private key that satisfies key-path verification directly. Consensus does not
check how `Q` was constructed, so committing to a provably-unspendable internal key (a NUMS point)
does not prevent this: the output remains spendable by anyone who can solve for `Q`. Removing this
property is precisely the design goal of BIP 360.

This classification answers one question: *can an adversary spend the output under current
consensus rules?* A related but distinct question is whether the holder retains a secret the
adversary lacks — for a BIP 341-conformant P2TR output, the internal key `P` and the script tree
are such a secret, since `Q` alone does not reveal them. That secret is irrelevant to the
attacker's ability to spend today, but it could underpin a future recovery mechanism that
accepts proof of knowledge of `P` as evidence of legitimate ownership. The two questions have
different answers for P2TR, and both are useful; this document deliberately scopes itself to the
first because it is observable from chain data alone. Whether a given `Q` was produced by tweaking
an internal key, or is a bare untweaked public key placed in a v1 output by a non-conformant
implementation, cannot be determined on-chain — which is exactly why rescue-provability cannot be
the basis of a deterministic classification, and why any recovery mechanism built on it would
fail an unknown fraction of P2TR outputs. Implementations MAY report holder-retained secrets as a
separate attribute; they MUST NOT let it lower the exposure level.

**P2SH and P2WSH are `EXPOSED_ON_SPEND`, not `NOT_EXPOSED`.** The script is unknown before it is
revealed, so no claim can be made about its key material — but every spend reveals the script in
full, and every script that requires a signature reveals key material with it. The fail-closed
rule therefore assigns `EXPOSED_ON_SPEND`. A P2SH or P2WSH output committing to a script that
requires no signature would in fact be unexposed, but this is unobservable before the spend and
MUST NOT be assumed.

**P2MR is `EXPOSED_ON_SPEND`, not `NOT_EXPOSED`.** BIP 360 removes the key path, so nothing about
a P2MR output's keys sits on the chain: it is not exposed at rest, which is the property BIP 360
set out to provide. That says nothing about the spend. A script-path spend publishes the executed
leaf script, its Merkle path, and whatever satisfies the leaf; with the tapscript available today
that is a secp256k1 signature and the key it verifies against. While the spend waits to confirm,
an adversary who derives that key from the mempool holds a complete recipe for spending the same
output through the same leaf. That is the race which defines `EXPOSED_ON_SPEND`, and it is the
same race a P2WSH spend runs. BIP 360 says as much: P2MR resists long exposure attacks, and
protection from short exposure attacks waits on post-quantum signatures. An implementation
cannot observe the leaves of an unspent tree, so it MUST NOT assume a leaf that needs no
signature, exactly as for P2SH and P2WSH. Versions of this document before 0.5.0 assigned
`NOT_EXPOSED` here on the strength of the at-rest property alone. That was an error.

A leaf spend also discloses the tree for every *other* output committing to the same root: the
leaf script and Merkle path it publishes, with the derived key, are a complete spend recipe for
any such output, which is therefore `EXPOSED_AT_REST` by the derived condition. Publication of a
leaf key alone does not make a P2MR output disclosed, since spending needs the leaf and its path
as well; the derived condition applies to a P2MR output only when a complete recipe has been
published, in practice when an output committing to the same tree was previously spent through a
leaf whose keys are disclosed.

Until BIP 360 activates, a witness version 2, 32-byte output is spendable by anyone under current
consensus rules. That is not exposure to a quantum adversary but the absence of any lock, and it is
outside this classification; implementations SHOULD flag it separately.

### Classification Under Partial History

An implementation that cannot retrieve the complete transaction history of a script — because of
indexer pagination limits, scan budgets, or pruning — MUST NOT conclude `NOT_EXPOSED` from the
absence of a spend in the retrieved subset.

Where an implementation has access to aggregate output statistics for a script, the following
inference is sound and requires no history traversal:

> If the script has a confirmed spent-output count greater than zero, at least one spend has
> occurred. For every type in the table above other than `UNDETERMINED`, a spend publishes the
> material committed to by the script — the key for key-committing types, the full script (and
> any keys it contains) for script-committing types, and for P2MR the executed leaf with its
> Merkle path and keys, which is a complete recipe for every output committing to the same tree.
> The script is therefore disclosed, and all of its outputs are `EXPOSED_AT_REST` by the derived
> condition.

For a script-hash or P2MR output whose revealed script or leaf requires no signature, this floor
over-approximates — no key material was actually published. The error is in the conservative
direction, which the fail-closed rule permits; an implementation that retrieves the revealing
transaction SHOULD refine the level from the actual script content.

This yields a classification in constant time from an aggregate counter, and remains correct as a
lower bound when history retrieval is truncated. Implementations SHOULD use it as a floor:
retrieved transactions then serve to identify *which* keys were disclosed and *when*, refining
the evidence without being able to weaken the level.

The rules above apply to outputs whose classification depends on spend history — those that would
otherwise be `EXPOSED_ON_SPEND`. Structural assignment needs no history at all: a P2PK or P2TR
output is `EXPOSED_AT_REST` from its `scriptPubKey` alone, and an unrecognized type is
`UNDETERMINED` regardless of what history shows. Where a history-dependent classification is
required but neither complete history nor aggregate statistics are available, the implementation
MUST report `UNDETERMINED` rather than a level derived from an admittedly incomplete view.

### Indexer Blind Spots

Address-indexed APIs commonly index outputs by the address encoded in their `scriptPubKey`. P2PK
and bare P2MS outputs encode no address, and such indexers frequently omit them from the history
of the corresponding P2PKH address, even where the same key controls both.

An implementation relying on an address-indexed data source therefore cannot observe P2PK
disclosure for a key it is examining, and may report `EXPOSED_ON_SPEND` for a key whose full
public key has been on-chain since 2009. Implementations SHOULD additionally query by script
hash where the data source permits, and MUST document this limitation where it does not.

### Out-of-Band Disclosure

The following disclose key material without producing evidence on the Bitcoin chain, and are
therefore outside this classification. Implementations MUST NOT report `NOT_EXPOSED` or
`EXPOSED_ON_SPEND` as an assertion that no disclosure has occurred; the levels describe only what
the chain shows.

* **Fork-chain spends** — spending an output on a chain sharing Bitcoin's UTXO history publishes
  the public key there, exposing the corresponding unspent Bitcoin output.
* **Extended public key disclosure** — an xpub shared with a service provider discloses every
  child key derivable from it, including keys for outputs never spent on any chain.
* **Sidechain, bridge, and cross-protocol reuse** of the same key.
* **Compromise or publication by any party holding the key.**

Implementations that can observe such disclosure through other means SHOULD surface it as a
separate signal, distinctly labelled as not chain-derived.

### Test Vectors

Vectors are given at script level so that they may be verified without network access. Each is a
`scriptPubKey` in hex, with the level required for an output paying to it that has no prior
disclosure.

Every public key appearing below is a valid secp256k1 point, so that implementations performing
point validation accept these vectors. Where a 32-byte value is a hash rather than a key — the
P2WSH witness script hash and the P2MR Merkle root — an arbitrary value is used, as any 32-byte
string is well-formed in those positions.

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

History-dependent vectors, which require chain state rather than a script alone:

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

**Why four levels rather than two.** A binary exposed/not-exposed split conflates two adversarial
situations that call for different responses. An `EXPOSED_AT_REST` holder is under a standing
threat and must move funds to a quantum-resistant output. An `EXPOSED_ON_SPEND` holder is not
under threat while the output sits unspent, but faces a race at the moment of spending; the
mitigations differ, and so must the labels. The fourth level, `UNDETERMINED`, is required by the
fail-closed rule rather than by any distinction in risk.

**Why keep a level nothing reaches.** `NOT_EXPOSED` has no member today. It stays because the
classification should outlive the current set of output types: when an output type spendable
without secp256k1 key material exists, implementations need a level for it that is not
`UNDETERMINED`, and defining it now fixes what that level must mean, a property of consensus
rules and never an inference about a script nobody has seen.

**Why disclosure mechanism does not change the level.** An earlier formulation of this
classification treated structural exposure (P2PK, P2TR) and reuse-derived exposure (a spent-from
P2PKH retaining a balance) as distinct levels. They are not distinct to an adversary: in both
cases the key is on-chain and the coins can be taken without warning. Separating them invites the
reading that reused addresses are safer than P2PK, which is false. Implementations that wish to
report the mechanism SHOULD do so as an additional attribute, not by weakening the level.

**On the name `EXPOSED_ON_SPEND`.** Review of the initial draft showed that this label can be
read as "already exposed by a spend" — the opposite of its meaning, which is "not exposed until
spent". The semantics are not in question; the label is. `EXPOSED_WHEN_SPENT` is the leading
alternative, and a rename before this document reaches Complete would be cheap. It has not been
applied yet so that the name stays stable while the point is discussed; implementations
tracking this draft should treat the two spellings as synonyms until the question is settled.

**Why attacker-spendability, not holder-provability.** A reviewer observed that a P2TR holder
retains a secret — the internal key — that a CRQC solving `Q` never learns, and asked whether
that makes P2TR unexposed. It does not change what the adversary can do, so it does not change
the level; but it is a real property with real uses, and the P2TR discussion above now names
both questions. The reason the classification is built on the first is observability: whether a
`Q` was tweaked from an internal key cannot be determined from the chain, so a classification
that depended on it could not be deterministic. Exposure is a statement about the adversary;
provability is a statement about the holder, and belongs in a rescue-protocol specification.

**Why no scoring.** Converting exposure into a numeric risk score requires weighing balance,
dormancy, owner sophistication, and assumptions about CRQC timelines — all of which are contested
and none of which are observable on-chain. Standardizing the observable while leaving the weighing
to implementers is what makes independent results comparable. This BIP deliberately stops at the
fact.

**Why the aggregate-counter floor is specified.** Naively, establishing exposure requires scanning
a script's full history for a spend, which is unbounded work for heavily-used scripts and
impossible for many light clients. The floor reduces the common case to reading one counter, and —
more importantly — it is the reason a truncated scan cannot produce a false `NOT_EXPOSED`. Without
it, every implementation must independently decide what to report when it runs out of scan budget,
and the divergence this BIP exists to remove reappears at the engineering layer.

**Relationship to BIP 361.** BIP 361 proposes to stop accepting new outputs to legacy types, then
to disable legacy signature verification. Its phases are defined over output *types*, which
consensus can evaluate directly. This BIP addresses the question consensus does not answer and
wallets must: given an output of a legacy type, has its key already been published, and how
urgently must this particular holder act. The two are complementary; neither depends on the other
being adopted.

**Relationship to BIP 360.** BIP 360 defines the two attacks this document classifies against and
lists which output types are vulnerable to the first; the table above starts from that list, and
the levels are named so that they read back onto its terms. BIP 360 also supplies the migration
destination: P2MR is not exposed at rest, which is what a holder of an `EXPOSED_AT_REST` output
needs, and it is `EXPOSED_ON_SPEND` like every hash-committed type until post-quantum leaves
exist. This document requires BIP 360 for its terminology and to classify P2MR outputs; the
remainder applies unchanged if BIP 360 is never activated.

## Appendix A: Holder Implications (Informative)

This appendix is informative. It records, for each level, the minimum action a holder should be
advised to take, together with a fixed key that implementations MAY expose alongside the level so
that different wallets present the same baseline consistently. Implementations SHOULD NOT present
advice that contradicts the floor. They are free to explain reasons, urgency and further options
in their own words; the floor fixes the substance of the advice, not its wording.

| Level | Action key | Floor |
| --- | --- | --- |
| `EXPOSED_AT_REST` | `MIGRATE` | Move the funds to an output type that is not exposed at rest as soon as one the holder trusts is available. Until then, do not add funds to the output. |
| `EXPOSED_ON_SPEND` | `SWEEP_WHEN_SPENDING` | No action is needed while the output is unspent. When it is spent, spend the entire balance and do not send change or new funds back to the same script. |
| `NOT_EXPOSED` | `NONE` | No action. |
| `UNDETERMINED` | `TREAT_AS_MIGRATE` | Until the implementation can classify the output, advise as for `EXPOSED_AT_REST`. |

The floor for `EXPOSED_AT_REST` names a property, not an output type. Any never-used
hash-committed script is not exposed at rest, and so is P2MR ([BIP 360](bip-0360.mediawiki)) once
it is available; all of them are `EXPOSED_ON_SPEND`, and the floor for that level then applies.
Implementations SHOULD say which destinations they consider available, and SHOULD NOT describe
any of them as `NOT_EXPOSED`.

## Backward Compatibility

This BIP introduces no consensus, policy, or peer-to-peer protocol change. It defines an
observation over existing chain data, and no existing software becomes non-compliant by not
implementing it.

Software that currently reports exposure under a different taxonomy will find its output changes
in three respects on adopting this document: reused, previously-spent scripts that retain a
balance move from an on-spend classification to `EXPOSED_AT_REST`; unrecognized output types
move from an unexposed classification to `UNDETERMINED`; and P2MR outputs, for software that
followed versions of this document before 0.5.0, move from `NOT_EXPOSED` to `EXPOSED_ON_SPEND`.
All three changes are in the conservative direction. Implementations SHOULD version their
reports so that consumers can distinguish classifications produced before and after adoption.

## Reference Implementation

A self-contained implementation in Python, with no dependencies beyond the standard library, is
available at:

    https://github.com/duncan0k/pubkey-exposure-classification

It implements the level assignment, the fail-closed combinator, the derived-disclosure condition,
and the constant-time floor, and executes every vector in this document — both script-level and
history-dependent — when run directly. The vectors are additionally published there as
`test_vectors.json` under CC0-1.0 for use by implementations in other languages.

## Changelog

* 0.5.1 — Noted that a witness version 2, 32-byte output is spendable by anyone until BIP 360
  activates, which is outside this classification and which implementations SHOULD flag
  separately.
* 0.5.0 — Changed the type to Informational. Cited BIP 360's long exposure and short exposure
  attacks as the source of the first two levels and mapped the levels onto those terms, after
  review by murch on Delving Bitcoin. Corrected the classification of P2MR from `NOT_EXPOSED` to
  `EXPOSED_ON_SPEND`: a leaf spend publishes a secp256k1 key in the mempool, the same race as
  P2WSH, and the at-rest property BIP 360 provides is not a spend-time property; rereading BIP 360
  for the citation surfaced the error. Redefined `NOT_EXPOSED` as a property of an output type's
  consensus rules that no deployed type has, added vectors for unspent and spent-from P2MR
  scripts, extended the aggregate floor to P2MR, and reworded the Appendix A note and the
  Backward Compatibility section accordingly. Reworked the Motivation to say what this document
  adds under BIP 360's list rather than that no BIP addresses the question.
* 0.4.0 — Rewrote the Abstract and Motivation to state the author's reasoning directly,
  including the misclassification in the author's own tooling that motivated the work. Added
  Appendix A (informative): a fixed action key and a minimum recommended action per level, at the
  request of wallet developers on Delving Bitcoin; wallets own wording, reasons and urgency above
  the floor. The naming question for `EXPOSED_ON_SPEND` remains open with no new input; the
  synonym rule from 0.3.0 stands.
* 0.3.0 — Distinguished attacker-spendability (the basis of this classification) from
  holder-provability (a holder-retained secret such as a P2TR internal key), with a note in the
  P2TR discussion and a Rationale entry on why only the former can be classified deterministically
  from chain data; recorded that `EXPOSED_ON_SPEND` has been misread as "already exposed" and
  that `EXPOSED_WHEN_SPENT` is under consideration; added the Discussion header. Both technical
  points arose from review by conduition on the mailing list.
* 0.2.0 — Clarified that the derived condition requires a complete spend recipe, and how it
  applies (and does not apply) to P2MR outputs; scoped the partial-history `UNDETERMINED` rule to
  history-dependent classifications, since structural assignment needs no history; noted that the
  aggregate-counter floor over-approximates for revealed scripts requiring no signature, and that
  the error is in the conservative direction; removed an impossible `NOT_EXPOSED` mention from
  the indexer blind-spot discussion.
* 0.1.0 — Initial draft.

## Copyright

This document is licensed under the BSD 2-Clause License and, at the recipient's option, under
CC0 1.0 Universal. The test vectors are additionally placed under CC0 1.0 Universal so that they
may be copied into implementations without licensing friction.
