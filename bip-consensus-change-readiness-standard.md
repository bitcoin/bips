```
  BIP: ?
  Title: Consensus Change Readiness Standard
  Authors: Asaf Fulks <asaf@asaffulkslaw.com>
  Status: Draft
  Type: Informational
  Assigned: ?
  License: CC0-1.0
```

## Abstract

Bitcoin's BIP process provides a mechanism for *proposing* consensus changes
but sets no minimum standard a proposal must meet *before* the community
considers activation: no required review period, no code-audit bar, no
agreed-upon activation-threshold floor, and no required assessment of
chain-split risk. This BIP defines a voluntary readiness standard for
scheduled consensus-change proposals — submission requirements, risk-tiered
minimum review periods, code-audit requirements, activation-threshold floors,
a chain-split risk assessment, sunset requirements, and a 20-criterion
readiness checklist that classifies a proposal Green / Yellow / Orange / Red.

The standard is advisory. It binds no one, mandates nothing, and confers no
authority to block a change; each node operator decides independently whether
to run any consensus change. A completed scorecard's only force is the
strength of the reasons it documents.

## Motivation

The BIP repository defines how a proposal is *written and tracked*. It does
not define when a proposal is *ready to activate*. In practice that gap has
been filled ad hoc, and the cost of filling it badly is a chain split.

The historical record shows both the gap and its consequences:

- **P2SH (2012)** set a ~55% coinbase-signal threshold; the signal fell short
  on the first poll, the chain forked between enforcing and non-enforcing
  miners, and the change carried only after it was re-cut to a hardcoded flag
  day (April 1, 2012, block 173,805).
- **SegWit2x (2017)** advanced a hard fork through a separate client promoted
  outside the reference client's review process, and was called off only days
  before its planned activation.
- **BIP 110 (2025)** proposed a high-risk, restriction-class soft fork on a
  55% threshold and moved from first proposal to activation client in roughly
  six weeks — an activation client whose own test suite was publicly reported
  failing, and no chain-split risk assessment published before signaling
  opened.

None of these episodes went wrong for lack of a *proposal* mechanism. They exposed the
absence of a *readiness* mechanism. Adjacent open-protocol communities have
long had one in spirit — the IETF's "rough consensus and running code"
(RFC 7282), RFC 2026's maturity gates, the PEP → BIP → EIP lineage — the idea
that a change earns activation by clearing documented maturity bars. This BIP
makes that bar explicit for Bitcoin consensus changes, as guidance.

A readiness standard also sits within the repository's documented remit: BIP 3
counts processes, guidelines, best practices, and incident reports (e.g.,
BIP 50) among the things BIPs describe, and it expressly leaves sentiment and
adoption tracking outside the repository's scope. This standard gives
proponents and reviewers a way to document readiness without asking the
repository — or its editors — to adjudicate it.

## Specification

The standard applies to **scheduled** consensus-change proposals. A genuine
emergency hard fork is evaluated against the emergency standards (Specification
§2, Category 4b) and is not scored on the checklist.

### 1. Submission requirements

A proposal submitted for review should include, at minimum: (A) a clear,
empirically supported **problem statement**; (B) a complete **technical
specification** sufficient for independent implementation; (C) a
**backward-compatibility analysis** identifying every transaction/script type
affected and quantifying users and value at risk; (D) a fully specified
**activation mechanism** (signaling method, threshold, window, timeout, defined
failure mode); (E) a **rollback procedure** — a self-executing sunset where the
proposal calls itself "temporary," and otherwise no affirmative obstruction of
future reversal; (F) a complete **reference implementation** with a test suite.

### 2. Minimum review periods (risk-tiered)

The tiers track risk to existing holdings and to network unity — whether a
change can invalidate currently valid transactions or split the chain — **not
the direction of the change**. Measured from publication of a complete spec and
reference implementation:

| Category | Description | Minimum review |
|---|---|---|
| 1 — Low risk | Policy/relay changes that don't move the consensus boundary | Not a consensus change; out of scope |
| 2 — Moderate | Soft fork adding rules without invalidating any currently valid tx (e.g., SegWit, Taproot) | **12 months** |
| 3 — High | Soft fork that invalidates/restricts currently valid tx or risks fund loss (e.g., BIP 110) | **24 months** |
| 4 — Hard fork | Any change old nodes reject | **36 months** general; **4a scheduled: 5 years**; **4b emergency: compressed, threat-calibrated** |

Hard forks additionally require explicit replay protection (or a published
rationale for its absence), demonstrated economic-node support, and a published
chain-split contingency plan. The need for replay protection is itself the
diagnostic of hard-fork status.

### 3. Code-audit requirements

Before activation signaling begins, the activation client must meet:
(A) **diverse independent review** — ≥ 3 reviewers whose organizational
affiliations differ from each other and from the authors, with prior
collaboration disclosed (the standard is diverse independent perspective, not
unachievable "pristine isolation"); (B) **test coverage** — unit, integration,
and regression tests, publicly reproducible; (C) **testnet deployment** —
≥ 3 months on signet/testnet, demonstrating activation, enforcement, and (if a
sunset is included) deactivation; (D) **fuzzing and adversarial testing**;
(E) **reviewer comprehension** — a named reviewer attests they understand the
consensus-critical change and can defend it, regardless of whether the code was
human- or AI-authored (the load-bearing requirement is comprehension, not
origin disclosure).

### 4. Activation-threshold floors

Thresholds are proposed as **minimum** standards, anchored to the chain-split
risk model (see Rationale):

- **Miner-activated soft fork (MASF):** minimum **90%** of hashrate over a
  signaling period of ≥ 2,016 blocks. 80–90% is risky (most of the safety
  margin gone); below 80% is presumptively dangerous; below 60% is reckless and
  should be rejected regardless of merit.
- **User-activated soft fork (UASF):** an extraordinary measure, appropriate
  only where a proposal has completed full review, has demonstrated broad
  economic-node support, sets an activation date ≥ 6 months out, and publishes a
  chain-split contingency plan.

### 5. Chain-split risk assessment

Every proposal should publish a formal assessment addressing, at minimum:
(A) **hashrate-distribution analysis** (credible path to threshold?);
(B) **economic-node analysis** (exchange/processor/infrastructure support);
(C) **replay protection** (and, if a soft fork that can't split absent miner
defection, the documented rationale for its absence); (D) a **contingency plan**
for failed activation or a persistent minority chain (split-detection trigger,
chain/ticker naming, user communication, exchange/custodian coordination,
replay-risk disclosure, wind-down path).

### 6. Sunset and reversibility

A proposal that describes itself as "temporary" must include a **self-executing
sunset**: an exact block height or MTP at which the new rules cease, implemented
in the activation client, tested on testnet, and requiring no later fork or
software update to take effect. "Temporary but requires intervention to expire"
is permanent with a stated aspiration.

### 7. Readiness checklist (the score)

Mark each criterion **Met** or **Not met**. Two narrow classes are excluded
from numerator and denominator: **temporal** (19, 20 — cannot fairly apply to a
proposal that activated before any published standard existed) and
**structural** (11 applies only with a miner-signaling threshold; 12 only where
a UASF mechanism is used). No other N/A is permitted.

**A. Proposal Quality**
1. Clear, empirically supported problem statement.
2. Complete technical specification; independently implementable.
3. Backward-compatibility analysis covering all affected transaction types, scripts, and use cases.
4. Fully specified activation mechanism (threshold, timeline, failure mode).
5. Rollback procedure; self-executing sunset if labeled "temporary."

**B. Code Quality**
6. ≥ 3 expert reviewers from distinct organizations; prior collaboration disclosed.
7. Comprehensive unit, integration, and regression tests.
8. Test-network deployment (signet or testnet) ≥ 3 months; deactivation tested if sunset included.
9. Fuzzing and adversarial testing performed.
10. Named human reviewer attests comprehension of consensus-critical code.

**C. Activation Safety**
11. Miner-signaling threshold (where used) ≥ 90%.
12. UASF (if used) has completed full review and broad economic-node support.
13. Chain-split risk assessment completed and published.
14. Replay protection, or documented rationale where soft fork cannot split absent defection.
15. Signaling only after the review floor elapses; enforcement ≥ 6 months after final client.

**D. Community Process**
16. Minimum review period for risk category (12 / 24 months; hard-fork floors above).
17. Public discussion across diverse stakeholders.
18. Major exchanges and infrastructure providers consulted.
19. Chain-split contingency plan published by proposal author.
20. Structured evaluation against a published readiness standard, published or answered by proponents.

**Classification**, by share of applicable criteria met:

| Share met | Classification |
|---|---|
| 100% | **Green** — met all applicable minimums; ready for activation signaling |
| 75–99% | **Yellow** — gaps to address before activation |
| 50–74% | **Orange** — significant deficiencies; do not proceed to signaling |
| Below 50% | **Red** — not ready |

Scorings should be published with their evidentiary basis and should cite the
edition/version evaluated against; the standard asks that evaluations be
legible and challengeable, not algorithmic.

## Rationale

**Why a 90% threshold floor.** Model post-activation hashrate as enforcing
(share *E*) and non-enforcing (1−*E*). The difference in cumulative work is the
same random walk Nakamoto used in §11 of the whitepaper; for *E* > ½ the
probability the non-enforcing chain ever leads by *k* blocks is
((1−*E*)/*E*)^*k*. These are first-passage probabilities over an unbounded
race, so they are conservative upper bounds for any finite activation window;
the finite-horizon double-spend analyses of Rosenfeld and Grunspan–Pérez-Marco
(see References), computed for the adversarial race, are a directional caution
the other way and do not narrow the gap that matters here. At the conventional
six-block finality depth (many services credit sooner, which only raises the
exposure): *E* =
0.55 → ≈ 0.30; *E* = 0.90 → ≈ 1.9×10⁻⁶; *E* = 0.95 → ≈ 2.1×10⁻⁸. Between 55%
and 95% the exposure does not taper — it collapses by five to seven orders of
magnitude. 90% is the lowest deployment threshold at which a modern soft fork has
activated without a split (Taproot), defended against a published model; 55%
(BIP 110, and P2SH in 2012) is not. BIP 91's 80% is not a counterexample: it
was a transient compulsory-signaling overlay coordinating BIP 141's 95%
deployment, not a rule-deployment threshold. The qualitative conclusion is
consistent with *BCAP* §3.5.2.

**Why risk-tiered review periods.** The cost of getting a change wrong scales
with its blast radius. Additive soft forks (Cat 2) can be absorbed faster than
restriction-class soft forks (Cat 3) that invalidate existing transactions;
hard forks (Cat 4) carry split risk that organic node-upgrade cycles need years
to absorb (≈ 95% adoption takes ~2–3 years empirically; the 5-year scheduled
floor sits deliberately above that).

**Why diverse review, not "unaffiliated."** Pristine reviewer isolation is
unachievable in a small developer community and weaponizable when claimed.
Diverse affiliation plus disclosure is achievable and legible.

**Why comprehension, not origin disclosure.** Code origin (human vs. AI) is
undetectable on inspection; reviewer comprehension is testable in any review
forum. The accountable-named-reviewer requirement catches AI, copy-paste, and
not-understood code uniformly.

**Why advisory (Informational).** The standard's authority is meant to come
from its usefulness, not from binding anyone. Each node operator decides
independently whether to run any change; the standard structures the decision,
it does not remove it. *(Under BIP 3's typology this is Informational —
"general guidelines or other information to the Bitcoin community." It is not
a Process BIP: BIP 3 describes Process BIPs as typically binding for the
corresponding process, and this standard binds no process.)*

## Backward Compatibility

None. This BIP specifies no change to consensus rules, network behavior, or any
on-chain artifact. It is a documentary standard for evaluating *other*
proposals.

## Reference Implementation

An interactive implementation of the Specification §7 checklist (live
Green/Yellow/Orange/Red scoring, with Taproot and BIP 110 preloaded as
reference scorings) is maintained in the project repository at
<https://github.com/asaffulks/consensus-change-standards>
(`docs/scorecard/index.html`, with a Markdown checklist `scorecard.md` and a
fillable `scorecard.pdf`), and served at
<https://asaffulks.github.io/consensus-change-standards/scorecard/>.

## Reference Scorings

Applying the Specification §7 checklist to the public record as of June 2026
(per-criterion working and evidentiary basis: source paper §5.4, 5th ed. 2026): **Taproot**
17/17 applicable (Green); **BIP 110** 3/20 (Red); **SegWit2x** ≈5/17
applicable (Red). A scoring grades the process by which a change was advanced,
as of the scoring date — not the outcome of its activation. A change can
activate without incident and still have been advanced outside every floor
above.

## References

- A. Fulks, *Consensus Change Standards: A Legal and Technical Framework for
  Bitcoin Protocol Governance* (5th ed. 2026) — the full treatment; history,
  legal analysis, and objections beyond this BIP's scope remain in the paper.
  DOI 10.5281/zenodo.20651832.
- Ren Crypto Fish, Steve Lee & Lyn Alden, *Analyzing Bitcoin Consensus: Risks
  in Protocol Upgrades* (Nov. 2024) [BCAP] — descriptive game theory this
  standard complements. <https://github.com/bitcoin-cap/bcap>
- Meni Rosenfeld, *Analysis of Hashrate-Based Double Spending* (2014),
  <https://arxiv.org/abs/1402.2009>; Cyril Grunspan & Ricardo Pérez-Marco,
  "Double Spend Races," *Int'l J. Theoretical & Applied Finance* 21, no. 8
  (2018), <https://arxiv.org/abs/1702.02867> — the double-spend race analyses
  noted in the Rationale.
- BIP 3 (BIP process; replaces BIP 2), and the activations and mechanisms
  referenced above: BIP 16 (P2SH), BIP 110, BIP 141 (SegWit),
  BIP 340/341/342 (Taproot), BIP 9, BIP 8, BIP 148, BIP 91.
- RFC 7282 ("On Consensus and Humming in the IETF"), RFC 2026 (Internet
  Standards Process).

## Copyright

This document is licensed under [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/).
