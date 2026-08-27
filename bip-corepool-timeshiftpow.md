```
  BIP: ?
  Layer: Consensus (hard fork)
  Title: Time-Shifted Proof of Work (TSPOW)
  Author: corepool <24285740+corepool@users.noreply.github.com>
  Comments-Summary: No comments yet.
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-TSPOW
               https://groups.google.com/g/bitcoindev/c/4bbb1017-8080-4916-8f85-082d2ebf5eacn
  Status: Draft
  Type: Informational
  Created: 2026-08-27
  License: BSD-2-Clause
  Discussions-To: https://groups.google.com/g/bitcoindev
  Post-History: 2026-08-27: https://groups.google.com/g/bitcoindev/c/4bbb1017-8080-4916-8f85-082d2ebf5eacn
```

## Abstract

This BIP describes **Time-Shifted Proof of Work (TSPOW)**, a consensus-design
pattern that splits traditional Proof-of-Work into two stages: (1) an
initial-work stage that issues a *warrant* (`H_n`) carrying the new-coin reward,
and (2) a time-shifted selection stage that picks a *block producer* from a
candidate pool, earning the transaction-fee reward. Version 3.0 of the design —
described here — augments the original scheme with a **dynamic sliding-window
candidate pool** and an **external randomness beacon** to harden the pool
management and the election-seed components.

This BIP is **informational**: it is a research proposal, not a recommendation
to fork the Bitcoin main chain. It specifies the protocol, states its
mathematical properties, and — honestly — documents both what the design does
and does not achieve: block-time variance is reduced by a factor `1/k`, warrant
hiding is economically disincentivized, private mining is eliminated *only* when
an honest external beacon is present, and a 51% adversary's power is
**not** changed by the scheme natively.

## Copyright

This BIP is licensed under the BSD-2-Clause license.

## Motivation

Bitcoin's single-stage Proof-of-Work binds three roles into one event: finding a
hash below target, earning the block reward, and authoring the block. This
coupling has two structural consequences:

1. **Unstable block time.** Block intervals are exponential; variance equals
   `1/lambda^2` with mean `1/lambda`, giving a unit coefficient of variation.
2. **Selfish-mining surface.** A valid proof can be withheld and later revealed
   to force reorganizations, amplifying an adversary's block share beyond its
   hash-power share and lowering the effective security threshold.

TSPOW separates the role that requires work (earning the new coin via a public
warrant) from the role that authors a block (a selection among mature warrants).
Because block production waits for `k` *accumulated* warrants rather than one
exponential arrival, the block interval follows a Gamma distribution with
variance divided by `k`. Because warrants expire and rewards are deferred,
withholding a warrant is economically self-defeating.

This BIP is informational: it documents the design and its security analysis for
the community as part of a research effort on alternative PoW constructions.

## Specification

### Notation

| Symbol | Meaning |
| --- | --- |
| `H` | Cryptographic hash function modeled as a random oracle (e.g. SHA-256) |
| `H_n` | A valid initial hash (warrant) found by a miner: `H(header, nonce) < D_1` |
| `alpha`, `beta` | Honest / adversarial hash-power fractions, `alpha > 1/2` |
| `D_1` | Initial-hash difficulty target (stage-1) |
| `S` | Target pool size (number of live candidate warrants) |
| `k` | Trigger batch size: one selection per `k` newly admitted warrants |
| `L` | Warrant lifetime in blocks; expired warrants are voided (no reward) |
| `Delta_max` | Maximum allowed delay (in blocks) between PoW finding and broadcast |
| `T_max` | Forced-trigger interval: maximum time between consecutive selections |
| `R` | Randomness from the external beacon; adversarial-reshaping hard |
| `PrevBlockHash` | Hash of the previous block, bound into the election |

### Stage 1 — Warrant issuance

A miner iterates nonces until `H(header, nonce) < D_1`, yielding a warrant
`H_n`. Rules:

- **Broadcast window:** `H_n` must be broadcast within `Delta_max` blocks of
  finding; later registration is invalid and earns no new-coin reward.
- **New-coin reward deferred:** `R_coin` is paid only after `H_n` is selected
  *and* the produced block gains sufficient confirmations.
- **Chain-linked registration:** each `H_n` references the hash of the previous
  pool element, forming an immutable, tamper-evident sequence (a chained FIFO).

### Stage 2 — Selection and block production

A selection is triggered when any of the following holds:

- `k` new warrants have been admitted since the last selection, or
- the pool exceeds `S_max`, or
- a forced-trigger interval `T_max` elapses with no selection.

```
winner = argmin_{h in Pool} H(h, R, PrevBlockHash)
```

- `R` is the latest external-beacon output (mandatory when the beacon is
  present; otherwise `PrevBlockHash` serves as the chain-derived seed).
- The winner's warrant is removed from the pool (**single-use bookkeeping**).
- The winning miner assembles transactions and broadcasts the block; **fees are
  settled only after the challenge window closes**.
- **Liveness fallback:** if no valid block arrives within a bounded timeout, the
  next-smallest election result takes over, and a forced trigger advances the
  chain clock.

### Difficulty adjustment and block-time stabilization

Stage-1 difficulty targets the *rate of valid warrants*, not block time
directly: the network as a whole produces `k` valid warrants per target block
interval. With warrant arrivals modeled as a Poisson process of rate `lambda`,
the inter-block time `T` is the sum of `k` independent exponential delays:

```
T ~ Gamma(k, lambda)
E[T] = k / lambda,   Var(T) = k / lambda^2
```

Setting `lambda = k * lambda_0` (so `E[T] = 1/lambda_0`) gives
`Var(T) = 1/(k lambda_0^2)`, i.e. variance a factor `1/k` smaller than
traditional PoW (`1/lambda_0^2`) and standard deviation `1/sqrt(k)` smaller. The
pool parameters are adaptive: `k_0 = sqrt(S)`, adjusted by at most 10% per
retarget against recent measured block intervals.

### Recommended parameters

| Parameter | Suggested value | Rationale |
| --- | --- | --- |
| `T_target` | 10 min | bitcoin-paced |
| `S` | 100–500 | sufficiently large candidate set |
| `k` | `sqrt(S)`, adaptive | variance reduction vs. trigger latency |
| `L` | 2–3 × target block interval | warrant lifetime |
| `T_max` | 2–3 × target block interval | guaranteed trigger cadence |

### Block structure (for implementation reference)

```
version
prev_block_hash
merkle_root
timestamp
bits                     # difficulty
nonce
+ warrant_ref            # reference to the winning H_n (single-use)
+ election               # (R, PrevBlockHash) inputs → winning H_n
+ pool_state_root        # Merkle root of the pool state
```

### Consensus validation pseudocode

```
def validate_block(block, chain_state):
    # 1. warrant registered on-chain, not expired
    entry = chain_state.pool.get(block.warrant_ref)
    assert entry is not None and not entry.expired()

    # 2. selection inputs are valid
    R = beacon.get_latest(block.height)
    winner_h = min(H(h, R, block.prev_block_hash) for h in chain_state.pool)
    assert winner_h == entry.h

    # 3. trigger rule respected (k-admission / S_max / T_max)
    assert is_valid_trigger(chain_state, block)

    # 4. pool state Merkle root matches
    assert block.pool_state_root == pool.commitment(chain_state.pool)

    # 5. regular validation
    validate_transactions(block.transactions)
    validate_merkle_root(block)
```

## Rationale

The design follows the v3.0 analysis (see
[Reference Implementation and Resources](#reference-implementation-and-resources)):

- **Batch triggering (`k`) rather than per-warrant production** turns the block
  interval into a Gamma sum, dividing variance by `k` (Section 3.1 of the
  whitepaper).
- **Expiry (`L`) + deferred reward** make withholding strictly suboptimal: a
  warrant delayed by `delta > Delta_max` earns zero; for `delta <= Delta_max`
  expected payoff is `R_coin + F/S - delta*c`, strictly decreasing in `delta`.
  A rational miner broadcasts immediately.
- **External beacon `R`** renders the election unpredictable and
  non-manipulable, making it impossible for an adversary to *generate a valid
  accounting block on a private branch*: without the honest beacon output, no
  private-branch election can match the public one.
- **Single-use bookkeeping + pool Merkle root** keep pool state consistent and
  prevent reuse of a warrant.

## Security Considerations

### What the design does *not* change (honest statement)

- **51% attacks.** TSPOW natively preserves "hash power is power": an
  adversary above 50% can still dominate warrant generation and therefore pool
  composition. The whitepaper explicitly defers to external mechanisms
  (staked hybrid consensus, finality checkpoints) for this.
- **Long-run double spend (without a beacon).** Without the external beacon,
  the private-branch block-production rate ratio to the honest rate is still
  `q/p`, so the double-spend probability is `(q/p)^z` — identical to
  traditional PoW. TSPOW's native gain is a *short-term* one: an attacker must
  first accumulate enough warrants, delaying private-chain startup, and honest
  block times are more predictable.

### What the design does change

| Attack | Native TSPOW | With external beacon `R` |
| --- | --- | --- |
| Warrant hiding / private mining | Disincentivized (expiry + deferred reward) | **Eliminated** (private branch lacks `R`) |
| Block-time variance | Divided by `k` (Gamma) | same |
| Selfish-mining amplification | Removed (no withheld proof rewrites the pool) | same |
| Pool-state manipulation | Chained FIFO + timestamp checks + optional VRF priority | same |
| Incentive collusion | Producer staking + challenge window + deferred fees | same |
| Fork / pool-state divergence | Pool-state root in header + finality gadget | same |

### Known residual risks (implementation layer)

1. **Pool-flooding / Sybil within the window.** An adversary below 50% can, within
   a single window, inject many warrants to crowd out honest candidates. The
   chain-linked FIFO and per-owner caps are mitigations; the risk is *not*
   fully eliminated and should be stress-tested in simulation.
2. **Beacon trust model.** The external beacon introduces a validator set and
   a trust assumption absent from pure PoW. If the beacon is compromised or
   censored, the election degenerates to the (weaker) chain-derived seed case.
   BIP 361-style post-quantum concerns apply to the beacon's threshold
   signature.
3. **Liveness of the elected producer.** A selected miner may decline to
   publish. The bounded fallback and forced trigger keep the chain moving, but
   worst-case delay equals one timeout per adversarial win; the theoretical
   bound requires `T_max` to be honored by all nodes.

## Backward Compatibility

TSPOW is a hard-fork change to any chain adopting it: it modifies the block
header (three new fields), replaces direct PoW block authorship with a
pool-based selection, and reallocates rewards (deferred new coin, deferred
fees). No existing single-stage PoW mechanism remains valid. Because this BIP
is **Informational**, it does not propose activating such a fork on the Bitcoin
network; it documents the design for research and for chains that choose to
adopt it.

## Reference Implementation and Resources

- Rust test chain: `test-chain/` — TSPOW simulation, DAA, 51%-attack analysis,
  block-time benchmarks, JSON TCP API.
- Python simulator: `simulator/` and `main.py` — two-phase mining simulation and
  PoW-vs-TSPOW comparison.
- C++ reference implementation: `refimpl/` — warrant, pool, and election
  verification (informational library).
- Verification scripts: `verify/` — numerical checks of the Gamma variance
  reduction `1/k`, the double-spend `(q/p)^z` bound, and pool-capacity
  relationships.
- Whitepaper v3.0: *TSPOW — Enhanced Consensus Protocol with Dynamic Cache Pool
  and External Randomness Beacon* (2026-08-27).
- Public repository: <https://github.com/corepool/timeshiftpow>.

## Changelog

* __0.3.1__ (2026-08-27):
    * Posted to the bitcoin-dev mailing list for discussion; recorded the
      thread in `Post-History` and `Comments-URI`.
* __0.3.0__ (2026-08-27):
    * Author attribution to `corepool` (developer of the
      [timeshiftpow repository](https://github.com/corepool/timeshiftpow)); BIP
      header re-aligned with BIP-2 preamble requirements (`Author`, `Created`,
      `Comments-Summary`/`Comments-URI`, `Discussions-To`; removed non-standard
      `Assigned`/`Version` headers).
* __0.2.0__ (2026-08-27):
    * Align with whitepaper v3.0: dynamic sliding-window pool (`S`, `k`, `L`,
      `T_max`) and external randomness beacon `R`.
    * Rewrite Security Considerations to state honestly what TSPOW does and
      does not change (51% and long-run double spend unchanged natively).
* __0.1.0__ (2026-08-27):
    * Initial draft based on the original fixed-FIFO TSPOW; documented the
      idealized-formal bounds and three known implementation-layer attack
      surfaces.