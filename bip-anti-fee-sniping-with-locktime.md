```
  BIP: ?
  Layer: Applications
  Title: Anti-Fee-Sniping with LockTime
  Authors: nervana21 <nervana21@pm.me>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: CC0-1.0
  Discussion: 2026-08-18: https://gnusha.org/pi/bitcoindev/wWGWjMw9TI22vp4VzCm4xJJS3IGA1UhndMKynUkB04BqeoRjhe-QbDbJU-GMQq0nnOnXuB__u8KcdIcxU5i8Cy9pbTbtJ7Hi583FzLVojek=@pm.me/
```

## Abstract

This BIP specifies wallet behavior that discourages fee sniping by setting a height-based `nLockTime` relative to a wallet's local chain tip. BIP326 treats existing `nLockTime` anti-fee-sniping as the baseline and, for some taproot spends, uses `nSequence`-based anti-fee-sniping instead. This BIP defines the `nLockTime` path that BIP326 left unspecified.

## Motivation

Fee sniping is an incentive-misaligned miner strategy. The miner orphans the best block to capture fees from its transactions and from the mempool instead of extending the tip. With `nLockTime` anti-fee-sniping, new transactions submitted to the mempool cannot be included in the remined first block and must wait for the second, which reduces the potential fee revenue of the attack and incentivizes extending the chain instead.

Anti-fee-sniping behavior has existed in Bitcoin Core since [2014](https://github.com/bitcoin/bitcoin/commit/ba7fcc8de06602576ab6a5911879d3d8df80d36a) and in Electrum since [2017](https://github.com/spesmilo/electrum/commit/de85b56e0aeac52463530dab3e54f1a35128ee3b). BIP326 refers to this baseline but never defined it. This BIP specifies rules for interoperable, privacy-compatible wallet behavior and documents the replacement floor needed to avoid fingerprinting fee bumps ([bitcoin#26526](https://github.com/bitcoin/bitcoin/issues/26526)).

## Background



### Absolute locktime

`nLockTime` is an absolute lock. A non-final transaction with an `nLockTime` set to block height `N` may only be included in block height `N + 1` or greater. A transaction with the maximum value in all `nSequence` fields is final and ignores `nLockTime`. `nLockTime` values less than 500_000_000 are block heights. Values at or above 500_000_000 are Unix timestamps. The 10% privacy branch uses an older height, which can still enter a remine of the tip.

## Specification



### Applicability

This BIP applies when a wallet discourages fee sniping with `nLockTime` and still controls both `nLockTime` and every input's `nSequence` for a new spend or a fee-bump replacement.

Wallets MUST NOT apply this BIP when any of the following hold:

- The user or a higher-level protocol has already set `nLockTime`.
- Any input already has a preset `nSequence`, even if non-final (for example a PSBT this wallet only funds, or a contract template).
- The wallet is following BIP326's `nSequence` anti-fee-sniping branch for that spend. In that case the wallet MAY set `nLockTime` to 0.

On BIP326's `nLockTime` branch, and for all non-taproot spends that otherwise qualify for `nLockTime` anti-fee-sniping, wallets MUST apply the locktime selection rules in this BIP.

Presigned transactions meant to stay valid across a wide height range are outside this BIP and SHOULD document their own locktime policy.

### Cosigners and PSBT roles

Hardware signers and PSBT cosigners SHOULD accept tip-relative anti-fee-sniping `nLockTime` values and SHOULD NOT require `nLockTime = 0` by default. Creator-chosen locktime and sequence values stay untouched under Applicability.

### Current and stale tip

Let `height` be the height of the wallet's local best block. Let `tip_time` be that block's timestamp. The tip is **current** when both of the following hold:

- The node is not in initial block download.
- `now - tip_time <= 8 * 60 * 60` (8 hours).

Otherwise the tip is **stale**.

### Locktime selection

Define `LOCKTIME_THRESHOLD = 500_000_000`.

Let `minimum_locktime` be a non-negative integer supplied by the caller. The default is 0.

When fee-bumping under this BIP, wallets MUST set `minimum_locktime` to the `nLockTime` of the transaction being replaced.

Only a `minimum_locktime` strictly below `LOCKTIME_THRESHOLD` is a height floor. A time-based `minimum_locktime` is not a height floor ([bitcoin#35628](https://github.com/bitcoin/bitcoin/issues/35628)). Let `floor` be that height floor, or 0 if `minimum_locktime` is absent or time-based.

#### Current tip

1. Set `nLockTime` to `height`.
2. With probability 10%, if `nLockTime > floor`, draw an integer `back` uniformly from `0 .. bound - 1` where `bound = min(100, height - floor + 1)`, and set `nLockTime = height - back`.

`randrange(n)` returns an integer in `0 .. n - 1`. The inclusive window `[floor, height]` has length `height - floor + 1`. Cap that length at 100. The same cap applies for every `floor`, including the default of 0.

The resulting `nLockTime` is never older than `floor` ([bitcoin#26526](https://github.com/bitcoin/bitcoin/issues/26526)).

Implementations SHOULD document their replacement locktime policy, including whether locktime type may change across a replacement ([bitcoin#35628](https://github.com/bitcoin/bitcoin/issues/35628)).

#### Stale tip

- If `floor <= height`, set `nLockTime` to `floor`.
- If `floor > height`, set `nLockTime` to 0.



### Sequence enforcement

Consensus ignores `nLockTime` unless at least one input has `nSequence` below `0xffffffff`.

Wallets MUST set at least one wallet-controlled input's `nSequence` below `0xffffffff` when applying this BIP.

Wallets SHOULD set every wallet-controlled input's `nSequence` to `2**32 - 2` (`0xfffffffe`).

### Pseudocode

```
LOCKTIME_THRESHOLD = 500_000_000

def height_floor(minimum_locktime):
    if minimum_locktime is None:
        return 0
    if minimum_locktime < LOCKTIME_THRESHOLD:
        return minimum_locktime
    return 0

def tip_is_current():
    # now() and tip_time() are Unix timestamps in seconds.
    return (not chain_is_ibd()) and (now() - tip_time()) <= 8 * 60 * 60

def apply_nlocktime_anti_fee_sniping(transaction, minimum_locktime=0):
    if transaction.has_preset_nlocktime() or any(input.has_preset_nsequence() for input in transaction.inputs):
        return
    # SHOULD: all wallet-controlled inputs non-final.
    for input in transaction.inputs:
        input.nsequence = 2**32 - 2
    height = blockchain.height()
    floor = height_floor(minimum_locktime)
    if not tip_is_current():
        if floor <= height:
            transaction.nlocktime = floor
        else:
            transaction.nlocktime = 0
        return
    transaction.nlocktime = height
    if randrange(10) == 0 and transaction.nlocktime > floor:
        gap = height - floor
        bound = min(100, gap + 1)
        transaction.nlocktime = height - randrange(bound)
```



### Test Vectors

Each case is input to the pseudocode, then expected `nlocktime` / `nsequence`. `rand10` is `randrange(10)` (`0` is the 10% privacy branch). `back` is the already-drawn `randrange(bound)` subtract (`0` means keep the tip). `tip_age` is `now() - tip_time()` in seconds. `minimum_locktime` `0` means no height floor. If `nlocktime_preset` or `nsequence_preset` is true, leave both fields unchanged. `nsequence` lists wallet-controlled input `nSequence` values (examples use one input). `4294967295` is `2^(32) - 1`, `4294967294` is `2^(32) - 2`.

```json
[
  {
    "comment": "current tip, common branch",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 3,
      "back": 99,
      "minimum_locktime": 0,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 800000,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "current tip, privacy branch back = 0",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 0,
      "back": 0,
      "minimum_locktime": 0,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 800000,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "current tip, privacy branch back = 99",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 0,
      "back": 99,
      "minimum_locktime": 0,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 799901,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "stale tip, age 28801 > 8 hours, new transaction",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 28801,
      "rand10": 3,
      "back": 99,
      "minimum_locktime": 0,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 0,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "stale tip, privacy RNG would have fired, new transaction still 0",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 28801,
      "rand10": 0,
      "back": 99,
      "minimum_locktime": 0,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 0,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "tip age exactly 8 hours is still current",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 28800,
      "rand10": 3,
      "back": 99,
      "minimum_locktime": 0,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 800000,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "IBD, tip otherwise current, new transaction",
    "given": {
      "height": 800000,
      "ibd": true,
      "tip_age": 0,
      "rand10": 3,
      "back": 99,
      "minimum_locktime": 0,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 0,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "preset nSequence, leave fields unchanged",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 3,
      "back": 99,
      "minimum_locktime": 0,
      "nlocktime_preset": false,
      "nsequence_preset": true,
      "nlocktime": 0,
      "nsequence": [7]
    },
    "expected": {
      "nlocktime": 0,
      "nsequence": [7]
    }
  },
  {
    "comment": "preset nLockTime, leave fields unchanged",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 3,
      "back": 99,
      "minimum_locktime": 0,
      "nlocktime_preset": true,
      "nsequence_preset": false,
      "nlocktime": 123,
      "nsequence": [4294967294]
    },
    "expected": {
      "nlocktime": 123,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "short chain, privacy back reaches 0",
    "given": {
      "height": 50,
      "ibd": false,
      "tip_age": 0,
      "rand10": 0,
      "back": 50,
      "minimum_locktime": 0,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 0,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "privacy branch, back reaches minimum_locktime",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 0,
      "back": 50,
      "minimum_locktime": 799950,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 799950,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "privacy branch, gap 200, 100-cap still applies, back 99",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 0,
      "back": 99,
      "minimum_locktime": 799800,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 799901,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "stale tip, keeps minimum_locktime",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 28801,
      "rand10": 0,
      "back": 99,
      "minimum_locktime": 799950,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 799950,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "stale tip, minimum_locktime ahead of local tip, locktime 0",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 28801,
      "rand10": 3,
      "back": 99,
      "minimum_locktime": 800100,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 0,
      "nsequence": [4294967294]
    }
  },
  {
    "comment": "time-based minimum_locktime is not a height floor",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 0,
      "back": 99,
      "minimum_locktime": 1700000000,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 799901,
      "nsequence": [4294967294]
    }
  }
]
```



## Rationale



### Privacy branch

The random older-height branch improves privacy when signing is delayed (for example high-latency mix networks). Without it, a transaction that sits unsigned across a block boundary is more clearly tied to the tip height observed at creation time.

### Fee bumping and replacements

Re-applying the 10% privacy branch on a fee bump can set a lower `nLockTime` than the replaced transaction. The same fingerprint appears if a lagging wallet writes `0` over a height-based original ([bitcoin#26526](https://github.com/bitcoin/bitcoin/issues/26526)).

The invariant is no backdating across a replacement of the same transaction. Callers pass the prior height-based locktime as the floor (`minimum_locktime`). Cap privacy draws at 100 so a far-behind replacement cannot land more than 99 blocks back and fingerprint the bump path.

### Stale tip

A stale or IBD tip makes a fresh tip-relative locktime encode an unreliable local height and stand out. *The Specification reuses* `floor` *when* `floor <= height`*,* and otherwise sets `nLockTime` to 0.

### Enforcing locktime

Tip-relative `nLockTime` with all-final `nSequence` is a known fingerprint ([locktime-stairs observation](https://b10c.me/observations/01-locktime-stairs/), [unenforced locktime charts](https://mainnet.observer/charts/transactions-not-enforced-locktime/)). Setting every wallet-controlled input to `2**32 - 2` is the conventional defense.

### Unconfirmed parents and child transactions

Finality is checked per transaction. A child's `nLockTime` does not protect an unconfirmed parent from a tip remine.

This BIP floors only same-transaction replacements, not package-wide child floors. Package-aware locktime policy is left to higher-level protocols.

### Anonymity set

Only a small share of transactions currently use height-based `nLockTime` (on the order of 5% at the time of this writing, see [height-based locktime chart](https://mainnet.observer/charts/transactions-height-based-locktime/)). Applying this BIP can stick out until broader correct adoption grows that set.

### Relationship to BIP326

BIP326 remains the specification for optional `nSequence`-based anti-fee-sniping on some taproot spends. This BIP fills in the `nLockTime` baseline that BIP326 assumed.

## Backward Compatibility

This BIP requires no consensus changes. Wallets may adopt it unilaterally.

## Reference Implementation

Bitcoin Core provides [IsCurrentForAntiFeeSniping](https://github.com/bitcoin/bitcoin/blob/f72537037d3350e2974efd760eaa7b04f820880c/src/wallet/spend.cpp#L980-L992) and [DiscourageFeeSniping](https://github.com/bitcoin/bitcoin/blob/f72537037d3350e2974efd760eaa7b04f820880c/src/wallet/spend.cpp#L994-L1048) in `src/wallet/spend.cpp`. Electrum provides [get_locktime_for_new_transaction](https://github.com/spesmilo/electrum/blob/d9b492ff06673f8695ee7b50c75ad07781b957eb/electrum/wallet.py#L205-L232) for new transactions. At those pinned revisions, neither applies this Specification's fee-bump height floor.

## Acknowledgements

Peter Todd introduced the behavior in Bitcoin Core. Chris Belcher's BIP326 refers to it as regular `nLockTime` anti-fee-sniping. Marco Falke noted during BIP326 review that wallets may implement only the `nLockTime` path. b10c documented unenforced locktime fingerprints.

## Copyright

This BIP is licensed under the Creative Commons CC0 1.0 Universal licence.

## References

[1] <https://github.com/bitcoin/bips/blob/master/bip-0326.mediawiki>

[2] <https://github.com/bitcoin/bitcoin/pull/2340>

[3] <https://github.com/spesmilo/electrum/blob/d9b492ff06673f8695ee7b50c75ad07781b957eb/electrum/wallet.py#L200-L227>

[4] <https://github.com/bitcoin/bitcoin/blob/f72537037d3350e2974efd760eaa7b04f820880c/src/wallet/spend.cpp#L979-L1047>

[5] <https://github.com/bitcoin/bips/pull/1269#discussion_r781981449>

[6] <https://github.com/bitcoin/bitcoin/issues/26526>

[7] <https://github.com/bitcoin/bitcoin/issues/35628>

[8] <https://b10c.me/observations/01-locktime-stairs/>

[9] <https://mainnet.observer/charts/transactions-height-based-locktime/>

[10] <https://mainnet.observer/charts/transactions-not-enforced-locktime/>