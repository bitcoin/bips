```
  BIP: ?
  Layer: Applications
  Title: Anti-Fee-Sniping with LockTime
  Authors: nervana21 <nervana21@pm.me>
  Status: Draft
  Type: Informational
  Assigned: ?
  License: CC0-1.0
```

## Abstract

This BIP specifies wallet behavior that discourages fee sniping by setting nLockTime. Bitcoin Core already implements this behavior. BIP326 assumes these nLockTime rules as the baseline and uses nSequence instead for some taproot spends.

## Motivation

Anti-fee-sniping behavior has existed in Bitcoin Core since [2014](https://github.com/bitcoin/bitcoin/commit/ba7fcc8de06602576ab6a5911879d3d8df80d36a) and in Electrum since [2017](https://github.com/spesmilo/electrum/commit/de85b56e0aeac52463530dab3e54f1a35128ee3b). BIP326 assumes this nLockTime behavior but never defined it. This BIP specifies those rules.

## Background

### Fee sniping

Fee sniping is an incentive-misaligned miner strategy. The miner orphans the best block to capture fees from its transactions and from the mempool instead of extending the tip. With nLockTime anti-fee-sniping, many of those transactions cannot enter the remined first block and must wait for the second, which weakens the attack and favors extending the chain instead.

### Absolute locktime

nLockTime is an absolute lock. Setting aside nSequence effects, a transaction with an nLockTime set to block height N may only be included in block height N + 1 or greater. A transaction with an nLockTime set to 0 is always final. nLockTime values less than 500_000_000 are block heights. The 10% privacy branch uses an older height, which can still enter a remine.

If every input has nSequence equal to 0xffffffff, nLockTime is ignored.

## Specification

Set nLockTime to the current tip block height. With probability 10%, subtract a uniform random integer in 0..99 from that height (clamped at 0). The random branch improves privacy when signing is delayed (for example in high-latency mix networks).

Ensure at least one input has nSequence below 0xffffffff so nLockTime takes effect. The pseudocode sets every wallet-controlled input to `2**32 - 2` as one conventional choice.

If the tip is not current, such as during initial block download, or when the current time minus the tip timestamp is greater than 8 hours (28_800 seconds), set nLockTime to 0 instead. A tip-relative locktime while far behind the network does not help against fee sniping and can fingerprint the wallet.

Do not apply this BIP when the user or a higher-level protocol sets nLockTime, or when any input already has a preset nSequence (for example a PSBT this wallet only funds, or a contract template). Leave those fields unmodified. Presigned transactions meant to stay valid across a wide height range should document their own locktime policy.

A child's nLockTime does not protect an unconfirmed parent. Finality is checked per transaction.

Wallets on BIP326's nSequence anti-fee-sniping branch may set nLockTime to 0. On BIP326's nLockTime branch, and for all non-taproot spends, follow this BIP.

### Pseudocode

```
def apply_nlocktime_anti_fee_sniping(transaction):
    if transaction.has_preset_nlocktime() or any(input.has_preset_nsequence() for input in transaction.inputs):
        return
    for input in transaction.inputs:
        input.nsequence = 2**32 - 2  # Conventional
    # skip if IBD or tip age > 8 hours
    if chain_is_ibd() or (now() - tip_time()) > 8 * 60 * 60:
        transaction.nlocktime = 0
        return
    transaction.nlocktime = blockchain.height()
    if randrange(10) == 0:
        transaction.nlocktime = max(0, transaction.nlocktime - randrange(100))
```

### Test Vectors

Each case is input to the pseudocode, then expected `nlocktime` / `nsequence`. `rand10` is `randrange(10)` (`0` is the 10% privacy branch). `rand100` is `randrange(100)` (values 0..99), subtracted only on that branch. `tip_age` is `now() - tip_time()` in seconds. If `nlocktime_preset` or `nsequence_preset` is true, leave both fields unchanged. `nsequence` is one wallet-controlled input. `4294967295` is `2^(32) - 1`, `4294967294` is `2^(32) - 2`.

```json
[
  {
    "comment": "current tip, common branch",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 3,
      "rand100": 99,
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
    "comment": "current tip, privacy branch r = 0",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 0,
      "rand100": 0,
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
    "comment": "current tip, privacy branch r = 99",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 0,
      "rand10": 0,
      "rand100": 99,
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
    "comment": "stale tip, age 28801 > 8 hours",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 28801,
      "rand10": 3,
      "rand100": 99,
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
    "comment": "stale tip, privacy RNG would have fired, still nLockTime 0",
    "given": {
      "height": 800000,
      "ibd": false,
      "tip_age": 28801,
      "rand10": 0,
      "rand100": 99,
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
      "rand100": 99,
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
    "comment": "IBD, tip otherwise current",
    "given": {
      "height": 800000,
      "ibd": true,
      "tip_age": 0,
      "rand10": 3,
      "rand100": 99,
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
      "rand100": 99,
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
      "rand100": 99,
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
    "comment": "privacy branch subtract then clamp at 0",
    "given": {
      "height": 50,
      "ibd": false,
      "tip_age": 0,
      "rand10": 0,
      "rand100": 99,
      "nlocktime_preset": false,
      "nsequence_preset": false,
      "nlocktime": 0,
      "nsequence": [4294967295]
    },
    "expected": {
      "nlocktime": 0,
      "nsequence": [4294967294]
    }
  }
]
```

## Rationale

### Fee bumping and replacements

Re-applying the 10% privacy branch when fee-bumping can set a lower nLockTime on the replacement than on the transaction being replaced. That fingerprints Core or Electrum style wallets ([bitcoin#26526](https://github.com/bitcoin/bitcoin/issues/26526)). Changing locktime type across a replacement (for example height-based to time-based) is related ([bitcoin#35628](https://github.com/bitcoin/bitcoin/issues/35628)). Implementations SHOULD document replacement locktime policy, including locktime type. When re-running the privacy branch on a height-based previous locktime, floor at that height. Do not go older unless that policy is intentional and documented.

### Enforcing locktime

Setting tip-relative nLockTime without a non-final nSequence is a known fingerprint. Past wallet bugs of this class are documented in the [locktime-stairs observation](https://b10c.me/observations/01-locktime-stairs/) and in [mainnet charts of unenforced locktimes](https://mainnet.observer/charts/transactions-not-enforced-locktime/).

### Anonymity set

Only a small share of transactions currently use height-based nLockTime (on the order of 5% at the time of this writing, see [height-based locktime chart](https://mainnet.observer/charts/transactions-height-based-locktime/)). Applying this BIP can stick out until broader correct adoption grows that set.

## Backward Compatibility

This BIP requires no consensus changes and wallets may adopt it unilaterally.

Hardware signers and PSBT cosigners should accept tip-relative anti-fee-sniping nLockTime values and should not require nLockTime=0 by default. Wallet software that funds PSBTs should apply this BIP when locktime and sequences are still wallet-controlled. Creator-chosen values stay untouched.

## Reference Implementation

Bitcoin Core provides [IsCurrentForAntiFeeSniping](https://github.com/bitcoin/bitcoin/blob/f72537037d3350e2974efd760eaa7b04f820880c/src/wallet/spend.cpp#L980-L992) and [DiscourageFeeSniping](https://github.com/bitcoin/bitcoin/blob/f72537037d3350e2974efd760eaa7b04f820880c/src/wallet/spend.cpp#L994-L1048) in `src/wallet/spend.cpp`. Electrum provides [get_locktime_for_new_transaction](https://github.com/spesmilo/electrum/blob/d9b492ff06673f8695ee7b50c75ad07781b957eb/electrum/wallet.py#L205-L232).

## Acknowledgements

Peter Todd introduced the behavior in Bitcoin Core. Chris Belcher's BIP326 refers to it as regular nLockTime anti-fee-sniping. Marco Falke noted during BIP326 review that wallets may implement only the nLockTime path. b10c documented unenforced locktime fingerprints.

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