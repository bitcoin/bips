# SPDX-License-Identifier: BSD-2-Clause
# Reference model of the adaptive block weight limit (draft BIP). Not consensus code.
def median_odd(values):
    assert len(values) % 2 == 1
    return sorted(values)[(len(values) - 1) // 2]

def next_max_block_weight(weights, short_w, long_w, mult, floor, cap):
    """weights: block weights of the chain up to and including the parent of the
    block being validated (oldest first). Returns the max weight for the next block."""
    candidate = 0
    have_short = len(weights) >= short_w + 1
    have_long = len(weights) >= long_w + 1
    if have_short and have_long:
        candidate = max(median_odd(weights[-(short_w + 1):]), median_odd(weights[-(long_w + 1):])) * mult
    elif have_short:
        candidate = median_odd(weights[-(short_w + 1):]) * mult
    return min(max(candidate, floor), cap)

def max_sigops_cost(limit):
    return limit // 50

if __name__ == "__main__":
    P = dict(short_w=2, long_w=4, mult=10, floor=1000, cap=1_000_000)
    vectors = [
        [],
        [500, 500],
        [50, 60, 70],
        [50, 60, 70, 80],
        [100, 200, 300, 400, 500],
        [900, 900, 900, 10, 10],
        [10, 10, 900, 900, 900],
        [400, 400, 400, 400, 99_999, 99_999, 99_999],
        [200_000] * 5,
    ]
    for v in vectors:
        print(v, "->", next_max_block_weight(v, **P))
    M = dict(short_w=12960, long_w=52560, mult=10, floor=4_000_000, cap=4_000_000_000)
    for w in (1_000_000, 3_993_000):
        l = next_max_block_weight([w] * 52561, **M)
        print("mainnet all", w, "->", l, max_sigops_cost(l))
    mixed = [3_000_000] * (52561 - 12961) + [3_900_000] * 12961
    l = next_max_block_weight(mixed, **M); print("mainnet mixed ->", l, max_sigops_cost(l))
