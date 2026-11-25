```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: OP_TX
  Authors: Rusty Russell <rusty@rustcorp.com.au>
           Julian Moik <julianmoik@gmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-3-Clause
  Discussion: https://groups.google.com/g/bitcoindev/c/GisTcPb8Jco/m/8znWcWwKAQAJ
  Version: 0.2.0
  Requires: 440, 441
```

## Introduction

### Abstract

This BIP defines OP_TX for Tapleaf 0xc2. OP_TX returns selected data from the spending transaction, its spent outputs, and the current Taproot execution context. It assigns OP_TX to opcode 0xbf, replacing that opcode's OP_SUCCESS191 behavior in Tapleaf 0xc2.

### Copyright

This document is licensed under the 3-clause BSD license.

### Motivation

Originally Bitcoin was designed to avoid any reliance on trusted third parties, and its scripting system is supposed to be the underlying mechanism to achieve this goal by allowing the network itself to enforce the spending conditions for an output. This aim is undermined if users cannot precisely specify the conditions under which their coins can be spent.

[BIP441](bip-0441.mediawiki) restores broad programmability to Bitcoin's scripting system, but expressing transaction-dependent spending conditions remains constrained. The main missing piece is the ability to directly query the transaction attempting to spend an output, beyond merely checking that it is signed by a given set of keys. Many proposals have addressed this limitation in narrower ways, including new signature modes, spending restrictions even in case of leaked key material, and more complicated multiparty protocols.

OP_TX exposes selected transaction fields, spent-output data, and current Taproot execution context on the stack. This permits arithmetic on values and examination of scripts. It can also collate multiple selected values into a single stack element, ready for hashing and comparison.

## Specification

### Opcode and Invocation

In Tapleaf 0xc2, opcode 0xbf is defined as OP_TX.

OP_TX is invoked as:

```text
<input scope operands> <output scope operands> <selector> OP_TX
```

The selector is a byte string provided as a single stack element and it specifies which data OP_TX reads.

### Selector Encoding

#### Selector Layout

Version 0 uses the following six-byte selector:

```text
Byte  Selector component
 0    version value
 1    output format and transaction-wide fields (bitmask)
 2    current-execution fields (bitmask)
 3    input/output scopes (two four-bit values)
 4    input fields (bitmask)
 5    output fields (bitmask)
```

#### Output Format and Transaction-Wide Fields

Byte 1 selects the output format and transaction-wide fields:

```text
0x01  COLLATE (combine all selected values into one stack element)
0x02  TX_VERSION
0x04  TX_LOCKTIME
0x08  TX_WEIGHT
0x10  INPUT_TOTAL_COUNT
0x20  INPUT_TOTAL_AMOUNT
0x40  OUTPUT_TOTAL_COUNT
0x80  OUTPUT_TOTAL_AMOUNT
```

#### Current-Execution Fields

Byte 2 selects fields from the current execution:

```text
0x01  CURRENT_INPUT_INDEX
0x02  CURRENT_TAPROOT_ANNEX
0x04  CURRENT_TAPSCRIPT
0x08  CURRENT_TAPLEAF_HASH
0x10  CURRENT_CONTROL_BLOCK
0x20  CURRENT_INTERNAL_KEY
0x40  CURRENT_TAPTREE_ROOT
0x80  CURRENT_CODESEPARATOR_POSITION
```

#### Input and Output Scopes

Byte 3 contains both input and output scopes. Bits 4–7 select the input scope, and bits 0–3 select the output scope. Each four-bit value must be one of the scope values defined below.

| Value | Name | Selected Inputs or Outputs | Stack Operands |
| --- | --- | --- | --- |
| `0x00` | NONE | Nothing | None |
| `0x01` | CURRENT | The executing input, or the output whose index equals the executing input index | None |
| `0x02` | ALL | Every input or output, in ascending index order | None |
| `0x03` | SINGLE | The input or output at `index` | `<index>` |
| `0x04` | RANGE | The inputs or outputs in `[start, start + count)`, in ascending index order | `<start> <count>` |
| `0x05` | RANGE_OR_EMPTY | The inputs or outputs in `[start, start + count)`, in ascending index order, including those that do not exist | `<start> <count>` |

Each scope operand is decoded as a BIP441 arbitrary-length unsigned integer, as for OP_CHECKLOCKTIMEVERIFY; execution fails if its value is 2<sup>32</sup> or more. Input scope operands are deepest on the stack, followed by output scope operands and then the selector. OP_TX consumes only the operands required by the two scopes; any lower stack elements remain unchanged.

`CURRENT`, `SINGLE`, and `RANGE` fail if any selected input or output does not exist. `RANGE` requires `count >= 1`, `start < total`, and `count <= total - start`.

`RANGE_OR_EMPTY` requires `1 <= count <= 32768` and never fails because a selected input or output does not exist. For each selected field, a missing input or output pushes an empty stack element, which is also the number zero, and contributes no bytes to a `COLLATE` result. An input scope of `RANGE_OR_EMPTY` cannot select `INPUT_WITNESS_ITEMS`.

#### Input and Output Field Masks

Byte 4 selects input fields:

```text
0x01  INPUT_PREVOUT_TXID
0x02  INPUT_PREVOUT_INDEX
0x04  INPUT_PREVOUT_AMOUNT
0x08  INPUT_PREVOUT_SCRIPTPUBKEY
0x10  INPUT_SCRIPTSIG
0x20  INPUT_SEQUENCE
0x40  INPUT_WITNESS_ITEM_COUNT
0x80  INPUT_WITNESS_ITEMS
```

Byte 5 selects output fields:

```text
0x01  OUTPUT_AMOUNT
0x02  OUTPUT_SCRIPTPUBKEY
Bits 2 through 7 are undefined and must be zero.
```

If an input or output scope is `NONE`, its corresponding field mask must be zero. Every other scope requires a nonzero corresponding field mask. A version-0 selector must request at least one field.

### Output Format

OP_TX pushes each selected value as a separate stack element unless `COLLATE` is set. `INPUT_WITNESS_ITEMS` is the only non-scalar field: it is a list of witness items, each of which is pushed as a separate stack element. Numeric fields use the normalized, minimal-length, little-endian unsigned encoding defined for Tapleaf 0xc2 by BIP441: zero is represented by an empty stack element and non-zero values have no trailing zero byte. Byte strings are pushed unchanged.

When `COLLATE` is set, OP_TX instead pushes exactly one stack element containing every selected value in the order listed below. Unlike the default output, where separate stack elements identify where each value ends, `COLLATE` removes those boundaries. It therefore uses fixed-width numeric encodings, CompactSize-prefixed byte strings, and a CompactSize item count before each input's witness items to keep adjacent selected values distinguishable.

### Selected Values

The table lists every value OP_TX can select. Transaction IDs use serialized outpoint byte order rather than reversed display order. `CompactSize(X)` means Bitcoin's canonical CompactSize byte serialization of the integer X.

| Name | Selector Location and Mask | Stack Output | COLLATE Encoding |
| --- | --- | --- | --- |
| TX_VERSION | Byte 1, `0x02` | The unsigned value of the transaction version's 32-bit pattern | The four-byte transaction version pattern |
| TX_LOCKTIME | Byte 1, `0x04` | Transaction locktime | `uint32_le` |
| TX_WEIGHT | Byte 1, `0x08` | Transaction weight as defined by BIP141 | `uint32_le` |
| INPUT_TOTAL_COUNT | Byte 1, `0x10` | Total transaction input count | `uint32_le` |
| INPUT_TOTAL_AMOUNT | Byte 1, `0x20` | Sum of all spent-output amounts | `uint64_le` |
| INPUT_PREVOUT_TXID | Byte 4, `0x01` | The 32-byte txid of the transaction containing the output spent by the selected input | The same 32 bytes |
| INPUT_PREVOUT_INDEX | Byte 4, `0x02` | The output index paired with `INPUT_PREVOUT_TXID` | `uint32_le` |
| INPUT_PREVOUT_AMOUNT | Byte 4, `0x04` | The amount of the output spent by the selected input | `uint64_le` |
| INPUT_PREVOUT_SCRIPTPUBKEY | Byte 4, `0x08` | The raw scriptPubKey of the output spent by the selected input | `CompactSize(length)` followed by `scriptPubKey` |
| INPUT_SCRIPTSIG | Byte 4, `0x10` | The selected input's raw `scriptSig` bytes | `CompactSize(length)` followed by `scriptSig` |
| INPUT_SEQUENCE | Byte 4, `0x20` | The selected input's sequence | `uint32_le` |
| INPUT_WITNESS_ITEM_COUNT | Byte 4, `0x40` | The number of witness stack items serialized for the selected input | `uint32_le` |
| INPUT_WITNESS_ITEMS | Byte 4, `0x80` | Each raw witness stack item, in serialized order | `CompactSize(item count)`, then each item as `CompactSize(length)` followed by the item |
| OUTPUT_TOTAL_COUNT | Byte 1, `0x40` | Total transaction output count | `uint32_le` |
| OUTPUT_TOTAL_AMOUNT | Byte 1, `0x80` | Sum of all transaction output amounts | `uint64_le` |
| OUTPUT_AMOUNT | Byte 5, `0x01` | The selected output's amount | `uint64_le` |
| OUTPUT_SCRIPTPUBKEY | Byte 5, `0x02` | The selected output's raw scriptPubKey | `CompactSize(length)` followed by `scriptPubKey` |
| CURRENT_INPUT_INDEX | Byte 2, `0x01` | The executing input's zero-based index | `uint32_le` |
| CURRENT_TAPROOT_ANNEX | Byte 2, `0x02` | The current Taproot annex including its `0x50` prefix, or an empty byte string when absent | `CompactSize(length)` followed by `annex` |
| CURRENT_TAPSCRIPT | Byte 2, `0x04` | The committed Tapscript being executed | `CompactSize(length)` followed by `tapscript` |
| CURRENT_TAPLEAF_HASH | Byte 2, `0x08` | The 32-byte TapLeaf hash of the current Tapscript | The same 32 bytes |
| CURRENT_CONTROL_BLOCK | Byte 2, `0x10` | The complete raw Taproot control block | `CompactSize(length)` followed by `control_block` |
| CURRENT_INTERNAL_KEY | Byte 2, `0x20` | The control block's 32-byte x-only internal key | The same 32 bytes |
| CURRENT_TAPTREE_ROOT | Byte 2, `0x40` | The 32-byte Merkle root of the current Taproot script tree | The same 32 bytes |
| CURRENT_CODESEPARATOR_POSITION | Byte 2, `0x80` | BIP342 position of the last executed OP_CODESEPARATOR, or `0xffffffff` if none | `uint32_le` |

The table rows define the output order. For each input or output, all requested fields are pushed before continuing to the next one.

`CURRENT_TAPLEAF_HASH` and `CURRENT_TAPTREE_ROOT` are the tapleaf hash *k<sub>0</sub>* and Merkle root *k<sub>m</sub>* that [BIP341](bip-0341.mediawiki) script-path validation computes for the current script, with leaf version 0xc2.

`INPUT_WITNESS_ITEMS` may produce any number of values for each selected input, including zero. A selector requesting only `INPUT_WITNESS_ITEMS` remains valid even when all selected inputs have empty witnesses: it produces no values in the default output. With `COLLATE`, an empty witness contributes the single byte `0x00`, and witness items from multiple inputs remain separable without `INPUT_WITNESS_ITEM_COUNT`.

### OP_TX Execution

An executed OP_TX performs the following steps in order:

1. Fail if the stack is empty. Otherwise, pop its top element as the selector.
2. Fail if the selector is empty.
3. Read the first byte as the selector version. If it is nonzero, terminate successfully as specified below.
4. Fail unless the version-0 selector is exactly six bytes and valid according to **Selector Encoding**.
5. Fail if the stack lacks any required scope operand. Otherwise, consume and validate those operands.
6. Determine the complete ordered results and their sizes, failing if a numeric value does not fit its `COLLATE` encoding.
7. Fail if adding the results would exceed any [BIP441](bip-0441.mediawiki) stack limits.
8. Deduct `BASE + S + OP_TX_SELECT(k) + R` as defined under **Varops Accounting**, failing if it exceeds the remaining varops budget.
9. Push the results.

### Future Selector Versions

Selector versions `0x01` through `0xff` are reserved for future soft-fork upgrades. If the selector's first byte is nonzero, the script succeeds immediately; any remaining selector bytes are ignored, no result is pushed, and only `BASE` is deducted. A future soft fork may assign stricter semantics and its own selector layout to a reserved version.

### Varops Accounting

OP_TX performs no hashing. An executed OP_TX with a reserved selector version costs `BASE`. An executed version-0 OP_TX costs:

```text
BASE + S + OP_TX_SELECT(k) + R
OP_TX_SELECT(k) = 1550 + 620 k
```

`BASE` is the [BIP440](bip-0440.mediawiki) fixed opcode cost. `S` pays BIP440's `READ` for each consumed scope operand, which is taken as a number. `OP_TX_SELECT` is specific to OP_TX and covers selector decoding and the per-value work of locating, encoding, and appending data. `k` is the number of selected values plus the number of records scanned for aggregate fields:

- Each selected transaction-wide field, current-execution field, and field of each selected input or output counts one.
- `INPUT_WITNESS_ITEMS` instead counts one for each selected input, plus one for each of its witness items, including empty items.
- Each selected field of a missing input or output under `RANGE_OR_EMPTY` also counts one.
- `INPUT_TOTAL_AMOUNT` adds the number of inputs, and `OUTPUT_TOTAL_AMOUNT` adds the number of outputs.
- `TX_WEIGHT` adds the number of inputs, outputs, and witness items in the transaction.

`R` pays BIP440's `WRITE(length)` for each pushed result, numeric or byte string, and with `COLLATE` for the single result.

Costs depend only on the selector, scope operands, and transaction, never on whether an implementation caches values.

The `OP_TX_SELECT` coefficients come from the same measurement procedure and rounding rules as the BIP440 primitives (BIP440, Derivation of Costs).

## Rationale

### Selector Design

OP_TX reads one selector from the stack. This follows the general approach of [BIP346](bip-0346.md) OP_TXHASH, but the selector bytes are different. OP_TX returns the selected fields themselves, either separately or collated, so scripts can use selected amounts in arithmetic instead of receiving only a hash.

The fixed six-byte selector keeps every field and scope choice visible in one value. `SINGLE` indices and `RANGE` bounds are separate numeric operands because scripts may calculate them from transaction data.

`RANGE_OR_EMPTY` lets a script handle up to a fixed number of inputs or outputs without first checking how many exist: summing the amounts of up to five inputs takes one OP_TX and four OP_ADDs. It is a separate scope so that `RANGE` still fails for a missing input or output, because a check applied to every selected entry, such as a maximum amount, passes for an empty one. Under `COLLATE`, a missing entry contributes no bytes, so a collated result never contains values absent from the transaction; selecting `INPUT_TOTAL_COUNT` or `OUTPUT_TOTAL_COUNT` also commits to how many entries exist. `RANGE_OR_EMPTY` cannot select `INPUT_WITNESS_ITEMS`: a missing entry is marked by one empty element per field, which does not fit the only field with any number of elements per input. The limit on `count` is BIP441's limit on stack elements, which a larger range would exceed without `COLLATE`, and it bounds the number of missing entries an implementation processes with `COLLATE`.

Within version 0, undefined selector bits and scope values fail. The separate version byte preserves those strict rules while reserving an explicit namespace in which a future soft fork can define a different selector layout.

Reserved versions succeed to preserve a soft-fork upgrade path under OP_TX; rejecting them would avoid immediate success but require a new opcode or Tapleaf version for future formats.

### Output and Field Choices

By default, OP_TX pushes selected values as separate stack elements so scripts can inspect or compare them individually and use numeric values in arithmetic. `COLLATE` instead produces a single byte string ready for hashing and comparison. Because `COLLATE` places multiple values in one byte string, numeric values use fixed widths and variable-length byte strings are length-prefixed, preserving the boundary between adjacent values.

For example, concatenating BIP441 minimal encodings would encode `TX_VERSION = 1` followed by `TX_LOCKTIME = 2` and `TX_VERSION = 513` followed by `TX_LOCKTIME = 0` as the same bytes, `01 02`. Their fixed four-byte `COLLATE` encodings differ, preventing a commitment to one pair from accepting the other.

The global fields `INPUT_TOTAL_AMOUNT` and `OUTPUT_TOTAL_AMOUNT` permit fee calculation for transactions with any number of inputs and outputs without requiring general iteration; `TX_WEIGHT` additionally permits fee-rate policies. Block height, time, and confirmation depth are chain context and remain outside OP_TX.

`INPUT_SCRIPTSIG` and the witness fields expose the raw unlocking data of every transaction input. The executing input's witness arguments are already on the stack, but OP_TX is needed to inspect other inputs and the complete raw witness. `CURRENT_TAPROOT_ANNEX` is exposed separately because Taproot removes the annex before executing the script.

`CURRENT_TAPSCRIPT` and `CURRENT_CONTROL_BLOCK` expose authenticated Taproot script-path context. `CURRENT_INTERNAL_KEY` provides the same value as [BIP349](bip-0349.md) `OP_INTERNALKEY` without requiring control-block parsing. `CURRENT_TAPLEAF_HASH` and `CURRENT_TAPTREE_ROOT` expose values already computed during script-path validation that would otherwise require hashing the Tapscript and reducing an arbitrary Merkle path. The control block remains available because it contains the sibling hashes needed to modify that path.

### Hash Commitments

`COLLATE` can reproduce existing transaction component hashes when the same fields are selected. For example, [BIP341](bip-0341.mediawiki) defines:

```text
sha_prevouts = SHA256(outpoint_0 || outpoint_1 || ...)
<00 01 00 20 03 00> OP_TX OP_SHA256
```

The selector collates every input's previous transaction ID and output index in serialized outpoint order, producing the same concatenation and therefore the same hash. `COLLATE` does not prefix the collection with a count or byte length because doing so would change the BIP341 hash.

`COLLATE` includes only the values requested by the selector, so a hash of its result commits only to those values. If a script must distinguish the executing input or script path from another with the same selected data, the selector must include the relevant current-execution fields. Similarly, selecting every input amount followed by every output amount without either count does not commit to the boundaries between the two collections. A script should select `INPUT_TOTAL_COUNT` or `OUTPUT_TOTAL_COUNT` when that distinction matters. Keeping hashing and comparison outside of OP_TX lets scripts choose their exact hash construction instead of hard-coding protocol-specific templates such as CTV or TemplateHash.

## Examples

### First Five Input Amounts

The following invocation chooses INPUT_PREVOUT_AMOUNT for inputs 0 through 4:

```text
OP_0 OP_5 <00 00 00 40 04 00> OP_TX
```

`OP_0` and `OP_5` supply the range's start and count. OP_TX pushes five stack values in ascending input order.

### Transaction Fee

The following selector requests the total input and output amounts without selecting individual inputs or outputs:

```text
00 a0 00 00 00 00
```

The complete calculation is:

```text
<00 a0 00 00 00 00> OP_TX OP_SUB
```

OP_TX pushes INPUT_TOTAL_AMOUNT followed by OUTPUT_TOTAL_AMOUNT, so OP_SUB produces the transaction fee.

### CTV-like Commitment

This example and the next commit to the same listed transaction properties as CTV and TemplateHash, but use different hash constructions and therefore produce non-interchangeable hashes.

[BIP119](bip-0119.mediawiki) CTV is normally used as:

```text
<ctv_hash> OP_CHECKTEMPLATEVERIFY
```

The same transaction properties can be committed to using OP_TX:

```text
<00 57 01 22 30 03> OP_TX OP_SHA256 <optx_ctv_hash> OP_EQUAL
```

The selector collates the version, locktime, input and output counts, every input's scriptSig and sequence, every output, and the current input index. These are the same transaction properties constrained by CTV. CTV hashes groups of fields before building its final message, while this construction hashes OP_TX's flat encoding.

The CTV form is 34 script bytes; the OP_TX form is 43. Script libraries can hide the latter behind a CTV-like helper without adding CTV-specific consensus behavior to OP_TX.

### TemplateHash-like Commitment

[BIP446](bip-0446.md) TemplateHash is normally used as:

```text
OP_TEMPLATEHASH <template_hash> OP_EQUAL
```

The corresponding OP_TX construction is:

```text
<00 57 03 22 20 03> OP_TX OP_SHA256 <optx_template_hash> OP_EQUAL
```

Both commit to the version, locktime, input and output counts, input sequences, outputs, current input index, and annex.

The TemplateHash form is 35 script bytes; the OP_TX form is 43.

## Security Considerations

### Runtime Selectors and Reserved Versions

Reserved selector versions make the script succeed immediately. If a script passes a selector supplied by the spender to OP_TX, the spender could choose a reserved version and bypass the remaining conditions. A script using a runtime selector must therefore validate its version, fields, and scopes before executing OP_TX. This concern does not apply when the selector is a constant placed directly before OP_TX in the Tapscript.

Scope operands may also be supplied by the spender. A script that requires particular indices or ranges must provide those operands itself or validate spender-provided values before executing OP_TX.

### Self-Reference

Storing a commitment inside data selected by OP_TX can create a circular dependency. For example, if a Tapscript contains an expected hash and selects `CURRENT_TAPSCRIPT`, `CURRENT_TAPLEAF_HASH`, or `CURRENT_TAPTREE_ROOT`, that expected hash becomes part of the data being hashed. The same problem can occur when a commitment is stored in a selected scriptSig, witness item, or control block. The commitment must instead be stored outside the selected data, or the field containing it must be omitted from the selector.

### Other Inputs' Witnesses

Signatures cannot commit to the witness containing them, so any witness that satisfies an input's script can replace it: its spender can choose other arguments or another leaf, and anyone relaying the transaction can, for example, append zero bytes to an argument used only as a number. Another input's leaf script and control block are its final witness items only in a Taproot script-path spend without an annex.

### Shared Outputs

Each input's script is evaluated separately, so one output can satisfy the checks of several inputs. Scripts that must not share an output should bind it to their input, for example with the `CURRENT` output scope.

## Backwards Compatibility

Before activation, opcode `0xbf` remains OP_SUCCESS191 in `0xc2` leaves. Defining stricter OP_TX semantics can only invalidate spends previously accepted through OP_SUCCESS191, making this change backward-compatible as a soft fork. The opcode's behavior in all other script versions is unchanged.

## Reference Implementation

The Bitcoin Core Tapleaf 0xc2 prototype implements OP_TX: <https://github.com/jmoik/bitcoin/tree/gsr>.

## Changelog

- 0.2.0: 2026-10-27: fully specify OP_TX using a versioned six-byte selector, stack operands for indices and ranges, scoped input and output fields, default and COLLATE outputs, resource accounting, and future selector versions.
- 0.1.0: 2025-09-27: initial draft.

## Thanks

I stand here on the shoulders of giants, including Russell O'Connor's original OP_TXHASH proposal and Steven Roose and Brandon Black's subsequent elaboration of that work. I also credit Jeremy Rubin for his tireless work exploring the uses of covenants and his OP_CHECKTEMPLATEVERIFY proposal.

While I ultimately found those proposals unsatisfying, it was their daunting intellectual prowess which forced me to slowly develop the groundwork for a proposal to meet the high standards they have set.
