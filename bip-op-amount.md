```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: OP_AMOUNT
  Author: Nuh <nuh@nuh.dev>
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-op_amount
  Status: Draft
  Type: Standards Track
  Created: 2026-01-01
  License: BSD-3-Clause
```

## Abstract

This BIP describes a new tapscript opcode (`OP_AMOUNT`) which pushes the amount of the selected input or output to the stack.

## Motivation

Many soft fork proposals are in the form of a bundle of other BIPs, each introducing a single capability at a time with one or more opcodes. 

Most capabilities have simple self-contained proposals addressing them sufficiently with good ergonomics (Vector commitments [BIP 347], State-carrying UTXOs [BIP 443], Commitment to transactions [OP_TEMPLATEHASH], Signatures [BIP 348]).

Amount introspection on the other hand, can either be achieved by unergonomic work arounds (OP_CAT and schnorr tricks), or with much more comprehensive introspections opcodes ([OP_TXHASH], or [OP_TX] from the great script restoration proposal), or they expect support for 64 bit arithmetics in tapscript with novel tapleaf version ([OP_INOUT_AMOUNT]).

This proposal aims to remedy that, by offering a simple amount introspection opcode, that covers introspection of inputs and outputs, without requiring any more introspection or 64 bit arithmetics or any other behavior, so that proposal could be bundled with other proposals offering other capabilities, together considered a good balance between ergonomicity and implementation complexity.

## Specification

When verifying taproot script path spends having leaf version `0xc0` (as defined in [BIP 342]), `OP_AMOUNT` replaces `OP_SUCCESS228` (0xe4). 

**Execution:**

1. Pop the top stack element and interpret it as a signed integer called `op_amount_selector` or the script fails otherwise.
2. Determine the target input or output based on the selector value:
   - **selector = 0**: Use the current input being validated
   - **selector < 0**: Use input at index `abs(selector) - 1`
   - **selector > 0**: Use output at index `selector - 1`
3. Retrieve the amount value from the determined input or output
4. Push the resulting amount onto the stack as a signed 64 bit integer

**Examples:**
- Selector `0` → amount of current input
- Selector `-1` → amount of input 0
- Selector `-2` → amount of input 1
- Selector `1` → amount of output 0
- Selector `2` → amount of output 

If the selected input or output are out of bound, the script should fail.

## Reference Implementation

A reference implementation is provided [here](https://github.com/Nuhvi/sake/blob/c3243f000b7ade3b7649a3b3c67b3801b8c12215/src/exec/sake_opcodes/op_amount.rs).

And for convenience inlined here:
```rust
pub const OP_AMOUNT_CURRENT_INPUT_SELECTOR: i64 = 0;
pub fn op_amount_input_selector(input_index: usize) -> i64 {
    -input_index.cast_signed() as i64 - 1
}
pub fn op_amount_output_selector(output_index: usize) -> i64 {
    output_index as i64 + 1
}

impl<'a> Exec<'a> {
    pub(crate) fn handle_op_amount(&mut self) -> Result<(), ExecError> {
        let selector = self.stack.popnum()?;

        let amount = match selector {
            OP_AMOUNT_CURRENT_INPUT_SELECTOR => self
                .prevouts
                .get(self.input_idx)
                .map(|txout| txout.value)
                .expect("number of inputs and prevouts checked earlier"),
            i64::MIN..=-1_i64 => self
                .prevouts
                .get(selector.unsigned_abs() as usize - 1)
                .map(|txout| txout.value)
                .ok_or(ExecError::OpAmountError(
                    OpAmountError::OutOfBoundInputIndex,
                ))?,
            1_i64..=i64::MAX => self
                .sighashcache
                .transaction()
                .output
                .get(selector as usize - 1)
                .map(|out| out.value)
                .ok_or(ExecError::OpAmountError(
                    OpAmountError::OutOfBoundOutputIndex,
                ))?,
        }
        .to_sat()
        .cast_signed();

        self.stack.pushnum(amount);

        Ok(())
    }
}
```

## Backward Compatibility

`OP_AMOUNT` replaces the witness v1-only opcode` OP_RETURN_228` with stricter verification semantics. Consequently, scripts using those opcodes which previously were valid will cease to be valid with this change.

Stricter verification semantics for an `OP_SUCCESSx` opcode are a soft fork, so existing software will be fully functional without upgrade except for mining and block validation

## Deployment

The activation mechanism, and the set of other BIPs to be concurrently deployed, are to be determined.

## Acknowledgements

The concept for `OP_AMOUNT` and its selector comes from Salvatore Ingala, especially within his proposal for Script Army Knife bundle of tapscript capabilities upgrade.

## Copyright

This document is licensed under the 3-clause BSD license.

[BIP 341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
[BIP 342]: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki
[BIP 347]: https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki
[BIP 348]: https://github.com/bitcoin/bips/blob/master/bip-0348.md
[BIP 443]: https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki
[OP_TEMPLATEHASH]: https://github.com/bitcoin/bips/pull/1974/files#bip-templatehash.md
[OP_TXHASH]: https://github.com/bitcoin/bips/blob/debd349e6181d949cbea0691fcc0d67b265b02a8/bip-0346.md
[OP_TX]: https://github.com/rustyrussell/bips/blob/d6164731904c26b85e11db2506f53388ae99219d/bip-unknown-optx.mediawiki
[OP_INOUT_AMOUNT]: https://github.com/Christewart/bips/blob/6a16339b6245f7c8231ad567858e8bc850cc910c/bip-op-inout-amount.mediawiki
