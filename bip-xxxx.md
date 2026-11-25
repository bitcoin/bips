```
BIP: ?
Layer: Applications
Title: bip39() Descriptor Key Expression
Authors: Pol Espinasa <polespinasa@protonmail.com>
Status: Draft
Type: Specification
Assigned: ?
License: BSD-3-Clause
Requires: 32, 39, 380
```

## Abstract

This document specifies a `bip39()` key expression for output script descriptors. `bip39()` expressions take a list of BIP 39 English words and an optional passphrase and produce an extended private master key using [BIP 39][BIP39] and [BIP 32][BIP32].

## Motivation

Bitcoin users commonly hold recovery seeds as BIP 39 mnemonics, yet some descriptor wallets lack a standardized way to import them. This gap has been documented for years:

- [bitcoin/bitcoin#19151][Core19151]: a Bitcoin Core contributor proposed supporting BIP 39 mnemonics directly in descriptors, noting it "would allow less painful imports and scans of third party wallet seeds" and sketching a syntax similar to the one specified here.

- [bitcoin/bitcoin#16393][Core16393]: a contributor requested partial (import) BIP 39 support for Bitcoin Core, for interoperability with existing wallets that use BIP 39 seeds.

- [bitcoin/bitcoin#17748][Core17748]: users discussed mnemonic-based backups and wallet interoperability.

- [bitcoin/bitcoin#32115][Core32115]: a contributor proposed a standalone Rust utility to import BIP 39 mnemonics. The discussion raised concerns about dependency review and requiring users to compile the utility themselves.

Users may need wallet-specific import workflows or a separate tool to convert a mnemonic and passphrase into an extended private key and descriptor.

A standardized key expression would allow supporting wallets to import a mnemonic and passphrase directly, without requiring a separate conversion workflow. This document specifies `bip39()` for that purpose. A `bip39()` expression is functionally equivalent to an `xprv` key expression and does not enable any new spending capability.

## Specification

A new key expression is defined: `bip39()`.

For descriptor evaluation, a `bip39()` expression produces the BIP 32 master extended private key (`xprv`) derived from its mnemonic and passphrase. It follows the same derivation and serialization rules as an `xprv` key expression and is valid in the same script-expression contexts.

A `bip39()` expression is self-contained: within the balanced parentheses of `bip39(...)`, the characters `[`, `]` and `,` delimit the word list and separate its two arguments, and are not interpreted as the BIP 380 key-origin brackets or key-separator tokens. A parser must switch to the `bip39()` sub-grammar upon encountering `bip39(` and resume ordinary BIP 380 parsing only after the matching `)`.

It takes a list of 12, 15, 18, 21 or 24 BIP 39 English words, in lowercase as they appear in the BIP 39 wordlist, and an optional passphrase enclosed in double quotes and encoded as specified in the Passphrase Encoding subsection below, following the BIP 39 specification:

`bip39([word1, word2, ..., wordN], "passphrase")`

If no passphrase is provided, an empty string `""` is used instead, as BIP 39 states; its presence in the descriptor is optional and can be skipped:

`bip39([word1, word2, ..., wordN])`

Within `bip39()`, outside the quoted passphrase, ASCII spaces (U+0020) are permitted only before and after mnemonic words and after the comma introducing the passphrase. Spaces inside the quoted passphrase are significant. For BIP 39 seed derivation, the mnemonic words are joined with a single ASCII space, without leading or trailing spaces.

### Passphrase Encoding

The passphrase is enclosed in double quotes (`"`) and encoded with the following rules, which allow any Unicode passphrase supported by BIP 39 to be represented while keeping ordinary printable passphrases human-readable:

* Printable BIP 380 characters may be written directly, except for `"` and `\`.
* `\"` represents a double quote (`U+0022`).
* `\\` represents a backslash (`U+005C`).
* `\u{HEX}` represents a Unicode scalar value, where `HEX` is 1 to 6 hexadecimal digits (case-insensitive `0-9`, `a-f`, `A-F`) denoting a code point in the range `U+0000` to `U+10FFFF`, excluding the surrogate range `U+D800`-`U+DFFF`.

Inside the quoted passphrase, the descriptor metacharacters `)`, `(`, `[`, `]`, `{`, `}`, `#` and `,` have no special meaning; only an unescaped `"` terminates it. For example:

```
"correct horse battery staple"
"say \"hello\""
"C:\\wallet"
"caf\u{e9}"
"\u{1f510} bitcoin"
"not#a#checksum"
```

The following make the whole descriptor invalid and must be rejected rather than silently altered, since silent modification could change the derived keys and could cause silent loss of funds:

* An escape sequence other than `\"`, `\\`, or `\u{HEX}` (for example `\x` or `\n`).
* A `\u{}` with zero or more than 6 hex digits, a non-hexadecimal digit between the braces, or a code point that is a surrogate (`U+D800`-`U+DFFF`) or greater than `U+10FFFF`.
* A missing closing double quote, an incomplete escape sequence, or unexpected characters after the closing double quote.

After decoding the escape sequences, implementations apply the BIP 39 seed derivation procedure: the decoded passphrase and the mnemonic sentence are each NFKD-normalized and UTF-8-encoded, then passed to PBKDF2 as specified in [BIP 39][BIP39] to produce the binary seed. The BIP 32 master extended private key is then derived from that seed as specified in [BIP 32][BIP32].

As with an `xprv` key expression, `bip39()` may be followed by BIP 32 derivation path elements and an optional final `/*`, `/*h`, or `/*'`, as specified in [BIP 380][BIP380]:

`bip39([word1, word2, ..., wordN], "passphrase")/NUM/.../*`

As `bip39()` is equivalent to an `xprv` key expression, it also supports the multipath derivation specifier `/<NUM;NUM;...;NUM>/` of [BIP 389][BIP389] (where each `NUM` may use the `h` or `'` hardened indicators), which allows a single descriptor to expand to multiple derivation paths such as the external and change chains `/<0;1>/*`.

A key-origin prefix is not allowed. Because `bip39()` produces a BIP 32 master key at depth 0, there is no prior derivation for a key origin to describe, so a leading `[...]` before `bip39(` makes the descriptor invalid.

An invalid mnemonic makes the whole descriptor invalid.

### Normalization and Watch-Only Export

A `bip39()` expression always produces an extended private key and, because it embeds the full seed material, it can never appear in a watch-only (public-only) descriptor.

A `bip39()` expression is a valid private key expression and may be persisted, exported, and round-tripped like any other private key expression such as `xprv`. Wallets may resolve a `bip39()` expression to its derived `xprv` key expression on import — for example to avoid retaining the mnemonic and passphrase — but this is a wallet policy decision, not a requirement of this specification.

When a descriptor is exported without private keys, each `bip39()` expression must first be replaced by its equivalent BIP 32 master extended private key, retaining any following derivation suffix unchanged. The resulting key expression is then normalized according to [BIP 380][BIP380], with the same public-only derivation limitations as any other `xprv` key expression.

### Descriptor Examples

#### bip39 P2WPKH descriptor with passphrase:

`wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "SATOSHI"))`

is equivalent to

`wpkh(xprv9s21ZrQH143K3WhtFPeEmTRQbQckSDMbuAn4hxGs4zLkD4N8b9fBpWDCPENoVq83vrML4fYwhKZPtgG5XR1vnSbwGs79FvQ4dET1KsB8P4q)`

#### bip39 TR descriptor without passphrase:

`tr(bip39([fancy, behave, cement, feel, gas, super, dutch, juice, cream, tape, bronze, increase, minor, meadow, rescue, someone, banana, recipe, orient, copy, blossom, team, chase, initial]))`

is equivalent to

`tr(xprv9s21ZrQH143K2RYd6U3ZPwZokU39ePUpH4Rnqdsob4kFY8S24EGW6beNSnTxEThEfsfsLftit9AvN5zWKhVx9hrX4wqEqfJfNPVgN1QAhN6)`

#### bip39 P2WPKH descriptor with derivation path:

`wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "SATOSHI")/84h/0h/0h/0/*)`

is equivalent to

`wpkh(xprv9s21ZrQH143K3WhtFPeEmTRQbQckSDMbuAn4hxGs4zLkD4N8b9fBpWDCPENoVq83vrML4fYwhKZPtgG5XR1vnSbwGs79FvQ4dET1KsB8P4q/84h/0h/0h/0/*)`

#### bip39 nested-segwit (P2SH-P2WPKH) descriptor with passphrase:

`sh(wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "SATOSHI")))`

is equivalent to

`sh(wpkh(xprv9s21ZrQH143K3WhtFPeEmTRQbQckSDMbuAn4hxGs4zLkD4N8b9fBpWDCPENoVq83vrML4fYwhKZPtgG5XR1vnSbwGs79FvQ4dET1KsB8P4q))`

#### bip39 P2WPKH descriptor with an escaped passphrase:

`wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "caf\u{e9}"))`

is equivalent to

`wpkh(xprv9s21ZrQH143K3786ZFxLXMxdQo5V5RrSrDWXwG8UppFnDipsxycLdR22K5eCJfaBEzRGgjtAJQvyQGreTULTSMPNWh25yVuknrJLu4VKm3s)`

The passphrase `"caf\u{e9}"` decodes to `café`. Per BIP 39 the decoded string is NFKD-normalized before seed derivation, so this is equivalent to any other passphrase text that NFKD-normalizes to the same string, such as `"cafe\u{301}"`.

#### bip39 P2WPKH descriptor with a multipath derivation:

`wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "SATOSHI")/84h/0h/0h/<0;1>/*)`

expands to the two descriptors

`wpkh(xprv9s21ZrQH143K3WhtFPeEmTRQbQckSDMbuAn4hxGs4zLkD4N8b9fBpWDCPENoVq83vrML4fYwhKZPtgG5XR1vnSbwGs79FvQ4dET1KsB8P4q/84h/0h/0h/0/*)`

`wpkh(xprv9s21ZrQH143K3WhtFPeEmTRQbQckSDMbuAn4hxGs4zLkD4N8b9fBpWDCPENoVq83vrML4fYwhKZPtgG5XR1vnSbwGs79FvQ4dET1KsB8P4q/84h/0h/0h/1/*)`

## Rationale

Per [BIP 39][BIP39], the English wordlist is the de facto standard and non-English mnemonic generation is strongly discouraged. Restricting `bip39()` to English additionally guarantees that every word fits within the [BIP 380][BIP380] character set, which is not the case for wordlists such as Spanish, French, Japanese, and Chinese that use accented or non-Latin characters.

The allowed characters defined in BIP 380 are:
```
0123456789()[],'/*abcdefgh@:$%{}
IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~
ijklmnopqrstuvwxyzABCDEFGH`#"\<space>
```

The passphrase encoding was chosen to keep common (printable ASCII) passphrases human-readable — they appear verbatim inside the quotes — while still representing every Unicode passphrase supported by BIP 39. Only the delimiter `"`, the escape introducer `\`, and characters outside the BIP 380 character set require escaping; the `\u{HEX}` escape covers the full Unicode scalar range (U+0000 to U+10FFFF). This avoids the gap that would otherwise leave passphrases containing characters such as `é`, CJK characters, or emoji unrepresentable.

For a fixed mnemonic, passphrase encodings whose decoded strings have the same NFKD-normalized form derive the same master extended private key. For example, `"caf\u{e9}"` and `"cafe\u{301}"` both normalize to `caf` followed by U+0065 U+0301 (displayed as “é”). Likewise, `"\u{41}"` and `"A"` decode to the same string. This is analogous to existing descriptor equivalences such as `0h` and `0'`. Implementations that compare descriptors for equality should resolve `bip39()` expressions to their derived `xprv` (see Normalization and Watch-Only Export) rather than compare the raw passphrase text.

## Backwards Compatibility

`bip39()` expressions extend the key-expression syntax specified in BIP 380. Existing implementations that do not support `bip39()` cannot interpret descriptors containing this expression. Such descriptors can be converted to equivalent `xprv`-based descriptors for use with existing implementations.

The quoted passphrase encoding allows any Unicode passphrase supported by BIP 39 to be represented.

## Security Considerations

A `bip39()` key expression is equivalent to an `xprv` key expression (as defined in the Specification), so the handling that applies to any descriptor containing private keys applies here equally. Like an `xprv`, a descriptor containing `bip39()` may be persisted and exported by the wallet, and must be guarded as private wallet data.

One aspect is specific to `bip39()` and is worth weighing by wallet authors: an `xprv` exposes a single master key, whereas a `bip39()` expression exposes the mnemonic sentence, which is reusable across passphrases. Disclosure of the mnemonic also enables offline guessing of other passphrases used with it. Wallets using other passphrases can be derived if those passphrases are known or recovered. Persisting or exporting a `bip39()` descriptor therefore exposes strictly more than persisting or exporting the equivalent `xprv`, and a wallet that retains the `bip39()` form should treat it with at least the same care as the seed itself. Wallets that prefer not to retain this additional exposure may resolve `bip39()` to `xprv` on import, as discussed in the "Normalization and Watch-Only Export" section.

For watch-only use — sharing with block explorers, watch-only wallets, co-signers that should not have unilateral spending power, or any untrusted environment — implementations must normalize the expression to an `xpub`-based descriptor as described in the "Normalization and Watch-Only Export" section, which removes all seed material. A `bip39()` expression must never be exported to a watch-only consumer.

## Test Vectors

Going from a `bip39()` key expression to an `xprv` is the same process as going from a BIP 39 mnemonic sentence (seedphrase) to an `xprv`; for that reason the same [test vectors][BIP39testvectors] as the ones defined in BIP 39 can be used.

The following valid descriptors exercise edge cases introduced by the quoted passphrase encoding. All use the mnemonic `legal winner thank year wave sausage worth useful legal winner thank yellow`. Each is equivalent to the `xprv` descriptor shown alongside it. Checksums are included except in the example that explicitly omits them.

- `#` in passphrase — only a `#` outside the quoted passphrase introduces the optional descriptor checksum:

    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "foo#bar"))#fxq7mnpw`

    is equivalent to

    `wpkh(xprv9s21ZrQH143K4c2XhdpLFYp3ffuRPaopHxjwe5pWgXH6kAqX2dPiQdPGgAkrbfz2VhZMeTUdTYmmkevozwiNMvRth1Aw5pcNsRix8aSeKAi)#8satut7x`

- `#` in passphrase without a checksum — the `#` inside the quoted passphrase remains part of the passphrase when the descriptor checksum is omitted:

    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "foo#bar"))`

    is equivalent to

    `wpkh(xprv9s21ZrQH143K4c2XhdpLFYp3ffuRPaopHxjwe5pWgXH6kAqX2dPiQdPGgAkrbfz2VhZMeTUdTYmmkevozwiNMvRth1Aw5pcNsRix8aSeKAi)`

- `,` in passphrase — commas have no special meaning inside a quoted string:

    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "foo,bar"))#3m4n50xq`

    is equivalent to

    `wpkh(xprv9s21ZrQH143K4FTherUTM5tBT6GmTB3Q9VG3an2VDXrxpWgQZb79H89dbSQPbpMQ2oosghFxJJvc1fLZJnC7MLxi7Ux4X96LLfXrWJj7VBT)#xxdnkpa7`

- `)` in passphrase — quoted strings are opaque to expression-level parsing:

    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "foo)bar"))#6hvdzscj`

    is equivalent to

    `wpkh(xprv9s21ZrQH143K3Qog5MR5QYGzTTPaxxFahyH1qTUEbbT9CZoPfE2rYS9Pu1t4q4dbKQ5vMsZif7BMmv2q21ZcHDpjvG5RpnCZ9sNs2t5ujev)#f6applf5`

- Leading and trailing spaces — spaces at the boundaries of the quoted string are significant:

    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], " leading and trailing spaces "))#z875r050`

    is equivalent to

    `wpkh(xprv9s21ZrQH143K4PPHRLkW85PkEY2n59XoLeS9UhE6G6jBqwz8aDchx9AGhTnMPVxsyuE5QBiTfNoLV7Xv1Qa6sLT9XVWcrBYhW459TXGhRkz)#4r68mrmk`

- Escaped double quote (`\"`) — the `\"` sequence encodes a literal `"`, so the passphrase decodes to `say "hello"`:

    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "say \"hello\""))#473jhpxe`

    is equivalent to

    `wpkh(xprv9s21ZrQH143K4RAeSJzjATJVxWUDkjRTNHXDma4BXNWQhnip7sRjuYpngBTHxb4zKQPLJsvDDGzg1aaFxn3exkLqLYPUop2nEAHUvDMzFNG)#g2lt5shn`

- Escaped backslash (`\\`) — the `\\` sequence encodes a literal `\`, so the passphrase decodes to `C:\wallet`:

    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "C:\\wallet"))#j6mt75rr`

    is equivalent to

    `wpkh(xprv9s21ZrQH143K3MWGZi36HpsEZ3SC7J9tPBjUmQYQ5sJqh8qyzuGgE3f1WgzDzHo47SneixuX9oVeqB5k2kdVUuQMVc1QiUGdq22gaBAbfuC)#5z32wesl`

- Unicode escape (`\u{e9}`) — the `\u{e9}` sequence encodes U+00E9, so the passphrase decodes to `café`:

    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "caf\u{e9}"))#05l5g328`

    is equivalent to

    `wpkh(xprv9s21ZrQH143K3786ZFxLXMxdQo5V5RrSrDWXwG8UppFnDipsxycLdR22K5eCJfaBEzRGgjtAJQvyQGreTULTSMPNWh25yVuknrJLu4VKm3s)#9a0vxmzx`

- NFKD compatibility normalization — the escapes decode to fullwidth `ＳＡＴＯＳＨＩ`, which NFKD normalizes to `SATOSHI`. NFD would leave the fullwidth characters unchanged:

    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "\u{ff33}\u{ff21}\u{ff34}\u{ff2f}\u{ff33}\u{ff28}\u{ff29}"))#ufmqx3tc`

    is equivalent to

    `wpkh(xprv9s21ZrQH143K3WhtFPeEmTRQbQckSDMbuAn4hxGs4zLkD4N8b9fBpWDCPENoVq83vrML4fYwhKZPtgG5XR1vnSbwGs79FvQ4dET1KsB8P4q)#v99927rr`

The following descriptors are invalid and must be rejected by a conforming parser:

- Wrong word count (11 words, not a valid BIP 39 length):
    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank], "SATOSHI"))`
- Invalid BIP 39 checksum (12 valid English words whose checksum does not match):
    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, abandon], "SATOSHI"))`
- Mnemonic word with an uppercase letter (words must use their exact lowercase spelling):
    `wpkh(bip39([Legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "SATOSHI"))`
- Disallowed key-origin prefix before `bip39(`:
    `wpkh([deadbeef]bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "SATOSHI"))`
- Passphrase with a raw character outside the BIP 380 character set (it must instead be written with a `\u{HEX}` escape):
    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "café"))`
- Passphrase with an unrecognized escape sequence:
    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "say \x hello"))`
- Passphrase with an invalid `\u{HEX}` escape (a surrogate code point):
    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "\u{D800}"))`
- Passphrase with a seven-digit Unicode escape (the numeric value is valid, but the encoding permits at most six hex digits):
    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "\u{0000041}"))`
- Passphrase with a Unicode escape greater than U+10FFFF:
    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "\u{110000}"))`
- Passphrase with a missing closing double quote:
    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "SATOSHI))`
- Passphrase with unexpected characters after the closing quote (a literal `"` inside the passphrase must instead be written as `\"`):
    `wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "SATO"SHI"))`
- Nested `bip39()` (its arguments are a word list and a passphrase, not key expressions):
    `wpkh(bip39(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "SATOSHI")))`


## References

- [BIP 32][BIP32]: Hierarchical Deterministic Wallets
- [BIP 39][BIP39]: Mnemonic code for generating deterministic keys
- [BIP 380][BIP380]: Output Script Descriptors General Operation
- [BIP 386][BIP386]: tr() Output Script Descriptors
- [BIP 389][BIP389]: Multipath Descriptor Key Expressions
- [bitcoin/bitcoin#19151][Core19151]: Support BIP39 mnemonic in descriptors
- [bitcoin/bitcoin#16393][Core16393]: Add partial BIP39 support (import only)
- [bitcoin/bitcoin#17748][Core17748]: Adoption of BIP39/44/49/84, and classification of (extended) pub/priv keys, addresses, mnemonics, etc
- [bitcoin/bitcoin#32115][Core32115]: Rust tool to import bip39 mnemonic

[BIP32]: bip-0032.mediawiki
[BIP39]: bip-0039.mediawiki
[BIP39testvectors]: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
[BIP380]: bip-0380.mediawiki
[BIP386]: bip-0386.mediawiki
[BIP389]: bip-0389.mediawiki
[Core19151]: https://github.com/bitcoin/bitcoin/issues/19151
[Core16393]: https://github.com/bitcoin/bitcoin/issues/16393
[Core17748]: https://github.com/bitcoin/bitcoin/issues/17748
[Core32115]: https://github.com/bitcoin/bitcoin/pull/32115

## Copyright

This document is licensed under the 3-Clause BSD License.