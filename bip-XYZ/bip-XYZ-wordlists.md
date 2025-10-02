# Wordlists

* [Emoji](emoji.txt)

## Wordlists (Special Considerations)

### Emoji

Credits: @EmojiSeedDevTeam

The Emoji wordlist is a deterministic mapping of the 2048 English BIP-39 words into
2048 unique pairs of emoji. It enables mnemonic phrases to be displayed visually
while remaining fully compatible with existing BIP-39 semantics (entropy, checksum, seed).

Emojis are chosen using the following rules:

1. Direct Match: if a word has a clear, universal emoji, duplicate it.
2. Months and holidays use seasonal/holiday symbols.
3. Numeric words map to keycap digits.
4. Abstract and Action Words use a primary metaphor plus a clarifier emoji.
5. Nouns: object  clarifier. Verbs/participles: action  clarifier.
6. Duplicate only for strong iconic matches; add clarifiers for ambiguity; if unresolved, fall back deterministically.
7. All 2048 pairs MUST be unique. If a collision occurs, rotate clarifier, then primary, and finally apply the fallback.
8. Use only fully-qualified Unicode emoji graphemes (per Unicode TR51). Avoid variation selectors and platform-specific implementations.
9. All curation rules are available here: https://emojiseed.com#readme

==== Security & Interop Notes ====

* No protocol changes: entropy, checksum, and BIP-39 wordlists are unchanged.
* Rendering differences across platforms exist; compare by code points (not rasterized glyphs).
* Wallets that do not support Emoji can ignore this wordlist without impact.

==== License ====

This addition inherits the MIT license.

