<pre>
  BIP: ?
  Layer: Applications
  Title: Multilingual mnemonic display and input conventions
  Author: Daniel Osemberg <ceo@blocksight.live>
  Discussions-To:
  Comments-Summary: No comments yet.
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-?
  Status: Draft
  Type: Informational
  Created: 2026-04-19
  Post-History:
  License: BSD-2-Clause
</pre>

## Abstract

This document specifies a convention for rendering and accepting BIP-39 mnemonics in a user's native language via a *display wordlist*: a 2048-entry list in the target language, index-parallel to the canonical English BIP-39 wordlist.

The seed of record remains the canonical English BIP-39 mnemonic. A display wordlist is a UX layer; it adds no new cryptographic surface, and any seed produced under this convention remains restorable in any BIP-39 wallet using its English form.

## Motivation

A wallet that wants to show or accept the seed phrase in a language other than the ten currently shipped with BIP-39 (English plus nine non-English canonical wordlists) has two practical options: ship a parallel display wordlist that maps to English position-for-position, or ask the user to write down and later transcribe an English phrase in a language they may not read. The latter is error-prone at the point of backup. A single misspelling on paper, or a single mis-read during restore, fails the BIP-39 checksum and can render the seed unrecoverable. Many multilingual wallets already solve this internally by rendering the mnemonic in the user's native script. This document specifies the format and the integrity rules so that such display wordlists are interoperable across wallets and so that the cryptographic chain remains identical to a single-language BIP-39 implementation.

The 10 canonical BIP-39 wordlists cover roughly a third of humanity by native language. The remaining two thirds, around 5 billion native speakers, have no canonical wordlist in their language. A portable display-layer convention lets any wallet extend coverage without diverging from the BIP-39 cryptographic chain.

## Specification

### Definitions

- **Canonical mnemonic**: the English BIP-39 mnemonic produced by applying the BIP-39 specification to the wallet's entropy. It is the only mnemonic ever fed to PBKDF2-HMAC-SHA512 during seed derivation.
- **Display wordlist**: a 2048-entry list in a non-English language, index-parallel to the canonical English BIP-39 wordlist. The entry at index `i` is the native-language token corresponding to the English word at index `i`.
- **Display mnemonic**: the user-facing rendering of a canonical mnemonic using a display wordlist. Display mnemonics are never used as the password input to PBKDF2.

### Seed derivation

A wallet that uses a display wordlist derives the BIP-39 seed exclusively from the canonical English mnemonic:

1. Generate entropy as defined in BIP-39.
2. Compute the canonical English mnemonic per BIP-39.
3. Render the display mnemonic by replacing each English word at index `i` with the corresponding display wordlist entry at index `i`.
4. Show the display mnemonic to the user for backup.
5. On restore, accept the display mnemonic, look up each token in the display wordlist's reverse mapping to recover the canonical English mnemonic, then derive the seed per BIP-39.

The NFKD-normalized canonical English mnemonic from step 2 is the only input that ever reaches PBKDF2 as the password. The passphrase argument to PBKDF2 (via the salt `"mnemonic" + passphrase` per BIP-39) is unchanged by this convention: it is supplied by the user as-is and is not translated, mapped, or otherwise modified by the display wordlist.

### Display wordlist requirements

A display wordlist MUST:

1. Contain exactly 2048 entries, one per line, UTF-8 encoded with no byte-order mark and Unix line endings (`\n`).
2. Have no duplicate entries.
3. Have no leading or trailing whitespace on any entry.
4. Have no embedded whitespace and no hyphen or dash character inside any entry. Forbidden characters include ASCII space (`U+0020`), ideographic space (`U+3000`), any other character with the Unicode `White_Space` property, ASCII hyphen-minus (`U+002D`), en-dash (`U+2013`), em-dash (`U+2014`), non-breaking hyphen (`U+2011`), and soft hyphen (`U+00AD`). Mnemonic words are tokenized on whitespace; an entry containing whitespace cannot survive the paper-backup round trip. Hyphens and dashes are forbidden because on paper they are easily confused across visually-similar codepoints (hyphen-minus vs en-dash vs em-dash) and would cause silent lookup failures on restore.
5. Be paired with a bidirectional mapping (`english_to_native` and `native_to_english`) that is bijective across all 2048 entries. This is the property that makes display-mnemonic to canonical-English-mnemonic resolution unambiguous in either direction.
6. Be stored in Unicode Normalization Form C (NFC). NFKD normalization is applied only to the canonical English mnemonic and the salt before PBKDF2, as BIP-39 already requires. The display wordlist itself never reaches PBKDF2.

A display wordlist SHOULD:

1. Maximize 4-character prefix uniqueness within the constraints of the target script. Realized uniqueness varies widely across scripts; wallets relying on prefix-based autocomplete fall back to full-word matching whenever prefix uniqueness is below 2048/2048.
2. Be reviewed by a fluent native speaker of the target language before publication. Native-speaker review catches register, idiom, and cultural-neutrality issues that mechanical validation cannot.
3. Carry a stable identifier triple of (language code, version string, SHA-256 of the wordlist file) so that a display backup can be matched on restore to the exact wordlist that produced it. The reference registry publishes this triple in each mapping JSON under the keys `language`, `version`, and `sha256`, with a `normalization_form` field set to `"NFC"` for TZUR Original wordlists. Wallets that bundle wordlists SHOULD persist this triple alongside wallet metadata. In registries that use a single pinned version tag (the reference registry's model, documented at `docs/GOVERNANCE.md`), the version string anchors the shipped corpus and is stable; integrators pin the SHA-256 of the wordlist file as the load-bearing change-detection identifier alongside it.

Note on ordering: a display wordlist is stored in index-parallel order with the canonical English wordlist, not sorted by native-language collation. The two orderings coincide only when the English wordlist happens to match the target script's collation, which is never the case in practice. Lookup efficiency is provided by a hashmap over the 2048-entry native-to-English mapping; sorting by native collation is not a requirement of this convention.

### Input parsing

A wallet that accepts a display mnemonic on restore tokenizes it on whitespace before lookup:

1. Tokenize on Unicode whitespace (characters with the Unicode `White_Space` property) plus the ideographic space (`U+3000`) used by the official Japanese BIP-39 mnemonic.
2. Normalize every token and the display wordlist to the same Unicode form (NFC) before comparison. Mismatched normalization between input and wordlist causes silent lookup failures on precomposed/decomposed accent pairs.
3. Preserve Zero-Width Non-Joiner characters (`U+200C`) during tokenization of languages that use them (Persian/Farsi contains ZWNJ in a significant fraction of its entries). ZWNJ handling MUST match wordlist authorship: wallets whose stored wordlist preserves ZWNJ MUST preserve ZWNJ during input-to-wordlist lookup; wallets whose stored wordlist strips ZWNJ MUST strip ZWNJ during lookup. Mixing the two across storage and lookup causes silent restore failures.
4. Look up each token in the display wordlist's `native_to_english` mapping.
5. If any token is not present in the mapping, the input is invalid; the wallet does not silently substitute, partial-match, or fall through to a different wordlist.
6. After resolution, the resulting English token sequence is validated and used per BIP-39.

### Backup and portability policy

Display mnemonics introduce a portability concern that does not exist in single-language BIP-39: a backup recorded only in the display language depends on the receiving wallet supporting the same display wordlist on restore. The canonical English mnemonic remains universally portable across every BIP-39 implementation. This section defines the wallet-level obligations that follow.

A wallet that exposes a display mnemonic to the user MUST:

1. Make the canonical English mnemonic available to the user as part of any backup or recovery flow that exposes a display mnemonic. "Available" means the user can view, copy, or export the canonical English mnemonic within the same flow, without leaving it.

A wallet that exposes a display mnemonic to the user SHOULD:

1. Surface a portability notice at backup time stating that only the canonical English mnemonic is guaranteed restorable in any BIP-39 wallet, and that a display-only backup depends on the receiving wallet supporting the same display wordlist.
2. Require explicit user confirmation that the canonical English mnemonic was recorded before finalizing wallet setup.
3. Persist the display wordlist's stable identifier triple (language code, version string, SHA-256 of the wordlist file) alongside wallet metadata, so that a wordlist-version mismatch on restore can be detected and either resolved by loading the matching version or recovered via canonical English input.

Wallet-level MUST and SHOULD clauses in this section are not mechanically enforceable from a wordlist artifact alone; they are exercised in the wallet implementation's test suite.

### Validation

Every wordlist MUST clause above is mechanically enforceable. A reference validator at `validation/validate_all.py` in the reference registry checks each: exactly 2048 entries per file, UTF-8 encoding without BOM, absence of duplicates, absence of leading or trailing whitespace, absence of embedded whitespace under the full Unicode `White_Space` property, absence of hyphen or dash codepoints inside any entry, NFC form for TZUR Original wordlists and for the native-side fields of mappings, test vectors, and compound-entry datasets, and round-trip consistency of the bidirectional mapping against the canonical English wordlist. SHOULD-clause metrics (4-character prefix uniqueness, native-speaker review status, wordlist identifier triple) are not enforced as errors by the validator and are tracked separately in the registry's construction notes and the per-mapping JSON metadata.

### Multi-word native concepts

Some languages express a single BIP-39 concept only as a multi-word native term: Hebrew `רופא שיניים` (dentist), Turkish `hindistan cevizi` (coconut), Indonesian `kebun binatang` (zoo), Vietnamese multi-syllable words that use native word-spacing. Requirement 4 forbids embedded whitespace, so a conformant wordlist stores such entries as a single glued orthographic token (e.g., `רופאשיניים`, `hindistancevizi`, `kebunbinatang`). This is a structural consequence of the tokenization rule, not an independent requirement.

Implementations SHOULD expose a per-language dataset of glued-compound indices to the user at backup and restore time, so users writing the seed on paper do not insert a separator that would fail the tokenization round trip. The reference registry publishes such a dataset at `validation/compound-entries.json` with per-language counts and index lists; implementations may consume it or generate their own.

## Backwards Compatibility

Seeds produced under this convention are bit-identical to seeds produced by any BIP-39 implementation given the same entropy, because the canonical English mnemonic is the only PBKDF2 input in both cases. A user whose wallet supports a display wordlist can recover the seed in any BIP-39 wallet by entering the canonical English mnemonic.

## Reference Implementation

- **Wordlist registry.** <https://github.com/osem23/bip39-wordlists-tzur>, `main` branch. Ships 30 index-paired display wordlists with bidirectional mappings at `wordlists/tzur-original/`, the 10 canonical BIP-39 wordlists preserved at `wordlists/reference-canonical/` for spec comparison, and a reference validator at `validation/validate_all.py`. Tag `v1.0` pins a stable snapshot for citation continuity.
- **Construction notes.** `docs/CONSTRUCTION.md` documents structural rules, disambiguation rules, multi-word-concept handling, per-language notes, and the three-layer validation methodology (structural, back-translation via Google Translate with LLM verdict, forward-translation via Microsoft Azure Translator with LLM verdict).
- **v2 multi-signal validation.** `docs/V2_VALIDATION.md` documents the post-v1 verification layer added in 2026-04: blind LLM top-8 generation, multilingual sentence-embedding similarity, and Wiktionary cross-reference, with reviewer process and per-language results.
- **Canonical comparison.** `docs/canonical-vs-tzur.md` reports the word-set overlap between the 9 canonical non-English BIP-39 wordlists and their TZUR Original counterparts. The two are independent sources: Korean canonical and TZUR Original share zero tokens; Japanese shares 11; Latin-script languages share 400 to 700.
- **Example decoders.** `examples/python/decode.py`, `examples/javascript/decode.mjs`, and `examples/swift/Decode.swift`. Each resolves a display mnemonic to its canonical English form, applies NFKD, and derives the BIP-39 seed via PBKDF2. All three produce byte-identical seeds for the same input.
- **Wallet implementation.** <https://github.com/osem23/tzur-wallet>. The TZUR Wallet suite (iPhone, Windows, and an AI-agent build) ships this convention in production. The seed-derivation path resolves any display mnemonic to the canonical English mnemonic before computing PBKDF2; tests cover the paper-backup tokenization round trip per language.
- **Implementer notes.** `docs/IMPLEMENTER_NOTES.md` is a non-normative companion that captures wallet-side operational guidance (backup-screen copy, restore-time input handling, compound-entry hints, ZWNJ strategies, wordlist governance, test fixtures). Nothing in that document is required for BIP conformance; it captures lessons that recur across implementations.
- **Governance.** `docs/GOVERNANCE.md` defines the repository's versioning model (single pinned `v1.0` tag, SHA-256 as load-bearing identifier), what can change in the repository post-ship, how audit findings on the shipped corpus are handled, the communication channel for repository updates, the process for non-wordlist changes, and the path for adding a new language under a future versioned tag.
- **Coverage methodology.** `docs/COVERAGE_METHODOLOGY.md` shows the per-language calculation behind the README's "roughly a third / two thirds" coverage framing, including definitional choices (L1 vs L1+L2, world-population denominator) and a sensitivity range.

## Test Vectors

The reference registry ships per-language conformance vectors under `test-vectors/`. Each file contains 14 vectors covering the five canonical BIP-39 entropy lengths, distributed 5 / 1 / 2 / 1 / 5 across 128, 160, 192, 224, and 256 bits respectively. Coverage is weighted toward the 12-word and 24-word mnemonics, which are the common deployment sizes; the three middle lengths carry at least one vector each. Every vector pairs a display-language mnemonic with the derived seed. Under this convention the display-language seed for a given entropy equals the English seed for the same entropy, by construction; this is the property that defines the convention. An implementation that reproduces every vector in a target language's file has a conformant encoding and PBKDF2 pipeline for that language.

The canonical English vector for 128-bit zero entropy with an empty passphrase is:

```
entropy  = 0x00000000000000000000000000000000
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
seed     = 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
```

The same entropy and passphrase rendered through the Hebrew display wordlist produces a byte-identical seed:

```
entropy  = 0x00000000000000000000000000000000
mnemonic = "נטוש נטוש נטוש נטוש נטוש נטוש נטוש נטוש נטוש נטוש נטוש אודות"
seed     = 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
```

This is the property that defines the convention: the seed is a function of the canonical English mnemonic and the passphrase, never of the display rendering. Per-language test-vector files at `test-vectors/<language>.json` exercise this property across all 30 languages and all five canonical BIP-39 entropy lengths.

## Conformance Profile

Every wordlist-level MUST clause in this specification maps to an executable check in the reference validator at `validation/validate_all.py`. The mapping below lets implementers confirm that a candidate wordlist artifact satisfies the spec by running the validator and observing zero errors.

| Spec clause | Test ID | Validator function | Check |
|---|---|---|---|
| §Display wordlist requirements MUST 1 | TEST-W-01 | `validate_wordlist` | Word count is exactly 2048, file is UTF-8 without BOM, lines split on `\n` |
| §Display wordlist requirements MUST 2 | TEST-W-02 | `validate_wordlist` | No duplicate entries within a wordlist |
| §Display wordlist requirements MUST 3 | TEST-W-03 | `validate_wordlist` | No leading or trailing whitespace on any entry |
| §Display wordlist requirements MUST 4 | TEST-W-04 | `validate_wordlist` | No embedded whitespace under the full Unicode `White_Space` property and no embedded hyphen-minus, en-dash, em-dash, non-breaking hyphen, or soft hyphen |
| §Display wordlist requirements MUST 5 | TEST-M-01 | `validate_mapping` | `english_to_native` and `native_to_english` are bijective across 2048 entries |
| §Display wordlist requirements MUST 6 (NFC at rest, wordlists) | TEST-W-05 | `validate_wordlist` | Each entry equals its NFC normalization (TZUR Original wordlists only; reference-canonical lists are excluded because the BIP-39 spec ships them in NFKD-equivalent form for some languages) |
| §Display wordlist requirements MUST 6 (NFC at rest, mappings) | TEST-M-02 | `validate_mapping` | Each native-side string in `english_to_native` values and `native_to_english` keys equals its NFC normalization |
| §Display wordlist requirements MUST 6 (NFC at rest, test vectors) | TEST-T-01 | `validate_test_vector` | Every `mnemonic` field in every test-vector entry equals its NFC normalization |
| §Display wordlist requirements MUST 6 (NFC at rest, compound entries) | TEST-C-01 | `validate_compound_entries` | Every native-script string in `validation/compound-entries.json` equals its NFC normalization |
| §Input parsing MUST 1-6 | TEST-X-01 | reference decoders | `examples/python/decode.py`, `examples/javascript/decode.mjs`, and `examples/swift/Decode.swift` reproduce every vector in `test-vectors/*.json` byte-for-byte |
| §Backup and portability policy MUST 1 | not validator-checkable | wallet test suite | The wallet's backup and recovery flow exposes the canonical English mnemonic to the user when a display mnemonic is shown |

A wordlist artifact that passes every `TEST-W-*`, `TEST-M-*`, `TEST-T-*`, and `TEST-C-*` check is structurally conformant. Conformance against `TEST-X-01` confirms encoding and PBKDF2 parity for that artifact in a reference language. Backup-policy MUSTs are wallet-level behavior and are out of scope for the wordlist validator; conformant wallets exercise them in their own test suites.

## Rationale

A display-only convention separates two concerns that are otherwise entangled. Cryptographic correctness stays with the canonical English BIP-39 wordlist, which has been deployed across the Bitcoin wallet ecosystem since 2013. Display and input vary per language without modifying anything that PBKDF2 sees. This keeps cross-wallet recoverability intact: every seed is restorable in any BIP-39 wallet via its English form, regardless of which display languages a given wallet supports.

The specific MUST clauses each address a concrete failure mode. Embedded whitespace inside an entry breaks the paper-backup round trip because mnemonic tokenization is whitespace-based; a multi-word entry fragments into two tokens that the wallet cannot resolve, and the seed becomes unrecoverable from text backup. The bijective mapping requirement ensures that translation in either direction is unambiguous. The NFC storage requirement prevents precomposed/decomposed accent mismatches from causing silent lookup failures on restore.

The 4-character prefix uniqueness recommendation from the original BIP-39 specification is achievable for English and most Latin-script languages but structurally infeasible for several scripts where word stems and limited short-prefix variety dominate. Requiring it would exclude those languages or force authorship of artificial vocabulary. Treating it as a SHOULD with informational reporting per language preserves the autocomplete benefit where feasible without excluding scripts where it is not.

Native-speaker review is recommended (SHOULD) rather than required (MUST) because its absence is a UX risk, not a cryptographic risk. The worst case is a poorly-chosen native word that a future PR can correct; no funds are at stake.

The 9 non-English canonical BIP-39 wordlists are alphabetized independent word selections, not translations of the English list, so they cannot serve as a display layer over an English mnemonic without the user facing semantically unrelated tokens at each index. This convention does not replace those wordlists; it sits parallel to them and fills the role they do not fill.

This convention does not eliminate the cross-wallet restore problem for display-only backups; it bounds the problem and defines wallet-level obligations (§Backup and portability policy) that mitigate it. The user-facing safety net is the canonical English mnemonic, which every conformant wallet exposes in any flow that shows a display mnemonic. A backup that includes the canonical English mnemonic is restorable in any BIP-39 wallet without depending on the receiving wallet's wordlist support.

A related concern is *display wordlist discovery* on cross-wallet restore: when a user has a display mnemonic, no metadata, and switches to a new wallet, how does that wallet know which wordlist to load? This convention does not address discovery directly. Discovery is a wallet-UX decision (offer a language picker on restore, autodetect from the script block of the input tokens, fall back to canonical English input) that varies legitimately across implementations. The convention's contribution to making discovery unnecessary in the common case is §Backup and portability policy SHOULD 3, which recommends persisting the wordlist identifier triple (language, version, SHA-256) alongside wallet metadata so that the receiving wallet can identify and verify the correct wordlist when restoring its own backup. Wallets that accept arbitrary external display backups without metadata accept the discovery problem as part of their UX surface.

## Security Considerations

- **PBKDF2 input is invariant under this convention.** Only the canonical English mnemonic reaches PBKDF2-HMAC-SHA512. An implementation that feeds the display mnemonic directly to PBKDF2 is non-conformant and produces incompatible seeds. The conformance test vectors in the reference registry exercise the resolve-to-English path for every supported language.
- **Strict single-wordlist tokenization.** On restore, every token in the display mnemonic MUST resolve within a single display wordlist. Wallets MUST NOT silently accept mnemonics whose tokens span multiple wordlists, partial-match across wordlists, or fall through to the canonical English wordlist when a display token is unrecognized. Mixed-wordlist input is malformed and is rejected.
- **Only the canonical English mnemonic guarantees cross-wallet recovery.** A user whose wallet supports a display wordlist can always recover the seed in any BIP-39 wallet by entering the canonical English mnemonic. A user who backs up only the display mnemonic and then needs to restore in a wallet that does not support the same display wordlist cannot recover without the mapping. The normative wallet-level obligations that follow from this property are defined in §Backup and portability policy above.
- **Paper-backup corruption.** A single transcription error in the display mnemonic fails the BIP-39 checksum just as it would in English. The display layer does not introduce new recovery paths and does not relax the checksum requirement.
- **Wordlist integrity.** If an attacker substitutes the display wordlist stored on disk with a different list, the user's displayed mnemonic on restore will differ from what was backed up. Wallets SHOULD treat bundled wordlists as integrity-critical assets and verify them against a signed manifest at load time.
- **Wordlist supply-chain attacks (homograph substitution).** Distributing display wordlists for many languages introduces an attack surface that does not exist when a wallet relies only on canonical English. A malicious wordlist could substitute a homograph at a specific index: a Cyrillic `а` (U+0430) replacing a Latin `a` (U+0061), an Arabic `ا` (U+0627) replacing a Persian `ا` from a different code-point, or a CJK compatibility variant replacing the canonical glyph. The substituted entry passes structural validation (still 2048 entries, still bijective in the mapping, still unique under exact-match comparison) but produces a backup that the user cannot transcribe correctly across keyboards or scripts without detection. Wallets SHOULD verify wordlist integrity at load time against the SHA-256 published in the corresponding mapping JSON's `sha256` field, and SHOULD treat any character outside the wordlist's expected script block as a build-time error. The mapping schema's `sha256` and `normalization_form` fields are intended to make this verification a one-line check at integration.
- **Native-speaker review is a UX risk, not a cryptographic risk.** Display wordlists without native-speaker review may contain culturally awkward, offensive, or regionally-inappropriate tokens. This affects user trust and backup legibility, not cryptographic correctness. Wordlist maintainers SHOULD publish native-speaker review status and accept corrections via pull request.

## Acknowledgments

This document builds on BIP-39 by Marek Palatinus, Pavol Rusnak, Aaron Voisine, and Sean Bowe.

## Copyright

This document is licensed under the BSD 2-clause license.
