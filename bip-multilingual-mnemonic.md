```
  BIP: ?
  Layer: Applications
  Title: Multilingual mnemonic display and input rules
  Authors: Daniel Osemberg <ceo@blocksight.live>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Discussion: 2026-06-13: https://groups.google.com/g/bitcoindev/c/Rwo7P5pTA0c
              2026-06-23: https://delvingbitcoin.org/t/bip39-native-language-display-wordlists-mapped-to-canonical-english/2637
  Requires: 39
```

## Abstract

This document specifies a convention for rendering and accepting BIP-39 mnemonics in a user's native language via a *display wordlist*: a 2048-entry list in the target language, index-parallel to the canonical English BIP-39 wordlist.

The seed of record remains the canonical English BIP-39 mnemonic. A display wordlist is a UX layer; it adds no new cryptographic surface, and any seed produced under this convention remains restorable in any BIP-39 wallet using its English form.

## Relationship to BIP-39

This document does **not** replace BIP-39, does not deprecate any existing BIP-39 wordlist, and does not change the canonical seed-derivation flow. It defines only a display and backup layer that sits above an unchanged BIP-39 core. The following points hold throughout this specification:

- **English BIP-39 remains canonical.** The English BIP-39 mnemonic is the only mnemonic fed to PBKDF2-HMAC-SHA512, and the only artifact that determines the derived seed and cross-wallet compatibility. This document does not alter BIP-39 entropy, checksum, Unicode normalization, or PBKDF2 rules.
- **Localized wordlists are a display and backup layer only.** A display wordlist is never the password input to PBKDF2. It exists so a user can read and write their backup in their own language.
- **The mapping is by word index.** The display token at index `i` corresponds to the English BIP-39 word at index `i`, and to nothing else. There is no per-language entropy, checksum, or key derivation.
- **The localized mnemonic is always reversible to the canonical English mnemonic.** The bidirectional mapping is bijective across all 2048 entries ([Display wordlist requirements](#display-wordlist-requirements)), so a conformant display mnemonic resolves back to exactly one English BIP-39 mnemonic, deterministically.
- **Wallets must give users access to the canonical English mnemonic.** In any flow that exposes a display mnemonic, a standard wallet MUST let the user view, copy, or export the canonical English BIP-39 mnemonic, so the backup is recoverable in any BIP-39 implementation ([Backup and portability policy](#backup-and-portability-policy)).
- **This document specifies a framework, not a blessed set of wordlists.** It defines what makes a display wordlist conformant (the construction, mapping, and input rules, and the conformance profile in which every wordlist-level MUST maps to an executable check). It ships no wordlists into this repository and blesses no individual list as canonical. The reference registry's lists are a bootstrap corpus, explicitly supersedable by native-speaker review; per-language list creation and curation belong to the respective language communities.

## Motivation

A wallet that wants to show or accept the seed phrase in a language other than the ten currently shipped with BIP-39 (English plus nine non-English canonical wordlists) has two practical options: ship a parallel display wordlist that maps to English position-for-position, or ask the user to write down and later transcribe an English phrase in a language they may not read. The latter is error-prone at the point of backup. A single misspelling on paper, or a single mis-read during restore, fails the BIP-39 checksum and can render the seed unrecoverable. Many multilingual wallets already solve this internally by rendering the mnemonic in the user's native script. This document specifies the format and the integrity rules so that such display wordlists are interoperable across wallets and so that the cryptographic chain remains identical to a single-language BIP-39 implementation.

The 10 canonical BIP-39 wordlists cover roughly a third of humanity by native language. The remaining two thirds, around 5 billion native speakers, have no canonical wordlist in their language. A portable display-layer convention lets any wallet extend coverage without diverging from the BIP-39 cryptographic chain.

Coverage in deployed wallets is uneven in a second way that motivates anchoring on English. English BIP-39 is supported essentially universally across the wallet ecosystem, while support for the nine non-English canonical wordlists is partial and varies by wallet; many wallets implement only English. A convention whose seed of record is the English mnemonic therefore inherits the broadest possible restore surface: a seed created in any display language is recoverable in any BIP-39 wallet through its English form, including wallets that ship no non-English wordlist at all.

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
2. Normalize every token and the display wordlist to the same Unicode form (NFC) before comparison. Mismatched normalization between input and wordlist causes silent lookup failures on precomposed/decomposed accent pairs. NFC, and the NFKD that BIP-39 applies before PBKDF2, are both safe: they never merge two distinct entries in a conformant wordlist (there are zero NFKD collisions across the reference wordlists).
3. If a wallet applies any *lossy* fold to input as a convenience — stripping diacritics, case-folding, or similar — and that fold maps a token to more than one wordlist entry, the wallet MUST reject the token and ask the user to disambiguate. It MUST NOT silently pick one entry. Distinct entries can collapse under accent stripping (for example Vietnamese `được` and `đuốc`, or Swedish `läger` and `lager`), and an arbitrary pick selects the wrong index and derives the wrong seed. Lossy folds are not required by this convention; a wallet that performs none is always conformant. Per-language collision counts are reported by the reference validator and documented in `validation/encoding-notes.md`.
4. Preserve Zero-Width Non-Joiner characters (`U+200C`) during tokenization of languages that use them (Persian/Farsi contains ZWNJ in a significant fraction of its entries). ZWNJ handling MUST match wordlist authorship: wallets whose stored wordlist preserves ZWNJ MUST preserve ZWNJ during input-to-wordlist lookup; wallets whose stored wordlist strips ZWNJ MUST strip ZWNJ during lookup. Mixing the two across storage and lookup causes silent restore failures.
5. Look up each token in the display wordlist's `native_to_english` mapping.
6. If any token is not present in the mapping, the input is invalid; the wallet does not silently substitute, partial-match, or fall through to a different wordlist.
7. After resolution, the resulting English token sequence is validated and used per BIP-39.

### Backup and portability policy

Display mnemonics introduce a portability concern that does not exist in single-language BIP-39: a backup recorded only in the display language depends on the receiving wallet supporting the same display wordlist on restore. The canonical English mnemonic remains universally portable across every BIP-39 implementation. This section defines the wallet-level obligations that follow.

A wallet that exposes a display mnemonic to the user MUST:

1. Make the canonical English mnemonic available to the user as part of any backup or recovery flow that exposes a display mnemonic. "Available" means the user can view, copy, or export the canonical English mnemonic within the same flow, without leaving it. This is an *availability* obligation on the wallet, not a requirement that the user record a second, English copy: a user may legitimately back up in the display language only. For that user there is no English transcription step and therefore no English transcription error, which is the failure mode this convention removes. The English mnemonic is the portability guarantee and the safety net (surfaced and labeled per the SHOULD clauses below), not a mandatory second artifact.

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

The BIP-39 checksum is preserved automatically, because the convention preserves word *indices*. BIP-39 computes its checksum over the entropy and verifies it against the trailing bits encoded by the word indices; the display token at index `i` maps back to the English word at index `i`, so a display mnemonic resolves to the same sequence of indices — and therefore the same English mnemonic and the same checksum — as the phrase it renders. The display layer never recomputes or relaxes the checksum; it inherits it unchanged from the canonical English mnemonic.

## Compatibility and Legacy Mnemonic Distinction

BIP-39 already defines nine non-English canonical wordlists (Japanese, Korean, Spanish, Chinese Simplified, Chinese Traditional, French, Italian, Czech, Portuguese). For those languages, a non-English phrase may be a *legacy BIP-39 mnemonic*: under BIP-39, the non-English words themselves — NFKD-normalized — are the PBKDF2 password, and the seed is derived directly from them. A *locale-mapped* (display) mnemonic under this proposal behaves differently: the non-English tokens are resolved by index to their English BIP-39 counterparts, and PBKDF2 is run on the resolved English mnemonic.

Consequently, for any language that has both a canonical BIP-39 wordlist and a display wordlist, the same sequence of non-English words admits two distinct interpretations that derive **different seeds**:

1. **Legacy BIP-39 interpretation.** The words are a BIP-39 mnemonic in their own language; PBKDF2 runs on those words directly (BIP-39, "Generating the mnemonic" and "From mnemonic to seed").
2. **Locale-mapped interpretation.** The words are a display rendering; they are mapped by index to English, and PBKDF2 runs on the resolved English mnemonic.

These interpretations are not interchangeable, and they cannot in general be told apart by inspecting the words: for the nine overlap languages a phrase can be structurally valid under both. A wallet that assumes the wrong interpretation derives the wrong seed and presents an empty or incorrect wallet; if the user then funds that wallet or relies on it for recovery, the result can be permanent loss of funds. This risk was raised on the bitcoin-dev mailing list (see Discussion): given, for example, a French 12-word phrase, software must not silently decide whether to run PBKDF2 on the French words (legacy BIP-39) or to map the indices to English first (this proposal).

This proposal does not, and cannot, resolve that ambiguity by examining the words alone. It is resolved by explicit mode selection and by labeling — never by silent auto-detection. Software must not automatically assume that a non-English BIP-39 phrase is locale-mapped under this proposal.

### Wallet implementation guidance

A wallet that implements this proposal:

1. **MUST distinguish legacy BIP-39 localized mnemonics from locale-mapped display mnemonics.** The two are different inputs that derive different seeds; a wallet MUST track which interpretation applies to a given phrase rather than inferring it from the words.
2. **MUST NOT silently reinterpret an existing non-English BIP-39 seed phrase.** A phrase entered as a legacy BIP-39 mnemonic (in any of the nine canonical non-English languages) MUST be derived per BIP-39 from those words directly. A wallet MUST NOT map it by index to English and re-derive unless the user has explicitly selected the locale-mapped interpretation.
3. **SHOULD ask, on import/restore, what kind of mnemonic the user is restoring** when the input could be either a legacy BIP-39 non-English mnemonic or a locale-mapped display mnemonic — for example by offering an explicit choice of "BIP-39 mnemonic in &lt;language&gt;" versus "display backup (maps to English)" — rather than auto-detecting.
4. **SHOULD label locale-mapped mnemonics clearly in the UI** at creation, backup, and restore, so that a user (and any future wallet) can tell a display backup apart from a legacy BIP-39 mnemonic. The wordlist identifier triple (language code, version string, SHA-256 of the wordlist file; [Backup and portability policy](#backup-and-portability-policy) SHOULD 3) is the recommended machine-readable label.
5. **MUST keep the canonical English mnemonic exportable or viewable by the user** ([Backup and portability policy](#backup-and-portability-policy) MUST 1). The English mnemonic is the unambiguous, universally portable form and the safety net against any interpretation error.
6. **MUST avoid creating ambiguity that could lead to loss of funds.** Where the type of a phrase cannot be established, a wallet MUST require explicit user input rather than guessing, and MUST surface the distinction between the two interpretations before deriving a seed.

A wallet generating a *new* wallet under this proposal does not face this ambiguity: it generates a canonical English BIP-39 mnemonic and renders it for display. The ambiguity arises only on import of a pre-existing non-English phrase, which is why the obligations above are concentrated at the import/restore boundary.

### Coexistence with the canonical non-English wordlists

This convention is additive and does not deprecate the nine canonical non-English BIP-39 wordlists. They remain required indefinitely, because existing seeds derive their PBKDF2 password directly from the native words; no display convention can retire a wordlist that funds depend on.

For new wallets, a wallet that adopts this convention need not derive seeds through the nine canonical non-English paths: the display layer renders one canonical-English seed in any supported language — including those nine — by index mapping. This does not make the canonical nine redundant. They offer native-language portability across wallets that implement them (a canonical-Japanese seed restores natively in any canonical-Japanese wallet); a display backup is portable only through its English form. That is the trade this convention makes for uniform coverage, and the reason the two models coexist rather than one superseding the other.

A wallet supporting one of the nine overlap languages SHOULD therefore support both paths and keep them explicitly separated: the legacy canonical derivation for importing a pre-existing native seed, and this convention for new wallets, with the interpretation chosen explicitly by the user ([Wallet implementation guidance](#wallet-implementation-guidance)) and never inferred from the words.

For *new* wallets specifically, a wallet that implements this convention SHOULD prefer the display-layer path over generating a fresh backup whose seed of record is one of the nine legacy non-English canonical wordlists, when both are available for the same language. The reason is interoperability, not correctness: a display-layer wallet always exposes the universally portable canonical English mnemonic ([Backup and portability policy](#backup-and-portability-policy) MUST 1), whereas a newly minted legacy non-English seed is only restorable in wallets that implement that specific non-English wordlist, which is a smaller and less predictable set. This is a recommendation about which backup to *create* going forward. It does not deprecate the legacy wordlists, does not invalidate any existing backup, and imposes no obligation to migrate funds: an existing legacy non-English seed remains a valid BIP-39 mnemonic and MUST continue to be importable and derivable exactly as before ([Wallet implementation guidance](#wallet-implementation-guidance) MUST 2).

## Reference Implementation

- **Wordlist registry.** <https://github.com/osem23/bip39-wordlists-tzur>, `main` branch. Ships 30 index-paired display wordlists with bidirectional mappings at `wordlists/tzur-original/`, the 10 canonical BIP-39 wordlists preserved at `wordlists/reference-canonical/` for spec comparison, and a reference validator at `validation/validate_all.py`. Tag `v1.0` pins a stable snapshot for citation continuity.
- **Construction notes.** `docs/CONSTRUCTION.md` documents structural rules, disambiguation rules, multi-word-concept handling, per-language notes, and the three-layer validation methodology (structural, back-translation via Google Translate with LLM verdict, forward-translation via Microsoft Azure Translator with LLM verdict).
- **v2 multi-signal validation.** `docs/V2_VALIDATION.md` documents the post-v1 verification layer added in 2026-04: blind LLM top-8 generation, multilingual sentence-embedding similarity, and Wiktionary cross-reference, with reviewer process and per-language results.
- **Canonical comparison.** `docs/canonical-vs-tzur.md` reports the word-set overlap between the 9 canonical non-English BIP-39 wordlists and their TZUR Original counterparts. The two are independent sources: Korean canonical and TZUR Original share zero tokens; Japanese shares 11; Latin-script languages share 400 to 700.
- **Prefix statistics.** `docs/prefix-statistics.md` reports per-language 2/3/4-character prefix uniqueness and the largest prefix-collision group, generated by `validation/prefix_stats.py`. It quantifies the SHOULD 1 recommendation above: 4-character prefix uniqueness holds for only Korean, so wallets relying on prefix autocomplete fall back to full-word matching for the other languages.
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

### Round-trip and address vectors

To let implementations prove the full pipeline — encoding, resolution back to English, and key derivation — each conformance vector SHOULD additionally carry the round trip and a derived-address check. A vector has these fields:

- `english_canonical` — the canonical English BIP-39 mnemonic.
- `display_mnemonic` — `english_canonical` rendered through the target language's display wordlist (mapped by index).
- `recovered_english` — the English mnemonic recovered from `display_mnemonic` via the wordlist's `native_to_english` mapping. It MUST equal `english_canonical`.
- `passphrase` — the BIP-39 passphrase (may be empty).
- `seed` — the BIP-39 seed (hex) derived from `english_canonical` and `passphrase`.
- `first_bip84_address` — the first native-SegWit (BIP-84) receive address at `m/84'/0'/0'/0/0` derived from `seed`. It is included so that a vector exercises derivation past the seed, and it is identical for `display_mnemonic` and `english_canonical` by construction.

Worked example (128-bit zero entropy, empty passphrase, Hebrew display wordlist):

```
english_canonical   = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
display_mnemonic    = "נטוש נטוש נטוש נטוש נטוש נטוש נטוש נטוש נטוש נטוש נטוש אודות"
recovered_english   = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
passphrase          = ""
seed                = 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
derivation          = m/84'/0'/0'/0/0
first_bip84_address = bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
```

Per-language files at `test-vectors/<language>.json` are to be extended with the `recovered_english` and `first_bip84_address` fields. The template below is a placeholder; values for each language and entropy length are to be generated and verified by the reference tooling before publication, and MUST NOT be hand-authored:

```
english_canonical   = <canonical English BIP-39 mnemonic>
display_mnemonic    = <english_canonical rendered through the target display wordlist>
recovered_english   = <recovered from display_mnemonic; MUST equal english_canonical>
passphrase          = <BIP-39 passphrase, may be empty>
seed                = <BIP-39 seed, hex — to be generated and verified>
first_bip84_address = <first m/84'/0'/0'/0/0 address — to be generated and verified>
```

## Conformance Profile

Every wordlist-level MUST clause in this specification maps to an executable check in the reference validator at `validation/validate_all.py`. The mapping below lets implementers confirm that a candidate wordlist artifact satisfies the spec by running the validator and observing zero errors.

| Spec clause | Test ID | Validator function | Check |
|---|---|---|---|
| [Display wordlist requirements](#display-wordlist-requirements) MUST 1 | TEST-W-01 | `validate_wordlist` | Word count is exactly 2048, file is UTF-8 without BOM, lines split on `\n` |
| [Display wordlist requirements](#display-wordlist-requirements) MUST 2 | TEST-W-02 | `validate_wordlist` | No duplicate entries within a wordlist |
| [Display wordlist requirements](#display-wordlist-requirements) MUST 3 | TEST-W-03 | `validate_wordlist` | No leading or trailing whitespace on any entry |
| [Display wordlist requirements](#display-wordlist-requirements) MUST 4 | TEST-W-04 | `validate_wordlist` | No embedded whitespace under the full Unicode `White_Space` property and no embedded hyphen-minus, en-dash, em-dash, non-breaking hyphen, or soft hyphen |
| [Display wordlist requirements](#display-wordlist-requirements) MUST 5 | TEST-M-01 | `validate_mapping` | `english_to_native` and `native_to_english` are bijective across 2048 entries |
| [Display wordlist requirements](#display-wordlist-requirements) MUST 6 (NFC at rest, wordlists) | TEST-W-05 | `validate_wordlist` | Each entry equals its NFC normalization (TZUR Original wordlists only; reference-canonical lists are excluded because the BIP-39 spec ships them in NFKD-equivalent form for some languages) |
| [Display wordlist requirements](#display-wordlist-requirements) MUST 6 (NFC at rest, mappings) | TEST-M-02 | `validate_mapping` | Each native-side string in `english_to_native` values and `native_to_english` keys equals its NFC normalization |
| [Display wordlist requirements](#display-wordlist-requirements) MUST 6 (NFC at rest, test vectors) | TEST-T-01 | `validate_test_vector` | Every `mnemonic` field in every test-vector entry equals its NFC normalization |
| [Display wordlist requirements](#display-wordlist-requirements) MUST 6 (NFC at rest, compound entries) | TEST-C-01 | `validate_compound_entries` | Every native-script string in `validation/compound-entries.json` equals its NFC normalization |
| [Input parsing](#input-parsing) MUST 1-6 | TEST-X-01 | reference decoders | `examples/python/decode.py`, `examples/javascript/decode.mjs`, and `examples/swift/Decode.swift` reproduce every vector in `test-vectors/*.json` byte-for-byte |
| [Backup and portability policy](#backup-and-portability-policy) MUST 1 | not validator-checkable | wallet test suite | The wallet's backup and recovery flow exposes the canonical English mnemonic to the user when a display mnemonic is shown |

A wordlist artifact that passes every `TEST-W-*`, `TEST-M-*`, `TEST-T-*`, and `TEST-C-*` check is structurally conformant. Conformance against `TEST-X-01` confirms encoding and PBKDF2 parity for that artifact in a reference language. Backup-policy MUSTs are wallet-level behavior and are out of scope for the wordlist validator; conformant wallets exercise them in their own test suites.

## Rationale

A display-only convention separates two concerns that are otherwise entangled. Cryptographic correctness stays with the canonical English BIP-39 wordlist, which has been deployed across the Bitcoin wallet ecosystem since 2013. Display and input vary per language without modifying anything that PBKDF2 sees. This keeps cross-wallet recoverability intact: every seed is restorable in any BIP-39 wallet via its English form, regardless of which display languages a given wallet supports.

The specific MUST clauses each address a concrete failure mode. Embedded whitespace inside an entry breaks the paper-backup round trip because mnemonic tokenization is whitespace-based; a multi-word entry fragments into two tokens that the wallet cannot resolve, and the seed becomes unrecoverable from text backup. The bijective mapping requirement ensures that translation in either direction is unambiguous. The NFC storage requirement prevents precomposed/decomposed accent mismatches from causing silent lookup failures on restore.

The 4-character prefix uniqueness recommendation from the original BIP-39 specification is achievable for English and most Latin-script languages but structurally infeasible for several scripts where word stems and limited short-prefix variety dominate. Requiring it would exclude those languages or force authorship of artificial vocabulary. Treating it as a SHOULD with informational reporting per language preserves the autocomplete benefit where feasible without excluding scripts where it is not.

Native-speaker review is recommended (SHOULD) rather than required (MUST) because its absence is a UX risk, not a cryptographic risk: it cannot change the derived seed, which is a function of the canonical English mnemonic alone. A poorly-chosen native word is corrected by publishing a *new versioned wordlist*, never by mutating a published one. A published list is frozen, and a display backup resolves against the exact version that produced it (pinned by SHA-256, [Display wordlist requirements](#display-wordlist-requirements) SHOULD 3); an existing backup is therefore never invalidated by a later correction, and the canonical English mnemonic remains the universal safety net regardless.

The 9 non-English canonical BIP-39 wordlists are alphabetized independent word selections, not translations of the English list, so they cannot serve as a display layer over an English mnemonic without the user facing semantically unrelated tokens at each index. This convention does not replace those wordlists; it sits parallel to them and fills the role they do not fill.

This convention does not eliminate the cross-wallet restore problem for display-only backups; it bounds the problem and defines wallet-level obligations ([Backup and portability policy](#backup-and-portability-policy)) that mitigate it. The user-facing safety net is the canonical English mnemonic, which every conformant wallet exposes in any flow that shows a display mnemonic. A backup that includes the canonical English mnemonic is restorable in any BIP-39 wallet without depending on the receiving wallet's wordlist support.

A related concern is *display wordlist discovery* on cross-wallet restore: when a user has a display mnemonic, no metadata, and switches to a new wallet, how does that wallet know which wordlist to load? This convention does not address discovery directly. Discovery is a wallet-UX decision (offer a language picker on restore, autodetect from the script block of the input tokens, fall back to canonical English input) that varies legitimately across implementations. The convention's contribution to making discovery unnecessary in the common case is [Backup and portability policy](#backup-and-portability-policy) SHOULD 3, which recommends persisting the wordlist identifier triple (language, version, SHA-256) alongside wallet metadata so that the receiving wallet can identify and verify the correct wordlist when restoring its own backup. Wallets that accept arbitrary external display backups without metadata accept the discovery problem as part of their UX surface.

## Security Considerations

- **PBKDF2 input is invariant under this convention.** Only the canonical English mnemonic reaches PBKDF2-HMAC-SHA512. An implementation that feeds the display mnemonic directly to PBKDF2 is non-conformant and produces incompatible seeds. The conformance test vectors in the reference registry exercise the resolve-to-English path for every supported language.
- **Strict single-wordlist tokenization.** On restore, every token in the display mnemonic MUST resolve within a single display wordlist. Wallets MUST NOT silently accept mnemonics whose tokens span multiple wordlists, partial-match across wordlists, or fall through to the canonical English wordlist when a display token is unrecognized. Mixed-wordlist input is malformed and is rejected.
- **Only the canonical English mnemonic guarantees cross-wallet recovery.** A user whose wallet supports a display wordlist can always recover the seed in any BIP-39 wallet by entering the canonical English mnemonic. A user who backs up only the display mnemonic and then needs to restore in a wallet that does not support the same display wordlist cannot recover without the mapping. The normative wallet-level obligations that follow from this property are defined in [Backup and portability policy](#backup-and-portability-policy) above.
- **Incorrect mnemonic interpretation (legacy vs locale-mapped).** For the nine languages that have both a canonical BIP-39 wordlist and a display wordlist, the same non-English words can be interpreted as a legacy BIP-39 mnemonic (PBKDF2 on those words directly) or as a locale-mapped display mnemonic (mapped by index to English, then PBKDF2). The two derive different seeds. A wallet that auto-detects the interpretation can derive the wrong seed and cause loss of funds. Wallets MUST resolve this by explicit mode selection and labeling, never by inspecting the words ([Compatibility and Legacy Mnemonic Distinction](#compatibility-and-legacy-mnemonic-distinction)).
- **Display-only backups misunderstood as portable.** A user who records only the display mnemonic, without understanding that only the canonical English mnemonic is universally portable, may be unable to restore in a wallet that does not support the same display wordlist. Wallets MUST make the canonical English mnemonic available, and SHOULD warn at backup time, so that a display-only backup is never mistaken for a portable BIP-39 backup.
- **Clear wallet warnings are required.** A wallet that shows display mnemonics MUST present clear warnings that distinguish a locale-mapped display backup from a legacy BIP-39 mnemonic and that identify the canonical English mnemonic as the portable form. Silent behavior at the backup or restore boundary is the principal way this convention could contribute to fund loss, and is what these warnings exist to prevent.
- **Deterministic, testable mapping.** The index mapping MUST be deterministic and reproducible: the same display wordlist and the same English mnemonic MUST always produce the same display mnemonic, and the display mnemonic MUST always resolve back to the same English mnemonic. This round-trip property MUST be covered by test vectors ([Test Vectors](#test-vectors)) so that any implementation can prove its encoding, resolution, and PBKDF2 pipeline against published reference values.
- **Paper-backup corruption.** A single transcription error in the display mnemonic fails the BIP-39 checksum just as it would in English. The display layer does not introduce new recovery paths and does not relax the checksum requirement.
- **Wordlist integrity.** If an attacker substitutes the display wordlist stored on disk with a different list, the user's displayed mnemonic on restore will differ from what was backed up. Wallets SHOULD treat bundled wordlists as integrity-critical assets and verify them against a signed manifest at load time.
- **Wordlist supply-chain attacks (homograph substitution).** Distributing display wordlists for many languages introduces an attack surface that does not exist when a wallet relies only on canonical English. A malicious wordlist could substitute a homograph at a specific index: a Cyrillic `а` (U+0430) replacing a Latin `a` (U+0061), an Arabic `ا` (U+0627) replacing a Persian `ا` from a different code-point, or a CJK compatibility variant replacing the canonical glyph. The substituted entry passes structural validation (still 2048 entries, still bijective in the mapping, still unique under exact-match comparison) but produces a backup that the user cannot transcribe correctly across keyboards or scripts without detection. Wallets SHOULD verify wordlist integrity at load time against the SHA-256 published in the corresponding mapping JSON's `sha256` field, and SHOULD treat any character outside the wordlist's expected script block as a build-time error. The mapping schema's `sha256` and `normalization_form` fields are intended to make this verification a one-line check at integration.
- **Native-speaker review is a UX risk, not a cryptographic risk.** Display wordlists without native-speaker review may contain culturally awkward, offensive, or regionally-inappropriate tokens. This affects user trust and backup legibility, not cryptographic correctness. Wordlist maintainers SHOULD publish native-speaker review status and accept corrections via pull request.

## Acknowledgments

This document builds on BIP-39 by Marek Palatinus, Pavol Rusnak, Aaron Voisine, and Sean Bowe.

## Copyright

This document is licensed under the BSD 2-clause license.
