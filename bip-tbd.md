BIP: ? <br>
Title: Redefinition of the Bitcoin Unit to the Base Denomination <br>
Author: John Carvalho <bitcoinerrorlog@gmail.com> <br>
Status: Draft <br>
Type: Informational <br>
Created: 2024-12-10 <br>
License: CC0-1.0 <br>

# Abstract

This BIP proposes redefining the commonly recognized "bitcoin" unit so that what was previously known as the smallest indivisible unit becomes the primary reference unit. Under this proposal, one bitcoin is defined as that smallest unit, eliminating the need for decimal places. By making the integral unit the standard measure, this BIP aims to simplify user comprehension, reduce confusion, and align on-chain values directly with their displayed representation.

# Motivation

The current convention defines one bitcoin as 100,000,000 of the smallest indivisible units. This representation requires dealing with eight decimal places, which can be confusing and foster the misconception that bitcoin is inherently decimal-based. In reality, Bitcoin’s ledger represents values as integers of a smallest unit, and the decimal point is merely a human-imposed abstraction.

By redefining the smallest unit as "one bitcoin," this BIP aligns user perception with the protocol’s true nature. It reduces cognitive overhead, ensures users understand Bitcoin as counting discrete units, and ultimately improves educational clarity and user experience.

# Specification

**Redefinition of the Unit:**

- Internally, the smallest indivisible unit remains unchanged.
- Historically, 1 bitcoin = 100,000,000 base units. Under this proposal, "1 bitcoin" equals that smallest unit.
- What was previously referred to as "1 bitcoin" now corresponds to 100 million bitcoins under the new definition.

**Terminology:**

- The informal terms "satoshi" or "sat" are deprecated.
- All references, interfaces, and documentation SHOULD refer to the base integer unit simply as "bitcoin."
- The currency code "BTC" is unaffected by these changes, and continues to mean 100,000,000 base units.

**Display and Formatting:**

- Applications SHOULD allow users to toggle between the legacy BTC format (1 BTC = 100,000,000 base units) and the new integral format (1 bitcoin = 1 base unit).
- Use of the ₿ symbol MAY be used to represent base-unit bitcoins but is OPTIONAL.

Example 1:

  - Old display: `0.00010000 Bitcoin`
  - New display: `₿10,000` or `10,000 bitcoins` or `0.00010000 BTC`

Example 2:

  - Old display: `10.23486 Bitcoin`
  - New display: `₿1,023,486,000` or `1,023,486,000 bitcoins` or `10.23486 BTC`

Example 3:

  - Old display: `0.345 BTC`
  - New display: No changes required or `₿34,500,000` or `34,500,000 bitcoins`

NOTE: Traditional number display abbreviations, like `2.5M` for millions, are also optional.

**Conversion:**

- Ledger and consensus rules remain unchanged.
- `BTC` as a currency code remains unchanged (1 BTC = 100,000,000 base units)
- Implementations adopting this standard MUST multiply previously displayed Bitcoin amounts by 100,000,000 to determine the new integer representation.

# Rationale

**Usability:**
Integer-only displays simplify mental arithmetic and reduce potential confusion or user error.

**Protocol Alignment:**
The Bitcoin protocol inherently counts discrete units. Removing the artificial decimal format aligns user perception with Bitcoin’s actual integral design.

**Educational Clarity:**
Presenting integers ensures newcomers do not mistakenly assume that Bitcoin’s nature is decimal-based. It conveys Bitcoin’s true design from the start.

**Future-Proofing:**
Adopting the smallest unit as the primary measure ensures a consistent standard that can scale smoothly as Bitcoin adoption grows.

**Perception of Supply:**
While the total count of base units is roughly 2.1 quadrillion, this proposal does not alter supply in any way. The change is purely representational. Comparisons can be drawn to other currencies like the Japanese yen or Indonesian rupiah, where high unit counts are standard and not perceived as inflationary.

# Addressing Alternative Approaches

## Refuting the "Bits" Proposal ([BIP 176](https://github.com/bitcoin/bips/blob/master/bip-0176.mediawiki))

An alternative suggestion (BIP 176) proposes using "bits" to represent one-millionth of a bitcoin (100 satoshis). While this reduces the number of decimal places in certain contexts, it fails to fully address the core issues our BIP aims to solve:

1. **Persistent Decimal Mindset:**
   Using "bits" still retains a layered decimal approach, requiring users to think in terms of multiple denominations (BTC and bits). This shifts complexity rather than eliminating it.

2. **Inconsistent User Experience:**
   Users must learn to toggle between BTC for large amounts and bits for small amounts. Instead of providing a unified view of value, it fragments the user experience.

3. **Incomplete Alignment with the Protocol’s Nature:**
   The "bits" proposal does not realign the displayed value with the integral nature of Bitcoin’s ledger. It continues to rely on fractional units, masking the fundamental integer-based accounting that Bitcoin employs.

4. **Not Permanently Future-Proof:**
   Though "bits" may simplify certain price ranges, future circumstances could demand additional denominations or scaling adjustments. Our integral approach resolves this problem entirely by making the smallest unit the standard measure, avoiding future fragmentation.

In essence, while BIP 176 attempts to simplify small amount representations, it only replaces one decimal representation with another. By redefining "bitcoin" as the smallest indivisible unit, this BIP eliminates reliance on decimal fractions and separate denominations entirely, offering a clearer, more intuitive, and ultimately more durable solution.

# Backward Compatibility

No consensus rules are altered, and on-chain data remains unchanged. Differences arise solely in display formats:

- **For Developers:**  
  Update GUIs, APIs, and documentation to present values as integers. Remove references to fractional Bitcoin. `BTC` units remain unchanged.

- **For Users:**  
  The actual value of holdings does not change. Transitional measures, such as dual displays or explanatory tooltips, can ease the adjustment period.

# Security Considerations

A short-term risk of confusion exists as users adapt to the new representation. Users accustomed to decimals may misinterpret initial displays. To mitigate this:

- Offer dual displays and tooltips during the transition.
- Provide clear educational materials and coordinated messaging.
- Use alerts or confirmations in applications if input values appear unexpectedly large or small.
- Highlight the unchanging 21M BTC supply cap and equivalence to avoid misinterpretation as inflationary.

# Reference Implementation

Some wallets, such as Bitkit, have successfully adopted integer-only displays, demonstrating the feasibility of this approach, without incident. Transitional features — like showing both old and new formats side-by-side — can help smooth the transition.

# Test Vectors

- Old: `1.00000000 Bitcoin` → New: ₿100,000,000 (or 100,000,000 bitcoins)
- Old: `0.00010000 Bitcoin` → New: ₿10,000 (or 10,000 bitcoins)
- Old: `0.00500000 Bitcoin` → New: ₿500,000 (or 500,000 bitcoins)
- Old: `0.005 BTC` → New: `0.005 BTC` (or ₿500,000 or 500,000 bitcoins)

All formerly fractional representations now directly correspond to whole-number multiples of the smallest unit.

# Implementation Timeline

**Phase 1 (3-6 months):** Introduce the concept, provide dual displays and educational materials. Begin pilot testing in willing wallet apps.

**Phase 2 (6-12 months):** Prominent services adopt integer-only displays by default. Community coordination and media campaigns ensure consistency.

**Phase 3 (12+ months):** Integer representation becomes standard. Documentation and user guides no longer reference decimal-based formats.

# Conclusion

Redefining the "bitcoin" unit as the smallest indivisible unit and removing decimal-based representations simplifies comprehension and aligns displayed values with the protocol’s integral accounting. While a transition period may be necessary, the long-term benefits include clearer communication, reduced confusion, and a more accurate understanding of Bitcoin’s fundamental design.

# Copyright

This BIP is licensed under CC0-1.0.
