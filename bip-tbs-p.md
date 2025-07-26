```
  BIP: XXX
  Layer: Applications
  Title: Taproot Script Token Recognition Standard
  Authors: Gobi Shanthan <gobi@torram.xyz>
          Lee Raj <lee@torram.xyz>
  Status: Draft
  Type: Informational
  Created: 2025-01-17
  License: BSD-2-Clause
```

## Abstract

This BIP defines a wallet interoperability standard for recognizing token-like patterns in Taproot script paths. The Token Standard on Bitcoin (TSB-P) enables consistent wallet recognition of embedded token metadata in standard Bitcoin transactions through structured Taproot leaf scripts. The standard requires no protocol modifications and serves purely as a wallet implementation guideline for interpreting specific script patterns.

## Motivation

Bitcoin wallets currently lack standardized methods for recognizing token-related transaction patterns, leading to inconsistent user experiences and implementation fragmentation. This proposal addresses wallet interoperability by defining a structured Taproot script format that wallets can optionally recognize and display to users.

This standard follows the precedent set by existing wallet-focused BIPs:
- BIP39: Standardized seed phrase interpretation
- BIP21: Payment URI format for wallet compatibility  
- BIP329: Wallet label standards

The goal is improved wallet interoperability for token recognition, not protocol enhancement or consensus modification.

## Specification

### Recognition Pattern

Wallets implementing this standard should recognize the following Taproot leaf script pattern:

```
OP_TRUE            # 0x51
OP_IF              # 0x63
  <0x03> "TSB"     # 3-byte marker
  <length> <tokenID>      # Variable length (max 16 bytes)
  <0x08> <amount>         # 8-byte amount
  <0x01> <typeCode>       # 1-byte type
  OP_DROP OP_DROP OP_DROP OP_DROP  # Clean up stack
  <length> <metadata>     # Variable metadata
  <0x08> <timestamp>      # 8-byte timestamp
  OP_DROP OP_DROP         # Clean up stack
  OP_TRUE                 # Spending condition
OP_ENDIF           # 0x68
```

### Field Definitions

| Field | Format | Description |
|-------|--------|-------------|
| Marker | 3 bytes ASCII | "TSB" pattern identifier |
| TokenID | Variable, max 16 bytes | Canonical format "NAME:TXID8" |
| Amount | 8 bytes big-endian | Token quantity |
| TypeCode | 1 byte | Token behavior (0-99) |
| Metadata | Variable UTF-8 | Token description |
| Timestamp | 8 bytes big-endian | Unix creation timestamp |

### Token Identity and Authenticity

**Format:** "NAME:TXID8" where NAME is the token name and TXID8 is the first 8 hex characters of the reveal transaction ID.

**Unique Token Identity:**
Each TSB-P token is uniquely identified by the combination of:
- **tokenID**: A human-readable identifier embedded in the Taproot leaf script
- **txid**: The transaction ID in which the token script was first revealed on-chain

This tuple (tokenID, txid) forms the canonical identity of a TSB-P token.

**Supply Enforcement Through Origin Validation:**
Wallets and indexers MUST enforce the following validation rules:
- The first on-chain appearance of a given tokenID is associated with the TXID of that transaction
- Any subsequent transaction using the same tokenID but with a different TXID MUST be treated as a duplicate/forged token
- A TSB-P token is considered authentic only if the tokenID and txid match the original creation event

**Anti-Counterfeiting Security:**
- **Global uniqueness**: Based on Bitcoin's TXID uniqueness guarantees
- **Forgery resistance**: Copying token data to different transaction results in different TXID
- **Deterministic validation**: Token origin is cryptographically verifiable using Bitcoin's transaction model
- **No central registry required**: Validation happens through blockchain history

**Size and Collision Analysis:**
- **16-byte maximum limit** balances functionality with size efficiency
- **8 hex characters** = 32 bits of entropy = 4.3 billion unique possibilities
- **Collision probability:** Negligible until ~65,000 tokens share same base name
- **Real examples:** "TORRAM:f55bb6b5" (15 bytes), "SPX:a1b2c3d4" (11 bytes)

### Type Codes

| Code | Name | Description | Examples |
|------|------|-------------|----------|
| 0 | Fungible Token | Standard fungible asset | USDC |
| 1 | Non-Fungible Token | Unique asset | Digital collectibles |
| 2 | Proof-of-Existence | Timestamped document proof | Document verification |
| 3 | Smart Contract Trigger | Programmable conditions | Conditional payments |
| 4 | Oracle-Verified Token | External verification required | TNX (Treasury Yield) |
| 5 | Compliance-Bound Token | KYC/AML enforcement | Regulated securities |
| 6 | Vesting Token | Time-based restrictions | Employee stock options |
| 7 | Multi-Sig Restricted | Multiple signatures required | SPLIT-FINAL3 |
| 8 | DAO Governance Token | Governance voting rights | TORRAM |
| 9 | Reserved | Future use | - |
| 10 | Wrapped Asset Token | Real-world asset representation | SPX (S&P 500) |
| 11-99 | Reserved | Future standard types | - |

### Example Implementation

```javascript
function recognizeTokenPattern(witnessScript) {
    const buffer = Buffer.from(witnessScript, 'hex');
    let offset = 0;
    
    // Check for OP_TRUE OP_IF pattern
    if (buffer[offset++] !== 0x51) return null; // OP_TRUE
    if (buffer[offset++] !== 0x63) return null; // OP_IF
    
    // Check TSB marker
    if (buffer[offset++] !== 0x03) return null;
    const marker = buffer.slice(offset, offset + 3).toString();
    if (marker !== 'TSB') return null;
    offset += 3;
    
    // Parse TokenID (variable length)
    const tokenIdLength = buffer[offset++];
    const tokenId = buffer.slice(offset, offset + tokenIdLength).toString();
    offset += tokenIdLength;
    
    // Parse Amount (8 bytes)
    if (buffer[offset++] !== 0x08) return null;
    const amount = buffer.readBigUInt64BE(offset);
    offset += 8;
    
    // Parse TypeCode (1 byte)
    if (buffer[offset++] !== 0x01) return null;
    const typeCode = buffer[offset++];
    
    // Skip 4x OP_DROP
    for (let i = 0; i < 4; i++) {
        if (buffer[offset++] !== 0x75) return null;
    }
    
    // Parse Metadata (variable length)
    const metadataLength = buffer[offset++];
    const metadata = buffer.slice(offset, offset + metadataLength).toString();
    offset += metadataLength;
    
    // Parse Timestamp (8 bytes)
    if (buffer[offset++] !== 0x08) return null;
    const timestamp = buffer.readBigUInt64BE(offset);
    offset += 8;
    
    // Verify 2x OP_DROP and OP_TRUE
    if (buffer[offset++] !== 0x75) return null;
    if (buffer[offset++] !== 0x75) return null;
    if (buffer[offset++] !== 0x51) return null;
    
    return {
        tokenId,
        amount: Number(amount),
        typeCode,
        metadata,
        timestamp: Number(timestamp),
        isValid: true
    };
}
```

## Rationale

### Feature Justification

**TokenID (Variable Length, 16-byte maximum):**
- **Anti-Counterfeiting:** Canonical format prevents namespace collisions through cryptographic uniqueness
- **Size Optimization:** Responsive to developer feedback about space efficiency
- **Practical Compatibility:** Accommodates real company names while maintaining predictable size limits

**Amount (8 bytes):**
- **Financial Scale:** Supports enterprise-level token supplies up to 18 quintillion units
- **Decimal Precision:** Accommodates micro-transactions and precise fractional amounts
- **Future-Proofing:** Prevents artificial limits on token economics

**Timestamp (8 bytes):**
- **Legal Provenance:** Establishes precise creation time for regulatory compliance
- **Chronological Ordering:** Critical for token history and audit trails
- **Authenticity:** Combined with TokenID provides complete provenance (when + who)

**TypeCode (1 byte, 0-99):**
- **Token Behavior:** Enables different token types for wallet-specific features
- **Extensibility:** Room for future innovations while showing restraint
- **Wallet Integration:** Allows type-appropriate user interfaces

**Metadata (Variable Length):**
- **User Experience:** Human-readable descriptions essential for adoption
- **Regulatory Requirements:** Many jurisdictions require clear token descriptions
- **Market Recognition:** Enables token discovery and identification

**OP_TRUE OP_IF Structure:**
- **Execution Model:** Creates executable branch requiring proper stack cleanup
- **Production Proven:** Successfully tested with hundreds of testnet transfers
- **Script Compatibility:** Uses standard Bitcoin Script opcodes

### Size Efficiency Analysis

**Total Impact:** ~45-150 bytes for typical tokens
- **Base pattern:** ~45 bytes for minimal tokens
- **Typical usage:** ~100 bytes including reasonable metadata
- **Competitive:** Similar efficiency to Runes while providing significantly more functionality
- **Justified:** Every byte serves a critical real-world purpose

## Security Considerations

### Two-Layer Validation Model

**Layer 1: Bitcoin Consensus (What Bitcoin Core validates)**
- UTXO ownership and spendability
- Taproot script-path execution validity  
- Transaction signature verification
- Standard Bitcoin transaction rules

**Layer 2: Wallet Recognition (What wallet software adds)**
- TSB pattern detection in witness scripts
- Token metadata parsing and extraction
- Token balance aggregation across UTXOs
- User interface for token information

### Important Limitations

**No Consensus Enforcement of Token Rules:**
- Bitcoin consensus does not validate token transfer restrictions
- Bitcoin consensus does not enforce token-specific business logic  
- Bitcoin consensus treats these as normal Taproot transactions
- Advanced token features depend on wallet implementation quality

### Security Properties

**Guaranteed by Bitcoin Consensus:**
- **Token ownership = UTXO ownership** (secured by Bitcoin's consensus rules)
- **Transaction immutability** (preserved in Bitcoin's blockchain)
- **Script execution integrity** (standard Taproot validation)

**Supply Enforcement (Client-Side):**
- **Token uniqueness**: Enforced through tokenID + TXID binding
- **Origin authentication**: Cryptographically verifiable via transaction history
- **Duplicate prevention**: Wallets reject tokens with mismatched TXID origins
- **No inflation**: Copying token data to new transactions creates different, invalid tokens

**Provided by Wallet Software:**
- **Balance aggregation** (across multiple UTXOs)
- **Type-specific features** (based on typeCode)
- **Metadata interpretation** (human-readable token information)

## Compatibility

**Bitcoin Protocol:** Uses only existing Bitcoin Script opcodes and Taproot functionality. No consensus changes required.

**Existing Wallets:** Non-compatible wallets see normal Bitcoin transactions. Token information remains invisible until wallet software is updated.

**Standards Compliance:** Follows BIP formatting and design principles established by other wallet-focused standards.

## Implementation Guidelines

### Token Detection Process

1. **UTXO Scanning:** Check witness scripts in spent Taproot transactions
2. **Pattern Recognition:** Look for "TSB" marker in script-path spends
3. **Field Parsing:** Extract and validate all token fields
4. **Balance Aggregation:** Sum token amounts across multiple UTXOs
5. **Type-Specific Display:** Present appropriate UI based on typeCode

### Performance Considerations

- Implement caching for recognized tokens
- Use background scanning to avoid UI blocking
- Index by tokenID for efficient lookups
- Consider rate limiting for blockchain scanning

### Error Handling

- Gracefully handle malformed token patterns
- Display unknown typeCodes as "Unknown Token Type"
- Validate field lengths and formats before parsing
- Provide fallback Bitcoin transaction information

## Test Vectors

### Basic Token (Type 0)

**Script Hex:**
```
5163035453420f544f5252414d3a66353562623662350800000002540be400015757575704544573740800000000683c5e0775755168
```

**Parsed Data:**
- TokenID: "TORRAM:f55bb6b5"
- Amount: 10,000,000,000
- TypeCode: 0 (Fungible Token)
- Metadata: "Test"
- Timestamp: 1748344967 (January 27, 2025)

## Reference Implementation

A complete production-ready implementation of the TSB-P token standard is available at:

**Repository:** https://github.com/GobiShanthan/TSB-P/tree/version3

**Implementation Features:**
- Complete CLI tool for token creation, reveal, and transfer operations
- Multi-input funding with automatic UTXO selection
- 3-transaction atomic sequence support for complex transfers
- Wallet-native token scanning and balance aggregation
- Real testnet examples with documented transaction histories

**Getting Started:**
```bash
git clone https://github.com/GobiShanthan/TSB-P.git
cd TSB-P
git checkout version3
go build -o tsb-token-cli taproot_token_cli.go taproot_token.go
./tsb-token-cli scan  # Detect tokens in wallet
```

**Integration Guide:** The repository includes comprehensive wallet integration documentation with production examples and parsing code.

This implementation has been tested with hundreds of successful token transfers on Bitcoin testnet, demonstrating the standard's reliability and practical utility.

## Network Considerations

**Current Status:** Testnet implementation and testing  
**Mainnet Deployment:** Pending completion of community review and testing

**Network Compatibility:**
- Uses only existing Bitcoin Script opcodes and Taproot functionality
- No network-specific modifications required
- Compatible with both testnet and mainnet when deployed

**Pre-Mainnet Requirements:**
- Complete community review of the BIP specification
- Extensive testnet validation with multiple wallet implementations
- Security audit of reference implementation
- Consensus on final specification details

## Acknowledgments

Thanks to the Bitcoin development community for feedback on token standardization approaches, particularly @murchandamus and @jonatack for detailed technical review that shaped this wallet-focused specification. Their concerns about size efficiency, technical precision, and appropriate scope significantly improved this proposal.

## References

- [BIP39] Mnemonic code for generating deterministic keys
- [BIP21] URI Scheme
- [BIP329] Wallet Labels Export Format  
- [BIP341] Taproot: SegWit version 1 spending rules
- [BIP342] Validation of Taproot Scripts

## Copyright

This document is licensed under the BSD 2-clause license.