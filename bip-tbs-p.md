BIP: XXX

Layer: Applications

Title: Wallet Recognition Standard for Taproot Token (TSB-P)

Author: Gobi Shanthan \<gobi@torram.xyz\>, Lee Raj. \<lee@torram.xyz\>

Comments-Summary: A standard for wallet interoperability in token pattern recognition

Status: Draft

Type: Informational

Created: 2025-04-20

License: BSD-2-Clause

Discussions-To: [[bitcoin-dev@lists.linuxfoundation.org](mailto:bitcoin-dev@lists.linuxfoundation.org)]

# Abstract

This document proposes a wallet interoperability standard for recognizing and interpreting token patterns in Taproot transactions, similar to how BIP39 standardized seed phrases without modifying consensus rules. The Token Standard on Bitcoin - Programmable (TSB-P) defines a structured format within Taproot leaf scripts that allows wallets to consistently identify, display, and interpret token information embedded in standard Bitcoin transactions.

By creating a "BIP39 for token recognition," this specification aims to improve user experience, reduce implementation fragmentation, and standardize representation of token-related activities on Bitcoin without requiring consensus changes or modifying Bitcoin's primary purpose as a currency.

# Motivation

## The Need for Wallet Interoperability

Bitcoin wallets currently lack a standardized approach to recognizing and displaying token-related transactions, resulting in several challenges:

1. **Inconsistent User Experience**: The same token-representing UTXO may appear differently across wallets or not be recognized at all
2. **Implementation Fragmentation**: Wallet developers must create custom token detection logic
3. **Excessive Blockchain Usage**: Some token approaches create unnecessary data bloat
4. **User Confusion**: Difficult to distinguish between token types and behaviors

## Relationship to Other Standards

This proposal draws inspiration from several successful Bitcoin standards:

- **BIP39**: Standardized seed phrases for wallets without changing consensus rules
- **BIP21**: Standardized payment request URIs for consistent wallet handling
- **BIP329**: Standardized wallet labels for better interoperability

Each of these standards improved Bitcoin's usability through wallet interoperability without requiring protocol modifications. TSB-P follows this pattern by standardizing how wallets recognize token-related patterns.

## Benefits of Standardization

A standardized wallet recognition pattern for token-representing UTXOs would:

1. **Improve User Experience**: Tokens are displayed consistently across compatible wallets
2. **Simplify Wallet Development**: Standard patterns are easier to implement
3. **Reduce Blockchain Impact**: Efficient representation using Taproot's advantages
4. **Enable Advanced Features**: Support for time-locks, multisig, and other Bitcoin Script features

Importantly, this standard does not seek to modify Bitcoin's consensus rules or create new token validation systems. It simply standardizes how wallets interpret specific Taproot script patterns, similar to how BIP39 standardized seed phrase interpretation.

# Specification

## Wallet Recognition Pattern Structure

This BIP defines a standardized Taproot leaf script pattern that compatible wallets should recognize and interpret:

```
OP_TRUE
OP_IF
  <"TSB">                  # 3-byte marker
  <tokenID>                # 16 bytes identifier
  <amount>                 # 8 bytes (uint64 big-endian)
  <typeCode>               # 1 byte token type
  OP_DROP                  # Drop markers from stack
  OP_DROP
  OP_DROP
  OP_DROP
  <metadata>               # Variable length user data
  <timestamp>              # 8 bytes (uint64 big-endian)
  OP_DROP                  # Drop optional fields
  OP_DROP
  <programmable_logic>     # Spending conditions
OP_ENDIF
```

### Example

Here's a concrete example of a token with specific values:

```
OP_TRUE                                   # Start conditional block
OP_IF
  "TSB"                                   # 3-byte marker
  0x6d79546f6b656e0000000000000000       # tokenID ("myToken" padded)
  0x00000000000f4240                      # amount (1000000 tokens)
  0x02                                    # typeCode (vesting token)
  OP_DROP                                 # Remove fields from stack
  OP_DROP
  OP_DROP
  OP_DROP
  0x54686973206973206120746573742074     # metadata ("This is a test token")
  0x000000006446e1fd                      # timestamp (2025-04-28 12:34:56)
  OP_DROP                                 # Remove optional fields
  OP_DROP
  OP_TRUE                                 # Basic spending condition
OP_ENDIF                                  # End conditional block
```

## Field Definitions

| **Field**     | **Format**          | **Description**                        |
|---------------|---------------------|----------------------------------------|
| "TSB"         | 3-byte ASCII string | Token marker for wallet scanning       |
| tokenID       | 16 bytes            | Unique token identifier (padded)       |
| amount        | 8 bytes (uint64 BE) | Token quantity in smallest units       |
| typeCode      | 1 byte              | Indicates token behavior type          |
| metadata      | Variable bytes      | User-defined data                      |
| timestamp     | 8 bytes (uint64 BE) | UNIX timestamp of token creation       |
| OP_DROP x6    | 6 bytes             | Remove marker fields from stack        |
| logic section | Script              | Bitcoin Script spending conditions     |

## Implementation Considerations

This specification is intended for wallet-level implementation, with these key points:

1. **No Consensus Changes**: This pattern works with existing Bitcoin Script interpreter rules
2. **Wallet Recognition Only**: The pattern serves as a marker for wallet software, not a consensus rule
3. **Standard Spending**: UTXOs with this pattern are spent using normal Bitcoin transaction validation
4. **Discoverability**: The "TSB" marker allows wallets to efficiently scan for relevant scripts
5. **Privacy**: Token data remains hidden until spent via Taproot script-path reveal

## Transport Mechanism

Each TSB-P pattern exists within a standard Bitcoin transaction that transfers actual satoshis to a Taproot address, ensuring:

1. **Economic Validity**: Every UTXO must hold BTC to exist (typically 546 sats minimum)
2. **Standard Propagation**: Transactions propagate normally in the Bitcoin network
3. **Taproot Privacy**: Patterns are revealed only when spending via script path

## Wallet Scanning Process

Compatible wallets should implement this scanning process:

1. Examine spent Taproot UTXOs for script paths in the witness data
2. Detect the "TSB" marker in the script
3. Parse tokenID, amount, typeCode, metadata, and timestamp fields
4. Present appropriate information to users based on the typeCode

## Standard Token Types

The typeCode field indicates how wallets should interpret the token pattern:

| **Code** | **Name**                    | **Description**                         |
|----------|-----------------------------|-----------------------------------------|
| 0x00     | Fungible Token (FT)         | Standard fungible asset                 |
| 0x01     | Non-Fungible Token (NFT)    | Unique asset                           |
| 0x02     | Proof-of-Existence          | Timestamped document or hash proof     |
| 0x03     | Smart Contract Trigger      | Triggers programmable conditions       |
| 0x04     | Oracle-Verified Token       | Requires external validation           |
| 0x05     | Compliance-Bound Token      | Enforces KYC/AML rules                 |
| 0x06     | Vesting Token               | Subject to time-based vesting          |
| 0x07     | Multi-Sig Restricted        | Requires multiple signatures           |
| 0x08     | DAO Governance Token        | Used for voting or governance          |
| 0x09-0xFE | Reserved                    | Reserved for future standard types     |
| 0xFF     | Custom                      | Application-specific logic             |

Wallets should present appropriate UI and functionality based on the typeCode.

# Rationale

## Design Principles

This wallet recognition standard was designed following these principles:

1. **Non-Invasive**: Uses existing Bitcoin functionality without protocol modifications
2. **Wallet Focused**: Improves interoperability without requesting consensus changes
3. **Efficient**: Minimizes additional data required for pattern recognition
4. **Clear Separation**: Distinguishes between consensus enforcement and wallet interpretation

## Design Decisions

### "TSB" Marker Selection

The 3-byte marker "TSB" (0x545342) was chosen because:

- It's short but distinctive enough for unambiguous detection
- It's human-readable for debugging purposes
- It has minimal collision probability with other script patterns

### Fixed Field Sizes

TokenID (16 bytes) and amount (8 bytes) use fixed sizes for:

- Reliable parsing across implementations
- Deterministic script sizes for fee estimation
- Efficient storage in Taproot leaves

### Type Code System

The single-byte typeCode field enables:

- Multiple token behavior patterns within the same standard
- Wallet-appropriate display of different token types
- Future extensibility without modifying the pattern format

### Timestamp Inclusion

The 8-byte timestamp field is a critical component that:

- Prevents token ID collisions by ensuring each issuance has a unique temporal identifier
- Mitigates key reuse attacks where an issuer might attempt to create duplicate tokens
- Creates unique token identities even when the same key and script are used
- Provides chronological metadata useful for token provenance and history

By combining (public key + script + timestamp) in the token's structure, each token issuance becomes cryptographically unique, even if the same issuer attempts to create multiple tokens with identical parameters.

### Taproot Integration

Taproot was chosen as the foundation because:

- It provides script privacy by default until revealed
- It maintains compatibility with standard Bitcoin validation
- It supports complex spending conditions efficiently

### Standard Satoshi Outputs

TSB-P uses standard satoshi outputs because:

- It maintains normal Bitcoin transaction validity rules
- It prevents dust outputs by ensuring economic value
- It avoids the blockchain impact of OP_RETURN-based approaches

## OP_TRUE vs Other Spending Conditions

The reference implementation uses OP_TRUE as the default spending condition for simplicity, but production implementations should use more restrictive conditions. The OP_TRUE is a placeholder that can be replaced with:

- Public key signature checks
- Timelocks
- Hash preimage reveals
- Multi-signature schemes
- Any other valid Bitcoin Script condition

# Compatibility

## Bitcoin Protocol Compatibility

This wallet recognition standard is fully compatible with the existing Bitcoin protocol:

- **Standard Transactions**: Uses standard Pay-to-Taproot (P2TR) outputs
- **No Consensus Changes**: Relies only on existing Bitcoin Script opcodes
- **Normal Validation**: All transactions follow standard Bitcoin validation rules
- **PSBT Compatibility**: Works with Partially Signed Bitcoin Transaction workflows

## Wallet Implementation Compatibility

The TSB-P pattern has varying levels of compatibility with existing software:

- **Non-Compatible Wallets**: Will treat TSB-P patterns as regular Bitcoin transactions
- **TSB-P Aware Wallets**: Can recognize and display token information to users
- **Existing Transactions**: Does not affect interpretation of existing transactions
- **Bitcoin Core**: No modifications to Bitcoin Core are required

When a user with a non-compatible wallet receives a TSB-P token, they will see:
- A normal Bitcoin transaction in their wallet
- Standard transaction history
- No indication of embedded token data

This ensures that users of non-compatible wallets can still receive and send Bitcoin associated with tokens, though they won't see the token-specific information.

## Integration with Existing Standards

TSB-P complements existing Bitcoin standards:

- **BIP341 (Taproot)**: Leverages Taproot's script path capabilities
- **BIP174 (PSBT)**: Compatible with PSBT workflows for transaction signing
- **BIP329 (Wallet Labels)**: Can be used alongside wallet labels for context

# Implementation

## Reference Implementations

Complete reference implementations are available in public GitHub repositories:

### TSB-P Token Creator and Validator

A full implementation of the TSB-P standard with token creation, spending, and validation capabilities is available at:
[github.com/GobiShanthan/TSB-P](https://github.com/GobiShanthan/TSB-P)

This Go-based implementation includes:

- **Token Creation**: Generate Taproot outputs with embedded token data
- **Script Compilation**: Create valid Bitcoin Script following the TSB-P format
- **Transaction Construction**: Build transactions that reveal token data
- **Pattern Extraction**: Parse and validate token data from on-chain transactions

The implementation provides a complete CLI tool for creating, funding, spending, and revealing TSB-P tokens on Bitcoin regtest networks.

### TSB-P Token Explorer

A web-based token explorer for discovering and displaying TSB-P tokens is available at:
[github.com/GobiShanthan/bitcoin-token-scanner](https://github.com/GobiShanthan/bitcoin-token-scanner)

This JavaScript implementation includes:

- **Token Scanner**: Find tokens in blockchain transactions
- **Pattern Parser**: Extract and validate token data from witness scripts
- **Caching Layer**: Efficiently store and retrieve token data
- **Web Interface**: Display token information to users

The explorer can scan Bitcoin regtest networks for TSB-P tokens and present them in a user-friendly interface, demonstrating how wallet providers could implement similar functionality.

## JavaScript Token Parser

The following JavaScript code illustrates a real-world implementation of a TSB-P token parser:

```javascript
class TokenParser {
  static parse(witnessHex) {
    try {
      const buffer = Buffer.from(witnessHex, 'hex');
      let offset = 0;
      
      // 1. Expect OP_TRUE (0x51)
      if (buffer[offset++] !== 0x51) {
        return null;
      }
      
      // 2. Expect OP_IF (0x63)
      if (buffer[offset++] !== 0x63) {
        return null;
      }
      
      // 3. Check marker push (0x03 and "TSB")
      if (buffer[offset++] !== 0x03) {
        return null;
      }
      const marker = buffer.slice(offset, offset + 3).toString();
      if (marker !== 'TSB') {
        return null;
      }
      offset += 3;
      
      // 4. TokenID
      if (buffer[offset++] !== 0x10) { // length 16
        return null;
      }
      const tokenIdRaw = buffer.slice(offset, offset + 16);
      const tokenId = tokenIdRaw.toString().replace(/\0+$/, '');
      offset += 16;
      
      // 5. Amount
      if (buffer[offset++] !== 0x08) {
        return null;
      }
      const amountBuf = buffer.slice(offset, offset + 8);
      const amount = amountBuf.readBigUInt64BE(0);
      offset += 8;
      
      // 6. TypeCode
      const typeCodeBuf = buffer[offset++];
      let typeCode = typeCodeBuf;
      // Convert OP_N values to integers if needed
      if (typeCode >= 0x51 && typeCode <= 0x60) {
        typeCode = typeCode - 0x50;
      }
      
      // 7. Expect 4x OP_DROP (0x75)
      for (let i = 0; i < 4; i++) {
        if (buffer[offset++] !== 0x75) {
          return null;
        }
      }
      
      // 8. Metadata
      const metadataLength = buffer[offset++];
      const metadataRaw = buffer.slice(offset, offset + metadataLength);
      const metadata = metadataRaw.toString();
      offset += metadataLength;
      
      // 9. Timestamp
      if (buffer[offset++] !== 0x08) {
        return null;
      }
      const timestampBuf = buffer.slice(offset, offset + 8);
      const timestamp = timestampBuf.readBigUInt64BE(0);
      offset += 8;
      
      // 10. Expect 2x OP_DROP
      if (buffer[offset++] !== 0x75 || buffer[offset++] !== 0x75) {
        return null;
      }
      
      // 11. Expect OP_TRUE (0x51)
      if (buffer[offset++] !== 0x51) {
        return null;
      }
      
      return {
        tokenId,
        amount: Number(amount),
        typeCode,
        metadata,
        timestamp: Number(timestamp),
        isValid: true
      };
    } catch (err) {
      return null;
    }
  }
}
```

## Wallet Scanning Function

For comprehensive token scanning in a wallet or explorer application, both unspent P2TR outputs and spent transactions need to be checked:

```javascript
function scanForTSBPatterns(walletUTXOs, blockchainTxs) {
  const tsbPatterns = [];
  
  // Part 1: Scan UTXOs for potential TSB-P outputs
  for (const utxo of walletUTXOs) {
    if (utxo.scriptPubKey && utxo.scriptPubKey.type === 'witness_v1_taproot') {
      // Mark potential token UTXOs for the wallet to track
      tsbPatterns.push({
        type: 'potential',
        utxo,
        status: 'unspent'
      });
    }
  }
  
  // Part 2: Scan witness data from spent transactions
  for (const tx of blockchainTxs) {
    for (const input of tx.vin) {
      if (input.txinwitness && input.txinwitness.length >= 2) {
        const witnessScript = input.txinwitness[0];
        
        // Use TokenParser to extract token data
        const tokenData = TokenParser.parse(witnessScript);
        
        if (tokenData) {
          tsbPatterns.push({
            type: 'confirmed',
            txid: tx.txid,
            tokenId: tokenData.tokenId,
            amount: tokenData.amount,
            typeCode: tokenData.typeCode,
            metadata: tokenData.metadata,
            timestamp: tokenData.timestamp,
            status: 'spent'
          });
        }
      }
    }
  }
  
  return tsbPatterns;
}
```

## Web Explorer Implementation

The TSB-P token explorer uses a caching mechanism to efficiently retrieve token data:

```javascript
class Token {
  // Cache management for efficient token lookups
  static async findAll(maxBlocks = config.scan.maxBlocks, forceRefresh = false) {
    const now = Date.now();
    
    // Return cached tokens if available and not expired
    if (!forceRefresh && tokenCache.length > 0 && (now - lastScanTime) < config.cache.ttl) {
      return tokenCache;
    }
    
    // Scan for new tokens
    const tokens = await Token.scanForTokens(maxBlocks);
    
    // Update cache
    tokenCache = tokens;
    lastScanTime = now;
    
    return tokens;
  }

  // Look up token by transaction ID
  static async findByTxid(txid) {
    // Try to find in cache first
    const cachedToken = tokenCache.find(token => token.txid === txid);
    if (cachedToken) {
      return cachedToken;
    }
    
    // If not in cache, check the transaction
    const tx = await BitcoinService.getRawTransaction(txid, true);
    if (!tx) {
      return null;
    }
    
    // Check inputs for witness data
    for (const vin of tx.vin) {
      if (vin.txinwitness && vin.txinwitness.length >= 2) {
        const witnessScript = vin.txinwitness[0];
        const tokenData = TokenParser.parse(witnessScript);
        
        if (tokenData) {
          // Add blockchain metadata
          tokenData.txid = txid;
          tokenData.blockHash = tx.blockhash;
          
          // Get block info for more details
          if (tx.blockhash) {
            const block = await BitcoinService.getBlock(tx.blockhash);
            tokenData.blockHeight = block.height;
            tokenData.blockTime = block.time;
          }
          
          return new Token(tokenData);
        }
      }
    }
    
    return null;
  }
}
```

## Test Vectors

The following test vectors provide an example for implementation validation:

### Standard Token Pattern (Type 0x00)

Script (hex):
```
5163035453421056657374696e670000000000000000000800000002540be40000537575757516457863
6c75736976652076657374696e6720746573740800000000680f006a75755168
```

Breakdown:
```
51          # OP_TRUE
63          # OP_IF
03          # Push 3 bytes
545342      # "TSB"
10          # Push 16 bytes
56657374...  # tokenID ("Vesting" padded with zeros)
08          # Push 8 bytes
0000000...  # amount (10000000000)
01          # Push 1 byte
00          # typeCode (fungible token)
75          # OP_DROP
75          # OP_DROP
75          # OP_DROP
75          # OP_DROP
16          # Push metadata
457863...   # "Exclusive vesting test"
08          # Push 8 bytes
0000000...  # timestamp
75          # OP_DROP
75          # OP_DROP
51          # OP_TRUE (programmable logic)
68          # OP_ENDIF
```

## Implementation Guidelines

When implementing TSB-P pattern recognition, wallet developers should consider:

### Performance Considerations 

1. **Scanning Overhead**: 
   - Optimize by caching results and incremental scanning
   - Consider background scanning to maintain UI responsiveness

2. **Script Size Impact**: 
   - TSB-P patterns add approximately 100-150 bytes to transaction witness data
   - Results in modest fee increases for token transactions

3. **Database Indexing**:
   - Maintain token indexes for quick lookups (tokenID, typeCode)

### Error Handling

1. **Validation**: Verify the "TSB" marker exactly before processing
2. **Field Sizes**: Ensure fields have correct lengths
3. **TypeCode**: Handle unknown typeCodes gracefully
4. **Parsing Errors**: Display fallback information if script parsing fails
5. **User Messaging**: Show "Unknown Token Type" for unrecognized typeCodes

### Visual Representation

Wallets should follow these UI guidelines for TSB-P tokens:

1. **Token List View**: Display tokenID, amount, and type icon
2. **Token Detail View**: Show full token information, metadata, and timestamp
3. **Type-Specific UI**: Customize display based on token type (e.g., vesting progress)
4. **Transaction History**: Distinguish token transactions from regular Bitcoin transactions

# Security Considerations

## Wallet Recognition Model

Users and developers should understand this standard's security model:

- **Wallet-Level Recognition**: TSB-P is a wallet recognition standard, not a consensus rule
- **Transaction Security**: Security of the underlying transaction follows standard Bitcoin rules
- **Scriptable Conditions**: Any spending rules are enforced by Bitcoin consensus
- **Pattern Recognition Only**: The TSB-P pattern itself is not enforced by Bitcoin nodes

## Pattern Security Properties

The TSB-P pattern has these security properties:

- **Unambiguous Detection**: Fixed field sizes and standardized format ensure reliable detection
- **Private by Default**: Tokens are initially indistinguishable from regular P2TR outputs
- **Revealed Only When Spent**: The pattern becomes visible only when spent via script path
- **Resistant to Tampering**: Changes to token data would invalidate the Taproot commitment

## Limitations for User Awareness

End-users should understand these limitations:

- **Wallet Compatibility**: Tokens are visible only in compatible wallets
- **No Supply Enforcement**: Bitcoin consensus does not enforce token supply limits
- **No Double-Spend Protection**: For token balances beyond what Bitcoin natively provides
- **Reorg Risks**: Subject to the same reorganization risks as any Bitcoin transaction

## Comparison to Other Standards

TSB-P's security model is similar to other wallet standards:

| **Standard** | **Security Model Comparison** |
|--------------|-------------------------------|
| BIP39        | Wallet interpretation of seed phrases |
| BIP21        | Wallet parsing of payment URIs |
| BIP329       | Wallet handling of metadata |
| TSB-P        | Wallet recognition of token patterns |

None of these standards modify Bitcoin's consensus rules—they standardize wallet behavior and interpretation.

# Future Extensions

## Additional Type Codes

The typeCode field (1 byte) allows for future token behavior patterns:

- **Dynamic Contracts** (Proposed Type 0x20): More complex programmable conditions
- **Federated Tokens** (Proposed Type 0x21): Multi-party governed tokens
- **Payment Channels** (Proposed Type 0x22): Token-aware Lightning Network integrations
- **Threshold Signatures** (Proposed Type 0x23): Advanced cryptographic access controls

## Optional Registry Integration

While not part of this specification, a token registry could complement TSB-P:

- **Metadata Association**: Human-readable names, symbols, decimal places
- **Issuer Information**: Optional verification of token creators
- **Asset Discovery**: Easier discovery of compatible tokens
- **Indexing Service**: Efficient lookup of token-related transactions

## Interoperability

TSB-P could interoperate with other Bitcoin standards and systems:

- **Lightning Network**: Potential for Lightning Channel integration
- **Ordinals**: Complementary to ordinal-based assets
- **DLCs (Discreet Log Contracts)**: Enhanced conditional logic
- **Statechains**: Movement of tokens across state transition boundaries

# Acknowledgements

This proposal draws inspiration from numerous Bitcoin standards and token approaches. Special thanks to the Bitcoin development community for feedback on earlier token standard proposals, particularly @murchandamus and @jonatack, whose technical review helped shape this wallet-focused approach.

# References

- [BIP341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP342: Tapscript](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [BIP39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP21: URI Scheme](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki)
- [BIP329: Wallet Labels](https://github.com/bitcoin/bips/blob/master/bip-0329.mediawiki)

# Copyright

This document is licensed under the BSD 2-clause license.