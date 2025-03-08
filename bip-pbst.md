# BIP-XXXX: Programmable Bitcoin Token Standard (PBTS)

```
BIP: XXXX
Layer: Applications
Title: Programmable Bitcoin Token Standard (PBTS)
Author: Gobi Shanthan <gobi@torram.xyz>, Lee Raj. <lee@torram.xyz>
Comments-Summary: No comments yet.
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-XXXX
Status: Draft
Type: Standards Track
Created: 2025-02-11
License: BSD-2-Clause
Discussions-To: bitcoin-dev@lists.linuxfoundation.org
Post-History: 2025-02-11
Requires: 340, 341, 342
```

## Abstract

The **Programmable Bitcoin Token Standard (PBTS)** introduces a method to create, transfer, and validate native Bitcoin-based tokens using **Bitcoin Script** and **Taproot**. PBTS enhances Bitcoin's Layer 1 functionality by enabling **tokenized assets** with programmable conditions without compromising security, decentralization, or predictability. Unlike Ethereum or Solana, PBTS **does not introduce Turing-complete smart contracts** but leverages **structured pre-commitments** and **Taproot optimizations** to enable secure, efficient programmable tokens.

PBTS is a **non-consensus-breaking, backward-compatible** standard that ensures tokens remain verifiable and transferable without requiring modifications to Bitcoin's core protocol.

## Copyright

This BIP is licensed under the BSD 2-clause license.

## Motivation

Bitcoin adheres to the principles of **minimalism and security**, which have made it the most robust and decentralized blockchain. PBTS aligns with this philosophy by introducing **programmability without complexity**, ensuring that Bitcoin's core remains unchanged while extending its utility in a predictable and efficient way.

Bitcoin currently lacks a **native** token standard that enables **flexible** and **fully Layer 1** token issuance with programmable conditions. Existing solutions such as **Ordinals, RGB, and Runes** either rely on **external tracking mechanisms** or **Layer 2 solutions** that introduce centralization risks. PBTS provides a **UTXO-based**, predefined, and non-intrusive method for issuing tokens that remain completely **verifiable on Bitcoin's base layer** with advanced programmable features like time-locked vesting and milestone-based escrow.

## Key Benefits

1. **No Additional Layers**  
   * Execution happens directly in **Bitcoin transactions**  
   * Complete validation on **Layer 1**  
   * No external dependencies for validation

2. **Predefined & Deterministic Execution**  
   * No infinite loops or dynamic state modifications  
   * Predictable execution paths  
   * Fixed state transitions

3. **Minimal Impact**  
   * Utilizes existing **Taproot** and **Script** functionality  
   * No consensus changes required  
   * Standard transaction format

4. **Scalability & Efficiency**  
   * **Merkle proof-based validation**  
   * Minimal transaction sizes through Taproot optimization  
   * Compatible with future Bitcoin scaling solutions

5. **Security Model**  
   * No external validators required  
   * Fully **self-custodial**  
   * Bitcoin-native security

6. **Programmable Conditions**
   * Time-locked transfers (vesting)
   * Milestone-based escrow with multiple release stages
   * Multi-signature requirements
   * Prepared for oracle integration

## Comparison with Existing Bitcoin Token Standards

| Feature                    | Ordinals                 | Runes           | PBTS                         |
|----------------------------|--------------------------|-----------------|------------------------------|
| UTXO-Based                 | ❌ No (Inscriptions)     | ✅ Yes          | ✅ Yes                       |
| Requires External Indexer? | ✅ Yes                   | ✅ Yes          | ❌ No                        |
| Efficient for Tokens?      | ❌ No                    | ✅ Somewhat     | ✅ Fully Optimized           |
| Scalability Impact         | ❌ High Blockchain Bloat | ⚠️ Medium       | ✅ Minimal (Uses Taproot)    |
| Bitcoin Script-Based?      | ❌ No                    | ✅ Yes          | ✅ Yes (Taproot-Optimized)   |
| Consensus Changes Required?| ❌ No                    | ❌ No           | ❌ No                        |
| Transaction Cost           | ❌ Expensive             | ⚠️ Medium       | ✅ Efficient                 |
| Programmable Conditions    | ❌ No                    | ⚠️ Limited      | ✅ Yes                       |
| Fully On-Chain Validation  | ❌ No                    | ❌ No           | ✅ Yes                       |

## Specification

### Overview

PBTS tokens are created, transferred, and validated directly on Bitcoin's Layer 1 using Taproot scripts to enable complex programmable conditions without requiring any modifications to the Bitcoin protocol.

### Token Creation

A **PBTS token** is created by locking a **UTXO** with a **Taproot script** that commits to a token issuance structure. The token metadata is encoded in the transaction output using a standardized format:

1. **Token Issuance Format**:
   * The output script is a Taproot output that contains:
     * Token ID: A 32-byte identifier (Hash of Issuer's Public Key + Script Hash)
     * Total Supply: Fixed integer representing the maximum possible supply
     * Decimals: Integer representing the decimal places (typically 8 to match satoshis)
     * Metadata Commitment: Optional hash of off-chain metadata (name, symbol, description)

2. **Example Issuance Script**:
```
<token_metadata_hash> OP_DROP
<issuer_pubkey> OP_CHECKSIG
```

### Token Contracts

PBTS supports several programmable contract types that define how tokens can be transferred and under what conditions they can be spent:

#### 1. Auto-Vest (Time-Locked) Contracts

Time-locked transfers where tokens become available to the recipient only after a specific date, using Bitcoin's CHECKLOCKTIMEVERIFY opcode.

**Script Pattern**:
```
IF
    <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <receiver_pubkey> OP_CHECKSIG
ELSE
    <issuer_pubkey> OP_CHECKSIG
ENDIF
```

#### 2. Milestone-Based Escrow

Structured transfers with multiple release stages, each requiring specific conditions like time thresholds and multi-signature approvals.

**Script Pattern**:
```
IF
    # Milestone 1
    <milestone1_locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <m1> <pubkey1> <pubkey2> <pubkeyN> <n> OP_CHECKMULTISIG
ELSEIF
    # Milestone 2
    <milestone2_locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <m2> <pubkey1> <pubkey2> <pubkeyN> <n> OP_CHECKMULTISIG
ELSEIF
    # Expiry condition (return to sender)
    <expiry_time> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <sender_pubkey> OP_CHECKSIG
ENDIF
```

#### 3. Oracle-Ready Contracts

Contracts designed to work with external data oracles, containing placeholder structures for future oracle implementation.

**Script Pattern**:
```
IF
    # Oracle verification
    <oracle_pubkey> OP_CHECKSIGVERIFY
    <condition_hash> OP_SHA256 <expected_result_hash> OP_EQUALVERIFY
    <receiver_pubkey> OP_CHECKSIG
ELSEIF
    # Expiry condition (return to sender)
    <expiry_time> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <sender_pubkey> OP_CHECKSIG
ENDIF
```

### Token Transfer

PBTS token transfers involve creating transactions that spend from token-containing UTXOs and create new UTXOs with the appropriate scripts to maintain token properties and conditions.

1. **Standard Transfer**:
   * Spends from a token UTXO
   * Creates new outputs with token metadata preserved
   * May split tokens across multiple outputs (for partial transfers)

2. **Conditional Transfer**:
   * Creates outputs with Taproot scripts encoding the conditional logic
   * Enables time-locked, multi-signature, or other programmable conditions

3. **Transaction Validation**:
   * Follows standard Bitcoin transaction validation rules
   * Leverages Bitcoin's native UTXO model for tracking ownership
   * Enables verification without external indexers or oracles

### Implementation Details

#### Taproot Integration

PBTS leverages Taproot's script path spending to enable complex script execution while maintaining payment efficiency:

1. **Key Path Spending**:
   * Used for standard transfers with no conditions
   * Minimizes transaction size and fees

2. **Script Path Spending**:
   * Used for conditional transfers (time locks, multi-sig, etc.)
   * Reveals only the relevant script path when executing

3. **Commitment Structure**:
   * Main output key commits to all possible spending paths
   * Each condition is a separate script leaf in the Taproot tree

#### On-Chain Token State Tracking

PBTS tokens maintain their state entirely on-chain:

1. **Token Properties**:
   * All token properties are verifiable through transaction outputs
   * Token metadata is committed via hashes in the script structure

2. **Ownership Tracking**:
   * Token ownership is represented by control of the corresponding UTXOs
   * Standard Bitcoin wallet functionality can be used to track and manage tokens

### Security Considerations

PBTS mitigates various attack vectors through:

1. **Double Spending Prevention**:
   * Each token is tied to a specific UTXO
   * Standard Bitcoin consensus rules prevent double-spending

2. **Replay Attack Protection**:
   * Uses unique script conditions for each transfer
   * Includes sequence numbers where appropriate

3. **Fee Optimization**:
   * Taproot implementation minimizes transaction sizes

4. **Predictable Execution**:
   * No dynamic loops or unpredictable execution paths
   * All contract conditions are pre-defined at creation time

5. **Time-Based Security**:
   * Uses CHECKLOCKTIMEVERIFY to enforce time constraints
   * Ensures time-locked funds cannot be spent prematurely


### Prerequisites

* Bitcoin Core v28.1.0+ with RPC enabled
* Go 1.16 or newer
* A Bitcoin testnet or mainnet wallet with funds

### Basic Usage

```bash
# Issue a new token
./pbts issue "Programmable Bitcoin Token" "PBTS" 8 1000000000

# List all tokens
./pbts list

# Create a time-locked vesting contract
./pbts vest <token_id> <sender_pubkey> <receiver_pubkey> <amount> <unlock_date>

# Create a milestone-based escrow
./pbts milestone <token_id> <sender> <receiver> <arbitrator> <amount> <milestone_count> \
  <milestone1_percentage> <milestone1_unlock_date> <milestone1_expiry_date> <milestone1_required_sigs> \
  <milestone2_percentage> <milestone2_unlock_date> <milestone2_expiry_date> <milestone2_required_sigs>
```

## Examples

### Time-Locked Vesting Contract

A successful time-locked vesting contract implemented on Bitcoin testnet:

```bash
./pbts vest 6ad138104a19ad3711a3ae6ec251f0c2 0234f63fb0b8acefb738a83f276ad6e5d18ec71613965c3f639f4158c3b07db1f4 03a7bd1d77432d2267813c908dca7ec7382a41a21a5da9e12d3726e63aae58bde3 10 2025-03-03
```

Generated Output:
```
🔄 Creating auto-vesting transfer of 10.000000 tokens (ID: 6ad138104a19ad3711a3ae6ec251f0c2) to 03a7bd1d77432d2267813c908dca7ec7382a41a21a5da9e12d3726e63aae58bde3 (unlocks at: 2025-03-03T00:00:00Z)...
Adjusting unlock time to ensure it's in the future: 2025-03-03T23:19:02-05:00
Created Taproot address: tb1pkcvzu54pey9sjrj5qeu7xnvppe5k3w34spv7yhtfxxg56uyscsuq4uah44
🏦 Auto-Vest Address: tb1pkcvzu54pey9sjrj5qeu7xnvppe5k3w34spv7yhtfxxg56uyscsuq4uah44 (unlocks at: 2025-03-03T23:19:02-05:00)
✅ Auto-vest transfer transaction broadcasted! TXID: 8c64767e003ed0b5786be07dac35b48eb32e53095af7802d5179808c36e7869d
```

This transaction (TXID: 8c64767e003ed0b5786be07dac35b48eb32e53095af7802d5179808c36e7869d) demonstrates a successful time-locked contract on Bitcoin testnet using Taproot functionality.

## Backward Compatibility

PBTS is fully backward compatible with the existing Bitcoin protocol. It:

1. Uses standard Bitcoin transactions
2. Leverages existing opcode functionality
3. Does not require any consensus changes
4. Can coexist with other token standards

## Test Vectors

[To be added in future update]

## References

- **Bitcoin Improvement Proposals (BIPs):**
  - [BIP-341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
  - [BIP-342: Validation of Taproot Scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
  - [BIP-340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- **Technical Documentation:**
  - [Bitcoin Script Reference](https://en.bitcoin.it/wiki/Script)
  - [UTXO Model Specification](https://developer.bitcoin.org/devguide/transactions.html)
- **Related Research:**
  - [RGB Protocol](https://rgb.tech/)
  - [Ordinals Specification](https://docs.ordinals.com/)
  - [Runes Documentation](https://runes.com/docs/)

