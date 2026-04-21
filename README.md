# Bitcoin Quantum-Secure Transition (BIP Proposal)

## 🛡️ The Goal
To protect *4 million BTC* stored in dormant legacy addresses (P2PK/P2PKH) from future attacks by Shor's algorithm. This project provides a path for owners to commit to *Post-Quantum Cryptography (PQC)* before a quantum threat becomes reality.

## 🚀 The Solution: Merkle-Based Root Commitments
Instead of relying on vulnerable Elliptic Curve signatures, this proposal uses *Merkle Tree Roots* to anchor multiple One-Time Signatures (OTS). Even a quantum computer cannot reverse a SHA-256 Merkle Path.

### Key Features:
- *Quantum-Resistant:* Built on hash-based structures.
- *Legacy Protection:* Specifically designed for dormant/forgotten wallets.
- *Low Bloat:* Uses Merkle Trees to keep the blockchain footprint small.

## 💻 How to Run the Demo
To see the Quantum-Resistant Root generation in action, run:
python3 quantum_demo.py

## 📄 Proposal Document
The full technical specification can be found in bip-quantum-secure.mediawiki
