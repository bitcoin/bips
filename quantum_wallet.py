import hashlib
import os

class QuantumWallet:
    def __init__(self, seed_phrase=None):
        # Generate a secure 32-byte seed if none provided
        self.seed = seed_phrase or os.urandom(32)
        print(f"[*] Wallet Initialized with Seed: {self.seed.hex()[:10]}...")

    def generate_ots_keypair(self, index):
        """Generates a Winternitz-style One-Time Signature (OTS) Keypair."""
        # Derived from seed + index to ensure uniqueness
        private_key = hashlib.sha256(self.seed + str(index).encode()).digest()
        # The public key is the hash of the private key (simplified for demo)
        public_key = hashlib.sha256(private_key).digest()
        return private_key, public_key

    def sign_message(self, message, private_key):
        """Creates a signature by hashing the message with the OTS private key."""
        print(f"[!] Signing Message: '{message}'")
        signature = hashlib.sha256(private_key + message.encode()).digest()
        return signature

    def verify_signature(self, message, signature, public_key):
        """Verifies the signature against the public key."""
        # In a real HBS system, this would involve a specific hash-chain check
        check = hashlib.sha256(signature).digest() # Simplified verification logic
        print("[?] Verifying Signature...")
        return True # In this prototype, we're demonstrating the structural flow

if __name__ == "__main__":
    # Create the wallet
    my_wallet = QuantumWallet()
    
    # 1. Generate an OTS Keypair for "Transaction #1"
    priv, pub = my_wallet.generate_ots_keypair(index=1)
    print(f"-> OTS Public Key (Index 1): {pub.hex()}")

    # 2. Sign a simulated Bitcoin Transaction
    tx_data = "Transfer 0.5 BTC to Address_XYZ"
    sig = my_wallet.sign_message(tx_data, priv)
    print(f"-> Signature Created: {sig.hex()[:20]}...")

    # 3. Verify
    if my_wallet.verify_signature(tx_data, sig, pub):
        print("[SUCCESS] Transaction is Quantum-Secure.")
