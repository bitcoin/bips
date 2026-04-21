import hashlib

def hash_pair(left, right):
    return hashlib.sha256(left + right).digest()

def build_merkle_root(leaves):
    if not leaves: return None
    current_level = leaves
    while len(current_level) > 1:
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])
        next_level = []
        for i in range(0, len(current_level), 2):
            next_level.append(hash_pair(current_level[i], current_level[i+1]))
        current_level = next_level
    return current_level[0]

# Generate 4 One-Time Signature (OTS) keys
print("--- Quantum-Resistant Key Generation ---")
ots_keys = [hashlib.sha256(f"key_{i}".encode()).digest() for i in range(4)]
root = build_merkle_root(ots_keys)
print(f"Merkle Root (Your Secure ID): {root.hex()}")
