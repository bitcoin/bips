```
  BIP: ?
  Layer: Applications
  Title: Standardization of On-Chain Identity Publication (Draft)
  Author: Edyth Kylak Johnson <edyth933@protonmail.com>
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-draft
  Status: Draft
  Type: Standards Track
  Created: 2025-11-19
  License: BSD-3-Clause
```

## Abstract
This document proposes a standardized message format for publishing identity attestations on the Bitcoin blockchain using CBOR-encoded payloads with domain-separated prefixes. The proposal defines canonical structures for individual and corporate identities, including nullifier hashing rules, revocation flags, optional signature layers, and consistent domain separation ensuring isolation between identity classes.

## Motivation
Identity anchoring on Bitcoin requires precise encoding, deterministic serialization, and strict compatibility across resolvers. Although several off-chain identity frameworks exist, their on-chain anchoring formats are inconsistent and non-interoperable. This BIP provides:

- A **canonical CBOR message schema** suitable for OP_RETURN or commitment anchoring.
- A **deterministic hashing strategy** using Poseidon for compatibility with ZK systems.
- **Domain-separated prefixes** to prevent replay, misinterpretation, and attestation collisions.
- An optional **Ed25519 signature wrapper** to authenticate updates without requiring full ZK proofs.

By defining a stable schema, Bitcoin can serve as a foundational publication medium for decentralized identifiers (DIDs) without requiring protocol-level changes.

## Specification

### 1. Format Overview
All identity messages MUST begin with a domain prefix followed by a newline ("\n"). The payload MUST be encoded in canonical CBOR (deterministic encoding per RFC 8949).

### 2. Domain Prefixes
Domain separation prevents cross‑type message replay. Current version prefixes:
- Personal identity: `"\x19v0iden:\n"`
- Corporate identity: `"\x19v0corp:\n"`

Future versions MAY introduce new prefixes (e.g., `v1iden`, `v1corp`).

## Personal Identity Attestation Format
Two payload types are defined: minimal and signed.

### Minimal Personal Identity Message
```
concat(
    '\x19v0iden:\n',
    cbor({
        sub: 'did:resolver:addr',
        nullifier_hash: poseidon([1, reg_num_from_issuer]),
        revoked: boolean
    })
)
```

### Signed Personal Identity Message
```
concat(
    '\x19v0iden:\n',
    cbor({
        kty: 'OKP',
        crv: 'Ed25519',
        x: string,
        sign: eddsa_sha256(cbor({ sub, nullifier_hash, revoked })),
        sub: 'did:resolver:addr',
        nullifier_hash: poseidon([1, reg_num_from_issuer]),
        revoked: boolean
    })
)
```

### Field Requirements
| Field | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | DID-formatted identity subject. |
| `nullifier_hash` | Yes | Poseidon([1, reg_num_from_issuer]) using domain=1. |
| `revoked` | Yes | Boolean flag indicating active/revoked status. |
| `kty`, `crv`, `x`, `sign` | Optional | Ed25519 signature metadata. |

Signature rules:
- The signing input MUST be `sha256(cbor({ sub, nullifier_hash, revoked }))`.
- The CBOR used for signing MUST be deterministic.

## Corporate Identity Attestation Format
```
concat(
    '\x19v0corp:\n',
    cbor({
        sub: 'did:resolver:addr',
        nullifier_hash: poseidon([1, reg_num_from_issuer]),
        revoked: boolean
    })
)
```

### Field Requirements
| Field | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | Corporate DID. |
| `nullifier_hash` | Yes | Poseidon([1, reg_num]) using domain=1. |
| `revoked` | Yes | Revocation flag. |

## Rationale
- **CBOR** provides compactness, determinism, and broad ecosystem support.
- **Poseidon** ensures ZK‑friendly hashing for future private identity systems.
- **Domain separation** prevents replay between personal and corporate identities.
- **Optional signature layer** supports authenticated updates without binding protocol-level logic.

## Backwards Compatibility
This BIP introduces a new standard. No backward compatibility constraints exist.

## Security Considerations
- Implementations MUST use deterministic CBOR (RFC 8949 Canonical CBOR).
- Registration numbers from Issuer SHOULD be unique.
- Nullifiers MUST be stable to ensure persistent revocation tracking.
- Prefixes MUST NOT be omitted to prevent domain-mixing replay attacks.

## Reference Implementation (Pseudocode)
```
function encodePersonal(sub, reg, revoked) {
    const payload = { sub, nullifier_hash: poseidon([1, reg]), revoked };
    return concat("\x19v0iden:\n", cbor_encode(payload));
}

function encodeCorporate(sub, reg, authorities, revoked) {
    const payload = { sub, nullifier_hash: poseidon([1, reg]), revoked };
    return concat("\x19v0corp:\n", cbor_encode(payload));
}
```

## Copyright
Licensed under the 3-clause BSD license.
