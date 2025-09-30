```
  BIP: ?
  Layer: Peer Services
  Title: User-Defined Dynamic Relay Policy Scripts
  Author: Aiden McClelland <me+bip@drbonez.dev>
  Status: Draft
  Type: Standards Track
  Created: 2025-09-23
  License: BSD-2-Clause
```

## Abstract

This BIP proposes a standardized mechanism to validate transactions for mempool acceptance using external scripts. Nodes load a directory of JavaScript (ES2020-compatible) scripts that define acceptance rules. Each submitted transaction (or transaction package) is passed through the configured scripts; if all scripts return successfully, the transaction is accepted into the mempool. If any script throws an error, the transaction is rejected. This framework allows flexible policy development without requiring changes to the node implementation.

## Copyright

This BIP is licensed under the BSD 2-clause license.

## Motivation

At present, mempool acceptance policy is enforced solely by Bitcoin node software and configurations provided by the software. This approach creates limitations and friction to the addition and removal of policies. A standardized interface for externally provided policy scripts provides a number of benefits:

- Allows users to eliminate or extend mempool policies without requiring node implementation developers to make code changes.
- Defines a standardized execution environment so scripts can be shared across different implementations.
- Provides a safer, more modular way to test policies.

## Rationale

JavaScript is a very well defined and widely understood scripting language with many available runtimes. It allows scripts to be portable across platform and architecture, and runtimes are well optimized such that significant performance penalties will not be incurred. This was somewhat inspired by a similar project using Lua presented at BTC++ by @jasonfoura.

## Specification

1. **Script Directory**
   - A node MAY specify a directory path containing `.js` files implementing policy functions.
   - Files can be nested arbitrarily in subdirectories.
   - Files beginning with a number (e.g. 0100-min-relay-fee.js) will be interpreted as policy scripts and executed automatically by the node software on transaction validation.
   - Filenames beginning with a `0` will be processed _before_ consensus validation. All other files will be processed _after_.
   - Files will be processed in ascending order according to the prefixed number.
   - Files that do not begin with a number, but end with a `js`, `mjs`, or `json` extension (e.g. helpers.js) will not be executed but can be imported into other files as ESModules.
   - All other files will be ignored.
   - JavaScript files in this directory are loaded at startup and compiled in an embedded JavaScript runtime (e.g., QuickJS / Duktape / V8 wrapper).
2. **Execution Model**
   - For every package of transactions submitted for mempool acceptance:
     - Individual transactions are treated as a package of length 1.
     - The package transactions are provided as an array of well‑defined JS objects with canonical fields, attached to the global object.
     - These fields may be computed dynamically using custom getters and memoized up to the implementation's discretion.
     - If all scripts complete without exception AND consensus validation succeeds, the package is accepted into the mempool and relayed.
     - If any script throws an error, the transaction is rejected with error code `script-policy-validation-failed` and a message referencing the failed script.
3. **Sandboxing**
   - Scripts MUST be executed in a restricted runtime environment (no filesystem or network access).
   - Available globals are limited to the transaction context and a standard library of pure functions.
4. **Error Handling**
   - Syntax errors at startup cause the node to fail script loading but do not prevent ordinary operation.
   - To reduce DoS vulnerabilities, the JavaScript Runtime should have limited memory, and validation should be subject to a timeout. If either of these limits are exceeded, the transaction should be rejected with error code `script-policy-validation-failed`.

### Type Definitions

To encourage consistency across implementations, transaction data available to scripts should conform to a well-defined type. A proposal for this type is specified below as a TypeScript definition file:

```typescript
export type Global = typeof globalThis & {
  package: Transaction[];
  mempool: MempoolMetadata;
};

export type Transaction = {
  version: number;
  nLockTime: number;
  vin: TxIn[];
  vout: TxOut[];
  size: number;
  weight: number;
  fee: bigint;
  blockheight: number | null; // null if in mempool / earlier in package
  conflicts: MempoolTransaction[];
};

export type TxIn = {
  prevout: OutPoint;
  scriptSig: Script;
  nSequence: number;
  scriptWitness: ScriptWitness;
};

export type OutPoint = {
  hash: string; // hex txid
  n: number;
  tx: Transaction; // getter required
  vout: TxOut; // getter required
};

export type Script = {
  hex: string;
  ops: Op[]; // getter recommended
  kind:
    | "nonstandard"
    | "anchor"
    | "pubkey"
    | "pubkeyhash"
    | "scripthash"
    | "multisig"
    | "nulldata"
    | "witness-v0-scripthash"
    | "witness-v0-keyhash"
    | "witness-v1-taproot"
    | "witness-unknown"; // getter recommended
};

export type Op = {
  code: number;
  data: string | null; // hex, null if not pushdata
};

export type ScriptWitness = {
  stack: string[]; // hex
};

export type TxOut = {
  nValue: bigint;
  scriptPubkey: Script;
};

export type MempoolTransaction = Transaction & {
  blockheight: null;
  evict(): void;
};

export type MempoolMetadata = {
  size: bigint;
  minFeerate: MempoolTransaction;
};
```

## Backwards Compatibility

The proposal does not alter consensus rules. Nodes that do not implement the BIP operate without any changes. Transactions rejected locally because of policy scripts may still propagate elsewhere.

All existing mempool/relay policies can be re-implemented as a default set of scripts bundled with the node implementation. Existing configuration values can be converted to a `config.json` imported by files in the directory.

## Security

- **Determinism**: Scripts should execute deterministically and quickly. Resource exhaustion attacks should be mitigated by memory limits and timeouts.
- **Sandboxing**: No network, filesystem, or process access is permitted.
- **Policy Divergence**: Differing script sets may fragment mempools across nodes. This is already the case for other local policy settings.

## Reference Implementation

WIP: https://github.com/dr-bonez/bitcoin/tree/feature/js-mempool-policy
