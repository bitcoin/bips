```
  BIP: ?
  Layer: Applications
  Title: Signing message encoding
  Authors: Pyth <pythcoiner@wizardsardine.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Discussion: 2026-04-28: https://delvingbitcoin.org/t/qr-based-signing-flow-payloads-in-miniscript-context/2464
              2026-11-12: https://groups.google.com/g/bitcoindev/c/gmHOr6JRJyU/m/kkWnI_NAAgAJ
  Requires: 32, 174, 321, 327, 340, 341, 352, 370, 373, 374, 375, 380, 388, 390
```

## Introduction

### Abstract

This document defines the byte encoding of the messages exchanged between a
**coordinator** (online software) and a **signer** (signing device), for wallets
described by output script descriptors (BIP-380) or wallet policies (BIP-388),
miniscript and MuSig2 included, and for silent payment wallets (BIP-352).

The encoding is **transport agnostic**: a `MESSAGE` is a self-contained byte string,
and how it is delivered (animated QR, USB, NFC, a file, etc.) is out of scope.

### Copyright

This BIP is licensed under the BSD 2-Clause License.  
Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the above copyright notice and this permission notice appear
in all copies.

### Motivation

No standard defines the messages a coordinator exchanges with an external signer. A
PSBT (BIP-174, BIP-370) carries the transaction, but signing needs more messages
around it: identify the signer and what it supports, export its keys, register a
descriptor or wallet policy (BIP-380, BIP-388), verify an address on its screen, and
return signatures. Without a common encoding for them, a coordinator implements one
format per signer.

This work is based on a former specification targeting QR codes, discussed in
[QR-based signing flow payloads in Miniscript context](https://delvingbitcoin.org/t/qr-based-signing-flow-payloads-in-miniscript-context/2464).
Nothing in its messages is specific to QR codes, so the scope was extended to any
external signer, whatever carries the bytes (USB, NFC, a file, etc.).

This BIP defines one binary encoding for these messages. It covers miniscript
descriptors, BIP-388 wallet policies, MuSig2 (BIP-373) and silent payment sends
(BIP-375), so any coordinator implementing it can drive any signer implementing it.

## Specification

### Integer Encodings

All variable-length integers (the `COUNT` and `LENGTH` fields below) are encoded as
[compact size](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer).
All fixed-width multi-byte integers are big-endian.

### Optional Fields

An OPTIONAL field is encoded as a 1-byte `PRESENCE` (`0x00` absent, `0x01`
present), followed by the field's encoding only when `PRESENCE` is `0x01`. Any
other `PRESENCE` value MUST be rejected.

### Vectors

A vector of some element type is encoded as a `COUNT` (compact size) followed by
`COUNT` elements back to back.

### Common Field Encodings

`BOOL`: 1-byte unsigned integer, `0x00` false or `0x01` true. Any other value MUST
be rejected.

`BYTES`: a `LENGTH` (compact size) followed by `LENGTH` raw bytes.

`STRING`: a `BYTES` (`LENGTH` followed by `LENGTH` raw bytes) whose content MUST be
valid UTF-8 and MUST NOT contain a nul byte.

`DESCRIPTOR_ALIAS`: a `STRING` whose encoded length MUST be at most 32 bytes.

`FINGERPRINT`: 4 bytes, the BIP-32 master key fingerprint.

`EXTENDED_KEY`: 78 bytes, the BIP-32 serialization of an extended public or private
key (4 version + 1 depth + 4 parent fingerprint + 4 child number + 32 chain code +
33 key). A private key carries `0x00` followed by its 32-byte key in place of the
33-byte public key, and its own version bytes, so both have the same length.

`PSBT`: a `BYTES` (`LENGTH` followed by `LENGTH` raw bytes) whose content is the
binary serialization of a version 0 (BIP-174) or version 2 (BIP-370) PSBT. Base64 is
NOT used on the wire.

`DERIVATION_PATH` follows this format:

`CHILD_COUNT` `CHILD` `...` `CHILD`

`CHILD_COUNT`: 1-byte unsigned integer (0–255), the number of children.
`CHILD`: 4-byte big-endian unsigned integer, a child index per BIP-32 (a hardened
step has bit 31 set, `index | 0x80000000`).

`DESCRIPTOR_BODY` follows this format:

`FORM` `BODY`

`FORM`: 1-byte unsigned integer selecting the descriptor form.

```
+-------+-----------------------+
| Value | Definition            |
+-------+-----------------------+
| 0x00  | Reserved              |
| 0x01  | BIP-380 descriptor    |
| 0x02  | BIP-388 wallet policy |
| 0x03  | Silent payment keys   |
+-------+-----------------------+
```

`BODY` depends on `FORM`:
- `0x01`: a `STRING`, the BIP-380 descriptor text.
- `0x02`: `KEYS` `POLICY`, the BIP-388 wallet policy. BIP-388 defines no byte
  encoding, so it is serialized here as its two components:
  - `KEYS`: a vector of `STRING`, the key information, each a BIP-388 `KEY_INFO`
    expression: an extended public key with optional key origin, no trailing
    derivation. Entry `i` is the key that `@i` refers to in `POLICY`, so the
    vector MUST be in `@0`, `@1`, ... order.
  - `POLICY`: a `STRING`, the descriptor template with `@i` key placeholders.

- `0x03`: `FINGERPRINT` `SPEND_PATH` `SCAN_PATH` `SCAN_KEY`, a silent payment
  account's keys:
  - `FINGERPRINT`: the `FINGERPRINT` of the master key.
  - `SPEND_PATH`: a `DERIVATION_PATH`, the path of the BIP-352 spend key from the
    master key.
  - `SCAN_PATH`: OPTIONAL `DERIVATION_PATH`, the path of the BIP-352 scan key from
    the master key, when the scan key is the signer's.
  - `SCAN_KEY`: OPTIONAL, 32 bytes, the BIP-352 scan private key as a big-endian
    scalar, when the scan key is not the signer's. The private key, not the public
    one: the BIP-352 label tweak of a labelled address is computed from it, so
    verifying one requires it. A scan private key carries no signing power, so
    leaking one has the same effect as leaking an xpub: it reveals the wallet's
    payments, nothing more.

  Exactly one of `SCAN_PATH` and `SCAN_KEY` MUST be present: a reader MUST reject
  the form when both or neither are.

`VENDOR`: `STRING`, the device vendor.

`MODEL`: `STRING`, the device model.

`VERSION`: in a response body, 8 bytes of device firmware version, `MAJOR` `MINOR`
`PATCH` `FLAG` (the message's protocol `VERSION` is defined under Encoding). `MAJOR`
and `MINOR` are 2-byte big-endian unsigned integers, `PATCH` is a 3-byte big-endian
unsigned integer, and `FLAG` is a 1-byte pre-release channel.

```
+--------+-------------------+
| `FLAG` | Pre-release       |
+--------+-------------------+
| 0x00   | Stable (final)    |
| 0x01   | Alpha             |
| 0x02   | Beta              |
| 0x03   | Release candidate |
+--------+-------------------+
```

Values `0x04`–`0xFF` are reserved. A reader SHOULD treat an unknown `FLAG` as an
unspecified pre-release rather than reject.

`CAPABILITIES`: 4-byte big-endian bitfield of the capabilities the signer supports.
Bit 0 is the LSB.

```
+------+----------------------------------+
| Bit  | Capability                       |
+------+----------------------------------+
| 0    | Miniscript, SegWit v0            |
| 1    | Miniscript, Taproot (v1)         |
| 2    | Silent Payments (v0)             |
| 3    | MuSig2                           |
| 4    | Reserved for future capabilities |
| 5    | PSBT trimming                    |
| 6–30 | Reserved for future capabilities |
| 31   | Upgrade signal (MSB)             |
+------+----------------------------------+
```

Bit 3 means the signer is a BIP-327 MuSig2 participant for BIP-390 `musig()` keys,
and MAY answer with `SIG_KIND` `0x04` / `0x05` (see Signing).

Bit 5 means the signer can answer a Signing request with a trimmed `PSBT` (see
Signing).

Bits 4 and 6–30 are reserved for future capabilities and MUST be `0` in this
version; a reader MUST ignore an unknown capability bit rather than reject, so a
newer signer can advertise capabilities an older coordinator does not know. Bit 31
(the MSB) MUST be `0` in this version; a `1` signals that the signer exposes
capabilities beyond this bitfield and the coordinator should upgrade to interpret
them.

A signer MUST answer a request needing a capability it does not advertise with
`ERROR` `0x0F` (unsupported operation), e.g. a Taproot miniscript descriptor
without bit 1, a silent payment request without bit 2, or a `musig()` key
without bit 3.

### Encoding

A message is encoded as follows:

`MAGIC` `VERSION` `MSG_TYPE` `REQUEST_ID` `BODY`

#### Magic

`MAGIC`: 6 bytes, the ASCII representation of **BIPXXX** (TBD)
(`0x42 0x49 0x50 0x58 0x58 0x58`). A parser MUST reject any input that does not
begin with `MAGIC` before parsing further. `BIPXXX` is a placeholder: once a BIP
number is assigned, the three `X` bytes are replaced by its ASCII digits (e.g.
**BIP138** -> `0x42 0x49 0x50 0x31 0x33 0x38`).

#### Version

`VERSION`: 1-byte unsigned integer representing the protocol version that produced
the message. This specification defines version `0x01`.

#### Message Type

`MSG_TYPE`: 1 byte, packing the direction, status, and message type.

Bits (bit 7 is the MSB):

```
+--------+-------------+------------------------------------------------------------+
| Bit(s) | Field       | Meaning                                                    |
+--------+-------------+------------------------------------------------------------+
| 7      | `DIRECTION` | `0` request, `1` response                                  |
| 6      | `STATUS`    | response-only: `0` ok, `1` error; MUST be `0` in a request |
| 5–0    | `TYPE`      | message type (table below)                                 |
+--------+-------------+------------------------------------------------------------+
```

`TYPE` values:

```
+-------+----------------------+
| Value | Type                 |
+-------+----------------------+
| 0x00  | Unreadable request   |
| 0x01  | Get Info             |
| 0x02  | Get Keys             |
| 0x03  | Register Descriptor  |
| 0x04  | Address Verification |
| 0x05  | Signing              |
+-------+----------------------+
```

Values `0x06`–`0x3F` are reserved. A parser MUST reject an unknown `TYPE`, and
MUST reject `STATUS` = `1` on a request (`DIRECTION` = `0`).

`TYPE` `0x00` (unreadable request) is valid only in an error response whose
`REQUEST_ID` is `0x0000`: the reply to a request the signer cannot read (see Error
response body). A parser MUST accept it there, and MUST reject it in a request, in
an ok response, and in an error response with another `REQUEST_ID`.

#### Request Id

`REQUEST_ID`: 2 opaque bytes with no `LENGTH` prefix. The requester chooses the
value, and the responder echoes it verbatim in the matching response, including an
error response, so a coordinator can pair a response with the request it sent. It
carries no structure and a receiver MUST NOT interpret it. It MUST be present in
every message.

The reply to a request the signer cannot read carries `REQUEST_ID` `0x0000` instead
(see Error response body). A coordinator SHOULD NOT choose `0x0000`, so this reply
never pairs with a request it sent.

#### Error response body

When `STATUS` = `1`, the response `BODY` is the following, regardless of `TYPE`,
in place of the type's normal (ok) response body:

`ERROR` `ERROR_MESSAGE`

`ERROR`: 1-byte unsigned integer selecting an entry from the global error table
below.
`ERROR_MESSAGE`: `STRING`, the error description.

Global error table:

```
+-----------+------------------------------------------------------+
| `ERROR`   | Meaning                                              |
+-----------+------------------------------------------------------+
| 0x00      | Reserved                                             |
| 0x01      | User declined / cancelled on device                  |
| 0x02      | Unsupported protocol version                         |
| 0x03      | Malformed request                                    |
| 0x04      | Unknown / unregistered `DESCRIPTOR_ALIAS`            |
| 0x05      | Descriptor registration failed                       |
| 0x06      | Unsupported descriptor form (`FORM`)                 |
| 0x07      | Invalid proof of registration                        |
| 0x08      | Address mismatch (Address Verification)              |
| 0x09      | Nothing to sign / no matching key for any input      |
| 0x0A      | Invalid or unparsable PSBT                           |
| 0x0B      | Internal device error                                |
| 0x0C      | Private key export refused (Get Keys)                |
| 0x0D      | MuSig2 session missing or mismatched                 |
| 0x0E      | Descriptor alias already registered                  |
| 0x0F      | Unsupported operation                                |
| 0x10      | Network mismatch                                     |
| 0x11–0xFE | Reserved for future standard codes                   |
| 0xFF      | Vendor-specific (meaning carried by `ERROR_MESSAGE`) |
+-----------+------------------------------------------------------+
```

`0x00` is reserved and MUST NOT be sent. `0x01`–`0x10` are the standard codes above;
`0x11`–`0xFE` are reserved for future standard codes. `0xFF` is vendor-specific: the
code alone is not meaningful, so `ERROR_MESSAGE` carries the description. A receiver
MUST NOT reject an unrecognized `ERROR`; `STATUS` = `1` already denotes an error,
and it SHOULD fall back to `ERROR_MESSAGE`.

A signer MUST answer `0x0F` to a request whose operation, or a capability it
needs, the signer does not support: a known `TYPE` it does not implement, or a
request needing a capability bit it does not advertise (see `CAPABILITIES`).
A signer MUST answer `0x10` to a request whose descriptor, keys, address or `PSBT`
are for a network it does not sign for (not in its Get Info `NETWORKS`), or for
another network than the one it is set to.

A signer MUST answer `0x03` with `REQUEST_ID` `0x0000` to a request it cannot read
far enough to know its `REQUEST_ID` or its `TYPE`: input that does not begin with
`MAGIC`, input that ends before `REQUEST_ID` is fully read, a `TYPE` that is
unknown, reserved or `0x00`, or `STATUS` = `1` on a request. Its `MSG_TYPE` has
`DIRECTION` = `1`, `STATUS` = `1` and `TYPE` `0x00` (unreadable request), and its
`VERSION` is the signer's own protocol version. A request whose header is readable
but whose `BODY` is malformed gets `0x03` with its own `REQUEST_ID` and `TYPE`.

#### Body

For an ok response (`STATUS` = `0`) and for requests, `BODY` is the type's
fields below, in listed order. Fields are ordered by the version in which they were
introduced (see Versioning); within a version they appear in listed order.

The message definitions below give each type's request body and ok response
body.

### Get Info

**Request** (`TYPE` = `0x01`, request):

The body is empty.

A signer answers it without user interaction, also when locked or without a seed.

**Ok response** (`TYPE` = `0x01`, response):

`VENDOR` `MODEL` `VERSION` `CAPABILITIES` `STATE` `NETWORKS` `MAX_MESSAGE` `MAX_ALIAS`
`FINGERPRINT`

`VENDOR`, `MODEL`, `VERSION`, `CAPABILITIES`: the device fields defined in Common
Field Encodings.
`STATE`: 1-byte unsigned integer, whether the signer can serve a request now.

```
+-----------+---------------------------------------+
| Value     | State                                 |
+-----------+---------------------------------------+
| 0x00      | Ready: seed present, signer unlocked  |
| 0x01      | Locked: seed present, signer locked   |
| 0x02      | Uninitialized: no seed                |
| 0x03–0xFF | Reserved                              |
+-----------+---------------------------------------+
```

Values `0x03`–`0xFF` are reserved. A reader MUST treat an unknown `STATE` as not
ready rather than reject, so a newer signer can report a state an older coordinator
does not know.

`NETWORKS`: 1-byte bitfield of the networks the signer signs for. Bit 0 is the LSB.

```
+-----+----------+
| Bit | Network  |
+-----+----------+
| 0   | Reserved |
| 1   | Mainnet  |
| 2   | Testnet  |
| 3   | Signet   |
| 4   | Regtest  |
| 5–7 | Reserved |
+-----+----------+
```

Bits 0 and 5–7 are reserved: they MUST be `0` when written, and a reader MUST
ignore them.
A signer MUST answer a request for a network it does not sign for with `ERROR`
`0x10` (network mismatch).

`MAX_MESSAGE`: 4-byte big-endian unsigned integer, the size in bytes of the largest
complete `MESSAGE` the signer accepts.
`MAX_ALIAS`: 1-byte unsigned integer, the length in bytes of the longest
`DESCRIPTOR_ALIAS` the signer stores. It MUST be at most 32, the `DESCRIPTOR_ALIAS`
bound, and a reader MUST reject a larger value.
`FINGERPRINT`: OPTIONAL, the `FINGERPRINT` of the master key. It is present only
when `STATE` is `0x00` (ready) and MUST be absent otherwise; a reader MUST reject a
response carrying it with any other `STATE`.

Fields added to this response later are appended after `FINGERPRINT`, so an older
reader ignores them as trailing bytes (see Versioning).

### Get Keys

**Request** (`TYPE` = `0x02`, request):

`KEYS`

`KEYS`: a vector of `KEY_REQUEST`, the keys to derive.

`KEY_REQUEST` follows this format:

`DERIVATION_PATH` `KIND`

`DERIVATION_PATH`: the path of the key from the master key.
`KIND`: 1-byte unsigned integer selecting the key returned at that path.

```
+-----------+-------------------------------+
| Value     | Definition                    |
+-----------+-------------------------------+
| 0x00      | Public: extended public key   |
| 0x01      | Private: extended private key |
| 0x02–0xFF | Reserved                      |
+-----------+-------------------------------+
```

Values `0x02`–`0xFF` are reserved; a parser MUST reject them.

Note: a silent payment wallet needs the BIP-352 scan private key to scan. When the
scan key is the signer's, the wallet fetches it with `KIND` `0x01` at the scan key's
path. The spend key never needs to leave the signer.

**Ok response** (`TYPE` = `0x02`, response):

`KEYS` `FINGERPRINT` `VENDOR` `MODEL` `VERSION` `CAPABILITIES`

`KEYS`: a vector of `EXTENDED_KEY`, one per request `KEY_REQUEST` in the same
order, each of the `KIND` requested.
`FINGERPRINT`: the `FINGERPRINT` of the master key. Mandatory.
`VENDOR`, `MODEL`, `VERSION`, `CAPABILITIES`: the device fields defined in Common
Field Encodings. Mandatory.

### Register Descriptor

**Request** (`TYPE` = `0x03`, request):

`DESCRIPTOR_ALIAS` `DESCRIPTOR`

`DESCRIPTOR_ALIAS`: the alias the descriptor is registered under on the device.
Mandatory.
`DESCRIPTOR`: OPTIONAL `DESCRIPTOR_BODY`. When absent, the request only queries the
registration status of `DESCRIPTOR_ALIAS`. At most one descriptor per request.

**Ok response** (`TYPE` = `0x03`, response):

`DESCRIPTOR_ALIAS` `REGISTERED` `STORED` `POR`

`DESCRIPTOR_ALIAS`: echoes the alias from the request.
`REGISTERED`: `BOOL`, whether the alias is registered on the device.
`STORED`: OPTIONAL `BOOL`, whether the device persisted the descriptor under
`DESCRIPTOR_ALIAS`. When `true`, a later request MAY reference the descriptor by
`DESCRIPTOR_ALIAS` alone. When `false` or absent, later requests carry the
`DESCRIPTOR_BODY`, together with the `POR` when the device issued one. `STORED`
and the presence of `POR` are independent.
`POR`: OPTIONAL `BYTES`, a proof of registration. It lets a signer keep a
registration outside its own storage: the signer hands it out at registration and
receives it back with later requests. This specification does not define its
content, so it is carried as opaque bytes.

A failed registration is reported as an error response (`STATUS` = `1`), not via a
body field.

### Address Verification

**Request** (`TYPE` = `0x04`, request):

`DESCRIPTOR_ALIAS` `DERIV` `ADDRESS` `DESCRIPTOR` `POR`

`DESCRIPTOR_ALIAS`: the alias the descriptor is registered under on the device.
`DERIV`: `DERIVATION_PATH`, the path under the descriptor.
`ADDRESS`: OPTIONAL `STRING`, the expected address (recommended).
`DESCRIPTOR`: OPTIONAL `DESCRIPTOR_BODY`, the full descriptor / wallet policy (for
stateless devices).
`POR`: OPTIONAL `BYTES`, a proof of registration (for stateless devices).

A silent payment address is verified with a `DESCRIPTOR` of `FORM` `0x03`
(silent payment keys) instead of a descriptor, with an optional `POR`:
- `DESCRIPTOR_ALIAS`: the alias the keys are registered under, or a display alias
  when they are not registered.
- `DERIV`: the BIP-352 label. Empty for the account's base address; one step `m`
  for the address labelled `m` (`m` ≥ 1, as label `0` is reserved for change).
- `ADDRESS`: the expected silent payment address.

The answer is a `URI` holding the address, or the error `0x08` when the address
differs from `ADDRESS`. It requires capability bit 2: a signer without it MUST
answer with `ERROR` `0x0F`.

**Ok response** (`TYPE` = `0x04`, response):

`URI`

`URI`: `STRING`, a BIP-321 payment URI for the verified address. A silent payment
address goes in its `sp` query parameter, e.g. `bitcoin:?sp=sp1q...`.

### Signing

**Request** (`TYPE` = `0x05`, request):

`DESCRIPTORS` `PSBT` `WANT_KIND` `ACCEPT_TRIMMED`

`DESCRIPTORS`: a vector of `DESCRIPTOR`, one entry per descriptor the inputs spend
from.
`PSBT`: the `PSBT` to sign.
`WANT_KIND`: OPTIONAL, the response `KIND` the coordinator prefers (see the response
below). A preference only: the signer MAY answer with another `KIND` it supports
(some devices could return only a `PSBT`), and MUST do so where the response below
requires `0x01`. A signer MUST ignore a `WANT_KIND` value it does not know rather
than reject, so a newer coordinator may prefer a newer `KIND`.
`ACCEPT_TRIMMED`: `BOOL`, whether the coordinator accepts a trimmed `PSBT` in a
`KIND` `0x01` answer (see the response below).

`DESCRIPTOR` follows this format:

`DESCRIPTOR_ALIAS` `DESCRIPTOR` `POR`

`DESCRIPTOR_ALIAS`: the alias the descriptor is registered under on the device.
`DESCRIPTOR`: OPTIONAL `DESCRIPTOR_BODY`: the descriptor / wallet policy itself.
`POR`: OPTIONAL `BYTES`, a proof of registration (for stateless devices).

**Ok response** (`TYPE` = `0x05`, response):

`KIND` `DATA`

`KIND`: 1-byte unsigned integer selecting the response form.

```
+-------+------------------------------------------------+
| Value | Definition                                     |
+-------+------------------------------------------------+
| 0x00  | Reserved                                       |
| 0x01  | PSBT (input PSBT with partial signatures)      |
| 0x02  | Signatures only                                |
+-------+------------------------------------------------+
```

`DATA` depends on `KIND`:
- `0x01`: a `PSBT`.
- `0x02`: `SIGS`, a vector of `SIG_ENTRY`.

When `ACCEPT_TRIMMED` is `false`, a `KIND` `0x01` `PSBT` is the request's `PSBT`
with partial signatures. When `true`, it MAY leave out fields of the request's
`PSBT`, and the coordinator merges it into its own copy as a PSBT Combiner does.

When the transaction has silent payment outputs, the `PSBT` is a BIP-370 version 2
PSBT, as BIP-375 requires, and a `KIND` `0x02` answer MUST contain, for each
distinct scan key among those outputs, an ECDH share (`SIG_KIND` `0x06`) and its
BIP-374 DLEQ proof (`SIG_KIND` `0x07`) for each eligible input whose private key
the signer holds, whether or not it signs that input, or a global share and proof
when it holds the private keys of every eligible input, as BIP-375 lays them out. A
signer that cannot provide them answers with `KIND` `0x01`. Output scripts are not
carried.

With silent payment outputs, the signer MUST NOT add a signature until every
silent payment output script is set in the `PSBT` or computable from the complete
shares; until then its answer carries the shares and proofs only. It MUST refuse a
`PSBT` with a `PSBT_IN_SIGHASH_TYPE` other than `SIGHASH_ALL`, and signs with
`SIGHASH_ALL` when none is set.

`SIG_ENTRY` follows this format:

`INPUT_INDEX` `SIG_KIND` `LENGTH` `KIND_FIELDS`

`INPUT_INDEX`: 4-byte big-endian unsigned integer, the input index.
`SIG_KIND`: 1-byte unsigned integer.
`LENGTH`: compact size, the byte length of `KIND_FIELDS`.

```
+-----------+-------------------+
| Value     | Definition        |
+-----------+-------------------+
| 0x00      | Reserved          |
| 0x01      | segwit            |
| 0x02      | tapkey            |
| 0x03      | taptree           |
| 0x04      | musig pubnonce    |
| 0x05      | musig partial sig |
| 0x06      | sp ecdh share     |
| 0x07      | sp dleq proof     |
| 0x08–0xFF | Reserved          |
+-----------+-------------------+
```

`0x00` is reserved and MUST NOT be sent; `0x08`–`0xFF` are reserved for future
kinds. A reader MUST skip an entry whose `SIG_KIND` it does not know, reserved
values included, by reading past its `LENGTH` bytes, rather than reject the message.
`KIND_FIELDS` of a known `SIG_KIND` MUST fill its `LENGTH` exactly; a reader MUST
reject the message otherwise.

`KIND_FIELDS` depends on `SIG_KIND`:
- `0x01` segwit: `PUBLIC_KEY` `SIGNATURE`.
  - `PUBLIC_KEY`: 33 bytes, the compressed public key that produced the
    signature.
  - `SIGNATURE`: `BYTES`, the value of the input's `PSBT_IN_PARTIAL_SIG` (`0x02`)
    entry keyed by `PUBLIC_KEY`: a DER-encoded ECDSA signature followed by its
    sighash type byte.
- `0x02` tapkey: `SIGNATURE`.
  - `SIGNATURE`: `BYTES`, the value of the input's `PSBT_IN_TAP_KEY_SIG` (`0x13`)
    field: a 64-byte BIP-340 signature, or 65 bytes with a sighash type byte. A
    reader MUST reject any other length.
- `0x03` taptree: `XONLY_PUBLIC_KEY` `TAP_LEAF_HASH` `SIGNATURE`.
  - `XONLY_PUBLIC_KEY`: 32 bytes.
  - `TAP_LEAF_HASH`: 32 bytes.
  - `SIGNATURE`: `BYTES`, the value of the input's `PSBT_IN_TAP_SCRIPT_SIG`
    (`0x14`) entry keyed by `XONLY_PUBLIC_KEY` and `TAP_LEAF_HASH`: 64 or 65 bytes
    as for `0x02`.
- `0x04` musig pubnonce: `PARTICIPANT` `AGGREGATE` `LEAF_HASH` `PUB_NONCE`.
  - `PARTICIPANT`: 33 bytes, the compressed participant key.
  - `AGGREGATE`: 33 bytes, the compressed aggregate key the participant provides
    the nonce or partial signature for: the taproot internal key, the taproot
    output key, a key in a script, or a parent key of one of those (BIP-373).
  - `LEAF_HASH`: OPTIONAL, 32 bytes, the BIP-341 tap leaf hash of the leaf script
    signed. Absent when `AGGREGATE` is the taproot internal key or the taproot
    output key, present otherwise.
  - `PUB_NONCE`: 66 bytes, no `LENGTH`.

  Together they are the key and value of the PSBT `PSBT_IN_MUSIG2_PUB_NONCE`
  (`0x1b`) field.
- `0x05` musig partial sig: `PARTICIPANT` `AGGREGATE` `LEAF_HASH` `PARTIAL_SIG`.
  - `PARTICIPANT`, `AGGREGATE`, `LEAF_HASH`: as for `0x04`.
  - `PARTIAL_SIG`: 32 bytes, no `LENGTH`.

  Together they are the key and value of the PSBT `PSBT_IN_MUSIG2_PARTIAL_SIG`
  (`0x1c`) field.
- `0x06` sp ecdh share: `GLOBAL` `SCAN_KEY` `SHARE`.
  - `GLOBAL`: `BOOL`, `true` when the share covers every eligible input of the
    transaction, `false` when it covers the input at `INPUT_INDEX` only.
  - `SCAN_KEY`: 33 bytes, the compressed scan key of the recipient the share is for.
  - `SHARE`: 33 bytes, the compressed ECDH share point.

  Together they are the key and value of the BIP-375 `PSBT_GLOBAL_SP_ECDH_SHARE`
  (`0x07`) field when `GLOBAL` is `true`, of the input's `PSBT_IN_SP_ECDH_SHARE`
  (`0x1d`) field when it is `false`.
- `0x07` sp dleq proof: `GLOBAL` `SCAN_KEY` `PROOF`.
  - `GLOBAL`, `SCAN_KEY`: as for `0x06`.
  - `PROOF`: 64 bytes, no `LENGTH`, the BIP-374 DLEQ proof of the share for the
    same `GLOBAL`, `INPUT_INDEX` and `SCAN_KEY`.

  Together they are the key and value of the BIP-375 `PSBT_GLOBAL_SP_DLEQ` (`0x08`)
  field when `GLOBAL` is `true`, of the input's `PSBT_IN_SP_DLEQ` (`0x1e`) field
  when it is `false`.

When `GLOBAL` is `true`, `INPUT_INDEX` MUST be `0`, and a reader MUST reject any
other value. `GLOBAL` is a field of its own rather than a reserved `INPUT_INDEX`
value, as every input index is a valid one.

In one response, a scope (global, or one input) and `SCAN_KEY` with a `0x06` or
`0x07` entry MUST have exactly one of each, and a reader MUST reject a share
without its proof, a proof without its share, or a duplicate of either.

#### MuSig2

A MuSig2 signature is one input and one BIP-373 key
`participant | aggregate [| leaf_hash]`, `participant` being one of the signer's
keys. The `PSBT` selects what the signer returns:

- The `PSBT` has no `PSBT_IN_MUSIG2_PUB_NONCE` (`0x1b`) for the key of one of its
  MuSig2 signatures: the public nonce (`SIG_KIND` `0x04`) of each of its MuSig2
  signatures, and no signature of any kind.[^round1]
- Otherwise: the partial signature (`SIG_KIND` `0x05`) of each of its MuSig2
  signatures for which the `PSBT` has a `PSBT_IN_MUSIG2_PUB_NONCE` from every
  participant, nothing for the others.

These are the two BIP-327 rounds, nonces then partial signatures. With `KIND`
`0x01` the same values go in the `PSBT`. A MuSig2 session missing or mismatched is
refused with `ERROR` `0x0D`.

[^round1]: **Why a public nonce for every MuSig2 signature?**
    A signer may keep one nonce state per signing session, drawn fresh at round 1,
    so a nonce returned earlier for another key would no longer match it.

### Versioning

`BODY` is encoded append-only: fields are ordered by the `VERSION` in which they
were introduced, then by listed order within a version. A parser built for version
`N`:

- For a message with `VERSION` ≤ `N`: parse exactly that version's field set.
- For a message with `VERSION` > `N`: parse the fields introduced up to version
  `N`, then ignore the trailing bytes.[^trailing] They belong to fields added in
  later versions, which by ordering come strictly after everything `N` knows.
- For a message with `VERSION` < `N`: only the fields introduced up to the
  message's version are present; the parser MUST NOT expect later-version fields.

The transport MUST deliver each `MESSAGE` in full and length-delimited; a parser
therefore always knows where it ends, so "ignore the trailing bytes" is
unambiguous.

Rules for future versions:
1. New fields MUST only be appended (a higher introduction version); an existing
   field MUST NOT be reordered, removed, or have its size/encoding changed.
2. A message type MUST NOT change its behaviour incompatibly with an earlier
   version: such a change takes a new `TYPE`, and the existing one keeps its
   behaviour.
3. To change an existing field's meaning, add a new field and deprecate the old.
4. Bump `VERSION` when adding fields; document each field's introduction version.

[^trailing]: **Why ignore trailing bytes?**
    Appending fields and ignoring unknown trailing bytes lets an older parser read
    a newer message (up to the fields it knows) and a newer parser read an older
    message (which simply carries fewer fields), without an external schema.

### Errors

- A parser MUST reject input whose first 6 bytes are not `MAGIC`.
- A parser MUST reject input that ends before a required field is fully read, a
  compact-size `LENGTH`/`COUNT` that exceeds the remaining input, a `BOOL` or
  `PRESENCE` outside `{0x00, 0x01}`, a discriminant outside its defined range: the
  `TYPE`, the `FORM`, the Get Keys `KIND` or the Signing response `KIND` (an
  unknown `SIG_KIND` is skipped and an unknown `WANT_KIND` ignored, as their
  sections define), `STATUS` = `1` on a request, `TYPE` `0x00` outside an error
  response with `REQUEST_ID` `0x0000`, a `STRING` that is not valid UTF-8 or that
  contains a nul byte, or a `FORM` `0x03` body with both or neither of `SCAN_PATH`
  and `SCAN_KEY`.
- A signer MUST answer a request it cannot read with `REQUEST_ID` `0x0000` and
  `TYPE` `0x00` (see Error response body).

## Rationale

See also the footnotes throughout the specification.

### Design

- **Binary, not text.** A binary encoding keeps the payload small. Fields are
  fixed-width or length-prefixed, and the `PSBT` goes as raw bytes, not Base64.
- **Transport agnostic.** A `MESSAGE` is a self-contained byte string. Splitting it
  over several QR codes, or carrying it over USB, NFC or a file, is the transport's
  job, so one encoding serves every channel.
- **Request id.** The responder echoes `REQUEST_ID`, also in an error response, so
  the coordinator pairs a response with its request whatever order they arrive in.
  A request too broken to read gets `REQUEST_ID` `0x0000`, which a coordinator does
  not choose, so that reply pairs with no request.
- **One byte per optional field.** `PRESENCE` marks an optional field without
  tags: the field order is fixed by this specification.
- **Append-only versioning.** New fields go after the existing ones and an older
  parser ignores them as trailing bytes. An unknown capability bit is ignored, an
  unknown `STATE` read as not ready, an unknown `FLAG` as a pre-release and an
  entry of unknown `SIG_KIND` skipped, rather than rejected, so a newer signer can
  still answer an older coordinator.
- **Signatures only.** A `KIND` `0x02` answer carries the signature entries, not the
  whole `PSBT` back, so its payload is smaller. `KIND` `0x01` stays for a signer
  that can only return a `PSBT`.
- **Trimmed PSBT.** The coordinator already holds the `PSBT` it sent, so a `KIND`
  `0x01` answer can leave out its fields for a smaller payload, and the coordinator
  merges it back as a PSBT Combiner does.
- **Aliases and proof of registration.** A signer that stores a registration is
  then reached by `DESCRIPTOR_ALIAS` alone. A signer that does not store it (`STORED`
  `false`) issues a `POR` instead, and gets the descriptor and the `POR` back with
  each later request.
- **Vendor error code.** `ERROR` `0xFF` lets a signer report a failure no standard
  code covers, its meaning carried by `ERROR_MESSAGE`. A receiver does not reject an
  unknown `ERROR`, so new standard codes can be added.

### Security

- **Untrusted coordinator.** The coordinator is untrusted. Nothing in a request
  narrows what the signer checks before it acts; a request only carries data.
- **Private key export.** Get Keys `KIND` `0x01` carries an extended private key in a
  response, so whatever carries the bytes carries that key.

## Backward Compatibility

This BIP defines a new format and changes no existing one. Version `0x01` is the
first; later versions extend it as Versioning defines, and an older parser reads a
newer message up to the fields it knows.

## Test Vectors

Machine-checkable vectors accompany this specification, in
[`bip-signing/test_vectors/`](./bip-signing/test_vectors/):

- `get_info.json`: Get Info request, an ok response from a ready signer with its
  `FINGERPRINT`, the same advertising PSBT trimming (capability bit 5), and one from
  a locked signer without `FINGERPRINT`.
- `get_keys.json`: Get Keys request/response.
- `register_descriptor.json`: Register Descriptor request/response, each `FORM`.
- `address_verification.json`: Address Verification request/response, including a
  silent payment address with the signer's own scan key (`SCAN_PATH`), the same
  with a `POR`, and a labelled one with a scan key it does not hold (`SCAN_KEY`).
- `signing.json`: Signing requests with `ACCEPT_TRIMMED` `false` and `true`, both
  response `KIND`s, including the MuSig2 signatures-only entries (`SIG_KIND` `0x04`
  and `0x05`, with and without a leaf hash), a silent payment send answered with a
  global ECDH share and DLEQ proof and one answered with per-input ones (`SIG_KIND`
  `0x06` and `0x07`), and an entry of an unknown `SIG_KIND` that a reader skips.
- `errors.json`: error responses (`STATUS` = `1`), standard and vendor codes,
  including `0x0D` (MuSig2 session), `0x0E` (alias already registered), `0x0F`
  (unsupported operation), `0x10` (network mismatch) and the reply to an
  unreadable request (`TYPE` `0x00`, `REQUEST_ID` `0x0000`).
- `versioning.json`: forward compatibility, a message whose `VERSION` is above 1
  and which carries trailing bytes a version-1 parser does not know.
- `invalid.json`: malformed messages a reader MUST reject, each a vector above with
  one change its `description` names: a bad `MAGIC`, a reserved or unknown `TYPE`,
  `FORM` and `KIND`, `TYPE` `0x00` on a request, an ok response or an error response
  with another `REQUEST_ID`, `STATUS` = `1` on a request, truncated input, an
  invalid `BOOL` or `STRING`, a `DESCRIPTOR_ALIAS` above 32 bytes, both or neither
  of `SCAN_PATH` and `SCAN_KEY`, unpaired or duplicate silent payment entries, a
  global one with an `INPUT_INDEX` other than `0`, signatures of the wrong length,
  and a Get Info response with a `MAX_ALIAS` above 32 or a `FINGERPRINT` while not
  ready.

Every file holds one JSON object with a single `vectors` array:

```json
{
  "vectors": [
    {
      "name": "get_keys_request_one_path",
      "description": "Get Keys request for the extended public key at m/48'/0'/0'/2', so a single KEY_REQUEST whose KIND is 0x00 (public).",
      "direction": "request",
      "hex": "4249505858580102000101048000003080000000800000008000000200",
      "decode_only": false
    }
  ]
}
```

Every field but `decode_error` is mandatory:

- `name`: unique within the file. An implementation pairs each vector with the
  message it builds for it by this name.
- `description`: what the message contains, in plain words.
- `direction`: `request` or `response`, matching bit 7 of `MSG_TYPE`.
- `hex`: the complete `MESSAGE`, from the first `MAGIC` byte to the last body
  byte, as lowercase hex with no separators.
- `decode_only`: when `false`, the vector is a round trip: decoding `hex` yields
  the described message, and encoding that message yields `hex` byte for byte.
  When `true`, only the decoding direction holds, because an encoder cannot
  produce these bytes: it writes the version it implements (`versioning.json`)
  and no malformed message (`invalid.json`). These two files are the only ones
  that set it.
- `decode_error`: `false` when absent. When `true`, decoding `hex` MUST fail for
  the reason `description` gives, and `decode_only` is `true`. The `invalid.json`
  vectors are the only ones that set it.
