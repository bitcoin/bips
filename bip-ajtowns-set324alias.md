```
  BIP: TBD
  Layer: Peer Services
  Title: BIP324 One-Byte Message Type ID Alias Assignment
  Authors: Anthony Towns <aj@erisian.com.au>
  Status: Draft
  Type: Standards Track
  Assigned: TBD
  License: BSD-2-Clause
  Requires: 324, 434
  Discussion: https://gnusha.org/pi/bitcoindev/aq9ADn7GscMHWc19@erisian.com.au/T/#u
```

## Abstract

Provides a new `set324alias` message that permits peers using
[BIP-324][BIP324] encrypted transport to assign one-byte message type ID
aliases to improve bandwidth usage for their outbound messages.

## Motivation

[BIP-324][BIP324] assigns one-byte message type IDs via a fixed table, and
adding additional entries to the table requires global coordination with
the potential for conflicts. Allowing peers to choose their own one-byte
message type IDs for their own outgoing messages avoids the need for
centralized coordination, and increases flexibility for experimentation
at the peer-to-peer layer.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

### Feature advertisement

Support for this feature is indicated via the [BIP-434][BIP434] `feature`
message, with `featureid` **TBD** and an empty `featuredata`.

Support for this feature SHOULD NOT be advertised on connections that
do not support one-byte message type IDs.

### `set324alias` message

The `set324alias` allows extending or modifying the set of aliases
defined by [BIP-324][BIP324].

The payload of the `set324alias` message contains a vector of aliases,
represented as a CompactSize encoded number of aliases being defined,
followed by that number of aliases.

| Type         | Name          | Description |
| ------------ | ------------- | ----------- |
| alias-vector | `aliases`     | The new aliases |

Each alias is represented by a single byte identifying the alias (with
value 1 to 255), followed by a CompactSize-prefixed string of up to 12
bytes giving the message type the alias corresponds to.

| Type         | Name          | Description |
| ------------ | ------------- | ----------- |
| `uint8_t`    | `id`          | The alias (1-255) |
| `var_string` | `msg_type`    | A 1-12 byte message type |

Nodes MUST NOT send `set324alias` before sending `verack`. Nodes MUST
NOT send `set324alias` to a peer that has not advertised support for
the feature. Nodes MUST NOT send more than 255 elements in `aliases`,
MUST NOT define an alias with `id=0`, and MUST NOT send a `msg_type`
longer than 12 bytes.

Nodes SHOULD NOT send `set324alias` on a connection that does not support
one-byte message types. Nodes SHOULD NOT send `set324alias` with an empty
`aliases` vector.

Nodes SHOULD define an alias for all messages that they expect to send
multiple times over a connection. Nodes SHOULD NOT define an alias for
any message that will only be sent at most once over the connection. Nodes
SHOULD NOT define aliases for messages that already have an alias defined
in [BIP-324][BIP324].

Nodes SHOULD send `set324alias` only once per connection, and SHOULD send it
as soon as possible (eg, immediately after receiving the `feature` message
indicating support).

Nodes MAY hardcode a bundle of aliases they prefer and send that bundle
to all peers that support this feature.

Nodes receiving a `set324alias` message MUST maintain a per-peer alias id
to message mapping, so that future messages using the one-byte alias are
correctly interpreted as if the 1-12 byte `msg_type` had been used instead.

A node receiving a `set324alias` message MUST apply the new aliases
immediately, as the very next message may make use of aliases declared
in that message.

Nodes receiving a `set324alias` message MUST update the aliases in order
(eg if `[1:foo, 2:bar, 1:baz]` is received, the one-byte message type
`1` will be interpreted as `baz` thereafter).

If a peer specifies an unknown `msg_type` in an alias, the node receiving
the alias SHOULD record the alias as being a generic unknown message
type rather than tracking each unknown `msg_type` distinctly. Nodes
MUST NOT treat a `set324alias` message defining an alias for unknown
messages as an error. Nodes MAY treat a later message using that alias
as an error if they would also have treated a message using `msg_type`
it aliases as an error.

A node receiving a `set324alias` message MUST continue to accept messages
that use the 1-12 byte `msg_type` rather than the alias.

## Reference implementation

**TODO** See https://github.com/ajtowns/bitcoin/commits/202605-bip324-id/ in the meantime.

## Backward compatibility

Non-implementing peers never receive a `set324alias` (gated on their
advertisement), so they keep the default mapping and are unaffected.

The long form message type stays valid for every message, so messages
whose one byte type ID alias has been reassigned to a different message
type can still be sent.

## Copyright

This BIP is licensed under the 2-clause BSD license.

[BIP324]: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
[BIP434]: https://github.com/bitcoin/bips/blob/master/bip-0434.md
