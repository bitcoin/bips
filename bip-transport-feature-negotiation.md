```
  BIP: ?
  Layer: Peer Services
  Title: Transport Feature Negotiation
  Authors: Liam Gilligan <liamdgilligan@gmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: CC0-1.0
  Discussion: 2026-09-17: https://groups.google.com/g/bitcoindev/c/LbTSN08fYlM
              2026-05-04: https://groups.google.com/g/bitcoindev/c/n_5WuKVYqwI
  Requires: 324
```

## Abstract

This document specifies the contents of the version packet of the V2 Transport defined in [BIP 324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki), which BIP 324 leaves unspecified and sends empty. Redefined as a negotiation packet, it carries a list of features, each a modification to the Transport Layer such as an encryption upgrade or authentication. The responder's negotiation packet advertises the features it supports and the initiator's selects which of them are used, so that such upgrades can be negotiated within the existing BIP 324 handshake. Each feature can carry data in these two packets, which can be all that its upgrade needs. A negotiated feature that needs more can then exchange further packets of its own, over as many rounds as it requires, before any messages are sent. A node supporting no features sends an empty negotiation packet, identical to the version packet sent today, so current BIP 324 implementations already comply with this specification.

## Motivation

BIP 324 specifies the V2 Transport and defined a version packet to enable upgrades to it: the version packet is sent empty, any other contents being reserved for future versions, with post-quantum handshake upgrades and optional authentication given as examples of what they could add.[^bip324version] It does not specify how such upgrades are negotiated, however. For Transport upgrades to be added, either a new Transport must be defined, or an upgrade mechanism must be specified for the version packet, which is the purpose of this document. Upgrades are already under discussion,[^pqthread] and each needs a way for two peers to agree on whether to use it.

This document specifies that mechanism, defining the contents of the version packet as a list of features. Each feature is a Transport upgrade specified on its own, so that upgrades can be negotiated per connection, adopted independently of one another, and replaced without a new Transport if one is broken or otherwise rejected.

## Definitions

- The **Transport Layer** specifies how messages are encoded on the wire and which security services[^securityservice] are provided during transmission. The objects it concerns itself with are **packets**, which can contain the Protocol Layer's messages.
- A **Transport** is a particular version of the Transport Layer. V1 and V2 are the two that exist today, V2 being specified by BIP 324.
- The **Protocol Layer** specifies which P2P messages and commands are used. The objects it concerns itself with are **messages**, which are contained in the Transport Layer's packets.
- A **Protocol** is a particular version of the Protocol Layer, as given by the protocol version carried in the `version` message (70017 at the time of writing).
- The **P2P handshake**, or simply **the handshake**, is the exchange in which two nodes ensure they are using compatible Transports and Protocols. It consists of two phases:
  - The **Transport Phase**, in which the Transport is established. V1 exchanges no bytes during its Transport Phase. V2's is specified by BIP 324 and terminated by the **version packet**, a packet which contains no message, though this document allows feature packets to extend the Transport Phase beyond it. BIP 324 leaves its contents unspecified and sends it empty, and as "the total size of a packet is 20 bytes plus the length of its contents", it is exactly 20 bytes on the wire.
  - The **Protocol Phase**, in which the Protocol is established through the messages exchanged from a `version` message to a `verack` message. The `verack` terminates both the Protocol Phase and the handshake itself. The `version` message is a message contained in a packet, and is never contained in the version packet.

  In BIP 324's terms, the Transport Phase of a V2 connection comprises its key exchange and version negotiation phases, the latter extended by any feature packets, and the Protocol Phase takes place at the start of its application phase. BIP 324 calls its first two phases "the handshake"; to avoid confusion with the P2P handshake, this document calls them the **BIP 324 handshake**.
- A **negotiation packet** is the version packet with its contents specified by this document, as a list of features. A negotiation packet containing no features is empty, and is therefore identical to the version packet BIP 324 nodes send today.
- A **feature** is a modification to the Transport Layer which can be negotiated, such as an encryption upgrade or authentication. A feature appears in the negotiation packet, whose contents are a list of features and nothing else, and is identified by a one-byte **header**.[^headerbyte] [BIP 434](https://github.com/bitcoin/bips/blob/master/bip-0434.md) uses "feature" for the Protocol Layer equivalent; the two never appear in the same packet.
- As in BIP 324, "the two parties are called the **initiator** (who established the connection) and the **responder** (who accepted the connection)."

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

For the purposes of this section, `CompactSize` refers to the variable-length integer encoding used across the existing P2P protocol to encode array lengths, among other things, in 1, 3, 5 or 9 bytes. Only `CompactSize` encodings which are minimally-encoded (ie the shortest length possible) are used by this specification.[^compactsize]

### Overview

Each of the two version packets in the BIP 324 handshake becomes a negotiation packet. The responder's advertises the features it supports, and the initiator's selects which of them are used. Each feature in a negotiation packet can carry a payload, and the payloads in the two negotiation packets can be all that an upgrade needs, in which case it is performed without any further packets and adds no round trips. Negotiated features that need more than those payloads may then exchange feature packets, which extend the Transport Phase, before the first packets containing messages are sent. Each negotiated feature can require any number of feature packets in either direction, over as many rounds as its specification defines. A node can also choose to [omit a payload](#omitting-payloads) from its negotiation packet and send it in a feature packet instead: including payloads cuts down on round trips, but an advertiser has to populate them, which may require computation, before it knows whether the selector supports their features. Features whose upgrades can be performed simultaneously may and should do so, and features can specify that their upgrades must be performed after other upgrades, for example an authentication feature run over an encryption upgrade. Below, features A and B stand for two negotiated features that exchange feature packets simultaneously, and feature C for one that waits for A:

```
 Initiator (selector)                                 Responder (advertiser)

   ---- ellswift_X + initiator_garbage ------------------------------------>

   <--- ellswift_Y + responder_garbage + responder_garbage_terminator +
            negotiation packet (advertisement, with any payloads) ----------

   ---- initiator_garbage_terminator +
            negotiation packet (selection, with any payloads) ------------->

   Feature packets follow only if a negotiated feature requires them:

   <--- feature packets of features A and B ------------------------------->
            (side by side, each over as many rounds as it specifies)

   <--- feature packets of feature C -------------------------------------->
            (once A is complete, and may rely on its upgrade)

                                  ...

   <--- packets containing messages --------------------------------------->
```

Decoy packets, which either node may send at any point after its garbage terminator, are omitted above. As with the version packet in BIP 324, a node's negotiation packet is the first non-decoy packet it sends after its garbage terminator. Both negotiation packets are sent in the flights that carry BIP 324's version packets, so negotiation adds no round trips, and neither does an upgrade performed with the payloads they carry; any round trips added are those that feature packets require.

### Negotiation packet

The contents of a negotiation packet are a list of features, concatenated. They are not packaged like a message,[^notamessage] so no message type is prefixed. Each feature is encoded as follows:

| Field | Size in bytes | Description |
| ----- | ------------- | ----------- |
| `length` | 1, 3, or 5[^lengthsize] | `CompactSize` giving the combined size of `header` and `payload` |
| `header` | 1 | Identifies the feature |
| `payload` | `length` - 1 | Feature-specific data, which can be empty |

A negotiation packet can carry as many features as fit in its contents, which MUST NOT exceed 4,000,000 bytes.[^maxsize] If a feature's payload would push the contents over that limit, it MUST be omitted and sent in a feature packet instead, as described in [Omitting payloads](#omitting-payloads).

A negotiation packet cannot be parsed if any `length` is truncated, is not minimally encoded, is zero, or exceeds the number of bytes remaining in the contents. What a node does with such a packet depends on its role, as described in [Advertisement and selection](#advertisement-and-selection).

The `header` indicates which feature is being negotiated. A selector MUST ignore features with headers it does not support, so that features can be advertised to nodes that do not implement them; an advertiser handles features it did not advertise as described in [Advertisement and selection](#advertisement-and-selection). Header values are recorded in a table maintained alongside this specification, as described in [Feature headers](#feature-headers). The value 0 is reserved so that a later revision can introduce a different structure: because `length` covers the header as well as the payload, a new header format can take on any shape, and nodes that do not understand it can still skip over it. Until an alternative header format is specified, nodes MUST NOT send a feature with header 0, and a selector MUST ignore any it receives.

A node MUST NOT send more than one feature with the same header. A node receiving a negotiation packet in which a header repeats MUST act on the first occurrence and ignore the rest.[^duplicates]

The `payload` contains information relevant to the feature being negotiated, and can be empty. How these bytes are interpreted is part of the feature's specification.[^featuredata]

The following function parses the contents of a negotiation packet. Every occurrence of a header after its first is left out of its result, while features with header 0 or with unsupported headers are left to the caller.

```python
def parse_negotiation_packet(contents):
    """Return a dict mapping headers to payloads in order of appearance, or None if `contents` cannot be parsed."""
    features = {}
    pos = 0
    while pos < len(contents):
        # Read a minimally encoded CompactSize.
        length = contents[pos]
        pos += 1
        if length >= 0xfd:
            size, minimum = {0xfd: (2, 0xfd), 0xfe: (4, 0x10000), 0xff: (8, 0x100000000)}[length]
            if size > len(contents) - pos:
                return None
            length = int.from_bytes(contents[pos:pos + size], 'little')
            pos += size
            if length < minimum:
                return None
        # The length covers the header as well as the payload.
        if length == 0 or length > len(contents) - pos:
            return None
        header, payload = contents[pos], contents[pos + 1:pos + length]
        pos += length
        # Only the first occurrence of a header counts.
        if header not in features:
            features[header] = payload
    return features
```

### Advertisement and selection

One negotiation packet from each node completes negotiation, but each acts differently. The responder sends its negotiation packet first,[^order] and it acts as the **advertisement**: it SHOULD contain every feature the responder supports, including those that are mutually incompatible. The initiator's negotiation packet acts as the **selection**: it responds with a subset of the advertisement's features, thus deciding which upgrades are performed. The responder is therefore the **advertiser**, and the initiator the **selector**.

A feature is **negotiated** if and only if it appears in both the advertisement and the selection. The selector MUST NOT select a feature that does not appear in the advertisement, nor features that are mutually incompatible. The advertiser SHOULD order mutually incompatible features from most preferred to least, and the selector SHOULD select the first of them that it also supports.[^preference]

A selector SHOULD disconnect if it cannot parse the advertisement, though it can also ignore a bad advertisement by selecting nothing from it: a selector that does not disconnect MUST send an empty selection. An advertiser has no such option, as there is no way to proceed from a bad selection. An advertiser that advertised any features MUST disconnect if it cannot parse the selection, or if the selection contains a feature it did not advertise or features that are mutually incompatible. An advertiser that advertised no features MAY instead ignore the selection it receives, as BIP 324 implementations do, since nothing in it can be negotiated.

A selector can only select features once it has received the advertisement. BIP 324 notes that "version packets can be sent immediately after sending the garbage terminator", before receiving the peer's; a selector that does so, as Bitcoin Core does, sends an empty selection.

A node supporting no features sends an empty negotiation packet in either role, identical to the version packet BIP 324 specifies. Current BIP 324 implementations are therefore already compliant, advertising and selecting features correctly and ignoring unsupported ones.[^ignore]

### Feature packets

A feature may specify that **feature packets** can be sent: additional packets whose contents can be used to perform its upgrade. Feature packets MUST NOT be sent unless their feature was negotiated, and they extend the Transport Phase past the negotiation packets. Their contents MUST begin with the header of their feature, followed by data the feature defines.

Features whose upgrades can be performed simultaneously SHOULD be: the feature packets of different features can be exchanged in any order, and a node does not hold back the feature packets of one feature for another unless a feature's specification has it wait. A feature is complete for a node once the node has sent every feature packet which that feature requires of it and received every feature packet of that feature which it expects. While any feature is incomplete, every non-decoy packet a node receives is a feature packet, and the node MUST disconnect if it is not one that the node expects, for example because its contents are empty or do not begin with the header of a negotiated feature, since the two nodes then disagree on what is being performed.

If no negotiated feature requires feature packets, the Transport Phase ends with the negotiation packets, in the same way BIP 324 ends it with the version packets. Otherwise, it ends with the last feature packet, and a node MUST NOT send a packet containing a message until it has sent every feature packet it is to send and received every feature packet it expects. Every non-decoy packet after the Transport Phase contains a message.

An advertiser that advertised any features cannot know whether the Transport Phase will be extended until it receives the selection, and so MUST NOT send a packet containing a message before then.[^nodelay]

### Omitting payloads

Any feature payload in a negotiation packet can be omitted and instead sent in a subsequent feature packet. How an omission is shown is up to the feature: the specification of a feature that can have a payload MUST define how a node shows that it has omitted it. It is RECOMMENDED that an empty payload mean that the payload is deferred to a feature packet. A feature that never has a payload has nothing to omit, and its payload is simply empty.

If a feature whose payload was omitted is negotiated, the node that omitted the payload MUST send it in the first feature packet it sends for that feature. The contents of that feature packet are the feature's header followed by the payload, exactly as the payload would have appeared in the negotiation packet. The feature thereby requires this feature packet, even if its specification defines no others.

A node has to omit a payload that would otherwise push the contents of its negotiation packet over the limit (see [Negotiation packet](#negotiation-packet)). An advertiser can also omit a payload to avoid computing potentially costly setup for a feature which its peer may not support, at the cost of up to one round trip.[^deferral]

### Specifying features

The specification of a feature MUST define:

- its header, recorded in the [table of headers](#feature-headers);
- the structure and interpretation of its payload, in an advertisement and in a selection, and how a node shows that it has omitted one;
- the features, if any, with which it is incompatible, so that the two cannot be negotiated together;
- the feature packets it requires, if any: which node sends each and in what order, and what its contents hold after the header, such that both nodes agree on which feature packets to expect;
- what a node does when the feature cannot be performed, for example on receiving a malformed payload or feature packet, such that the connection never continues with the two nodes disagreeing on whether it was performed; and
- any change it makes to how later packets are encrypted or authenticated, or to the session ID, and the packet from which that change applies.

Features that require payloads SHOULD allow the selector to always send its payload in the selection, whether or not the advertiser omitted its own. This keeps the cost of an advertiser [omitting its payload](#omitting-payloads) to one round trip.

Authentication features SHOULD authenticate everything exchanged before them, including the contents of both negotiation packets, so that successful authentication shows that nothing was stripped or altered.[^transcript]

### Feature headers

This document defines no features. It reserves the following headers:

| Header | Use |
| ------ | --- |
| 0 | Reserved for an alternative header format |
| 240 to 255 | Reserved for experiments |

Headers 240 to 255 are never assigned to a specification. A node that uses one of them has to expect that other nodes use it differently.

Additional headers may be defined by other BIPs. They should be added to the [feature headers table](bip-transport-feature-negotiation/feature_headers.md) to ease coordination.[^msgtypeids] Headers 1 to 239 that do not appear in that table are unassigned.

### Connection policy

Nodes SHOULD accept inbound connections regardless of what features their peers select.[^partition] A node MAY disconnect peers it connected to based on the features they support.

## Rationale

### Using the version packet

BIP 324 left the version packet unspecified for exactly this purpose: negotiating future Transport upgrades.[^bip324version] There are two main alternatives: BIP 434 and defining a V3 Transport. Neither fits, as explained below, and that leaves in-band negotiation inside V2. Given that a negotiation packet is needed in any case, defining an entirely new one instead of redefining the version packet would add overhead and potentially round trips. The version packet exists, is unused, and is positioned ideally and intentionally for this purpose: every V2 node already sends one, and already ignores the contents of the one it receives.[^ignore]

### Alternatives

**BIP 434.** BIP 434 "defines a peer-to-peer (P2P) message that can be used for announcements and negotiation related to support of new peer-to-peer features", but it negotiates which messages are sent and how they encode data, making it a Protocol Feature Negotiation of sorts. Encryption and authentication are Transport features, not Protocol features. The timing is also an issue: BIP 434 negotiates between the `version` and `verack` messages, so a Transport upgrade negotiated through it would take effect partway through the Protocol Phase, which would then take place over two separate Transports.

**A V3 Transport.** Defining a V3 Transport that incorporates an upgrade is also an option, but it would require committing to one specific design from the outset. If that design were broken or otherwise rejected, a V4 Transport would be needed to replace it. Negotiating upgrades in band allows for modularity and backward compatibility, which a V3 Transport does not offer: upgrades can be adopted and replaced independently of one another, and nodes that support none of them continue to use BIP 324 unchanged.

### Features rather than a version number

BIP 324 describes its upgrade path as "transport versioning",[^bip324version] and the version packet could instead carry a single version number, with each version including every upgrade before it. Upgrades may not be adopted in so strict an order, however: some nodes may support an encryption upgrade but not authentication, or vice versa, or different versions of each. A list of features lets each upgrade be negotiated on its own.

### Scope of features

In practice, no Transport features are foreseen other than encryption and authentication upgrades, which are also the examples BIP 324 gives.[^bip324version] Features are nonetheless not restricted to those. Restricting them would make coordinating encryption upgrades easier, as their place among other features could be fixed in advance, but a feature's specification can itself name the features it has to wait for. Nor could a restriction be enforced between nodes, which ignore the features they do not support: whether a feature belongs is decided when its header is assigned. The one limit is that a feature modifies the Transport Layer. Negotiating which messages are sent, and how they encode data, is left to BIP 434.

### Roles

**The responder advertises.** In BIP 324 the responder sends its version packet in the same flight as its public key, before it can have received the initiator's, which follows in the next flight. Making the responder's negotiation packet the advertisement and the initiator's the selection therefore completes negotiation within the flights BIP 324 already uses. As a consequence, the initiator gets to choose between potentially mutually incompatible features. The responder needs no way to take that choice for itself, such as passing the role of advertiser to the initiator, as it can always withhold supported features from its advertisement to enforce what it wants.

**The advertisement includes incompatible features.** Advertising every supported feature, including alternatives that cannot be used together, such as two versions of the same upgrade, lets the selector choose among them in a single exchange. Ordering them by preference lets the advertiser guide that choice without withholding the alternatives it would still accept, which is how BIP 434 handles versions of a feature.[^preference]

**The initiator selects.** BIP 434 has both peers announce the features they support, and each enables those the other announced as well. Here only the responder announces, and the initiator answers with a selection. The initiator therefore reveals only the features it uses on a connection rather than everything it supports, and which of several mutually incompatible features is used is stated by the selection, so the two nodes never have to arrive at the same answer separately. The cost is that a selector has to wait for the advertisement before it sends its own negotiation packet, where BIP 324 lets both version packets be sent without waiting for the other.

**Each role handles a bad packet differently.** A selector that cannot parse the advertisement can always ignore it: by selecting nothing from it, the selector makes sure that nothing in it is used. An advertiser has no such option. If it cannot parse the selection, or the selection asks for what it cannot do, there is no way to proceed, as the selector takes features to be negotiated that the advertiser cannot perform. The obligation to disconnect binds only an advertiser that advertised features, so that BIP 324 implementations, which ignore the version packet they receive, already meet it.

### Order of features

This document does not specify the order in which negotiated features are performed. A feature packet begins with its feature's header, so a node can tell which feature it belongs to whatever the order, and features that do not depend on one another can share the same flights, where performing them one at a time would add round trips. A feature that does depend on another, such as an authentication feature run over an encryption upgrade, says so in its own specification. A node that receives a packet it does not expect disconnects, as the two nodes then disagree on what is being performed, and ignoring the packet would leave each waiting for the other.

### Size limit and omitted payloads

BIP 324 allows the contents of a packet to reach 2<sup>24</sup>-1 bytes, but implementations accept less (see [Backward Compatibility](#backward-compatibility)), and an advertisement is sent to every initiator, including those that support no features. The contents of a negotiation packet are therefore limited to 4,000,000 bytes, the size of the largest message payload. Features whose payload bytes together exceed that limit can still be used, although some payloads will have to be deferred to feature packets instead. The same mechanism lets an advertiser avoid computing potentially costly setup for a feature which its peer may not support. How an omission is shown is left to each feature, since some features never have a payload and only a feature's specification says whether it does. An empty payload is recommended because it needs no encoding of its own.

### One-byte headers

A feature is identified by a single byte, assigned through a table as BIP 324 assigns its one-byte message type IDs. There should be far fewer than 100 features, as Transport features other than encryption and authentication upgrades are not foreseen, so one byte is enough. If more features are added than the one-byte header can hold, header 0, reserved for an alternative header format, can be used to extend the range. BIP 434 instead identifies Protocol features by an identifier chosen without coordination, where the `featureid` "MUST be a globally unique identifier for the feature". Header 0 also reserves the ability to add identifiers like BIP 434's later, should they be needed. Headers 240 to 255 are set aside for experiments, so that a trial does not take a value which a specification may later be assigned.

### Staggered negotiation

Splitting feature advertisements across separate negotiation packets would allow nodes to withhold advertising authentication features until after an encryption upgrade is performed, for example. No mechanism for this is specified here: it is left to a later feature, which could be performed after an encryption upgrade and carry a further advertisement and selection in its feature packets. The cost of adding it later is that not every peer will support it. A responder has to decide what to advertise before it knows whether its peer supports that feature, so anything it withholds cannot be negotiated with a peer that does not, unless it is advertised openly. A feature that is to be withheld can avoid this by requiring support for staggering, so that no peer supports one without the other.

## Security Considerations

**Stripping features.** Negotiation packets are encrypted and authenticated under BIP 324's session keys, but BIP 324 does not authenticate peers, so a man-in-the-middle *can* strip features from either negotiation packet. A node cannot tell whether its peer does not support a feature or had its advertisement or selection stripped.

An authentication feature can make stripping detectable. If every node challenges every peer, there is no signal telling a man-in-the-middle which connections are safe to tamper with, and a node expecting an authenticated connection can treat a missing authentication advertisement as evidence of interference. The connection need not end, and should continue unauthenticated as with any peer lacking some feature, but the interference becomes visible. An authentication feature that authenticates everything exchanged before it, as [Specifying features](#specifying-features) asks, shows on success that neither negotiation packet was stripped.

**Exposure of advertisements.** The responder sends its advertisement to every initiator that completes the key exchange, so the features a node supports are visible to anyone who connects to it, and the advertisement is protected only by BIP 324's encryption, as no upgrade has yet been performed. The selection is protected in the same way, though it reaches only the responder and shows only the features the initiator selected. Features are best designed so that their advertisement payloads do not identify the node; withholding a feature's advertisement until after an encryption upgrade is what staggered negotiation would allow (see [Staggered negotiation](#staggered-negotiation)). Large payloads also change the sizes of the BIP 324 handshake's flights, which a passive observer can see, though garbage and decoy packets can be used to shape them as BIP 324 intends.[^shaping]

## Backward Compatibility

BIP 324 requires a node to ignore the contents of the version packet it receives, and Bitcoin Core does so,[^ignore] as do btcd and the Rust `bip324` library.[^otherimpls] An unupgraded initiator therefore ignores an upgraded responder's advertisement and sends an empty version packet, which is an empty selection. An unupgraded responder sends an empty version packet, which is an empty advertisement, from which an upgraded initiator can select nothing. Either way, no feature is negotiated, no feature packets are sent, and the connection proceeds exactly as specified by BIP 324.

Implementations may limit the size of packets they accept. Bitcoin Core disconnects a peer that sends any packet, the version packet included, whose contents exceed 4,000,013 bytes.[^maxcontents] The limit of 4,000,000 bytes on the contents of a negotiation packet keeps every advertisement within that.

V1 connections are unaffected, as V1 exchanges no bytes during its Transport Phase and so has no version packet in which to negotiate.

## Copyright

This BIP is licensed under the CC0-1.0 license.

[^bip324version]: BIP 324's responder "Sends a version packet with empty content, to indicate support for the v2 P2P protocol proposed by this document. Any other value for content is reserved for future versions." Its note on what those versions could add reads "Examples of features that could be added in future versions include post-quantum cryptography upgrades to the handshake, and optional authentication", and among its goals is upgradability, through "an upgrade path using transport versioning which can be used to add features like authentication, PQC handshake upgrade, etc. in the future."

[^pqthread]: For example, [A Post-Quantum Path for BIP 324](https://groups.google.com/g/bitcoindev/c/n_5WuKVYqwI).

[^securityservice]: As defined by [NIST](https://csrc.nist.gov/glossary/term/security_service).

[^headerbyte]: This is distinct from BIP 324's "1-byte header which consists of transport layer protocol flags", which begins every packet's plaintext and carries its ignore bit. A packet's contents follow that header byte, so a feature's header is part of the contents.

[^compactsize]: This definition is taken verbatim from [BIP 434](https://github.com/bitcoin/bips/blob/master/bip-0434.md), which adapts that of [BIP 152](https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki). Where BIP 152 leaves other encodings "with undefined behavior", this specification treats them as a parse failure; see [Negotiation packet](#negotiation-packet).

[^notamessage]: A packet containing a message begins its contents with a message type; see [BIP 324's message structure](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki#v2-bitcoin-p2p-message-structure). The negotiation packet never contains a message.

[^lengthsize]: `CompactSize` also has a 9-byte form, but it is minimal only for values of 2<sup>32</sup> or more, which exceed the size of any packet's contents, so a 9-byte `length` is never valid.

[^maxsize]: Each BIP 324 packet begins with "a 3-byte encrypted length field, encoding the length of the contents (between 0 and 2<sup>24</sup>-1, inclusive)"; see [BIP 324's packet encryption](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki#packet-encryption). The contents of a negotiation packet are limited to less: to the size of the largest message payload, of which BIP 324 notes that "The current Bitcoin P2P protocol has no messages which support more than 4000000 bytes of application payload." This keeps every negotiation packet within what Bitcoin Core accepts in any packet; see [Backward Compatibility](#backward-compatibility).

[^duplicates]: This is only relevant in the event that the repeated features carry distinct payloads.

[^featuredata]: Wording from BIP 434's description of `featuredata`.

[^order]: BIP 324 lists the flights of its handshake as follows: "the initiator sends public key + garbage", "the responder sends public key + garbage + garbage terminator + decoy packets (optional) + version packet", and "the initiator sends garbage terminator + decoy packets (optional) + version packet".

[^preference]: This is BIP 434's approach to versions of a feature, in which a peer's incompatible features are "ordered from most preferred to least" and the initiating peer is to "enable the first feature that your peer announced, that you also support". There both peers announce their features and the listening peer's order decides; here only the advertiser announces, and its order decides in the same way.

[^ignore]: BIP 324 specifies this receive behavior: "Receives a packet, ignores its contents. The idea is that features added by future versions get negotiated based on what is supported by both parties... we defer specifying the encoding for such version content until there is a need for it." Bitcoin Core implements it literally; see `VERSION_CONTENTS` in [Bitcoin Core `src/net.h`](https://github.com/bitcoin/bitcoin/blob/master/src/net.h), whose documentation reads "BIP324 stipulates that senders should leave this empty, and receivers should ignore it. Future extensions can change what is sent as long as an empty version packet contents is interpreted as no extensions supported." Any BIP 324 compliant implementation should do the same.

[^nodelay]: This delays nothing in practice. A responder's first message is its `version` message, which it sends in response to the initiator's, and the initiator's cannot arrive before the selection. See `ProcessMessage` in [Bitcoin Core `src/net_processing.cpp`](https://github.com/bitcoin/bitcoin/blob/master/src/net_processing.cpp): "Inbound peers send us their version message when they connect. We send our version message in response."

[^deferral]: If the feature is negotiated, the advertiser sends the omitted payload in a feature packet once it has received the selection, rather than in the advertisement before it. Where the selector could still send its own payload in the selection, that feature packet is the only one added, and the Transport Phase ends one flight, or half a round trip, later. Where the selector's payload depends on the advertiser's, it follows in a further feature packet, and the Transport Phase ends a full round trip later. In the first case the advertiser is the first node able to send a message, so the half round trip is only what the connection loses if the advertiser sends its `version` message without waiting for the selector's. If it waits, as responders do today, the selector's first message, which could otherwise have followed the selection, leaves a full round trip later in either case. Omitting the payload costs nothing where the advertiser has to send a feature packet at that point in any case.

[^transcript]: BIP 324 anticipates that "peer operators can compare session IDs manually, or using optional authentication methods possibly introduced in future protocol versions." Authenticating the session ID does most of this: the session ID and the keys protecting every packet are derived from the same shared secret, so it shows that the packets exchanged so far came from the authenticated peer, and it detects a man-in-the-middle who establishes a separate session with each node, as their session IDs then differ. It does not detect an attacker able to recover the keys of a single session, who could alter packets, the negotiation packets included, while both nodes see the same session ID. Authenticating the packets themselves does.

[^msgtypeids]: Wording from BIP 324, which keeps its table of additional message type IDs in an auxiliary file as well: [One-byte message type allocations](https://github.com/bitcoin/bips/blob/master/bip-0324/message_type_ids.md).

[^partition]: This is to avoid partitioning, as with BIP 324's goal that "v2 clients will allow inbound v1 connections to minimize risk of network partitions." If a peer does not support the desired level of encryption or authentication, the connection can be treated like a V1 connection, that is, sensitive data can be withheld from insecure or unauthenticated connections.

[^shaping]: BIP 324 describes garbage as "providing a form of shapability", and says of decoy packets: "These form the primary shapability mechanism in the protocol. How and when to use them is out of scope for this document."

[^otherimpls]: Both discard the contents of the version packet they receive: see `CompleteHandshake` in [btcd `v2transport/transport.go`](https://github.com/btcsuite/btcd/blob/master/v2transport/transport.go) and `receive_version` in [rust-bitcoin `bip324` `protocol/src/handshake.rs`](https://github.com/rust-bitcoin/bip324/blob/main/protocol/src/handshake.rs).

[^maxcontents]: `MAX_CONTENTS_LEN` in `V2Transport::ProcessReceivedPacketBytes`, [Bitcoin Core `src/net.cpp`](https://github.com/bitcoin/bitcoin/blob/master/src/net.cpp): one byte for the long message type encoding, 12 bytes of message type, and a payload of at most `MAX_PROTOCOL_MESSAGE_LENGTH` (4,000,000) bytes.
