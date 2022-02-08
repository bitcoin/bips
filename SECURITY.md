# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :v:                |
| 5.0.x   | :v:                |
| 4.0.x   | :v:                |
| < 4.0   | :v:                |

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
declined, etc.
==Clearer Type field==

Often it is unclear where the line is drawn between Informational and Standards Track (eg, BIPs 49, 84).

==Clarify author reassignment==

We have several BIPs abandoned by their original author(s) that should probably get reassigned, but also likely nobody wants to be the author for them. Some kind of "ghost author" where someone simply ACKs changes but takes no responsibility for the BIP might be a good idea?

==Drop BIP Comments==

In theory, it's a nice idea, but in practice it seems to rarely be used, and just annoy BIP authors.

TODO: Talk to people apparently annoyed by them.

==Document process for adding BIP editors==

Historically, we've had a single BIP editor simply passing the torch to the next. It seems time to expand to multiple editors, and some explicit process for adding them should be specified.

==Cleanup auto-Rejection==

The timeout to Rejected status has become controversial. Perhaps split out a new status for BIPs not doing anything but not explicitly rejected?

For more details on this see: https://github.com/bitcoin/bips/pull/1012, https://github.com/bitcoin/bips/pull/1016, https://github.com/bitcoin/bips/pull/1006

==BIP versions==

A number of BIPs, including the BIP process itself, have found it better to just take the old BIP and revise it, rather than describing changes. It might be useful to have (eg) BIP 174v2 instead of an entirely new BIP number for PSBTv2.

==Markdown==

Lightning has created a parallel process called BOLT. My only guess is this is due to a preference for Markdown. If people want to use Markdown, let's restore it as an allowed format.

==Merge BOLTs==

Figure out what would be needed to merge BOLTs in so there isn't a separate specification repository/process.

==Greater controls over soft fork, hard fork BIPs and activation BIPs==

I'm open to ideas on this but I think (after Taproot) any soft fork BIP should only state recommended activation parameters by the author(s) and the activation BIP that is recommended by the author(s) (and no changes to the activation BIP should be included within the soft fork BIP itself). Activation BIPs should be finalized prior to including recommended activation parameters in a soft fork BIP. In Taproot's case we are in a scenario where we don't know which activation BIP Core is using and that is not in a situation we want to be in in the future.

What I'm concerned about is a future scenario where a malicious party (e.g Mallory) gets a BIP number, lays out soft fork changes in the BIP, includes complex changes to an activation BIP or maybe even an entirely new activation BIP within the soft fork BIP itself all without community consensus. Mallory then attempts to activate the soft fork either by pressurizing Core maintainers to merge the soft fork changes or releasing an alternative implementation. I wonder to what extent BIP maintainers should step in or be entirely helpless in this scenario. Perhaps a disputed label by BIP maintainers if the soft fork changes (excluding activation) have not been merged into Core. The precedent that Taproot does set (thankfully) is overwhelming consensus within Core and in the wider community on what was included in the Taproot soft fork (excluding activation). What was disputed was what activation BIP should be used, what the activation parameters should be and who should release the activation code. In terms of the actual soft fork (Taproot) it was not disputed barring a single long term contributor's quantum concerns. I expect future soft forks will have the same disagreements on activation mechanisms. But what must continue is a commitment to overwhelming consensus on the soft fork itself. I'm open to ideas on what (if anything) BIP maintainers can do to ensure that is the case.

I am also not sure on this process that BIP authors get to merge whatever they want (potentially downright inaccuracies) into potential soft fork BIPs without review of other subject matter experts. But that would be a bigger change and I'd need to give it more thought.

It is good if we get a second BIP maintainer. To ask Luke to merge in activation parameters that aren't exactly the same activation parameters as the ones in a release he is contributing to is not fair on Luke. 

==Revisit the requirement for BIP champions to ACK spelling changes==

A while back Luke opened a PR (https://github.com/bitcoin/bips/pull/596) to allow BIP editors to merge spelling fixes without notifying and getting an ACK from a BIP champion. I think we either get something like this merged or we ask people not to open PRs with spelling fixes across multiple BIPs. Given there were concerns from kanzure etc on Luke's PR it looks likely that it is the latter rather than the former.

==Add list of projects/services implementing the BIP==

Developers may use these lists to estimate which BIPs have become de facto standards, which ones never gained traction or were abandoned. 

==Additional number/document registries==

Versionbits assignments, Lightning extensions, BIP 39 word lists, etc could use some kind of additional number registries and/or document subdirectories.

==Bitcoin Core policy changes impacting Lightning/Layer 2 security guarantees==

Bitcoin Core policy (https://github.com/bitcoin/bitcoin/tree/master/src/policy) changes can have unintended impact on Lightning/Layer 2 security and should (imo) be BIPed. Ideally policy guarantees would be in some way binding for Lightning/Layer 2 (brought up and requested on multiple occasions) but at the very least they should be discussed, communicated on the mailing list and BIPed. Interesting recent case study was https://github.com/bitcoin/bitcoin/pull/22665 and Core not implementing the exact wording of BIP 125 RBF. In this case (for various reasons) it seems to be resolved by Core just removing references to BIP 125.
