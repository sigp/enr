# NAT Extension for ENRs

This document details the extra fields added to ENRs to minimally support NAT
hole-punching in [discv5](https://github.com/sigp/discv5).


## Extended Fields

This library supports the following additional fields:

| Key | Value |
| `features` | A bitfield representing which features are supported |
| `nat` | IPv4 address, 4 bytes, representing a NAT'd external IP address |
| `nat6` | IPv6 address, 16 bytes, representing a NAT'd external IPv6 address |

### Features

This field is a generic bitfield that allows ENRs to indicate which features
they support. The current supported features are:
- 1 - NAT_SUPPORT: Setting the first bit (big-endian) indicates that this node
	supports NAT hole-punching. This means it can act as a relayer to
	facilitate hole punching between other nodes that also support this
	feature.

Features may be added in the future.

### NAT

The `nat` and `nat6` fields are used to indicate that the current node is
behind a NAT and the external address in this field is only reachable via a
hole-punching technique. 

Nodes that have either the `nat` or `nat6` fields in their ENR, should not have
the `ip` field set. Having both the `ip` field and `nat` field set is
considered an invalid configuration.

#### Symmetric and Asymmetric NATs

An asymmetric NAT is one where the router maintains an external IP:PORT mapped
to an internal node. Typically packets are restricted such that only external
hosts that have been contacted by the local host can send packets through this
mapping.

A symmetric NAT involves individual port mappings for every external host
contacted by the local host. Each external host, therefore has its own port in
which it can contact the local host via the external ip address. 

For asymmetric NATs, nodes should put a known contactable external port for
their mapping in either the `udp` or `udp6` fields in addition to the
corresponding `nat` and/or `nat6` fields.

For symmetric NATs, nodes should leave the `udp` or `udp6` fields unset and
only set the `nat` and/or `nat6` fields in their ENR. 

Thus, the different forms of NAT'd peers can be identified via the ENRs as:
- Symmetric: `nat` and/or `nat6` field set, `udp` or `udp6` field unset.
- Asymmetric: `nat` and/or `nat6` field set and the `udp` and/or `udp6` fields
	set.
