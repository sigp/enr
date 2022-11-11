# NAT Extension for ENRs

This document details the extra fields added to ENRs to minimally support NAT
hole-punching in [discv5](https://github.com/sigp/discv5).


## Extended Fields

This library supports the following additional fields:

| Key | Value |
| --- | ----- |
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

The `nat` and `nat6` fields are used to indicate how an external peer should
attempt a connection to the local node. Setting these fields, indicate that the
local node has identified itself as being behind a NAT and a hole-punching
technique should be used to contact it.

Nodes that have either the `nat` or `nat6` fields in their ENR, should not have
the corresponding `ip` field set. Having both the `ip` field and `nat` field set is
considered an invalid configuration.

### Connections to an ENR

The fields of an ENR should dictate how external peers are able to initiate 
connections. The following general rules apply (this is detailed for the IPv4
case but is generalised to the IPv6 case and corresponding fields):

- The `ip` and `nat` fields are absent. This indicates the peer is unsure of its
external/reachable address.
- The `ip` field is present and the `nat` field is absent. This indicates that
	external peers can connect directly to the IP address given by the `ip`
	field. The corresponding `udp` or `tcp` port can be used.
- The `ip` field is absent and the `nat` field is present. There are two cases
	here:
	- The `udp` and/or the `tcp` port field is present. This indicates the peer
		is behind a NAT and an appropriate hole-punching technique should be
		used and can be contacted via the IP address in the `nat` field and the
		port in either the `udp` or `tcp` port.
	- The `udp` and `tcp` port fields are absent. This indicates the peer is
		behind a NAT that maps each external connection to a new port
		(Symmetric NAT). There is no contactable port to reach this peer.
		Specific hole-punching techniques can be used to reach this peer. 
- The `ip` and `nat` fields are both present. This is considered an invalid
	configuration.
