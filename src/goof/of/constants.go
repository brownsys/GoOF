// OpenFlow protocol.
package of

/* Version number:
 * Non-experimental versions released: 0x01
 * Experimental versions released: 0x81 -- 0x99
 *
 * The most significant bit being set in the version field indicates an
 * experimental OpenFlow version.
 */
const OFP_VERSION = 0x01

const OFP_MAX_TABLE_NAME_LEN = 32
const OFP_MAX_PORT_NAME_LEN = 16

const OFP_TCP_PORT = 6633
const OFP_SSL_PORT = 6633

const EthAlen = 6 /* Bytes in an Ethernet address. */

/* Port numbering.  Physical ports are numbered starting from 1. */
const (
	/* Maximum number of physical switch ports. */
	OFPP_MAX = 0xff00

	/* Fake output "ports". */
	OFPP_IN_PORT = 0xfff8 /* Send the packet out the input port.  This
	   virtual port must be explicitly used
	   in order to send back out of the input
	   port. */
	OFPP_TABLE = 0xfff9 /* Perform actions in flow table.
	   NB: This can only be the destination
	   port for packet-out messages. */
	OFPP_NORMAL = 0xfffa /* Process with normal L2/L3 switching. */
	PortFlood   = 0xfffb /* All physical ports except input port and
	   those disabled by STP. */
	OFPP_ALL        = 0xfffc /* All physical ports except input port. */
	OFPP_CONTROLLER = 0xfffd /* Send to controller. */
	OFPP_LOCAL      = 0xfffe /* Local openflow "port". */
	OFPP_NONE       = 0xffff /* Not associated with a physical port. */
)

const (
	/* Immutable messages. */
	OFPT_HELLO        Type = iota /* Symmetric message */
	OFPT_ERROR                    /* Symmetric message */
	OFPT_ECHO_REQUEST             /* Symmetric message */
	OFPT_ECHO_REPLY               /* Symmetric message */
	OFPT_VENDOR                   /* Symmetric message */

	/* Switch configuration messages. */
	OFPT_FEATURES_REQUEST   /* Controller/switch message */
	OFPT_FEATURES_REPLY     /* Controller/switch message */
	OFPT_GET_CONFIG_REQUEST /* Controller/switch message */
	OFPT_GET_CONFIG_REPLY   /* Controller/switch message */
	OFPT_SET_CONFIG         /* Controller/switch message */

	/* Asynchronous messages. */
	OFPT_PACKET_IN    /* Async message */
	OFPT_FLOW_REMOVED /* Async message */
	OFPT_PORT_STATUS  /* Async message */

	/* Controller command messages. */
	OFPT_PACKET_OUT /* Controller/switch message */
	OFPT_FLOW_MOD   /* Controller/switch message */
	OFPT_PORT_MOD   /* Controller/switch message */

	/* Statistics messages. */
	OFPT_STATS_REQUEST /* Controller/switch message */
	OFPT_STATS_REPLY   /* Controller/switch message */

	/* Barrier messages. */
	OFPT_BARRIER_REQUEST /* Controller/switch message */
	OFPT_BARRIER_REPLY   /* Controller/switch message */

	/* Queue Configuration messages. */
	OFPT_QUEUE_GET_CONFIG_REQUEST /* Controller/switch message */
	OFPT_QUEUE_GET_CONFIG_REPLY   /* Controller/switch message */
)

const OFP_DEFAULT_MISS_SEND_LEN uint16 = 128

const (
	FragNormal ConfigFlags = 0 // No special handling for IP fragments.
	FragDrop   ConfigFlags = 1 // Drop fragments.
	FragReasm  ConfigFlags = 2 // Reassemble (only if OFPC_IP_REASM set).
)

// Capabilities supported by the datapath.
const (
	FlowStats    = 1 << 0 /* Flow statistics. */
	TableStats   = 1 << 1 /* Table statistics. */
	PortStats    = 1 << 2 /* Port statistics. */
	STP          = 1 << 3 /* 802.1d spanning tree. */
	ofcpReserved = 1 << 4 /* Reserved must be zero. */
	IpReasm      = 1 << 5 /* Can reassemble IP fragments. */
	QueueStats   = 1 << 6 /* Queue statistics. */
	ArpMatchIp   = 1 << 7 /* Match IP addresses in ARP pkts. */
)

// Flags to indicate behavior of the physical port.  These flags are
// used in PhyPort to describe the current configuration.  They are
// used in the PortMod message to configure the port's behavior.
const (
	OfppcPortDown   uint32 = 1 << 0 // port is administratively down
	OfppcNoStp      uint32 = 1 << 1 // disable 802.1d spanning tree on port
	OfppcNoRecv     uint32 = 1 << 2 // drop all packets except spanning tree packets
	OfppcNoRecvStp  uint32 = 1 << 3 // drop received 802.1d stp packets
	OfppcNoFlood    uint32 = 1 << 4 // do not include this port when flooding
	OfppcNoFwd      uint32 = 1 << 5 // drop packets forwarded to port
	OfppcNoPacketIn uint32 = 1 << 6 // do not send packet-in msgs for port
)

// Current state of the physical port.  These are not configurable from
// the controller.
const (
	OfppsLinkDown uint32 = 1 << 0 /* No physical link present. */
	// The OfppsStp* bits have no effect on switch operation.  The
	// controller must adjust OfppcNoRecv, OfppcNoFwd,
	// OfppcNoPacketIn appropriately to fully implement an 802.1D spanning
	// tree.
	OfppsStpListen  uint32 = 0 << 8 // Not learning or relaying frames
	OfppsStpLearn   uint32 = 1 << 8 // learning but not relaying frames
	OfppsStpForward uint32 = 2 << 8 // learning and relaying frames
	OfppsStpBlock   uint32 = 3 << 8 // not part of spanning tree
	OfppsStpMask    uint32 = 3 << 8 // bit mask for ofpps_stp_* values
)

// Features of physical ports available in a datapath
const (
	Ppf10MBHd    uint32 = 1 << 0  /* 10 Mb half-duplex rate support. */
	Ppf10MBFd    uint32 = 1 << 1  /* 10 Mb full-duplex rate support. */
	Ppf100MBHd   uint32 = 1 << 2  /* 100 Mb half-duplex rate support. */
	Ppf100MBFd   uint32 = 1 << 3  /* 100 Mb full-duplex rate support. */
	Ppf1GBHd     uint32 = 1 << 4  /* 1 Gb half-duplex rate support. */
	Ppf1GBFd     uint32 = 1 << 5  /* 1 Gb full-duplex rate support. */
	Ppf10GBFd    uint32 = 1 << 6  /* 10 Gb full-duplex rate support. */
	PpfCopper    uint32 = 1 << 7  /* Copper medium. */
	PpfFiber     uint32 = 1 << 8  /* Fiber medium. */
	PpfAutoneg   uint32 = 1 << 9  /* Auto-negotiation. */
	PpfPause     uint32 = 1 << 10 /* Pause. */
	PpfPauseAsym uint32 = 1 << 11 /* Asymmetric pause. */
)

// What changed about the physical port
const (
	PprAdd    = iota // The port was added.
	PprDelete        // The port was removed.
	PprModify        // Some attribute of the port has changed.
)

// Why is this packet being sent to the controller?
const (
	ReasonNoMatch uint8 = iota /* No matching flow. */
	ReasonAction               /* Action explicitly output to controller. */
)

const (
	FCAdd          = iota /* New flow. */
	FCModify              /* Modify all matching flows. */
	FCModifyStrict        /* Modify entry strictly matching wildcards */
	FCDelete              /* Delete all matching flows. */
	FCDeleteStrict        /* Strictly match wildcards and priority. */
)

/* Flow wildcards. */
const (
	FwInPort  uint32 = 1 << 0 /* Switch input port. */
	FwDlVlan  uint32 = 1 << 1 /* VLAN id. */
	FwDlSrc   uint32 = 1 << 2 /* Ethernet source address. */
	FwDlDst   uint32 = 1 << 3 /* Ethernet destination address. */
	FwDlType  uint32 = 1 << 4 /* Ethernet frame type. */
	FwNwProto uint32 = 1 << 5 /* IP protocol. */
	FwTpSrc   uint32 = 1 << 6 /* TCP/UDP source port. */
	FwTpDst   uint32 = 1 << 7 /* TCP/UDP destination port. */

	/* IP source address wildcard bit count.  0 is exact match 1 ignores the
	 * LSB 2 ignores the 2 least-significant bits ... 32 and higher wildcard
	 * the entire field.  This is the *opposite* of the usual convention where
	 * e.g. /24 indicates that 8 bits (not 24 bits) are wildcarded. */
	FwNwSrcShift uint32 = 8
	FwNwSrcBits  uint32 = 6
	FwNwSrcMask  uint32 = ((1 << FwNwSrcBits) - 1) << FwNwSrcShift
	FwNwSrcAll   uint32 = 32 << FwNwSrcShift

	/* IP destination address wildcard bit count.  Same format as source. */
	FwNwDstShift uint32 = 14
	FwNwDstBits  uint32 = 6
	FwNwDstMask  uint32 = ((1 << FwNwDstBits) - 1) << FwNwDstShift
	FwNwDstAll   uint32 = 32 << FwNwDstShift

	FwDlVlanPcp uint32 = 1 << 20 /* VLAN priority. */
	FwNwTos      uint32 = 1 << 21 /* IP ToS (DSCP field 6 bits). */
	FwAll uint32 = ((1 << 22) - 1) // Wildcard all fields
)

/* The wildcards for ICMP type and code fields use the transport source
 * and destination port fields respectively. */
const FW_ICMP_TYPE = FwTpSrc
const FW_ICMP_CODE = FwTpDst

/* Values below this cutoff are 802.3 packets and the two bytes
 * following MAC addresses are used as a frame length.  Otherwise the
 * two bytes are used as the Ethernet type.
 */
const OFP_DL_TYPE_ETH2_CUTOFF = 0x0600

/* Value of dl_type to indicate that the frame does not include an
 * Ethernet type.
 */
const OFP_DL_TYPE_NOT_ETH_TYPE = 0x05ff

/* The VLAN id is 12-bits so we can use the entire 16 bits to indicate
 * special conditions.  All ones indicates that no VLAN id was set.
 */
const OFP_VLAN_NONE = 0xffff
