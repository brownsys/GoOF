package of

/* Version number:
 * Non-experimental versions released: 0x01
 * Experimental versions released: 0x81 -- 0x99
 */
/* The most significant bit being set in the version field indicates an
 * experimental OpenFlow version.
 */
const OFP_VERSION =  0x01

const OFP_MAX_TABLE_NAME_LEN = 32
const OFP_MAX_PORT_NAME_LEN = 16

const OFP_TCP_PORT = 6633
const  OFP_SSL_PORT = 6633

const OFP_ETH_ALEN = 6    /* Bytes in an Ethernet address. */

/* Port numbering.  Physical ports are numbered starting from 1. */
const (
  /* Maximum number of physical switch ports. */
  OFPP_MAX = 0xff00

  /* Fake output "ports". */
  OFPP_IN_PORT  = 0xfff8  /* Send the packet out the input port.  This
        virtual port must be explicitly used
        in order to send back out of the input
        port. */
  OFPP_TABLE  = 0xfff9  /* Perform actions in flow table.
        NB: This can only be the destination
        port for packet-out messages. */
  OFPP_NORMAL   = 0xfffa  /* Process with normal L2/L3 switching. */
  PortFlood = 0xfffb  /* All physical ports except input port and
                         those disabled by STP. */
  OFPP_ALL  = 0xfffc  /* All physical ports except input port. */
  OFPP_CONTROLLER = 0xfffd  /* Send to controller. */
  OFPP_LOCAL  = 0xfffe  /* Local openflow "port". */
  OFPP_NONE   = 0xffff   /* Not associated with a physical port. */
)

type OfpType uint8

const (
  /* Immutable messages. */
  OFPT_HELLO OfpType = iota  /* Symmetric message */
  OFPT_ERROR     /* Symmetric message */
  OFPT_ECHO_REQUEST  /* Symmetric message */
  OFPT_ECHO_REPLY    /* Symmetric message */
  OFPT_VENDOR    /* Symmetric message */

  /* Switch configuration messages. */
  OFPT_FEATURES_REQUEST  /* Controller/switch message */
  OFPT_FEATURES_REPLY  /* Controller/switch message */
  OFPT_GET_CONFIG_REQUEST  /* Controller/switch message */
  OFPT_GET_CONFIG_REPLY  /* Controller/switch message */
  OFPT_SET_CONFIG    /* Controller/switch message */

  /* Asynchronous messages. */
  OFPT_PACKET_IN     /* Async message */
  OFPT_FLOW_REMOVED  /* Async message */
  OFPT_PORT_STATUS   /* Async message */

  /* Controller command messages. */
  OFPT_PACKET_OUT    /* Controller/switch message */
  OFPT_FLOW_MOD    /* Controller/switch message */
  OFPT_PORT_MOD    /* Controller/switch message */

  /* Statistics messages. */
  OFPT_STATS_REQUEST   /* Controller/switch message */
  OFPT_STATS_REPLY   /* Controller/switch message */

  /* Barrier messages. */
  OFPT_BARRIER_REQUEST   /* Controller/switch message */
  OFPT_BARRIER_REPLY   /* Controller/switch message */

  /* Queue Configuration messages. */
  OFPT_QUEUE_GET_CONFIG_REQUEST  /* Controller/switch message */
  OFPT_QUEUE_GET_CONFIG_REPLY   /* Controller/switch message */
)

/* Header on all OpenFlow packets. */
type OfpHeader struct {
  Version uint8 /* OFP_VERSION. */
  Type OfpType   /* One of the OFPT_ constants. */
  Length uint16 /* Length including this OfpHeader. */
  Xid uint32  /* Transaction id associated with this packet.
       Replies use the same id as was in the request
       to facilitate pairing. */
}
const OfpHeaderSize = 8


/* OFPT_HELLO.  This message has an empty body but implementations must
 * ignore any data included in the body to allow for future extensions. */
type OfpHello struct {
  OfpHeader
}

type OfpEchoRequest struct {
  OfpHeader
  Body []byte
}

type OfpEchoReply struct {
  OfpHeader
  Body []byte
}

const OFP_DEFAULT_MISS_SEND_LEN uint16 = 128

type  OfpConfigFlags uint16

const (
  /* Handling of IP fragments. */
  OFPC_FRAG_NORMAL OfpConfigFlags = 0 /* No special handling for fragments. */
  OFPC_FRAG_DROP OfpConfigFlags = 1  /* Drop fragments. */
  /* Reassemble (only if OFPC_IP_REASM set). */
  OFPC_FRAG_REASM OfpConfigFlags = 2 
  OFPC_FRAG_MASK OfpConfigFlags = 3
)

/* Switch configuration. */
type OfpSwitchConfig struct {
  OfpHeader
  flags OfpConfigFlags     /* OFPC_* flags. */
  MissSendLen uint16 /* Max bytes of new flow that datapath should
        send to the controller. */
}

/* Capabilities supported by the datapath. */
type OfpCapabilities uint32
const (
  OFPC_FLOW_STATS OfpCapabilities = 1 << 0  /* Flow statistics. */
  OFPC_TABLE_STATS OfpCapabilities = 1 << 1  /* Table statistics. */
  OFPC_PORT_STATS OfpCapabilities = 1 << 2  /* Port statistics. */
  OFPC_STP OfpCapabilities = 1 << 3 /* 802.1d spanning tree. */
  OFPC_RESERVED OfpCapabilities = 1 << 4 /* Reserved must be zero. */
  OFPC_IP_REASM OfpCapabilities = 1 << 5 /* Can reassemble IP fragments. */
  OFPC_QUEUE_STATS OfpCapabilities = 1 << 6 /* Queue statistics. */
  /* Match IP addresses in ARP pkts. */
  OFPC_ARP_MATCH_IP OfpCapabilities = 1 << 7 
)

/* Flags to indicate behavior of the physical port.  These flags are
 * used in OfpPhyPort to describe the current configuration.  They are
 * used in the OfpPortMod message to configure the port's behavior.
 */
type OfpPortConfig uint32
const (
  OFPPC_PORT_DOWN OfpPortConfig = 1 << 0  /* Port is administratively down. */
  /* Disable 802.1D spanning tree on port. */
  OFPPC_NO_STP OfpPortConfig = 1 << 1  
  /* Drop all packets except 802.1D spanning tree packets. */
  OFPPC_NO_RECV OfpPortConfig = 1 << 2 
  /* Drop received 802.1D STP packets. */
  OFPPC_NO_RECV_STP OfpPortConfig = 1 << 3  
  /* Do not include this port when flooding. */
  OFPPC_NO_FLOOD OfpPortConfig = 1 << 4  
  /* Drop packets forwarded to port. */
  OFPPC_NO_FWD OfpPortConfig = 1 << 5  
  /* Do not send packet-in msgs for port. */
  OFPPC_NO_PACKET_IN OfpPortConfig = 1 << 6   
)

/* Current state of the physical port.  These are not configurable from
 * the controller.
 */
type OfpPortState uint32
const (
  OFPPS_LINK_DOWN OfpPortState = 1 << 0 /* No physical link present. */

  /* The OFPPS_STP_* bits have no effect on switch operation.  The
   * controller must adjust OFPPC_NO_RECV OFPPC_NO_FWD and
   * OFPPC_NO_PACKET_IN appropriately to fully implement an 802.1D spanning
   * tree. */
  /* Not learning or relaying frames. */
  OFPPS_STP_LISTEN OfpPortState = 0 << 8 
  /* Learning but not relaying frames. */
  OFPPS_STP_LEARN OfpPortState = 1 << 8 
  OFPPS_STP_FORWARD OfpPortState = 2 << 8 /* Learning and relaying frames. */
  OFPPS_STP_BLOCK OfpPortState = 3 << 8 /* Not part of spanning tree. */
  OFPPS_STP_MASK OfpPortState = 3 << 8  /* Bit mask for OFPPS_STP_* values. */
)

/* Features of physical ports available in a datapath. */
type OfpPortFeatures uint32
const (
  OFPPF_10MB_HD OfpPortFeatures = 1 << 0 /* 10 Mb half-duplex rate support. */
  OFPPF_10MB_FD OfpPortFeatures = 1 << 1 /* 10 Mb full-duplex rate support. */
  /* 100 Mb half-duplex rate support. */
  OFPPF_100MB_HD OfpPortFeatures = 1 << 2
  /* 100 Mb full-duplex rate support. */
  OFPPF_100MB_FD OfpPortFeatures = 1 << 3 
  OFPPF_1GB_HD OfpPortFeatures = 1 << 4 /* 1 Gb half-duplex rate support. */
  OFPPF_1GB_FD OfpPortFeatures = 1 << 5 /* 1 Gb full-duplex rate support. */
  OFPPF_10GB_FD OfpPortFeatures = 1 << 6 /* 10 Gb full-duplex rate support. */
  OFPPF_COPPER OfpPortFeatures = 1 << 7 /* Copper medium. */
  OFPPF_FIBER OfpPortFeatures = 1 << 8 /* Fiber medium. */
  OFPPF_AUTONEG OfpPortFeatures = 1 << 9 /* Auto-negotiation. */
  OFPPF_PAUSE OfpPortFeatures = 1 << 10 /* Pause. */
  OFPPF_PAUSE_ASYM OfpPortFeatures = 1 << 11 /* Asymmetric pause. */
)

/* Description of a physical port */
type OfpPhyPort struct {
  PortNo uint16
  HwAddr [OFP_ETH_ALEN]uint8
  name [OFP_MAX_PORT_NAME_LEN]uint8 /* Null-terminated */

  config OfpPortConfig /* Bitmap of OFPPC_* flags. */
  state OfpPortState   /* Bitmap of OFPPS_* flags. */

  /* Bitmaps of OFPPF_* that describe features.  All bits zeroed if
   * unsupported or unavailable. */
  curr OfpPortFeatures /* Current features. */
  advertised OfpPortFeatures /* Features being advertised by the port. */
  supported OfpPortFeatures /* Features supported by the port. */
  peer OfpPortFeatures /* Features advertised by peer. */
}
const PhyPortSize = 48

type SwitchFeaturesRequest struct {
  OfpHeader
}

/* Switch features. */
type SwitchFeatures struct {
  OfpHeader
  SwitchFeaturesPart
  /* Port info.*/
  Ports []OfpPhyPort  /* Port definitions.  The number of ports
         is inferred from the length field in
         the header. */
}

type SwitchFeaturesPart struct {
  DatapathId uint64   /* Datapath unique ID.  The lower 48-bits are for
        a MAC address while the upper 16-bits are
        implementer-defined. */
  NBuffers uint32   /* Max packets buffered at once. */
  NTables uint8   /* Number of tables supported by datapath. */
  Pad [3]uint8   /* Align to 64-bits. */
  /* Features. */
  Capabilities OfpCapabilities  /* Bitmap of support "OfpCapabilities". */
  Actions OfpActionType   /* Bitmap of supported "OfpActionType"s. */
}
const SwitchFeaturesPartSize = 24


/* What changed about the physical port */
type OfpPortReason uint8
const (
  OFPPR_ADD = iota    /* The port was added. */
  OFPPR_DELETE     /* The port was removed. */
  OFPPR_MODIFY    /* Some attribute of the port has changed. */
)

/* A physical port has changed in the datapath */
type OfpPortStatus struct {
  OfpHeader
  reason OfpPortReason    /* One of OFPPR_*. */
  pad [7]uint8    /* Align to 64-bits. */
  desc OfpPhyPort
}

/* Modify behavior of the physical port */
type OfpPortMod struct {
  OfpHeader
  PortNo uint16
  HwAddr [OFP_ETH_ALEN]uint8 /* The hardware address is not
         configurable.  This is used to
         sanity-check the request so it must
         be the same as returned in an
         OfpPhyPort struct. */

  config OfpPortConfig  /* Bitmap of OFPPC_* flags. */
  mask OfpPortConfig  /* Bitmap of OFPPC_* flags to be changed. */

  advertise OfpPortFeatures /* Bitmap of "OfpPortFeatures"s.  Zero all
         bits to prevent any action taking place. */
  pad [4]uint8    /* Pad to 64-bits. */
}

/* Why is this packet being sent to the controller? */
type OfpPacketInReason uint8
const (
  OFPR_NO_MATCH = iota  /* No matching flow. */
  OFPR_ACTION     /* Action explicitly output to controller. */
)

/* Packet received on port (datapath -> controller). */
type PacketIn struct {
  OfpHeader
  PacketInPart
	/* Ethernet frame halfway through 32-bit word so the IP header is 32-bit 
   aligned.  The amount of data is inferred from the length field in the 
   header.  Because of padding offsetof(struct OfpPacketIn data) == 
   sizeof(struct OfpPacketIn) - 2. */
  EthFrame interface{}
}

type PacketInPart struct {
  BufferId uint32  /* ID assigned by datapath. */
  TotalLen uint16  /* Full length of frame. */
  InPort uint16    /* Port on which frame was received. */
  Reason OfpPortReason  /* Reason packet is being sent (one of OFPR_*) */
  Pad uint8
}
const PacketInPartSize = 10

type OfpActionType uint16
const (
  OFPAT_OUTPUT OfpActionType = iota  /* Output to switch port. */
  OFPAT_SET_VLAN_VID   /* Set the 802.1q VLAN id. */
  OFPAT_SET_VLAN_PCP   /* Set the 802.1q priority. */
  OFPAT_STRIP_VLAN   /* Strip the 802.1q header. */
  OFPAT_SET_DL_SRC   /* Ethernet source address. */
  OFPAT_SET_DL_DST   /* Ethernet destination address. */
  OFPAT_SET_NW_SRC   /* IP source address. */
  OFPAT_SET_NW_DST   /* IP destination address. */
  OFPAT_SET_NW_TOS   /* IP ToS (DSCP field 6 bits). */
  OFPAT_SET_TP_SRC   /* TCP/UDP source port. */
  OFPAT_SET_TP_DST   /* TCP/UDP destination port. */
  OFPAT_ENQUEUE    /* Output to queue.  */
  OFPAT_VENDOR OfpActionType = 0xffff
)

// Added by Arjun.
type OfpActionHeader struct {
  Type OfpActionType
  Len uint16
}

/* Action structure for OFPAT_OUTPUT which sends packets out 'port'.
 * When the 'port' is the OFPP_CONTROLLER 'MaxLen' indicates the max
 * number of bytes to send.  A 'MaxLen' of zero means no bytes of the
 * packet should be sent.*/
type ActionOutput struct {
  OfpActionHeader
  Port  uint16      /* Output port. */
  MaxLen uint16     /* Max length to send to controller. */
}
const actionSize = 8

// Sets Max length to 0
func MkActionOutput(port uint16) *ActionOutput {
  return &ActionOutput{OfpActionHeader{OFPAT_OUTPUT, actionSize},port, 0}
} 

/* Action structure for OFPAT_SET_VLAN_VID. */
type OfpActionVlanVid struct {
  OfpActionHeader
  VlanVid uint16     /* VLAN id. */
  pad [2]uint8
}

/* Action structure for OFPAT_SET_VLAN_PCP. */
type OfpActionVlanPcp struct {
  OfpActionHeader
  VlanPcp uint8     /* VLAN priority. */
  pad [3]uint8
}

/* Action structure for OFPAT_SET_DL_SRC/DST. */
type OfpActionDlAddr struct {
  OfpActionHeader
  DlAddr [OFP_ETH_ALEN]uint8  /* Ethernet address. */
  pad [6]uint8
}

/* Action structure for OFPAT_SET_NW_SRC/DST. */
type OfpActionNwAddr struct {
  OfpActionHeader
  NwAddr uint32    /* IP address. */
}


/* Action structure for OFPAT_SET_TP_SRC/DST. */
type OfpActionTpPort struct {
  OfpActionHeader
  TpPort uint16     /* TCP/UDP port. */
  pad [2]uint8
}


/* Action structure for OFPAT_SET_NW_TOS. */
type OfpActionNwTos struct {
  OfpActionHeader
  NwTos uint8     /* IP ToS (DSCP field 6 bits). */
  pad [3]uint8
}

/* Action header for OFPAT_VENDOR. The rest of the body is vendor-defined. */
type OfpActionVendorHeader struct {
  OfpActionHeader
  vendor uint32    /* Vendor ID which takes the same form
           as in "struct OfpVendorHeader". */
}


/* Send packet (controller -> datapath). */
type OfpPacketOut struct {
  OfpHeader
  BufferId uint32     /* ID assigned by datapath (-1 if none). */
  InPort uint16     /* Packet's input port (OFPP_NONE if none). */
  ActionsLen uint16  /* Size of action array in bytes. */
  actions interface{} /* Actions */
}

type FlowModCommand uint16
const (
  FCAdd = iota     /* New flow. */
  FCModify         /* Modify all matching flows. */
  FCModifyStrict  /* Modify entry strictly matching wildcards */
  FCDelete         /* Delete all matching flows. */
  FCDeleteStrict  /* Strictly match wildcards and priority. */
)

/* Flow wildcards. */
const (
  FW_IN_PORT uint32 = 1 << 0  /* Switch input port. */
  FW_DL_VLAN  uint32 = 1 << 1  /* VLAN id. */
  FW_DL_SRC   uint32 = 1 << 2  /* Ethernet source address. */
  FW_DL_DST   uint32 = 1 << 3  /* Ethernet destination address. */
  FW_DL_TYPE  uint32 = 1 << 4  /* Ethernet frame type. */
  FW_NW_PROTO uint32 = 1 << 5  /* IP protocol. */
  FW_TP_SRC   uint32 = 1 << 6  /* TCP/UDP source port. */
  FW_TP_DST   uint32 = 1 << 7  /* TCP/UDP destination port. */

  /* IP source address wildcard bit count.  0 is exact match 1 ignores the
   * LSB 2 ignores the 2 least-significant bits ... 32 and higher wildcard
   * the entire field.  This is the *opposite* of the usual convention where
   * e.g. /24 indicates that 8 bits (not 24 bits) are wildcarded. */
  FW_NW_SRC_SHIFT uint32 = 8
  FW_NW_SRC_BITS uint32 = 6
  FW_NW_SRC_MASK uint32 = ((1 << FW_NW_SRC_BITS) - 1) << FW_NW_SRC_SHIFT
  FW_NW_SRC_ALL uint32 = 32 << FW_NW_SRC_SHIFT

  /* IP destination address wildcard bit count.  Same format as source. */
  FW_NW_DST_SHIFT uint32 = 14
  FW_NW_DST_BITS uint32 = 6
  FW_NW_DST_MASK uint32 = ((1 << FW_NW_DST_BITS) - 1) << FW_NW_DST_SHIFT
  FW_NW_DST_ALL uint32 = 32 << FW_NW_DST_SHIFT

  FW_DL_VLAN_PCP uint32 = 1 << 20  /* VLAN priority. */
  FW_NW_TOS uint32 = 1 << 21  /* IP ToS (DSCP field 6 bits). */

  /* Wildcard all fields. */
  FW_ALL uint32 = ((1 << 22) - 1)
)

/* The wildcards for ICMP type and code fields use the transport source
 * and destination port fields respectively. */
const FW_ICMP_TYPE = FW_TP_SRC
const FW_ICMP_CODE = FW_TP_DST

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

/* Fields to match against flows */
type Match struct {
  Wildcards uint32    /* Wildcard fields. */
  InPort uint16      /* Input switch port. */
  DlSrc [OFP_ETH_ALEN]uint8 /* Ethernet source address. */
  DlDst [OFP_ETH_ALEN]uint8 /* Ethernet destination address. */
  VLanID uint16      /* Input VLAN id. */
  VLanPCP uint8     /* Input VLAN priority. */
  Pad0 uint8      /* Align to 64-bits */
  EthFrameType uint16      /* Ethernet frame type. */
  NwTOS uint8      /* IP ToS (actually DSCP field 6 bits). */
  NwProto uint8      /* IP protocol or lower 8 bits of ARP opcode. */
  Pad1 uint16       /* Align to 64-bits */
  NwSrc uint32       /* IP source address. */
  NwDst uint32       /* IP destination address. */
  TpSrc uint16       /* TCP/UDP source port. */
  TpDst uint16       /* TCP/UDP destination port. */
}

const matchSize = 40

/* The match fields for ICMP type and code use the transport source and
 * destination port fields respectively. */
// #define icmp_type tp_src
// #define icmp_code tp_dst

/* Value used in "idle_timeout" and "hard_timeout" to indicate that the entry
 * is permanent. */
const FlowPermanent = 0

/* By default choose a priority in the middle. */
const DefaultPriority = 0x8000

const (
  SendFlowRem uint16 = 1 << 0  /* Send flow removed message when flow
                                * expires or is deleted. */
  CheckOverlap uint16 = 1 << 1 /* Check for overlapping entries first. */
  Emergency uint16 = 1 << 2    /* Remark this is for emergency. */
)

/* Flow setup and teardown (controller -> datapath). */
type FlowMod struct {
  OfpHeader
  FlowModPart
  Actions []interface{}  /* The action length is inferred
                            from the length field in the
                            header. */
}

type FlowModPart struct {
  Match
  Cookie uint64          /* Opaque controller-issued identifier. */
  /* Flow actions. */
  Command FlowModCommand /* One of OFPFC_*. */
  IdleTimeout uint16     /* Idle time before discarding (seconds). */
  HardTimeout uint16     /* Max time before discarding (seconds). */
  Priority uint16        /* Priority level of flow entry. */
  BufferId uint32        /* Buffered packet to apply to (or -1).
                            Not meaningful for OFPFC_DELETE*. */
  OutPort uint16         /* For OFPFC_DELETE* commands require
                            matching entries to include this as an
                            output port.  A value of OFPP_NONE
                            indicates no restriction. */
  Flags uint16           /* One of OFPFF_*. */
}
const FlowModPartSize = 64
