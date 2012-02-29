package of

import (
  "io"
  "os"
  "encoding/binary"
  "bytes"
  "fmt"
  "packets"
)

// Messages from the switch to the controller support this interface.
type FromSwitch interface {
  Read(header *Header, body []byte) os.Error
}

// Messages from the controller to the switch support this interface.
type ToSwitch interface {
  Write(w io.Writer) os.Error
}

type Action interface {
  WriteAction(w io.Writer) os.Error
  ActionLen() uint16
}

var pad64 = make([]byte,8,8)

/* Version number:
 * Non-experimental versions released: 0x01
 * Experimental versions released: 0x81 -- 0x99
 *
 * The most significant bit being set in the version field indicates an
 * experimental OpenFlow version.
 */
const OFP_VERSION =  0x01

const OFP_MAX_TABLE_NAME_LEN = 32
const OFP_MAX_PORT_NAME_LEN = 16

const OFP_TCP_PORT = 6633
const  OFP_SSL_PORT = 6633

const EthAlen = 6  /* Bytes in an Ethernet address. */

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

type Type uint8

const (
  /* Immutable messages. */
  OFPT_HELLO Type = iota  /* Symmetric message */
  OFPT_ERROR   /* Symmetric message */
  OFPT_ECHO_REQUEST  /* Symmetric message */
  OFPT_ECHO_REPLY  /* Symmetric message */
  OFPT_VENDOR  /* Symmetric message */

  /* Switch configuration messages. */
  OFPT_FEATURES_REQUEST  /* Controller/switch message */
  OFPT_FEATURES_REPLY  /* Controller/switch message */
  OFPT_GET_CONFIG_REQUEST  /* Controller/switch message */
  OFPT_GET_CONFIG_REPLY  /* Controller/switch message */
  OFPT_SET_CONFIG  /* Controller/switch message */

  /* Asynchronous messages. */
  OFPT_PACKET_IN   /* Async message */
  OFPT_FLOW_REMOVED  /* Async message */
  OFPT_PORT_STATUS   /* Async message */

  /* Controller command messages. */
  OFPT_PACKET_OUT  /* Controller/switch message */
  OFPT_FLOW_MOD  /* Controller/switch message */
  OFPT_PORT_MOD  /* Controller/switch message */

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
type Header struct {
  Version uint8 /* OFP_VERSION. */
  Type Type   /* One of the OFPT_ constants. */
  Length uint16 /* Length including this Header. */
  Xid uint32  /* Transaction id associated with this packet.
     Replies use the same id as was in the request
     to facilitate pairing. */
}
const HeaderSize = 8


/* OFPT_HELLO.  This message has an empty body but implementations must
 * ignore any data included in the body to allow for future extensions. */
type Hello struct {
  Header
}

func (m *Hello)Write(w io.Writer) os.Error {
  m.Length = HeaderSize
  m.Type = OFPT_HELLO
  m.Version = OFP_VERSION
  return binary.Write(w, binary.BigEndian, m)
}

func (m *Hello)Read(h *Header, body []byte) os.Error {
  m.Header = *h
  return nil
}

type EchoRequest struct {
  Header
  Body []byte
}

func (m *EchoRequest) Write(w io.Writer) os.Error {
  m.Length = uint16(HeaderSize + len(m.Body))
  m.Type = OFPT_ECHO_REQUEST
  m.Version = OFP_VERSION
  return binary.Write(w, binary.BigEndian, m)
}

func (m *EchoRequest) Read(h *Header, body []byte) os.Error {
  m.Body = body
  m.Header = *h
  return nil
}

type EchoReply struct {
  Header
  Body []byte
}

func (m *EchoReply) Write(w io.Writer) os.Error {
  m.Length = uint16(HeaderSize + len(m.Body))
  m.Type = OFPT_ECHO_REPLY
  m.Version = OFP_VERSION
  return binary.Write(w, binary.BigEndian, m)
}

func (m *EchoReply) Read(h *Header, body []byte) os.Error {
  m.Body = body
  m.Header = *h
  return nil
}

const OFP_DEFAULT_MISS_SEND_LEN uint16 = 128

type  ConfigFlags uint16

const (
  FragNormal ConfigFlags = 0 // No special handling for IP fragments.
  FragDrop ConfigFlags = 1   // Drop fragments.
  FragReasm ConfigFlags = 2  // Reassemble (only if OFPC_IP_REASM set).
)

type SwitchConfig struct {
  Xid uint32
  Flags ConfigFlags   // OFPC_* flags
  MissSendLen uint16 // Max bytes of new flow to send to the controller
}

const switchConfigSize uint16 = 12

func (m *SwitchConfig) Write(w io.Writer) os.Error {
  h := Header{OFP_VERSION, OFPT_FLOW_MOD, switchConfigSize, m.Xid}
  binary.Write(w, binary.BigEndian, &h)
  binary.Write(w, binary.BigEndian, m.Flags)
  return binary.Write(w, binary.BigEndian, m.MissSendLen)
}

// Capabilities supported by the datapath.
const (
  FlowStats = 1 << 0   /* Flow statistics. */
  TableStats = 1 << 1  /* Table statistics. */
  PortStats = 1 << 2   /* Port statistics. */
  STP = 1 << 3          /* 802.1d spanning tree. */
  ofcpReserved = 1 << 4     /* Reserved must be zero. */
  IpReasm = 1 << 5     /* Can reassemble IP fragments. */
  QueueStats = 1 << 6  /* Queue statistics. */
  ArpMatchIp = 1 << 7 /* Match IP addresses in ARP pkts. */
)

// Flags to indicate behavior of the physical port.  These flags are
// used in PhyPort to describe the current configuration.  They are
// used in the PortMod message to configure the port's behavior.
const (
  OfppcPortDown uint32 = 1 << 0 // port is administratively down
  OfppcNoStp uint32 = 1 << 1 // disable 802.1d spanning tree on port
  OfppcNoRecv uint32 = 1 << 2 // drop all packets except spanning tree packets
  OfppcNoRecvStp uint32 = 1 << 3  // drop received 802.1d stp packets
  OfppcNoFlood uint32 = 1 << 4 // do not include this port when flooding
  OfppcNoFwd uint32 = 1 << 5 // drop packets forwarded to port
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
  OfppsStpListen uint32 = 0 << 8  // Not learning or relaying frames
  OfppsStpLearn uint32 = 1 << 8   // learning but not relaying frames
  OfppsStpForward uint32 = 2 << 8 // learning and relaying frames
  OfppsStpBlock uint32 = 3 << 8   // not part of spanning tree
  OfppsStpMask uint32 = 3 << 8    // bit mask for ofpps_stp_* values
)

// Features of physical ports available in a datapath
const (
  Ppf10MBHd uint32 = 1 << 0 /* 10 Mb half-duplex rate support. */
  Ppf10MBFd uint32 = 1 << 1 /* 10 Mb full-duplex rate support. */
  Ppf100MBHd uint32 = 1 << 2 /* 100 Mb half-duplex rate support. */
  Ppf100MBFd uint32 = 1 << 3 /* 100 Mb full-duplex rate support. */
  Ppf1GBHd uint32 = 1 << 4 /* 1 Gb half-duplex rate support. */
  Ppf1GBFd uint32 = 1 << 5 /* 1 Gb full-duplex rate support. */
  Ppf10GBFd uint32 = 1 << 6 /* 10 Gb full-duplex rate support. */
  PpfCopper uint32 = 1 << 7 /* Copper medium. */
  PpfFiber uint32 = 1 << 8 /* Fiber medium. */
  PpfAutoneg uint32 = 1 << 9 /* Auto-negotiation. */
  PpfPause uint32 = 1 << 10 /* Pause. */
  PpfPauseAsym uint32 = 1 << 11 /* Asymmetric pause. */
)

/* Description of a physical port */
type PhyPort struct {
  PortNo uint16
  HwAddr [EthAlen]uint8
  Name [OFP_MAX_PORT_NAME_LEN]uint8 /* Null-terminated */

  Config uint32 /* Bitmap of Ofppc* flags. */
  State uint32 /* Bitmap of Ofpps* flags. */

  // Bitmaps of Ppf* that describe features.  All bits zeroed if
  // unsupported or unavailable.
  Curr uint32 /* Current features. */
  Advertised uint32 /* Features being advertised by the port. */
  Supported uint32 /* Features supported by the port. */
  Peer uint32 /* Features advertised by peer. */
}
const phyPortSize = 48

type SwitchFeaturesRequest struct {
  Xid uint32
}

func (m *SwitchFeaturesRequest) Write(w io.Writer) os.Error {
  h := Header{OFP_VERSION, OFPT_FEATURES_REQUEST, HeaderSize, m.Xid}
  return binary.Write(w, binary.BigEndian, &h)
}

type SwitchFeatures struct {
  *Header
  DatapathId uint64   /* Datapath unique ID.  The lower 48-bits are for
    a MAC address while the upper 16-bits are
    implementer-defined. */
  NBuffers uint32   /* Max packets buffered at once. */
  NTables uint8   /* Number of tables supported by datapath. */
  Pad [3]byte
  Capabilities uint32 /* Bitmap of support "Capabilities". */
  Actions ActionType   /* Bitmap of supported "ActionType"s. */
  Ports []PhyPort  // Port definitions.
}

const switchFeaturesPartSize = 24

func (m *SwitchFeatures) Read(h *Header, body []byte) os.Error {
  m.Header = h
  buf := bytes.NewBuffer(body)
  binary.Read(buf, binary.BigEndian, &m.DatapathId)
  binary.Read(buf, binary.BigEndian, &m.NBuffers)
  binary.Read(buf, binary.BigEndian, &m.NTables)
  binary.Read(buf, binary.BigEndian, &m.Pad)
  binary.Read(buf, binary.BigEndian, &m.Capabilities)
  binary.Read(buf, binary.BigEndian, &m.Actions)
  portsSize := h.Length - HeaderSize - switchFeaturesPartSize
  if portsSize % phyPortSize != 0 {
    return os.NewError(fmt.Sprintf("FEATURES_REPLY misaligned (%d port size)", 
                       portsSize))
  }
  numPorts := portsSize / phyPortSize
  m.Ports = make([]PhyPort, numPorts, numPorts)
  return binary.Read(buf, binary.BigEndian, m.Ports)
}

// What changed about the physical port
const (
  PprAdd = iota // The port was added.
  PprDelete     // The port was removed.
  PprModify     // Some attribute of the port has changed.
)

/* A physical port has changed in the datapath */
type PortStatus struct {
  *Header
  Reason uint8 // One of Ppr*
  Pad [7]uint8      // Align to 64-bits
  Desc PhyPort
}

func (m *PortStatus)IsPortAdded() bool {
  return m.Reason == PprAdd
}

func (m *PortStatus)IsPortDeleted() bool {
  return m.Reason == PprDelete
}

func (m *PortStatus)IsPortModified() bool {
  return m.Reason == PprModify
}

func (m *PortStatus)Read(h *Header, body []byte) os.Error {
  buf := bytes.NewBuffer(body)
  m.Header = h
  binary.Read(buf, binary.BigEndian, &m.Reason)
  binary.Read(buf, binary.BigEndian, &m.Pad)
  return binary.Read(buf, binary.BigEndian, &m.Desc)
}

// Modify behavior of the physical port.
type PortMod struct {
  Xid uint32
  PortNo uint16
  // The hardware address is not configurable.  This is used to sanity-check the
  // request so it must be the same as returned in an PhyPort struct.
  HwAddr [EthAlen]uint8 
  Config uint32     // Bitmap of Ofppc* flags.
  Mask uint32      // Bitmap of Ofppc* flags to be changed.
  Advertise uint32 // Bitmap of Ofppc* flags.  Zero all to prevent any action.
}


func (m *PortMod) Write(w io.Writer) os.Error {
  h := Header{OFP_VERSION, OFPT_PORT_MOD, 32, m.Xid}
  binary.Write(w, binary.BigEndian, h)
  binary.Write(w, binary.BigEndian, m.PortNo)
  binary.Write(w, binary.BigEndian, m.HwAddr)
  binary.Write(w, binary.BigEndian, m.Config)
  binary.Write(w, binary.BigEndian, m.Mask)
  binary.Write(w, binary.BigEndian, m.Advertise)
  _, err := w.Write(pad64)
  return err
}

// Why is this packet being sent to the controller?
const (
  ReasonNoMatch uint8 = iota  /* No matching flow. */
  ReasonAction   /* Action explicitly output to controller. */
)

/* Packet received on port (datapath -> controller). */
type PacketIn struct {
  *Header
  BufferId uint32 // ID assigned by datapath
  TotalLen uint16 // Full length of frame
  InPort uint16   // Port on which frame was received
  Reason uint8    // Reason packet is being sent (one of Reason*)
  Pad uint8
	/* Ethernet frame halfway through 32-bit word so the IP header is 32-bit 
   aligned.  The amount of data is inferred from the length field in the 
   header.  Because of padding offsetof(struct PacketIn data) == 
   sizeof(struct PacketIn) - 2. */
  EthFrame interface{}
}

func (m *PacketIn) PacketNotMatched() bool {
  return m.Reason == ReasonNoMatch
}

func (m *PacketIn) Read(h *Header, body []byte) os.Error {
  m.Header = h
  m.BufferId = binary.BigEndian.Uint32(body[0:])
  m.TotalLen = binary.BigEndian.Uint16(body[4:])
  m.InPort = binary.BigEndian.Uint16(body[6:])
  m.Reason = body[9]
  frm, err := packets.Parse(body[10:])
  m.EthFrame = frm
  if err != nil {
    return err
  }
  return nil
}

///////////////////////////////////////////////////////////////////////////////
// Actions

type ActionType uint16
const (
  OFPAT_OUTPUT ActionType = iota  /* Output to switch port. */
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
  OFPAT_ENQUEUE  /* Output to queue.  */
  OFPAT_VENDOR ActionType = 0xffff
)

func genericWriteAction(w io.Writer, a Action, t ActionType) os.Error {
  binary.Write(w, binary.BigEndian, t)
  binary.Write(w, binary.BigEndian, a.ActionLen())
  return binary.Write(w, binary.BigEndian, a)
}

/* Action structure for OFPAT_OUTPUT which sends packets out 'port'.
 * When the 'port' is the OFPP_CONTROLLER 'MaxLen' indicates the max
 * number of bytes to send.  A 'MaxLen' of zero means no bytes of the
 * packet should be sent.*/
type ActionOutput struct {
  Port  uint16    /* Output port. */
  MaxLen uint16   /* Max length to send to controller. */
}

func (m *ActionOutput) ActionLen() uint16 {
  return 8
}

func (m *ActionOutput) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_OUTPUT) 
}


type ActionVlanVid struct {
  VlanVid uint16   /* VLAN id. */
  pad [2]uint8
}

func (m *ActionVlanVid) ActionLen() uint16 {
  return 8
}

func (m *ActionVlanVid) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_SET_VLAN_VID)
}

type ActionVlanPcp struct {
  VlanPcp uint8   /* VLAN priority. */
  uint16
  uint8
}

func (m *ActionVlanPcp) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_SET_VLAN_PCP)
}

func (m *ActionVlanPcp) ActionLen() uint16 {
  return 8
}

type ActionSetDlSrc struct {
  DlAddr [EthAlen]uint8  /* Ethernet address. */
  uint32
  uint16
}

func (m *ActionSetDlSrc) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_SET_DL_SRC)
}

func (m *ActionSetDlSrc) ActionLen() uint16 {
  return 16
}

type ActionSetDlDst struct {
  DlAddr [EthAlen]uint8  /* Ethernet address. */
  uint32
  uint16
}

func (m *ActionSetDlDst) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_SET_DL_DST)
}

func (m *ActionSetDlDst) ActionLen() uint16 {
  return 16
}

type ActionNwAddrSrc struct {
  NwAddr uint32  /* IP address. */
}

func (m *ActionNwAddrSrc) ActionLen() uint16 {
  return 8
}

func (m *ActionNwAddrSrc) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_SET_NW_SRC)
}

type ActionNwAddrDst struct {
  NwAddr uint32  /* IP address. */
}

func (m *ActionNwAddrDst) ActionLen() uint16 {
  return 8
}

func (m *ActionNwAddrDst) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_SET_NW_DST)
}


type ActionTpPortSrc struct {
  TpPort uint16   /* TCP/UDP port. */
  uint16
}

func (m *ActionTpPortSrc) ActionLen() uint16 {
  return 8
}

func (m *ActionTpPortSrc) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_SET_TP_SRC)
}

type ActionTpPortDst struct {
  TpPort uint16   /* TCP/UDP port. */
  uint16
}

func (m *ActionTpPortDst) ActionLen() uint16 {
  return 8
}

func (m *ActionTpPortDst) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_SET_TP_DST)
}

/* Action structure for OFPAT_SET_NW_TOS. */
type ActionNwTos struct {
  NwTos uint8   /* IP ToS (DSCP field 6 bits). */
  uint16
  uint8
}

func (m *ActionNwTos) ActionLen() uint16 {
  return 8
}

func (m *ActionNwTos) WriteAction(w io.Writer) os.Error {
  return genericWriteAction(w, m, OFPAT_SET_NW_TOS)
}

type PacketOut struct {
  Xid uint32        // Transaction ID
  BufferId int32    // ID assigned by datapath (-1 if none)
  InPort uint16     // Packet's input port (OFPP_NONE if none)
  Actions []Action  // Actions 
  Data []byte      // Only meaningful if BufferId is -1
}

func (m *PacketOut) actionsLen() uint16 {
  size := uint16(0)
  for _, a := range m.Actions {
    size = size + a.ActionLen()
  }
  return size
}

func (m *PacketOut) Write(w io.Writer) os.Error {
  actionsLen := m.actionsLen()
  dataLen := uint16(len(m.Data))
  h := Header{OFP_VERSION, OFPT_PACKET_OUT, actionsLen + dataLen + 16, m.Xid}
  binary.Write(w, binary.BigEndian, &h)
  binary.Write(w, binary.BigEndian, m.BufferId)
  binary.Write(w, binary.BigEndian, m.InPort)
  binary.Write(w, binary.BigEndian, actionsLen)
  for _, a := range m.Actions {
    a.WriteAction(w)
  }
  return binary.Write(w, binary.BigEndian, m.Data)
}






type FlowModCommand uint16
const (
  FCAdd = iota   /* New flow. */
  FCModify     /* Modify all matching flows. */
  FCModifyStrict  /* Modify entry strictly matching wildcards */
  FCDelete     /* Delete all matching flows. */
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
  Wildcards uint32  /* Wildcard fields. */
  InPort uint16    /* Input switch port. */
  DlSrc [EthAlen]uint8 /* Ethernet source address. */
  DlDst [EthAlen]uint8 /* Ethernet destination address. */
  VLanID uint16    /* Input VLAN id. */
  VLanPCP uint8   /* Input VLAN priority. */
  Pad0 uint8    /* Align to 64-bits */
  EthFrameType uint16    /* Ethernet frame type. */
  NwTOS uint8    /* IP ToS (actually DSCP field 6 bits). */
  NwProto uint8    /* IP protocol or lower 8 bits of ARP opcode. */
  Pad1 uint16     /* Align to 64-bits */
  NwSrc uint32     /* IP source address. */
  NwDst uint32     /* IP destination address. */
  TpSrc uint16     /* TCP/UDP source port. */
  TpDst uint16     /* TCP/UDP destination port. */
}

const matchSize = 40

/* The match fields for ICMP type and code use the transport source and
 * destination port fields respectively. */
// #define icmp_type tp_src
// #define icmp_code tp_dst

/* Value used in "idle_timeout" and "hard_timeout" to indicate that the entry
 * is permanent. */
const FlowPermanent = 0

const (
  SendFlowRem uint16 = 1 << 0  /* Send flow removed message when flow
                * expires or is deleted. */
  CheckOverlap uint16 = 1 << 1 /* Check for overlapping entries first. */
  Emergency uint16 = 1 << 2  /* Remark this is for emergency. */
)

////////////////////////////////////////////////////////////////////////////////
// Flow modification message

/* Flow setup and teardown (controller -> datapath). */
type FlowMod struct {
  Xid uint32
  Match Match
  Cookie uint64      /* Opaque controller-issued identifier. */
  Command FlowModCommand /* One of OFPFC_*. */
  IdleTimeout uint16   /* Idle time before discarding (seconds). */
  HardTimeout uint16   /* Max time before discarding (seconds). */
  Priority uint16    /* Priority level of flow entry. */
  BufferId uint32    /* Buffered packet to apply to (or -1).
              Not meaningful for OFPFC_DELETE*. */
  OutPort uint16     /* For OFPFC_DELETE* commands require
              matching entries to include this as an
              output port.  A value of OFPP_NONE
              indicates no restriction. */
  Flags uint16       /* One of OFPFF_*. */
  Actions []Action // Flow actions.
}

func (m *FlowMod) Write(w io.Writer) os.Error {
  var size uint16 = HeaderSize + 64
  for _, a := range m.Actions {
  size += a.ActionLen()
  }
  h := &Header{OFP_VERSION, OFPT_FLOW_MOD, size, m.Xid}
  binary.Write(w, binary.BigEndian, h)
  binary.Write(w, binary.BigEndian, m.Match)
  binary.Write(w, binary.BigEndian, m.Cookie)
  binary.Write(w, binary.BigEndian, m.Command)
  binary.Write(w, binary.BigEndian, m.IdleTimeout)
  binary.Write(w, binary.BigEndian, m.HardTimeout)
  binary.Write(w, binary.BigEndian, m.Priority)
  binary.Write(w, binary.BigEndian, m.BufferId)
  binary.Write(w, binary.BigEndian, m.OutPort)
  binary.Write(w, binary.BigEndian, m.Flags)
  for _, action := range m.Actions {
    err := action.WriteAction(w)
    if err != nil {
      return err
    }
  }
  return nil
}

///////////////////////////////////////////////////////////////////////////////
// Flow removed message

/* Why was this flow removed? */
type FlowRemovedReason uint8
const (
  // Flow idle time exceeded idle_timeout.
  RemovedReasonIdleTimeout FlowRemovedReason = iota 
  RemovedReasonHardTimeout /* Time exceeded hard_timeout. */
  RemovedReasonDelete /* Evicted by a DELETE flow mod. */
)

// Message sent from datapath to controller when a flow is removed.
type FlowRemoved struct {
  Header
  FlowRemovedPart
}

type FlowRemovedPart struct {
  Match   /* Description of fields. */
  Cookie uint64      /* Opaque controller-issued identifier. */
  Priority uint16    /* Priority level of flow entry. */
  Reason FlowRemovedReason       /* One of OFPRR_*. */
  uint8       /* Align to 32-bits. */
  DurationSec uint32  /* Time flow was alive in seconds. */
  DurationNsec uint32  /* Time flow was alive in nanoseconds beyond
                          duration_sec. */
  IdleTimeout uint16  /* Idle timeout from original flow mod. */
  uint16      /* Align to 64-bits. */
  PacketCount uint64
  ByteCount uint64
}

func (m *FlowRemoved)Read(h *Header, body []byte) os.Error {
  buf := bytes.NewBuffer(body)
  err := binary.Read(buf, binary.BigEndian, &m.FlowRemovedPart)
  if err != nil {
    return err
  }
  m.Header = *h
  return nil
}

////////////////////////////////////////////////////////////////////////////////
// Error messages

/* Values for 'type' in ofp_error_message.  These values are immutable: they
 * will not change in future versions of the protocol (although new values may
 * be added). */
type ErrorType uint16
const (
  HelloFailed ErrorType = iota     /* Hello protocol failed. */
  BadRequest      /* Request was not understood. */
  BadAction       /* Error in action description. */
  FlowModFailed    /* Problem modifying flow entry. */
  PortModFailed    /* Port mod request failed. */
  QueueOpFailed     /* Queue operation failed. */
)

type ErrorMsg struct {
  Header 
  Type ErrorType
  Code uint16
  /* Variable-length data.  Interpreted based on the type and code. */
  Data []byte
}

func (m *ErrorMsg)Read(h *Header, body []byte) os.Error {
  buf := bytes.NewBuffer(body)
  m.Header = *h
  err := binary.Read(buf, binary.BigEndian, &m.Type)
  if err != nil {
    return err
  }
  err = binary.Read(buf, binary.BigEndian, &m.Code)
  if err != nil {
    return err
  }
  m.Data = body[4:] // rest of body
  return nil
}

///////////////////////////////////////////////////////////////////////////////
// Statistics

type Stat interface {
  WriteStat(w io.Writer) os.Error
  Length() uint16
}

type StatsType uint16
const (
  /* Description of this OpenFlow switch.
   * The request body is empty.
   * The reply body is struct ofpDescStats. */
  StatsDesc StatsType = iota

  /* Individual flow statistics.
   * The request body is struct ofpFlowStatsRequest.
   * The reply body is an array of struct ofpFlowStats. */
  StatsFlow

  /* Aggregate flow statistics.
   * The request body is struct ofpAggregateStatsRequest.
   * The reply body is struct ofpAggregateStatsReply. */
  StatsAggregate

  /* Flow table statistics.
   * The request body is empty.
   * The reply body is an array of struct ofpTableStats. */
  StatsTable

  /* Physical port statistics.
   * The request body is struct ofpPortStatsRequest.
   * The reply body is an array of struct ofpPortStats. */
  StatsPort

  /* Queue statistics for a port
   * The request body defines the port
   * The reply body is an array of struct ofpQueueStats */
  StatsQueue

  /* Vendor extension.
   * The request and reply bodies begin with a 32-bit vendor ID which takes
   * the same form as in "struct ofpVendorHeader".  The request and reply
   * bodies are otherwise vendor-defined. */
  StatsVendor StatsType = 0xffff
)

type StatsRequest struct {
  Header
  Type StatsType              /* One of the OFPST_* constants. */
  Flags uint16             /* OFPSF_REQ_* flags (none yet defined). */
  Body []byte            /* Body of the request. */
}


type StatsReplyFlags uint16
const (
  StatsReplyMore StatsReplyFlags = 1 << 0 /* More replies to follow. */
)

type StatsReply struct {
  Header
  Type uint16              /* One of the OFPST_* constants. */
  Flags StatsReplyFlags    /* OFPSF_REPLY_* flags. */
  Body []byte           /* Body of the reply. */
}

const DescStrLen = 256
const SerialNumLen = 32
/* Body of reply to OFPST_DESC request.  Each entry is a NULL-terminated
 * ASCII string. */
type DescStats struct {
  MfrDesc [DescStrLen]byte       /* Manufacturer description. */
  HwDesc [DescStrLen]byte        /* Hardware description. */
  SwDesc [DescStrLen]byte        /* Software description. */
  SerialNum [SerialNumLen]byte   /* Serial number. */
  DpDesc [DescStrLen]byte        /* Human readable description of datapath. */
}

/* Body for ofpStatsRequest of type OFPST_FLOW. */
type FlowStatsRequest struct {
  Match  /* Fields to match. */
  TableId uint8 /* ID of table to read (from ofpTableStats)
                   0xff for all tables or 0xfe for emergency. */
  uint8              /* Align to 32 bits. */
  OutPort uint16  /* Require matching entries to include this
                     as an output port.  A value of OFPP_NONE
                    indicates no restriction. */
}


