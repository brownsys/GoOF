package of

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"goof/packets"
	"io"
)

// Messages from the switch to the controller support this interface.
type FromSwitch interface {
	Read(header *Header, body []byte) error
}

// Messages from the controller to the switch support this interface.
type ToSwitch interface {
	Write(w io.Writer) error
}

type Action interface {
	WriteAction(w io.Writer) error
	ActionLen() uint16
}

var pad64 = make([]byte, 8, 8)

type Type uint8

/* Header on all OpenFlow packets. */
type Header struct {
	Version uint8  /* OFP_VERSION. */
	Type    Type   /* One of the OFPT_ constants. */
	Length  uint16 /* Length including this Header. */
	Xid     uint32 /* Transaction id associated with this packet.
	   Replies use the same id as was in the request
	   to facilitate pairing. */
}


func (h *Header) String() string {
  return fmt.Sprintf("Type=%v, Version=%x, Length=%d, Xid=%d", h.Type, 
		h.Version, h.Length, h.Xid)
}


const HeaderSize = 8

/* OFPT_HELLO.  This message has an empty body but implementations must
 * ignore any data included in the body to allow for future extensions. */
type Hello struct {
	Header
}

func (m *Hello) Write(w io.Writer) error {
	m.Length = HeaderSize
	m.Type = OFPT_HELLO
	m.Version = OFP_VERSION
	return binary.Write(w, binary.BigEndian, m)
}

func (m *Hello) Read(h *Header, body []byte) error {
	m.Header = *h
	return nil
}

type EchoRequest struct {
	Header
	Body []byte
}

func (m *EchoRequest) Write(w io.Writer) error {
	m.Length = uint16(HeaderSize + len(m.Body))
	m.Type = OFPT_ECHO_REQUEST
	m.Version = OFP_VERSION
	return binary.Write(w, binary.BigEndian, m)
}

func (m *EchoRequest) Read(h *Header, body []byte) error {
	m.Body = body
	m.Header = *h
	return nil
}

type EchoReply struct {
	Header
	Body []byte
}

func (m *EchoReply) Write(w io.Writer) error {
	m.Length = uint16(HeaderSize + len(m.Body))
	m.Type = OFPT_ECHO_REPLY
	m.Version = OFP_VERSION
	return binary.Write(w, binary.BigEndian, m)
}

func (m *EchoReply) Read(h *Header, body []byte) error {
	m.Body = body
	m.Header = *h
	return nil
}


type ConfigFlags uint16


type SwitchConfig struct {
	Xid         uint32
	Flags       ConfigFlags // OFPC_* flags
	MissSendLen uint16      // Max bytes of new flow to send to the controller
}

const switchConfigSize uint16 = 12

func (m *SwitchConfig) Write(w io.Writer) error {
	h := Header{OFP_VERSION, OFPT_FLOW_MOD, switchConfigSize, m.Xid}
	binary.Write(w, binary.BigEndian, &h)
	binary.Write(w, binary.BigEndian, m.Flags)
	return binary.Write(w, binary.BigEndian, m.MissSendLen)
}


/* Description of a physical port */
type PhyPort struct {
	PortNo uint16
	HwAddr [EthAlen]uint8
	Name   [OFP_MAX_PORT_NAME_LEN]uint8 /* Null-terminated */

	Config uint32 /* Bitmap of Ofppc* flags. */
	State  uint32 /* Bitmap of Ofpps* flags. */

	// Bitmaps of Ppf* that describe features.  All bits zeroed if
	// unsupported or unavailable.
	Curr       uint32 /* Current features. */
	Advertised uint32 /* Features being advertised by the port. */
	Supported  uint32 /* Features supported by the port. */
	Peer       uint32 /* Features advertised by peer. */
}

const phyPortSize = 48

type SwitchFeaturesRequest struct {
	Xid uint32
}

func (m *SwitchFeaturesRequest) Write(w io.Writer) error {
	h := Header{OFP_VERSION, OFPT_FEATURES_REQUEST, HeaderSize, m.Xid}
	return binary.Write(w, binary.BigEndian, &h)
}

type SwitchFeatures struct {
	*Header
	DatapathId uint64 /* Datapath unique ID.  The lower 48-bits are for
	   a MAC address while the upper 16-bits are
	   implementer-defined. */
	NBuffers     uint32 /* Max packets buffered at once. */
	NTables      uint8  /* Number of tables supported by datapath. */
	Pad          [3]byte
	Capabilities uint32     /* Bitmap of support "Capabilities". */
	Actions      ActionType /* Bitmap of supported "ActionType"s. */
	Ports        []PhyPort  // Port definitions.
}

const switchFeaturesPartSize = 24

func (m *SwitchFeatures) Read(h *Header, body []byte) error {
	m.Header = h
	buf := bytes.NewBuffer(body)
	binary.Read(buf, binary.BigEndian, &m.DatapathId)
	binary.Read(buf, binary.BigEndian, &m.NBuffers)
	binary.Read(buf, binary.BigEndian, &m.NTables)
	binary.Read(buf, binary.BigEndian, &m.Pad)
	binary.Read(buf, binary.BigEndian, &m.Capabilities)
	binary.Read(buf, binary.BigEndian, &m.Actions)
	portsSize := h.Length - HeaderSize - switchFeaturesPartSize
	if portsSize%phyPortSize != 0 {
		return errors.New(fmt.Sprintf("FEATURES_REPLY misaligned (%d port size)",
			portsSize))
	}
	numPorts := portsSize / phyPortSize
	m.Ports = make([]PhyPort, numPorts, numPorts)
	return binary.Read(buf, binary.BigEndian, m.Ports)
}


/* A physical port has changed in the datapath */
type PortStatus struct {
	*Header
	Reason uint8    // One of Ppr*
	Pad    [7]uint8 // Align to 64-bits
	Desc   PhyPort
}

func (m *PortStatus) IsPortAdded() bool {
	return m.Reason == PprAdd
}

func (m *PortStatus) IsPortDeleted() bool {
	return m.Reason == PprDelete
}

func (m *PortStatus) IsPortModified() bool {
	return m.Reason == PprModify
}

func (m *PortStatus) Read(h *Header, body []byte) error {
	buf := bytes.NewBuffer(body)
	m.Header = h
	binary.Read(buf, binary.BigEndian, &m.Reason)
	binary.Read(buf, binary.BigEndian, &m.Pad)
	return binary.Read(buf, binary.BigEndian, &m.Desc)
}

// Modify behavior of the physical port.
type PortMod struct {
	Xid    uint32
	PortNo uint16
	// The hardware address is not configurable.  This is used to sanity-check the
	// request so it must be the same as returned in an PhyPort struct.
	HwAddr    [EthAlen]uint8
	Config    uint32 // Bitmap of Ofppc* flags.
	Mask      uint32 // Bitmap of Ofppc* flags to be changed.
	Advertise uint32 // Bitmap of Ofppc* flags.  Zero all to prevent any action.
}

func (m *PortMod) Write(w io.Writer) error {
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


/* Packet received on port (datapath -> controller). */
type PacketIn struct {
	*Header
	BufferId uint32 // ID assigned by datapath
	TotalLen uint16 // Full length of frame
	InPort   uint16 // Port on which frame was received
	Reason   uint8  // Reason packet is being sent (one of Reason*)
	Pad      uint8
	/* Ethernet frame halfway through 32-bit word so the IP header is 32-bit 
	   aligned.  The amount of data is inferred from the length field in the 
	   header.  Because of padding offsetof(struct PacketIn data) == 
	   sizeof(struct PacketIn) - 2. */
	EthFrame *packets.EthFrame
}

func (m *PacketIn) PacketNotMatched() bool {
	return m.Reason == ReasonNoMatch
}

func (m *PacketIn) Read(h *Header, body []byte) error {
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

type PacketOut struct {
	Xid      uint32   // Transaction ID
	BufferId int32    // ID assigned by datapath (-1 if none)
	InPort   uint16   // Packet's input port (OFPP_NONE if none)
	Actions  []Action // Actions 
	Data     []byte   // Only meaningful if BufferId is -1
}

func (m *PacketOut) actionsLen() uint16 {
	size := uint16(0)
	for _, a := range m.Actions {
		size = size + a.ActionLen()
	}
	return size
}

func (m *PacketOut) Write(w io.Writer) error {
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

/* Fields to match against flows */
type Match struct {
	Wildcards    uint32         /* Wildcard fields. */
	InPort       uint16         /* Input switch port. */
	DlSrc        [EthAlen]uint8 /* Ethernet source address. */
	DlDst        [EthAlen]uint8 /* Ethernet destination address. */
	VLanID       uint16         /* Input VLAN id. */
	VLanPCP      uint8          /* Input VLAN priority. */
	Pad0         uint8          /* Align to 64-bits */
	EthFrameType uint16         /* Ethernet frame type. */
	NwTOS        uint8          /* IP ToS (actually DSCP field 6 bits). */
	NwProto      uint8          /* IP protocol or lower 8 bits of ARP opcode. */
	Pad1         uint16         /* Align to 64-bits */
	NwSrc        uint32         /* IP source address. */
	NwDst        uint32         /* IP destination address. */
	TpSrc        uint16         /* TCP/UDP source port. */
	TpDst        uint16         /* TCP/UDP destination port. */
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
	SendFlowRem uint16 = 1 << 0 /* Send flow removed message when flow
	 * expires or is deleted. */
	CheckOverlap uint16 = 1 << 1 /* Check for overlapping entries first. */
	Emergency    uint16 = 1 << 2 /* Remark this is for emergency. */
)

////////////////////////////////////////////////////////////////////////////////
// Flow modification message

/* Flow setup and teardown (controller -> datapath). */
type FlowMod struct {
	Xid         uint32
	Match       Match
	Cookie      uint64         /* Opaque controller-issued identifier. */
	Command     FlowModCommand /* One of OFPFC_*. */
	IdleTimeout uint16         /* Idle time before discarding (seconds). */
	HardTimeout uint16         /* Max time before discarding (seconds). */
	Priority    uint16         /* Priority level of flow entry. */
	BufferId    uint32         /* Buffered packet to apply to (or -1).
	   Not meaningful for OFPFC_DELETE*. */
	OutPort uint16 /* For OFPFC_DELETE* commands require
	   matching entries to include this as an
	   output port.  A value of OFPP_NONE
	   indicates no restriction. */
	Flags   uint16   /* One of OFPFF_*. */
	Actions []Action // Flow actions.
}

func (m *FlowMod) Write(w io.Writer) error {
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
	RemovedReasonHardTimeout                   /* Time exceeded hard_timeout. */
	RemovedReasonDelete                        /* Evicted by a DELETE flow mod. */
)

// Message sent from datapath to controller when a flow is removed.
type FlowRemoved struct {
	Header
	FlowRemovedPart
}

type FlowRemovedPart struct {
	Match                          /* Description of fields. */
	Cookie       uint64            /* Opaque controller-issued identifier. */
	Priority     uint16            /* Priority level of flow entry. */
	Reason       FlowRemovedReason /* One of OFPRR_*. */
	uint8                          /* Align to 32-bits. */
	DurationSec  uint32            /* Time flow was alive in seconds. */
	DurationNsec uint32            /* Time flow was alive in nanoseconds beyond
	   duration_sec. */
	IdleTimeout uint16 /* Idle timeout from original flow mod. */
	uint16             /* Align to 64-bits. */
	PacketCount uint64
	ByteCount   uint64
}

func (m *FlowRemoved) Read(h *Header, body []byte) error {
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
	HelloFailed   ErrorType = iota /* Hello protocol failed. */
	BadRequest                     /* Request was not understood. */
	BadAction                      /* Error in action description. */
	FlowModFailed                  /* Problem modifying flow entry. */
	PortModFailed                  /* Port mod request failed. */
	QueueOpFailed                  /* Queue operation failed. */
)

type Error struct {
	Header
	Type ErrorType
	Code uint16
	/* Variable-length data.  Interpreted based on the type and code. */
	Data []byte
}

func (m *Error) Read(h *Header, body []byte) error {
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

func errorTypeToString(t ErrorType) string {
	switch (t) {
	case HelloFailed:
		return "OFPET_HELLO_FAILED"
	case BadRequest:
		return "OFPET_BAD_REQUEST"
	case BadAction:
		return "OFPET_BAD_ACTION"
	case FlowModFailed:
		return "OFPET_FLOW_MOD_FAILED"
	case PortModFailed:
		return "OFPET_FLOW_MOD_FAILED"
	case QueueOpFailed:
		return "OFPET_QUEUE_OP_FAILED"
	}
	return fmt.Sprintf("unknown error (code: %v)", t)
}

func (m *Error) String() string {
  return fmt.Sprintf("Type=%v", errorTypeToString(m.Type))
}

///////////////////////////////////////////////////////////////////////////////
// Statistics

type Stat interface {
	WriteStat(w io.Writer) error
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
	Type  StatsType /* One of the OFPST_* constants. */
	Flags uint16    /* OFPSF_REQ_* flags (none yet defined). */
	Body  []byte    /* Body of the request. */
}

type StatsReplyFlags uint16

const (
	StatsReplyMore StatsReplyFlags = 1 << 0 /* More replies to follow. */
)

type StatsReply struct {
	Header
	Type  uint16          /* One of the OFPST_* constants. */
	Flags StatsReplyFlags /* OFPSF_REPLY_* flags. */
	Body  []byte          /* Body of the reply. */
}

const DescStrLen = 256
const SerialNumLen = 32

/* Body of reply to OFPST_DESC request.  Each entry is a NULL-terminated
 * ASCII string. */
type DescStats struct {
	MfrDesc   [DescStrLen]byte   /* Manufacturer description. */
	HwDesc    [DescStrLen]byte   /* Hardware description. */
	SwDesc    [DescStrLen]byte   /* Software description. */
	SerialNum [SerialNumLen]byte /* Serial number. */
	DpDesc    [DescStrLen]byte   /* Human readable description of datapath. */
}

/* Body for ofpStatsRequest of type OFPST_FLOW. */
type FlowStatsRequest struct {
	Match         /* Fields to match. */
	TableId uint8 /* ID of table to read (from ofpTableStats)
	   0xff for all tables or 0xfe for emergency. */
	uint8          /* Align to 32 bits. */
	OutPort uint16 /* Require matching entries to include this
	   as an output port.  A value of OFPP_NONE
	  indicates no restriction. */
}
