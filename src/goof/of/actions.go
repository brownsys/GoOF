package of

import (
	"encoding/binary"
	"io"
)

type ActionType uint16

const (
	OFPAT_OUTPUT       ActionType = iota /* Output to switch port. */
	OFPAT_SET_VLAN_VID                   /* Set the 802.1q VLAN id. */
	OFPAT_SET_VLAN_PCP                   /* Set the 802.1q priority. */
	OFPAT_STRIP_VLAN                     /* Strip the 802.1q header. */
	OFPAT_SET_DL_SRC                     /* Ethernet source address. */
	OFPAT_SET_DL_DST                     /* Ethernet destination address. */
	OFPAT_SET_NW_SRC                     /* IP source address. */
	OFPAT_SET_NW_DST                     /* IP destination address. */
	OFPAT_SET_NW_TOS                     /* IP ToS (DSCP field 6 bits). */
	OFPAT_SET_TP_SRC                     /* TCP/UDP source port. */
	OFPAT_SET_TP_DST                     /* TCP/UDP destination port. */
	OFPAT_ENQUEUE                        /* Output to queue.  */
	OFPAT_VENDOR       ActionType = 0xffff
)

func genericWriteAction(w io.Writer, a Action, t ActionType) error {
	binary.Write(w, binary.BigEndian, t)
	binary.Write(w, binary.BigEndian, a.ActionLen())
	return binary.Write(w, binary.BigEndian, a)
}

/* Action structure for OFPAT_OUTPUT which sends packets out 'port'.
 * When the 'port' is the OFPP_CONTROLLER 'MaxLen' indicates the max
 * number of bytes to send.  A 'MaxLen' of zero means no bytes of the
 * packet should be sent.*/
type ActionOutput struct {
	Port   uint16 /* Output port. */
	MaxLen uint16 /* Max length to send to controller. */
}

func (m *ActionOutput) ActionLen() uint16 {
	return 8
}

func (m *ActionOutput) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_OUTPUT)
}

type ActionVlanVid struct {
	VlanVid uint16 /* VLAN id. */
	pad     [2]uint8
}

func (m *ActionVlanVid) ActionLen() uint16 {
	return 8
}

func (m *ActionVlanVid) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_SET_VLAN_VID)
}

type ActionVlanPcp struct {
	VlanPcp uint8 /* VLAN priority. */
	uint16
	uint8
}

func (m *ActionVlanPcp) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_SET_VLAN_PCP)
}

func (m *ActionVlanPcp) ActionLen() uint16 {
	return 8
}

type ActionSetDlSrc struct {
	DlAddr [EthAlen]uint8 /* Ethernet address. */
	uint32
	uint16
}

func (m *ActionSetDlSrc) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_SET_DL_SRC)
}

func (m *ActionSetDlSrc) ActionLen() uint16 {
	return 16
}

type ActionSetDlDst struct {
	DlAddr [EthAlen]uint8 /* Ethernet address. */
	uint32
	uint16
}

func (m *ActionSetDlDst) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_SET_DL_DST)
}

func (m *ActionSetDlDst) ActionLen() uint16 {
	return 16
}

type ActionNwAddrSrc struct {
	NwAddr uint32 /* IP address. */
}

func (m *ActionNwAddrSrc) ActionLen() uint16 {
	return 8
}

func (m *ActionNwAddrSrc) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_SET_NW_SRC)
}

type ActionNwAddrDst struct {
	NwAddr uint32 /* IP address. */
}

func (m *ActionNwAddrDst) ActionLen() uint16 {
	return 8
}

func (m *ActionNwAddrDst) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_SET_NW_DST)
}

type ActionTpPortSrc struct {
	TpPort uint16 /* TCP/UDP port. */
	uint16
}

func (m *ActionTpPortSrc) ActionLen() uint16 {
	return 8
}

func (m *ActionTpPortSrc) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_SET_TP_SRC)
}

type ActionTpPortDst struct {
	TpPort uint16 /* TCP/UDP port. */
	uint16
}

func (m *ActionTpPortDst) ActionLen() uint16 {
	return 8
}

func (m *ActionTpPortDst) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_SET_TP_DST)
}

/* Action structure for OFPAT_SET_NW_TOS. */
type ActionNwTos struct {
	NwTos uint8 /* IP ToS (DSCP field 6 bits). */
	uint16
	uint8
}

func (m *ActionNwTos) ActionLen() uint16 {
	return 8
}

func (m *ActionNwTos) WriteAction(w io.Writer) error {
	return genericWriteAction(w, m, OFPAT_SET_NW_TOS)
}
