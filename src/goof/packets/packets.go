package packets

import (
	"bytes"
	"encoding/binary"
  "io"
)

type EthType uint16
const EthTypeIP EthType = 0x0800

type Protocol uint8
const ProtocolTCP = 8

type IPHeader struct {
	VersionIHL      uint8 // version and IHL fields
	TOS             uint8
	TotalLength     uint16
	Identification  uint16
	FlagsFragoffset uint16
	TTL             uint8
	Protocol        Protocol
	HeaderChecksum  uint16
	SrcAddr         uint32
	DstAddr         uint32
}

const IPHeaderSize = 20

type EthernetHeader struct {
	DstMAC [6]byte
	SrcMAC [6]byte
	Type   EthType
}

type TCPHeader struct {
	SrcPort uint16
	DstPort uint16
}

type IPFragment struct {
	*IPHeader
  Body interface{}
}

type EthFrame struct {
	*EthernetHeader
  Body interface{}
}

func ParseTCPHeader(buf io.Reader, h *IPHeader) (*TCPHeader, error) {
  switch h.Protocol {
  case ProtocolTCP:
		var tcp TCPHeader
		err := binary.Read(buf, binary.BigEndian, &tcp)
		if err != nil {
			return nil, err
		}
		return &tcp, nil
  }
  
  return nil, nil
}

func ParseIPFragment(buf io.Reader, h *EthernetHeader) (*IPFragment, error) {
	switch h.Type {
	case EthTypeIP:
		var ip IPHeader
		err := binary.Read(buf, binary.BigEndian, &ip)
		if err != nil {
			return nil, err
		}
		optionsLen := ((ip.VersionIHL & 0xf) << 2) - IPHeaderSize
		options := make([]byte, optionsLen)
		buf.Read(options) // TODO: error checking?
    
    frag := &IPFragment{&ip, nil}
    frag.Body, err = ParseTCPHeader(buf, &ip)
    return frag, err
	}

  return nil, nil
}

func Parse(body []byte) (frame *EthFrame, err error) {
	buf := bytes.NewBuffer(body)
	var eth EthernetHeader
	err = binary.Read(buf, binary.BigEndian, &eth)
	if err != nil {
		return
	}
  frame = &EthFrame{&eth, nil}
  frame.Body, err = ParseIPFragment(buf, &eth)
  return frame, err
}
