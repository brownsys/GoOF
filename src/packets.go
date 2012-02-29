package packets

import (
  "bytes"
  "os"
  "encoding/binary"
)

type Packet interface {
}

type EthType uint16
const EthTypeIP EthType = 0x0800

type Protocol uint8
const ProtocolTCP = 8

type IPHeader struct {
  VersionIHL uint8 // version and IHL fields
  TOS uint8 
  TotalLength uint16
  Identification uint16
  FlagsFragoffset uint16
  TTL uint8
  Protocol Protocol
  HeaderChecksum uint16
  SrcAddr uint32
  DstAddr uint32
}
const IPHeaderSize = 20

type EthernetHeader struct {
  DstMAC [6]byte
  SrcMAC [6]byte
  Type EthType
}

type TCPHeader struct {
  SrcPort uint16
  DstPort uint16
}

type IPFragment struct {
  EthernetHeader
  IPHeader
  Tcp *TCPHeader
}

type EthernetFrame struct {
  EthernetHeader
}

func Parse(body []byte) (r interface{}, err os.Error) {
  buf := bytes.NewBuffer(body)
  var eth EthernetHeader
  err = binary.Read(buf, binary.BigEndian, &eth)
  if err != nil {
    return
  }
  switch (eth.Type) {
  case EthTypeIP:
    var ip IPHeader
    err = binary.Read(buf, binary.BigEndian, &ip)
    if err != nil {
      return
    }
    optionsLen := ((ip.VersionIHL & 0xf) << 2) - IPHeaderSize
    options := make([]byte, optionsLen)
    buf.Read(options) // TODO: error checking?
  
    switch (ip.Protocol) {
    case ProtocolTCP:
      var tcp TCPHeader
      err = binary.Read(buf, binary.BigEndian, &tcp)
      if err != nil {
        return
      }
      return &IPFragment{eth,ip,&tcp}, nil
    default:
      return &IPFragment{eth,ip,nil}, nil
    }
  }

  return &EthernetFrame{eth}, os.NewError("unknown ethernet type")
}


