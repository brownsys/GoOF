package controller

import (
  "net"
  "of"
  "encoding/binary"
  "bufio"
  "log"
  "os"
  "io"
  "bytes"
  "packets"
)

type PacketInHandler func(msg *of.PacketIn)
type NewSwitchHandler func(sw *Switch)

func emptyPacketInHandler(msg *of.PacketIn) {
  log.Printf("PacketIn message discarded.\n")
}

type Controller struct {
  listener *net.TCPListener
}

type Switch struct {
  tcpConn *net.TCPConn
  rb *bufio.Reader
  controller *Controller
  HandlePacketIn PacketInHandler
}

func NewController() *Controller {
  return &Controller{nil}
}

func (self *Controller)Accept(port int, h NewSwitchHandler) os.Error {
  listener, err := net.ListenTCP("tcp", &net.TCPAddr{net.IPv4(0,0,0,0),port})
  if err != nil {
    return err
  }
  self.listener = listener

  for {
    tcpConn, err := self.listener.AcceptTCP()
    if err != nil {
      continue
    }
    rb := bufio.NewReader(tcpConn)
    sw := &Switch{tcpConn, rb, self, emptyPacketInHandler}
    go h(sw)
  }

  panic("unreachable code")
}

func (self *Switch)Send(msg interface{}) os.Error {
  return WriteMsg(self.tcpConn, msg)
}

func (self *Switch)Recv() interface{} {
  return ReadMsg(self.rb)
}

func (self *Switch)Serve() {
  err := self.Send(&of.OfpHello{})
  if err != nil {
    log.Printf("Send HELLO failed, err=%s", err);
    return
  }
  err = self.Send(&of.SwitchFeaturesRequest{})
  if err != nil {
    log.Printf("First SWITCH_FEATURES_REQUEST failed, err=%s", err)
    return
  }
  self.loop()
  log.Panicf("Unreachable code in (*Switch)serve")
}

func (self *Switch)loop() {
  for {
    msg := self.Recv()
    switch m := msg.(type) {
    case *of.OfpHeader:
      log.Printf("Recv unknown packet type: %s", m.Type)
    case *of.OfpHello:
      err := self.Send(&of.OfpHello{of.OfpHeader{Xid: m.Xid}})
      if err != nil {
        log.Printf("send HELLO response failed, err = %s", err)
        self.Close()
        return
      }
      log.Printf("Sent HELLO response.\n")
    case *of.OfpEchoRequest:
      err := self.Send(&of.OfpEchoReply{of.OfpHeader{Xid: m.Xid},
                                              m.Body})
      if err != nil {
        log.Printf("send ECHO reply failed, err = %s", err)
        self.Close()
        return
      }
      log.Printf("echo reply")
    case *of.PacketIn:
      self.HandlePacketIn(m)
    default:
      log.Printf("unhandled msg recvd")
    }
  }
}

func (self *Switch)Close() {
  self.tcpConn.Close()
}

// Fills in the OfpHeader.Version, OfpHeader.Type and OfpHeader.Length fields
func WriteMsg(b io.Writer, msg interface{}) os.Error {
  switch m := msg.(type) {
  case *of.OfpHello:
    m.Length = of.OfpHeaderSize
    m.Type = of.OFPT_HELLO
    m.Version = of.OFP_VERSION
    return binary.Write(b, binary.BigEndian, m)
  case *of.SwitchFeaturesRequest:
    m.Length = of.OfpHeaderSize
    m.Type = of.OFPT_FEATURES_REQUEST
    m.Version = of.OFP_VERSION
    return binary.Write(b, binary.BigEndian, m)
  case *of.OfpEchoRequest:
    m.Length = uint16(of.OfpHeaderSize + len(m.Body))
    m.Type = of.OFPT_ECHO_REQUEST
    m.Version = of.OFP_VERSION
    return binary.Write(b, binary.BigEndian, m)
  case *of.OfpEchoReply:
    m.Length = uint16(of.OfpHeaderSize + len(m.Body))
    m.Type = of.OFPT_ECHO_REPLY
    m.Version = of.OFP_VERSION
    return binary.Write(b, binary.BigEndian, m)
  case *of.FlowMod:
    b2 := bytes.NewBuffer(make([]byte, 0, 64))
    for _, action := range m.Actions {
      err := binary.Write(b2, binary.BigEndian, action)
      if err != nil {
        log.Panicf("Error writing action; err = %s", err)
      }
    }
    m.Length = of.OfpHeaderSize + of.FlowModPartSize + uint16(b2.Len())
    m.Type = of.OFPT_FLOW_MOD
    m.Version = of.OFP_VERSION
    err := binary.Write(b, binary.BigEndian, m.OfpHeader)
    if err != nil {
      log.Panicf("Error writing action header; err = %s", err)
    }
    err = binary.Write(b, binary.BigEndian, m.FlowModPart)
    if err != nil {
      log.Panicf("Error writing flow mod part; err = %s", err)
    }
    _, err = b.Write(b2.Bytes())
    if err != nil {
      log.Panicf("Error writing actions; err = %s", err)
    }
    return nil
  }
  log.Panicf("Unknown message type, msg = %s", msg)
  return os.NewError("unknown msg type")
}

func ReadMsg(netBuf *bufio.Reader) interface{} {
  var header of.OfpHeader
  rawHeader := make([]byte, of.OfpHeaderSize)
  // Panic if fewer bytes are read and don't care about recovering this
  // connection.
  _, err := io.ReadFull(netBuf, rawHeader)
  if err != nil {
    log.Panicf("error reading header; %s", err)
  }
  binary.Read(bytes.NewBuffer(rawHeader), binary.BigEndian, &header) // no err
  
  var rawBody []byte
  rawBody = make([]byte, header.Length - of.OfpHeaderSize)
  _, err = io.ReadFull(netBuf, rawBody)
  if err != nil {
    log.Panicf("error reading body; %s", err)
  }
  b := bytes.NewBuffer(rawBody)
  
  switch (header.Type) {
  case of.OFPT_HELLO:
    body := make([]byte, header.Length - of.OfpHeaderSize)
    err = binary.Read(b, binary.BigEndian, body)
    if err != nil {
      log.Panicf("error reading body of hello; %s", err)
    }
    return &of.OfpHello{header}
  case of.OFPT_ECHO_REQUEST:
    body := make([]byte, header.Length - of.OfpHeaderSize)
    err = binary.Read(b, binary.BigEndian, body)
    if err != nil {
      log.Panicf("error reading OFPT_ECHO_REQUEST body; %s", err)
    }
    return &of.OfpEchoRequest{header,body}
  case of.OFPT_ECHO_REPLY:
    body := make([]byte, header.Length - of.OfpHeaderSize)
    err = binary.Read(b, binary.BigEndian, body)
    if err != nil {
      log.Panicf("error reading OFPT_ECHO_REPLY_BODY; %s", err)
    }
    return &of.OfpEchoReply{header,body}
  case of.OFPT_FEATURES_REPLY:
    var part of.SwitchFeaturesPart
    err = binary.Read(b, binary.BigEndian, &part)
    if err != nil {
      log.Panicf("Error reading OFPT_FEATURES_REPLY static body; %s", err)
    }
    portsSize := header.Length - of.OfpHeaderSize -
      of.SwitchFeaturesPartSize
    if portsSize % of.PhyPortSize != 0 {
      log.Panicf("OFPT_FEATURES_REPLY misaligned; ports take %d bytes", 
                 portsSize)
    }
    numPorts := portsSize / of.PhyPortSize
    ports := make([]of.OfpPhyPort, numPorts, numPorts)
    err = binary.Read(b, binary.BigEndian, &part)
    if err != nil {
      log.Panicf("Error reading OFPT_FEATURES_REPLY ports section; %s", err)
    }
    return &of.SwitchFeatures{header,part,ports}
  case of.OFPT_PACKET_IN:
    var part of.PacketInPart
    err = binary.Read(b, binary.BigEndian, &part)
    if err != nil {
      log.Panicf("Error reading OFPT_PACKET_IN static body; %s", err)
    }
    frame, err := packets.Parse(b)
    if err != nil {
      log.Panicf("Error reading OFPT_PACKET_IN frame; %s", err)
    }
    return &of.PacketIn{header,part,frame}
  }

  body := make([]byte, header.Length - of.OfpHeaderSize)
  err = binary.Read(b, binary.BigEndian, body)
  log.Printf("Unknown message, returning header %s", header)
  return header
}
