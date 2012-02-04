package controller

import (
  "net"
  "openflow"
  "encoding/binary"
  "bufio"
  "log"
  "os"
)

type Controller struct {
  listener *net.TCPListener
}

type Switch struct {
  tcpConn *net.TCPConn
  rb *bufio.Reader
  wb *bufio.Writer
  b *bufio.ReadWriter
}

func (self *Controller)Accept(net_ string, laddr *net.TCPAddr) os.Error {
  listener, err := net.ListenTCP(net_, laddr)
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
    wb := bufio.NewWriter(tcpConn)
    sw := &Switch{tcpConn, rb, wb, bufio.NewReadWriter(rb, wb)}
    go sw.serve()
  }

  panic("unreachable code")
}

func (self *Switch)Send(msg interface{}) os.Error {
  return WriteMsg(self.wb, msg)
}

func (self *Switch)Recv() (interface{}, os.Error) {
  return ReadMsg(self.rb)
}

func (self *Switch)serve() {
  err := self.Send(&openflow.OfpHello{})
  if err != nil {
    log.Printf("Send HELLO failed");
    return
  }
  msg, err := self.Recv()
  if err != nil {
    log.Printf("Recv HELLO failed");
    return
  }
  switch m := msg.(type) {
  case openflow.OfpHello:
  default:
    log.Printf("Expected HELLO reply, got %s", m)
    return
  }
  self.loop()
}

func (self *Switch)loop() {
  for {
    msg, err := self.Recv()
    if err != nil {
      log.Printf("Recv failed, err = %s", err)
      self.Close()
      return
    }
    switch m := msg.(type) {
    case openflow.OfpHeader:
      log.Printf("Recv unknown packet type: %s", m.Type)
    case openflow.OfpHello:
      err := self.Send(&openflow.OfpHello{openflow.OfpHeader{Xid: m.Xid}})
      if err != nil {
        log.Printf("send HELLO response failed, err = %s", err)
        self.Close()
        return
      }
    case openflow.OfpEchoRequest:
      err := self.Send(&openflow.OfpEchoReply{openflow.OfpHeader{Xid: m.Xid},
                                              m.Body})
      if err != nil {
        log.Printf("send ECHO reply failed, err = %s", err)
        self.Close()
        return
      }
    default:
      log.Printf("unhandled msg type: %s", m)
    }
  }
}

func (self *Switch)Close() {
  self.tcpConn.Close()
}

// Fills in the OfpHeader.Version, OfpHeader.Type and OfpHeader.Length fields
func WriteMsg(b *bufio.Writer, msg interface{}) os.Error {
  switch m := msg.(type) {
  case openflow.OfpHello:
    m.Length = openflow.OfpHeaderSize
    m.Type = openflow.OFPT_HELLO
    m.Version = openflow.OFP_VERSION
    return binary.Write(b, binary.BigEndian, m)
  case openflow.OfpEchoRequest:
    m.Length = uint16(openflow.OfpHeaderSize + len(m.Body))
    m.Type = openflow.OFPT_ECHO_REQUEST
    m.Version = openflow.OFP_VERSION
    return binary.Write(b, binary.BigEndian, m)
  case openflow.OfpEchoReply:
    m.Length = uint16(openflow.OfpHeaderSize + len(m.Body))
    m.Type = openflow.OFPT_ECHO_REPLY
    m.Version = openflow.OFP_VERSION
    return binary.Write(b, binary.BigEndian, m)
  }
  return os.NewError("unknown msg. type")
}

func ReadMsg(b *bufio.Reader) (res interface{}, err os.Error) {
  var header openflow.OfpHeader
  err = binary.Read(b, binary.BigEndian, &header)
  if err != nil {
    return
  }
  switch (header.Type) {
  case openflow.OFPT_HELLO:
    body := make([]byte, header.Length - openflow.OfpHeaderSize)
    err = binary.Read(b, binary.BigEndian, body)
    if err != nil {
      return
    }
    return &openflow.OfpHello{header}, nil
  case openflow.OFPT_ECHO_REQUEST:
    body := make([]byte, header.Length - openflow.OfpHeaderSize)
    err = binary.Read(b, binary.BigEndian, body)
    if err != nil {
      return
    }
    return &openflow.OfpEchoRequest{header,body}, nil
  case openflow.OFPT_ECHO_REPLY:
    body := make([]byte, header.Length - openflow.OfpHeaderSize)
    err = binary.Read(b, binary.BigEndian, body)
    if err != nil {
      return
    }
    return &openflow.OfpEchoReply{header,body}, nil
  }
    

  body := make([]byte, header.Length - openflow.OfpHeaderSize)
  err = binary.Read(b, binary.BigEndian, body)
  return header, nil
}
