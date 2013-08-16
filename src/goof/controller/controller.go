package controller

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"goof/of"
	"io"
	"log"
	"net"
)

type PacketInHandler func(msg *of.PacketIn)
type SwitchFeaturesHandler func(msg *of.SwitchFeatures)
type NewSwitchHandler func(sw *Switch)
type ErrorHandler func(msg *of.Error)
type PortStatusHandler func(msg *of.PortStatus)

func emptyPacketInHandler(msg *of.PacketIn) {
	log.Printf("PacketIn message discarded")
}

func emptySwitchFeaturesHandler(msg *of.SwitchFeatures) {
	log.Printf("SwitchFeatures message discarded")
}

func emptyErrorHandler(msg *of.Error) {
  log.Printf("unhandled error: %v", msg)
}

func emptyPortStatusHandler(msg *of.PortStatus) {
	log.Printf("unhandled OFPT_PORT_STATUS")
}

type Controller struct {
	listener *net.TCPListener
}

type Switch struct {
	tcpConn              *net.TCPConn
	rb                   *bufio.Reader
	controller           *Controller
	HandlePacketIn       PacketInHandler
	HandleSwitchFeatures SwitchFeaturesHandler
	HandleError ErrorHandler
	HandlePortStatus PortStatusHandler
}

func NewController() *Controller {
	return &Controller{nil}
}

func (self *Controller) Accept(port int, h NewSwitchHandler) error {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: port})
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
		sw := &Switch{tcpConn, rb, self, emptyPacketInHandler,
			emptySwitchFeaturesHandler, emptyErrorHandler,
		emptyPortStatusHandler}
		go h(sw)
	}

	panic("unreachable code")
}

func (self *Switch) Send(msg of.ToSwitch) error {
	return msg.Write(self.tcpConn)
}

func (self *Switch) Recv() interface{} {
	return ReadMsg(self.rb)
}

func (self *Switch) Serve() {
	self.loop()
	log.Panicf("Unreachable code in (*Switch)serve")
}

func (self *Switch) loop() {
	for {
		msg := self.Recv()
		switch m := msg.(type) {
		case *of.Header:
			log.Printf("Recv unknown packet type: %s", m.Type)
		case *of.Hello:
			err := self.Send(&of.Hello{of.Header{Xid: m.Xid}})
			if err != nil {
				log.Printf("send HELLO response failed, err = %s", err)
				self.Close()
				return
			}
      err = self.Send(&of.SwitchFeaturesRequest{0})
			if err != nil {
				log.Printf("send features request failed, err = %s", err)
				self.Close()
				return
			}
		case *of.EchoRequest:
			err := self.Send(&of.EchoReply{of.Header{Xid: m.Xid},
				m.Body})
			if err != nil {
				log.Printf("send ECHO reply failed, err = %s", err)
				self.Close()
				return
			}
		case *of.PortStatus:
			self.HandlePortStatus(m)
		case *of.PacketIn:
			self.HandlePacketIn(m)
		case *of.SwitchFeatures:
			self.HandleSwitchFeatures(m)
		case *of.Error:
			self.HandleError(m)
		default:
			log.Printf("unhandled msg recvd")
		}
	}
}

func (self *Switch) Close() {
	self.tcpConn.Close()
}

func ReadMsg(netBuf *bufio.Reader) interface{} {
	var header of.Header
	rawHeader := make([]byte, of.HeaderSize)
	// Panic if fewer bytes are read and don't care about recovering this
	// connection.
	_, err := io.ReadFull(netBuf, rawHeader)
	if err != nil {
		log.Panicf("error reading header; %s", err)
	}
	binary.Read(bytes.NewBuffer(rawHeader), binary.BigEndian, &header) // no err

	var rawBody []byte
	rawBody = make([]byte, header.Length-of.HeaderSize)
	_, err = io.ReadFull(netBuf, rawBody)
	if err != nil {
		log.Panicf("error reading body; %s", err)
	}

	var msg of.FromSwitch
	switch header.Type {
	case of.OFPT_HELLO:
		msg = new(of.Hello)
	case of.OFPT_ECHO_REQUEST:
		msg = new(of.EchoRequest)
	case of.OFPT_ECHO_REPLY:
		msg = new(of.EchoReply)
	case of.OFPT_FEATURES_REPLY:
		msg = new(of.SwitchFeatures)
	case of.OFPT_PACKET_IN:
		msg = new(of.PacketIn)
	case of.OFPT_ERROR:
		msg = new(of.Error)
	case of.OFPT_PORT_STATUS:
		msg = new(of.PortStatus)
	default:
		log.Printf("Unknown message, returning header %v", header.String())
		return header
	}
	err = msg.Read(&header, rawBody)
	if err != nil {
		log.Printf("Error reading msg: %v", err)
	}
	return msg

}
