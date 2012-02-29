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

func emptyPacketInHandler(msg *of.PacketIn) {
	log.Printf("PacketIn message discarded")
}

func emptySwitchFeaturesHandler(msg *of.SwitchFeatures) {
	log.Printf("SwitchFeatures message discarded")
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
}

func NewController() *Controller {
	return &Controller{nil}
}

func (self *Controller) Accept(port int, h NewSwitchHandler) error {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{net.IPv4(0, 0, 0, 0), port})
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
			emptySwitchFeaturesHandler}
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
	err := self.Send(&of.Hello{})
	if err != nil {
		log.Printf("Send HELLO failed, err=%s", err)
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
			log.Printf("Sent HELLO response.\n")
		case *of.EchoRequest:
			err := self.Send(&of.EchoReply{of.Header{Xid: m.Xid},
				m.Body})
			if err != nil {
				log.Printf("send ECHO reply failed, err = %s", err)
				self.Close()
				return
			}
			log.Printf("echo reply")
		case *of.PacketIn:
			self.HandlePacketIn(m)
		case *of.SwitchFeatures:
			self.HandleSwitchFeatures(m)
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
	default:
		log.Printf("Unknown message, returning header %s", header)
		return header
	}
	err = msg.Read(&header, rawBody)
	if err != nil {
		log.Printf("Error reading msg: %v", err)
	}
	return msg

}
