package main

import (
  "goof/controller"
  "log"
  "goof/of"
  "os"
  "goof/packets"
  "runtime/pprof"
)

// Exactly match ethernet frame type, and src and dst addresses
const wildcards = of.FW_IN_PORT | of.FW_DL_VLAN | of.FW_DL_SRC | of.FW_DL_DST |
  of.FW_TP_SRC | of.FW_TP_DST | of.FW_DL_VLAN_PCP | of.FW_NW_TOS | 
  of.FW_NW_PROTO

func newSwitch(sw *controller.Switch) {
  defer func() {
    pprof.StopCPUProfile()
    recover()
  }()

  // Learning switch
  routes := make(map[uint32]uint16, 1000)
  

  sw.HandlePacketIn = func(msg *of.PacketIn) {
    switch f := msg.EthFrame.(type) {
    case *packets.IPFragment:
      routes[f.SrcAddr] = msg.InPort
      outPort, found := routes[f.DstAddr]
      if !found {
        err := sw.Send(&of.FlowMod{
          Xid: msg.Xid,
          Match: of.Match{Wildcards: wildcards,
                          EthFrameType: uint16(packets.EthTypeIP),
                          NwSrc: f.SrcAddr,
                          NwDst: f.DstAddr},
          Flags: of.FCAdd,
          Actions: []of.Action{&of.ActionOutput{of.PortFlood, 0}}})
        if err != nil {
          log.Printf("Erroring sending: %v", err)
        }
      } else {
        log.Printf("known, would send to %x", outPort)
      }
      return
    case *packets.EthernetFrame:
      log.Printf("Unknown packet type: %x", f.Type)
      return
    }
    log.Printf("No ethernet frame in PacketIn\n")
  }

  sw.Serve()
}

func main() {
  f, _ := os.Create("profile")
  err2 := pprof.StartCPUProfile(f)
  if err2 != nil { panic(err2) }
  defer func() {
    log.Printf("Unprofiling")
  }()
  
  log.Printf("Starting server ...")
  ctrl := controller.NewController()
  err := ctrl.Accept(6633, newSwitch)


  panic(err)
}
