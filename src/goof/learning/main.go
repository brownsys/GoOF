package main

import (
  "goof/controller"
  "log"
  "goof/of"
  "os"
  "runtime/pprof"
)

// Exactly match ethernet frame type, and src and dst addresses
const wildcards = of.FwAll ^ of.FwDlSrc ^ of.FwDlDst

func newSwitch(sw *controller.Switch) {
  defer func() {
    pprof.StopCPUProfile()
    recover()
  }()

  // Learning switch
  routes := make(map[[of.EthAlen]uint8]uint16, 1000)

  sw.HandlePacketIn = func(msg *of.PacketIn) {
    routes[msg.EthFrame.SrcMAC] = msg.InPort
      outPort, found := routes[msg.EthFrame.DstMAC]
      if !found {
        err := sw.Send(&of.FlowMod{
          Xid: msg.Xid,
          Match: of.Match{Wildcards: wildcards,
                          DlSrc: msg.EthFrame.SrcMAC,
                          DlDst: msg.EthFrame.DstMAC},
          Flags: of.FCAdd,
          Actions: []of.Action{&of.ActionOutput{of.PortFlood, 0}}})
        if err != nil {
          log.Printf("Erroring sending: %v", err)
        }
      } else {
        log.Printf("known, would send to %x", outPort)
      }
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
