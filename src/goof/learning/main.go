package main

import (
  "goof/controller"
  "log"
  "goof/of"
  "os"
  "runtime/pprof"
)

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
			log.Printf("Sending flood ...")
      err := sw.Send(&of.FlowMod{
      Xid: msg.Xid,
      Match: of.Match{
				Wildcards: of.FwAll ^ of.FwDlSrc ^ of.FwDlDst,
        DlSrc: msg.EthFrame.SrcMAC,
        DlDst: msg.EthFrame.DstMAC },
			BufferId: msg.BufferId,
      Flags: of.FCAdd,
			HardTimeout: 5,
      Actions: []of.Action{&of.ActionOutput{of.PortFlood, 0}}})
      if err != nil {
        log.Printf("Erroring sending: %v", err)
      }
    } else {
      err := sw.Send(&of.FlowMod{
      Xid: msg.Xid,
      Match: of.Match{
				Wildcards: of.FwAll ^ of.FwDlSrc ^ of.FwDlDst,
        DlSrc: msg.EthFrame.SrcMAC,
        DlDst: msg.EthFrame.DstMAC },
			BufferId: msg.BufferId,
      Flags: of.FCAdd,
			HardTimeout: 60,
      Actions: []of.Action{&of.ActionOutput{outPort, 0}}})			
      if err != nil {
        log.Printf("Erroring sending: %v", err)
      }

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
