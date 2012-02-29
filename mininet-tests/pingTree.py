#!/usr/bin/python
from subprocess import Popen
from mininet.node import RemoteController
from mininet.node import UserSwitch
from mininet.net import Mininet
from mininet.topolib import TreeTopo
import re

controller = Popen(['../learning'])
tree4 = TreeTopo(depth=1,fanout=2)
net = Mininet(topo=tree4,controller=RemoteController,switch=UserSwitch)
try:
  net.start()
  print "Starting ping storm ..."
  for src in net.hosts:
    for dst in net.hosts:
      cmd = 'ping -c1 %s' % dst.IP()
      out = src.cmd(cmd)
      m = re.search(r"(\d+)% packet loss", out)
      if m.group(1) != "0":
        print '%s$ %s' % (src.IP(), cmd)
        print out
finally:
  net.stop()
  controller.kill()
