#!/usr/bin/python
from subprocess import Popen
from mininet.node import RemoteController
from mininet.net import Mininet
from mininet.topolib import TreeTopo


controller = Popen(['./learning'])
try:
  tree4 = TreeTopo(depth=1,fanout=2)
  net = Mininet(topo=tree4,controller=RemoteController)
  net.start()
  h1, h4  = net.hosts[0], net.hosts[1]
  print h1.cmd('ping -c1 %s' % h4.IP())
  net.stop()
finally:
  controller.kill()
