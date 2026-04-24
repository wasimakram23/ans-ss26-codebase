from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import OVSBridge
from mininet.cli import CLI

class BridgeTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        # Hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # Switches as pure bridges
        s1 = self.addSwitch('s1', cls=OVSBridge)
        s2 = self.addSwitch('s2', cls=OVSBridge)

        # Host–switch links
        self.addLink(h1, s1, bw=15, delay='10ms', cls=TCLink)
        self.addLink(h2, s1, bw=15, delay='10ms', cls=TCLink)
        self.addLink(h3, s2, bw=15, delay='10ms', cls=TCLink)
        self.addLink(h4, s2, bw=15, delay='10ms', cls=TCLink)

        # Inter-switch link
        self.addLink(s1, s2, bw=20, delay='45ms', cls=TCLink)

topo = BridgeTopo()

# IMPORTANT: controller=None disables OpenFlow and prevents c0 from appearing
net = Mininet(topo=topo, controller=None)

net.start()
CLI(net)
net.stop()
