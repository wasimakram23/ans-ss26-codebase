from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.topo import Topo

from topo import FatTreeTopo # Assuming the class above is in topo.py

class FatTreeNet(Topo):
    def __init__(self):
        Topo.__init__(self)

def run():
    topo = FatTreeTopo(k=4)
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1',
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()