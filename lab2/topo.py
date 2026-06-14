from mininet.topo import Topo

class FatTreeTopo(Topo):
    def __init__(self, k=4, **opts):
        super(FatTreeTopo, self).__init__(**opts)
        self.k = k
        cr_sw_maps = {}
        agg_sw_maps = {}
        edg_sw_maps = {}
        sw_cn = 1

        # Generate core switches
        for j in range(1, (k // 2) + 1):
            for i in range(1, (k // 2) + 1):
                sw_name = f'cs{sw_cn}'
                self.addSwitch(sw_name)
                cr_sw_maps[(j, i)] = sw_name
                sw_cn += 1

        # Generate switches for pods
        for p in range(k):
            # Create Aggregation Switches for Pod p
            for s in range(k // 2, k):
                sw_name = f'as{sw_cn}'
                self.addSwitch(sw_name)
                agg_sw_maps[(p, s)] = sw_name
                sw_cn += 1

                # Connect agg and core switches based on stride rules
                str_rl = s - (k // 2)
                for i in range(1, (k // 2) + 1):
                    cr_sw_name = cr_sw_maps[(str_rl + 1, i)]
                    self.addLink(sw_name, cr_sw_name, bw=15, delay='5ms')

            # Create Edge Switches for Pod p
            for s in range(0, k // 2):
                sw_name = f'es{sw_cn}'
                self.addSwitch(sw_name)
                edg_sw_maps[(p, s)] = sw_name
                sw_cn += 1

                # Connect edge and aggregate switches
                for agg_s in range(k // 2, k):
                    agg_sw_name = agg_sw_maps[(p, agg_s)]
                    self.addLink(sw_name, agg_sw_name, bw=15, delay='5ms')

                # Create host for edge switches
                for h_id in range(2, (k // 2) + 2):
                    host_name = f'h{p}{s}{h_id}'
                    host_ip = f'10.{p}.{s}.{h_id}'
                    host_mac = f'00:00:00:{p:02x}:{s:02x}:{h_id:02x}'
                    host = self.addHost(host_name, ip=host_ip + '/8', mac=host_mac)
                    self.addLink(sw_name, host, bw=15, delay='5ms')
