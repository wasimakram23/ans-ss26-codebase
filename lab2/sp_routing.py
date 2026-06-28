from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.topology import event
from ryu.topology.api import get_switch, get_link


class ShortestPathRouting(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ShortestPathRouting, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.datapath_lst = {}
        self.sw_adj_lst = {}
        self.edsw_host_port_lst = {}
        self.arp_trck = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        self.logger.info("Miss flow rule added for Switch %d", dp.id)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.update_topology()
        self.logger.info("Topology data received from Topology API App")
        for dpid in self.sw_adj_lst:
            self.logger.info("Switch %d: Adjacency list %s", dpid, str(self.sw_adj_lst[dpid]))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88CC: return  # LLDP
        if eth.ethertype == 0x86DD: return  # IPv6

        if dp.id not in self.sw_adj_lst or not self.sw_adj_lst[dp.id]:
            self.update_topology()

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        is_link_port = (dp.id in self.sw_adj_lst) and (in_port in self.sw_adj_lst[dp.id].values())

        if not is_link_port:
            if ip_pkt:
                self.edsw_host_port_lst.setdefault(dp.id, {})[ip_pkt.src] = in_port
            elif arp_pkt:
                self.edsw_host_port_lst.setdefault(dp.id, {})[arp_pkt.src_ip] = in_port

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            is_arp_req = False
            if arp_pkt.opcode == arp.ARP_REQUEST:
                arp_key = (src_ip, dst_ip, dp.id)
                is_arp_req = True
                if arp_key in self.arp_trck:
                    return
                self.arp_trck[arp_key] = True
                self.logger.info("ARP request from %s to %s via switch %d", src_ip, dst_ip,dp.id)
            elif arp_pkt.opcode == arp.ARP_REPLY:
                keys_to_clear = [k for k in self.arp_trck.keys() if k[0] == dst_ip and k[1] == src_ip]
                self.logger.info("ARP reply from %s to %s via switch %d", src_ip, dst_ip,dp.id)
                for k in keys_to_clear:
                    self.arp_trck.pop(k, None)

            self.handle_arp(dp, in_port, pkt, eth, arp_pkt,is_arp_req)
            return

        if ip_pkt:
            dst_ip = ip_pkt.dst
            target_dpid = None
            target_out_port = None

            for dpid, hosts in self.edsw_host_port_lst.items():
                if dst_ip in hosts:
                    target_dpid = dpid
                    target_out_port = hosts[dst_ip]
                    break

            if target_dpid is None:
                self.logger.info("No target dpid found to %s via switch %d for ip_pkt. Flooding via incoming port %d", dst_ip, dp.id,in_port)
                self.flood(dp, in_port, eth, msg.data)
                return

            if dp.id == target_dpid:
                out_port = target_out_port
            else:
                self.logger.info("Finding Shortest path from %d to %d", dp.id,target_dpid)
                path = self.get_sp_djk(dp.id, target_dpid)
                if not path or len(path) < 2:
                    self.logger.info("No Shortest path from %d to %d. Flooding via incoming port %d", dp.id,target_dpid,in_port)
                    self.flood(dp, in_port, eth, msg.data)
                    return
                self.logger.info("Shortest path from %d to %d is %s", dp.id,target_dpid,str(path))
                next_hop = path[1]
                out_port = self.sw_adj_lst[dp.id][next_hop]

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(dp, 10, match, actions, msg.buffer_id)

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=msg.data)
                dp.send_msg(out)

    def add_flow(self, dp, priority, match, actions, buffer_id=None):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=dp,
                                    priority=priority,
                                    match=match,
                                    instructions=inst,
                                    buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=dp,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        dp.send_msg(mod)

    def update_topology(self):
        switch_list = get_switch(self.topology_api_app, None)
        for switch in switch_list:
            self.datapath_lst[switch.dp.id] = switch.dp
            self.sw_adj_lst.setdefault(switch.dp.id, {})

        link_list = get_link(self.topology_api_app, None)
        for link in link_list:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            self.sw_adj_lst.setdefault(src_dpid, {})[dst_dpid] = src_port

    def get_sp_djk(self, src_dpid, dst_dpid):
        if src_dpid not in self.sw_adj_lst or dst_dpid not in self.sw_adj_lst:
            return None

        # --- FIX 1: FORCE BI-DIRECTIONAL PATH SYMMETRY ---
        # Always run Dijkstra from the smaller DPID to the larger DPID
        is_reversed = src_dpid > dst_dpid
        s_node = dst_dpid if is_reversed else src_dpid
        d_node = src_dpid if is_reversed else dst_dpid

        dst_lst = {}
        parent_lst = {}

        for node in self.sw_adj_lst:
            dst_lst[node] = float('inf')
            parent_lst[node] = None

        dst_lst[s_node] = 0
        uv_nodes = list(self.sw_adj_lst.keys())

        while uv_nodes:
            # --- FIX 2: DETERMINISTIC TIE-BREAKING FOR MULTIPLE PATHS ---
            # Sorting uv_nodes ensures that if two nodes have equal distance,
            # the tie-break is consistently decided by numerical DPID order.
            cur_node = min(sorted(uv_nodes), key=lambda node: dst_lst[node])
            uv_nodes.remove(cur_node)

            if dst_lst[cur_node] == float('inf') or cur_node == d_node:
                break

            # --- FIX 3: DETERMINISTIC NEIGHBOR ITERATION ---
            # Sorting the neighbor keys removes any dependency on the
            # asynchronous order in which Ryu populated the adjacency dict.
            for neighbor in sorted(self.sw_adj_lst.get(cur_node, {}).keys()):
                new_dist = dst_lst[cur_node] + 1
                if new_dist < dst_lst.get(neighbor, float('inf')):
                    dst_lst[neighbor] = new_dist
                    parent_lst[neighbor] = cur_node

        # Reconstruct path from s_node to d_node
        path = []
        curr = d_node
        while curr is not None:
            path.insert(0, curr)
            curr = parent_lst[curr]

        # If a valid path was found, adjust orientation based on who initiated the request
        if path and path[0] == s_node:
            if is_reversed:
                path.reverse()  # Mirror the path back to the actual src->dst direction
            return path
        return None

    def handle_arp(self, dp, in_port, pkt, eth_pkt, arp_pkt,is_arp_req):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        target_ip = arp_pkt.dst_ip

        target_dpid = None
        target_port = None
        artype = "Request" if is_arp_req else "Reply"
        for dpid, hosts in self.edsw_host_port_lst.items():
            if target_ip in hosts:
                target_dpid = dpid
                target_port = hosts[target_ip]
                break

        if target_dpid is not None:
            if dp.id == target_dpid:
                out_port = target_port
            else:
                self.logger.info("Arp %s. Finding Shortest path from %d to %d",artype, dp.id, target_dpid)
                path = self.get_sp_djk(dp.id, target_dpid)
                if not path or len(path) < 2:
                    self.logger.info("Arp %s.No Shortest path from %d to %d. Flooding via incoming port %d",artype, dp.id,target_dpid, in_port)
                    self.flood(dp, in_port, eth_pkt, pkt.data)
                    return
                self.logger.info("Arp %s.Shortest path from %d to %d is %s",artype, dp.id, target_dpid, str(path))
                next_hop = path[1]
                out_port = self.sw_adj_lst[dp.id][next_hop]

            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=pkt.data)
            dp.send_msg(out)
        else:
            self.logger.info("Arp %s.No target dpid found to %s via switch %d for arp_pkt. Flooding via incoming port %d",artype,target_ip, dp.id, in_port)
            self.flood(dp, in_port, eth_pkt, pkt.data)

    def flood(self, dp, in_port, eth_pkt, data=None):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data if data else eth_pkt.data)
        dp.send_msg(out)