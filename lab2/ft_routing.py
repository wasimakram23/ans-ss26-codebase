from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ether_types

# declare constants
K = 4
PRIO_HOST = 30
PRIO_PREFIX = 20
PRIO_SUFFIX = 10
PRIO_ARP = 1
PRIO_MISS = 0


class FatTreeRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FatTreeRouter, self).__init__(*args, **kwargs)
        self.k = K
        self.pod_sw_cnt = K
        self.half = K // 2
        self.num_core = self.half * self.half
        self.ip_mac_maps = self.generate_host_table()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        # table miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, PRIO_MISS, match, actions)

        # arp flow entry
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, PRIO_ARP, match, actions)

        type, pod, idx = self.get_switch_info(dp.id)
        if type == 'core':
            self.ins_cr_sw_flow(dp)
        elif type == 'agg':
            self.ins_agg_sw_flow(dp, pod, idx)
        else:
            self.ins_edg_sw_flow(dp, pod, idx)
        self.logger.info('dpid %s: installed %s table', dp.id, type)

    def add_flow(self, dp, prio, match, actions):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=prio,
                                   match=match, instructions=inst))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(dp, in_port, eth, pkt)

    def handle_arp(self, dp, in_port, eth, pkt):
        req = pkt.get_protocol(arp.arp)
        if req is None or req.opcode != arp.ARP_REQUEST:
            return
        if req.src_ip == '0.0.0.0' or req.dst_ip == req.src_ip:
            return
        target_mac = self.ip_mac_maps.get(req.dst_ip)
        if target_mac is None:
            return
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            src=target_mac,
            dst=eth.src))
        reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=target_mac,
            src_ip=req.dst_ip,
            dst_mac=req.src_mac,
            dst_ip=req.src_ip))
        reply.serialize()
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=reply.data))

    def generate_host_table(self):
        table = {}
        for pod in range(self.k):
            for edge in range(self.half):
                for hid in range(2, self.half + 2):
                    ip = '10.%d.%d.%d' % (pod, edge, hid)
                    mac = '00:00:00:%02x:%02x:%02x' % (pod, edge, hid)
                    table[ip] = mac
        return table

    def get_switch_info(self, dpid):
        if 1 <= dpid <= self.num_core:
            return ('core', None, dpid - 1)
        off = dpid - self.num_core - 1
        pod = off // self.pod_sw_cnt
        pos = off % self.pod_sw_cnt
        if pos < self.half:
            return ('agg', pod, pos)
        return ('edge', pod, pos - self.half)

    def ins_cr_sw_flow(self, dp):
        parser = dp.ofproto_parser
        for pod in range(self.k):
            match = self.get_ip_match_rule(dp, '10.%d.0.0' % pod, '255.255.0.0')
            actions = [parser.OFPActionOutput(pod + 1)]
            self.add_flow(dp, PRIO_PREFIX, match, actions)

    def ins_agg_sw_flow(self, dp, pod, idx):
        parser = dp.ofproto_parser
        s = self.half + idx
        for e in range(self.half):
            match = self.get_ip_match_rule(dp, '10.%d.%d.0' % (pod, e), '255.255.255.0')
            actions = [parser.OFPActionOutput(self.half + 1 + e)]
            self.add_flow(dp, PRIO_PREFIX, match, actions )

        for hid in range(2, self.half + 2):
            up = 1 + ((hid - 2 + s) % self.half)
            match = self.get_ip_match_rule(dp, '0.0.0.%d' % hid, '0.0.0.255')
            actions = [parser.OFPActionOutput(up)]
            self.add_flow(dp, PRIO_SUFFIX, match, actions)

    def ins_edg_sw_flow(self, dp, pod, idx):
        parser = dp.ofproto_parser
        s = idx
        for hid in range(2, self.half + 2):
            match = self.get_ip_match_rule(dp, '10.%d.%d.%d' % (pod, idx, hid))
            actions = [parser.OFPActionOutput(self.half + hid - 1)]
            self.add_flow(dp, PRIO_HOST, match, actions)

        for hid in range(2, self.half + 2):
            up = 1 + ((hid - 2 + s) % self.half)
            match = self.get_ip_match_rule(dp, '0.0.0.%d' % hid, '0.0.0.255')
            actions = [parser.OFPActionOutput(up)]
            self.add_flow(dp, PRIO_SUFFIX, match, actions)

    def get_ip_match_rule(self, dp, ip, mask=None):
        parser = dp.ofproto_parser
        if mask is None:
            return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=(ip, mask))
