from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp


class SDNRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNRouter, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.arp_table = {}

        # routing (s3 ports)
        self.routes = {
            "10.0.1.": 1,
            "10.0.2.": 2,
            "192.168.1.": 3
        }

        # router interface MACs (REAL, not fake logic)
        self.router_mac = {
            1: "aa:aa:aa:aa:aa:01",
            2: "aa:aa:aa:aa:aa:02",
            3: "aa:aa:aa:aa:aa:03"
        }

        # buffer packets until ARP resolution
        self.buffer = {}

    # ---------------- FLOW INSTALL ----------------
    def add_flow(self, dp, priority, match, actions):
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)

    # ---------------- SWITCH INIT ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]

        self.add_flow(dp, 0, match, actions)

    # ---------------- MAIN HANDLER ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):

        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        if eth.ethertype in (0x88cc, 0x86dd):
            return

        if dpid == 3:
            self.router(dp, pkt, msg)
        else:
            self.l2_switch(dp, pkt, msg)

    # ---------------- L2 SWITCH ----------------
    def l2_switch(self, dp, pkt, msg):

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        in_port = msg.match['in_port']
        eth = pkt.get_protocol(ethernet.ethernet)

        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][eth.src] = in_port

        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=eth.dst)
            self.add_flow(dp, 1, match, actions)

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        dp.send_msg(out)

    # ---------------- ROUTER ----------------
    def router(self, dp, pkt, msg):

        parser = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match['in_port']

        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        # ---------------- ARP ----------------
        if arp_pkt:
            self.handle_arp(dp, pkt, in_port)
            return

        # ---------------- IP ----------------
        if not ip:
            return

        src_ip = ip.src
        dst_ip = ip.dst

        # firewall rule
        if src_ip.startswith("192.168.1.") and dst_ip.startswith("10."):
            return

        # find route
        out_port = None
        for subnet, port in self.routes.items():
            if dst_ip.startswith(subnet):
                out_port = port
                break

        if not out_port:
            return

        # learn MAC first (critical fix)
        if dst_ip not in self.arp_table:
            self.trigger_arp(dp, out_port, dst_ip)
            self.buffer.setdefault(dst_ip, []).append((dp, msg))
            return

        self.forward_packet(dp, msg, in_port, out_port, src_ip, dst_ip)

    # ---------------- ARP HANDLER ----------------
    def handle_arp(self, dp, pkt, in_port):

        parser = dp.ofproto_parser
        ofp = dp.ofproto
        arp_pkt = pkt.get_protocol(arp.arp)

        # learn all IP-MAC mappings
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

        # reply for gateway
        if arp_pkt.opcode == arp.ARP_REQUEST:
            if arp_pkt.dst_ip in self.get_gateway_ips():

                mac = self.get_gateway_ips()[arp_pkt.dst_ip]

                reply = packet.Packet()
                reply.add_protocol(ethernet.ethernet(
                    ethertype=0x0806,
                    dst=arp_pkt.src_mac,
                    src=mac
                ))

                reply.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=mac,
                    src_ip=arp_pkt.dst_ip,
                    dst_mac=arp_pkt.src_mac,
                    dst_ip=arp_pkt.src_ip
                ))

                reply.serialize()

                out = parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=ofp.OFPP_CONTROLLER,
                    actions=[parser.OFPActionOutput(in_port)],
                    data=reply.data
                )
                dp.send_msg(out)

        # flush buffered packets
        if arp_pkt.src_ip in self.buffer:
            for dp2, msg2 in self.buffer[arp_pkt.src_ip]:
                self.router(dp2, packet.Packet(msg2.data), msg2)
            del self.buffer[arp_pkt.src_ip]

    # ---------------- ARP TRIGGER ----------------
    def trigger_arp(self, dp, port, dst_ip):

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        arp_req = packet.Packet()

        arp_req.add_protocol(ethernet.ethernet(
            ethertype=0x0806,
            src=self.router_mac[port],
            dst="ff:ff:ff:ff:ff:ff"
        ))

        arp_req.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=self.router_mac[port],
            src_ip=self.get_gateway(port),
            dst_mac="00:00:00:00:00:00",
            dst_ip=dst_ip
        ))

        arp_req.serialize()

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(port)],
            data=arp_req.data
        )
        dp.send_msg(out)

    # ---------------- FORWARDING ----------------
    def forward_packet(self, dp, msg, in_port, out_port, src_ip, dst_ip):

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        dst_mac = self.arp_table[dst_ip]
        src_mac = self.router_mac[out_port]

        actions = [
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]

        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=0x0800,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )

        self.add_flow(dp, 10, match, actions)

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )

        dp.send_msg(out)

    # ---------------- HELPERS ----------------
    def get_gateway_ips(self):
        return {
            "10.0.1.1": "aa:aa:aa:aa:aa:01",
            "10.0.2.1": "aa:aa:aa:aa:aa:02",
            "192.168.1.1": "aa:aa:aa:aa:aa:03"
        }

    def get_gateway(self, port):
        if port == 1:
            return "10.0.1.1"
        if port == 2:
            return "10.0.2.1"
        if port == 3:
            return "192.168.1.1"