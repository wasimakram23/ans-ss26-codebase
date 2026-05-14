from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types,icmp


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

    # Handle switch initializer for miss flow
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("Switch feature handler for Switch %s", ev.msg.datapath.id)

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("switch_features_handler done for Switch %s", datapath.id)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        eth_type = eth_pkt.ethertype

        if not eth_pkt:
            return

        #  Ignore LLDP
        if eth_type == ether_types.ETH_TYPE_LLDP:
            return
        #  Ignore IPv6 (biggest noise source)
        if eth_type == ether_types.ETH_TYPE_IPV6:
            return

        #  Ignore multicast MAC addresses
        #if eth_pkt.dst.startswith("33:33") or eth_pkt.dst == "ff:ff:ff:ff:ff:ff":
        #    # Allow ARP broadcast only (handled below)
        #    if eth_type != ether_types.ETH_TYPE_ARP:
        #        return

        if dpid == 3:
            self.logger.info("Packet in handler for Router")
            self.handle_router(dp, pkt, msg)
        else:
            self.logger.info("Packet in handler for Switch")
            self.handle_switch(dp, pkt, msg)

    def handle_switch(self, dp, pkt, msg):

        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        in_port = msg.match['in_port']
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        src = eth_pkt.src
        dst = eth_pkt.dst
        dpid = dp.id

        self.logger.info("packet in Switch id:%s src_mac:%s dst_mac:%s in_port:%s", dpid, src, dst, in_port)

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,eth_dst=dst)
            self.add_flow(dp, 1, match, actions)
            self.logger.info("Flow added for Switch:%s Src:%s Dst:%s Port:%s", dpid, src, dst, in_port)

        out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        dp.send_msg(out)
        self.logger.info("packet in handler done for Switch %s", dpid)

    def handle_router(self, dp, pkt, msg):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match['in_port']

        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if arp_pkt:
            self.logger.info("Arp handler begin")
            self.handle_arp(dp, pkt, in_port)
            self.logger.info("Arp handler done")
            return

        if not ip:
            return

        src_ip = ip.src
        dst_ip = ip.dst

        # handle self gateway ping only
        if dst_ip in self.get_gateway_ips_with_mac() and self.is_self_gateway(src_ip, dst_ip):
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                self.reply_icmp(dp, pkt, msg, in_port)
                return

        # firewall rule external should not ping internal servers
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
        self.logger.info("Router handler done for Router")

    def handle_arp(self, dp, pkt, in_port):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        arp_pkt = pkt.get_protocol(arp.arp)
        # learn all IP-MAC mappings
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        self.logger.info("ARP table: %s", self.arp_table)

        # reply for gateway
        if arp_pkt.opcode == arp.ARP_REQUEST:
            self.logger.info("ARP request for %s", arp_pkt.dst_ip)
            if arp_pkt.dst_ip in self.get_gateway_ips_with_mac():

                mac = self.get_gateway_ips_with_mac()[arp_pkt.dst_ip]
                self.logger.info("ARP reply begin")
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
                self.logger.info("ARP reply done")

        # flush buffered packets
        if arp_pkt.src_ip in self.buffer:
            for dp2, msg2 in self.buffer[arp_pkt.src_ip]:
                self.logger.info("Flushing buffered packet for %s", arp_pkt.src_ip)
                self.handle_router(dp2, packet.Packet(msg2.data), msg2)
            del self.buffer[arp_pkt.src_ip]

    def trigger_arp(self, dp, port, dst_ip):

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        arp_req = packet.Packet()

        self.logger.info("Triggering ARP from src_mac: %s, src_ip= %s for %s", self.router_mac[port], self.get_gatewayip_by_port(port), dst_ip)
        arp_req.add_protocol(ethernet.ethernet(
            ethertype=0x0806,
            src=self.router_mac[port],
            dst="ff:ff:ff:ff:ff:ff"
        ))

        arp_req.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=self.router_mac[port],
            src_ip=self.get_gatewayip_by_port(port),
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

    def forward_packet(self, dp, msg, in_port, out_port, src_ip, dst_ip):
        self.logger.info("Forwarding packet from src_ip:%s  in_port:%s to dst_ip:%s out_port:%s", src_ip,in_port,dst_ip,out_port)
        self.logger.info("Packet: %s", msg.data)
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

        self.logger.info("Flow added for Switch:%s Src:%s Dst:%s Port:%s", dp.id, src_mac, dst_mac, out_port)
        self.add_flow(dp, 10, match, actions)

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )

        dp.send_msg(out)

    def reply_icmp(self, dp, pkt, msg, in_port):

        parser = dp.ofproto_parser
        ofp = dp.ofproto

        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        gateway_mac = self.get_gateway_ips_with_mac()[ip_pkt.dst]

        reply = packet.Packet()

        # ethernet
        reply.add_protocol(ethernet.ethernet(
            ethertype=0x0800,
            src=gateway_mac,
            dst=eth.src
        ))

        # ip
        reply.add_protocol(ipv4.ipv4(
            dst=ip_pkt.src,
            src=ip_pkt.dst,
            proto=1
        ))

        # icmp echo reply
        reply.add_protocol(icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data
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

    def get_gateway_ips_with_mac(self):
        return {
            "10.0.1.1": "aa:aa:aa:aa:aa:01",
            "10.0.2.1": "aa:aa:aa:aa:aa:02",
            "192.168.1.1": "aa:aa:aa:aa:aa:03"
        }

    def get_gatewayip_by_port(self, port):
        if port == 1:
            return "10.0.1.1"
        if port == 2:
            return "10.0.2.1"
        if port == 3:
            return "192.168.1.1"

    def is_self_gateway(self, src_ip, dst_ip):
        parts = src_ip.split('.')
        gateway_ip_prefix = '.'.join(parts[:3])
        return dst_ip.startswith(gateway_ip_prefix)
