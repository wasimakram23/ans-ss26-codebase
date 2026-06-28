#!/usr/bin/env python3
import time
import re
import sys
import argparse
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink

# Import your topology class directly from topo.py
from topo import FatTreeTopo

def parse_iperf_throughput(output_str):
    """Parses iperf output string to extract throughput in Mbits/sec."""
    # Matches strings like: "0.0-10.0 sec  17.2 MBytes  14.4 Mbits/sec"
    match = re.findall(r'([\d.]+)\s+Mbits/sec', output_str)
    if match:
        return float(match[-1]) # Return the last metric (the summary average)
    return 0.0

def parse_ping_latency(output_str):
    """Parses ping output string to extract average RTT in ms."""
    # Matches strings like: "rtt min/avg/max/mdev = 40.124/40.540/41.210/0.412 ms"
    match = re.search(r'rtt\s+min/avg/max/mdev\s+=\s+[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s+ms', output_str)
    if match:
        return float(match.group(1))
    return 0.0

def run_experiments(routing_type):
    info(f"\n--- Starting Automated Experiment Suite for Mode: [{routing_type.upper()}] ---\n")
    
    # Initialize your custom k=4 FatTree topology
    topo = FatTreeTopo(k=4)
    net = Mininet(topo=topo, switch=OVSKernelSwitch, link=TCLink, controller=None)
    
    info("*** Connecting to Remote Ryu Controller...\n")
    net.addController('c1', controller=RemoteController, ip="127.0.0.1", port=6653)
    net.start()
    
    # Let switches fully connect to controller and exchange feature requests
    info("*** Waiting for controller flow handshakes to complete...\n")
    time.sleep(20)
    
    # Retrieve host node handles using exact naming schemas from topo.py
    # Format: h{pod}{edge_idx}{host_id}
    h002 = net.get('h002') # Pod 0, Edge 0, ID 2 (10.0.0.2)
    h012 = net.get('h012') # Pod 0, Edge 1, ID 2 (10.0.1.2)
    h013 = net.get('h013') # Pod 0, Edge 1, ID 3 (10.0.1.3)
    h102 = net.get('h102') # Pod 1, Edge 0, ID 2 (10.1.0.2)
    h213 = net.get('h213') # Pod 2, Edge 1, ID 3 (10.2.1.3)

    # -------------------------------------------------------------------------
    # Enhanced Warm-up phase: Force end-to-end discovery before loading bandwidth
    # -------------------------------------------------------------------------
    info("*** Phase 0: Deep pinging topology nodes to resolve Dijkstra paths...\n")
    # Warm up local path
    h012.cmd('ping -c 3 10.0.0.2')
    time.sleep(1)
    
    # Warm up Inter-Pod Flow 1 (h002 -> h102)
    h002.cmd('ping -c 3 10.1.0.2')
    time.sleep(1)
    
    # Warm up Inter-Pod Flow 2 (h013 -> h213)
    h013.cmd('ping -c 3 10.2.1.3')
    time.sleep(2)

    results = {}

    # -------------------------------------------------------------------------
    # Scenario 1: Intra-Pod (Low-Contention Traffic)
    # -------------------------------------------------------------------------
    info("\n*** Phase 1: Running Intra-Pod Low-Contention Test (h012 -> h002)...\n")
    # Start background TCP listener on server h002
    h002.cmd('iperf -s -p 5001 &')
    time.sleep(1)
    
    # Execute iperf client on h012
    iperf_out_local = h012.cmd('iperf -c 10.0.0.2 -p 5001 -t 10')
    ping_out_local = h012.cmd('ping -c 5 10.0.0.2')
    
    # Kill iperf server
    h002.cmd('killall iperf')
    
    results['intra_throughput'] = parse_iperf_throughput(iperf_out_local)
    results['intra_latency'] = parse_ping_latency(ping_out_local)

    # -------------------------------------------------------------------------
    # Scenario 2: Inter-Pod Concurrent Bottleneck Simulation
    # -------------------------------------------------------------------------
    info("\n*** Phase 2: Running Inter-Pod High-Contention Test (Parallel Core Flows)...\n")
    # Spin up external target listeners
    h102.cmd('iperf -s -p 5002 &')
    h213.cmd('iperf -s -p 5003 &')
    time.sleep(1)
    
    # Fire off concurrent clients with a small stagger to prevent controller race conditions
    info("-> Triggering staggered cross-pod iperf streams...\n")
    h002.cmd('iperf -c 10.1.0.2 -p 5002 -t 12 > /tmp/flow1.log &')
    time.sleep(0.75)  # Gives the controller time to compute and install the first path
    h013.cmd('iperf -c 10.2.1.3 -p 5003 -t 12 > /tmp/flow2.log &')
    
    # Wait for the concurrent flows to expire safely
    time.sleep(15)
    
    # Collect results from temporary files
    flow1_out = h002.cmd('cat /tmp/flow1.log')
    flow2_out = h013.cmd('cat /tmp/flow2.log')
    
    # Record interactive cross-pod RTT latency during the load
    ping_out_inter = h002.cmd('ping -c 5 10.1.0.2')
    
    # Clean up environment processes
    h102.cmd('killall iperf')
    h213.cmd('killall iperf')
    h002.cmd('rm /tmp/flow1.log')
    h013.cmd('rm /tmp/flow2.log')
    
    results['inter_f1_throughput'] = parse_iperf_throughput(flow1_out)
    results['inter_f2_throughput'] = parse_iperf_throughput(flow2_out)
    results['inter_latency'] = parse_ping_latency(ping_out_inter)

    # -------------------------------------------------------------------------
    # Reporting Printout
    # -------------------------------------------------------------------------
    print("\n" + "="*50)
    print(f" EXPERIMENTAL RESULTS FOR: {routing_type.upper()} ROUTING")
    print("="*50)
    print(f"1. Intra-Pod Throughput : {results['intra_throughput']} Mbps")
    print(f"2. Intra-Pod Avg Latency: {results['intra_latency']} ms")
    print("-"*50)
    print(f"3. Inter-Pod Flow 1 BW  : {results['inter_f1_throughput']} Mbps")
    print(f"4. Inter-Pod Flow 2 BW  : {results['inter_f2_throughput']} Mbps")
    print(f"5. Inter-Pod Total BW   : {results['inter_f1_throughput'] + results['inter_f2_throughput']} Mbps")
    print(f"6. Inter-Pod Latency    : {results['inter_latency']} ms")
    print("="*50 + "\n")
    
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    
    parser = argparse.ArgumentParser(description="Automate Mininet Lab2 Experiments.")
    parser.add_argument('--routing', choices=['sp', 'ft'], required=True, 
                        help="Specify routing mode currently active in Ryu ('sp' for Shortest Path, 'ft' for Two-Level Suffix Routing).")
    args = parser.parse_args()
    
    run_experiments(args.routing)