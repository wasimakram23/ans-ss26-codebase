import sys


# Define FatTreeTopo locally to simulate it and trace its execution
class FatTreeTopoTrace:
    def __init__(self, k=4):
        self.k = k
        self.switches = []
        self.hosts = []
        self.links = []

        core_switches = {}  # (j, i) -> sw_name
        agg_switches = {}  # (p, s) -> sw_name
        edge_switches = {}  # (p, s) -> sw_name

        switch_counter = 1

        print("--- 1. Core Switches ---")
        # Total: (k/2)^2 core switches
        for j in range(1, (k // 2) + 1):
            for i in range(1, (k // 2) + 1):
                sw_name = f'cs{switch_counter}'
                self.switches.append(sw_name)
                core_switches[(j, i)] = sw_name
                print(f"Added Core Switch: {sw_name} at grid ({j}, {i})")
                switch_counter += 1
        print("Core Switches")
        print(core_switches)
        print("\n--- 2. Pods, Aggregation, Edge, and Hosts ---")
        for p in range(k):
            print(f"\n--- Processing Pod {p} ---")
            # Create Aggregation Switches for Pod p
            for s in range(k // 2, k):
                sw_name = f'as{switch_counter}'
                self.switches.append(sw_name)
                agg_switches[(p, s)] = sw_name
                print(f"  Added Aggregation Switch: {sw_name} for Pod {p}, index {s}")
                switch_counter += 1

                # Connect Aggregation to Core switches based on stride rules
                stride = s - (k // 2)
                for i in range(1, (k // 2) + 1):
                    core_sw = core_switches[(stride + 1, i)]
                    self.links.append((sw_name, core_sw))
                    print(f"    Linked Aggregation {sw_name} to Core ({stride + 1}, {i}):{core_sw}")

            # Create Edge Switches for Pod p
            for s in range(0, k // 2):
                sw_name = f'es{switch_counter}'
                self.switches.append(sw_name)
                edge_switches[(p, s)] = sw_name
                print(f"  Added Edge Switch: {sw_name} for Pod {p}, index {s}")
                switch_counter += 1

                # Connect Edge to Aggregation switches inside the same pod
                for agg_s in range(k // 2, k):
                    agg_sw = agg_switches[(p, agg_s)]
                    self.links.append((sw_name, agg_sw))
                    print(f"    Linked Edge {sw_name} to Aggregation {agg_sw}")

                # Create and Connect Hosts to the Edge Switch
                for h_id in range(2, (k // 2) + 2):
                    host_name = f'h{p}{s}{h_id}'
                    host_ip = f'10.{p}.{s}.{h_id}'
                    host_mac = f'00:00:00:{p:02x}:{s:02x}:{h_id:02x}'
                    self.hosts.append((host_name, host_ip, host_mac))
                    self.links.append((sw_name, host_name))
                    print(f"    Added Host {host_name} (IP: {host_ip}/8, MAC: {host_mac}) and linked to Edge {sw_name}")

        print("Agg Switches")
        print(agg_switches)
        print("Edg Switches")
        print(edge_switches)

FatTreeTopoTrace(k=4)