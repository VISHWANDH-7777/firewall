# traffic_simulator.py

import random
import time
from datetime import datetime
import pandas as pd
import numpy as np
from scapy.all import *

class TrafficGenerator:
    def __init__(self):
        self.normal_services = {
            80: 'http',
            443: 'https',
            53: 'dns',
            22: 'ssh',
            25: 'smtp',
            110: 'pop3',
            143: 'imap'
        }
        self.malicious_ips = ['185.130.5.253', '45.227.253.108', '91.234.36.84']
        self.internal_network = "192.168.1.0/24"

    def generate_normal_traffic(self, count=1000):
        traffic_data = []
        for _ in range(count):
            # Generate normal web traffic pattern
            src_ip = f"192.168.1.{random.randint(2, 254)}"
            dst_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            dst_port, service = random.choice(list(self.normal_services.items()))
            src_port = random.randint(49152, 65535)  # Ephemeral ports
            
            # Add some normal traffic patterns
            packet_size = random.randint(40, 1500)
            protocol = 6  # TCP
            
            # Add timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            traffic_data.append([
                timestamp, src_ip, dst_ip, src_port, dst_port, 
                packet_size, protocol, service, 'normal'
            ])
        return traffic_data

    def generate_attack_traffic(self, attack_type='syn_flood', count=50):
        traffic_data = []
        for _ in range(count):
            if attack_type == 'syn_flood':
                # SYN Flood attack
                src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                dst_ip = "192.168.1.1"
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([80, 443, 22])
                packet_size = 40  # Minimal SYN packet
                protocol = 6
                service = 'tcp'
                attack = 'syn_flood'
                
            elif attack_type == 'port_scan':
                # Port scan detection
                src_ip = random.choice(self.malicious_ips)
                dst_ip = f"192.168.1.{random.randint(2, 254)}"
                src_port = random.randint(1024, 65535)
                dst_port = random.randint(1, 1024)  # Common ports
                packet_size = 40
                protocol = 6
                service = 'scan'
                attack = 'port_scan'
                
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            traffic_data.append([
                timestamp, src_ip, dst_ip, src_port, dst_port,
                packet_size, protocol, service, attack
            ])
        return traffic_data

def generate_dataset():
    generator = TrafficGenerator()
    
    # Generate normal traffic (90% of dataset)
    normal_data = generator.generate_normal_traffic(900)
    
    # Generate various attack traffic (10% of dataset)
    attack_data = []
    attack_data.extend(generator.generate_attack_traffic('syn_flood', 50))
    attack_data.extend(generator.generate_attack_traffic('port_scan', 50))
    
    # Combine and save
    columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
               'packet_size', 'protocol', 'service', 'label']
    
    df_normal = pd.DataFrame(normal_data, columns=columns)
    df_attack = pd.DataFrame(attack_data, columns=columns)
    
    all_traffic = pd.concat([df_normal, df_attack], ignore_index=True)
    all_traffic.to_csv("simulated_traffic.csv", index=False)
    print(f"Generated {len(all_traffic)} traffic records (normal: {len(df_normal)}, attack: {len(df_attack)})")

if __name__ == "__main__":
    generate_dataset()