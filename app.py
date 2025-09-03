# app.py

from flask import Flask, render_template, request, jsonify, Response
import pandas as pd
import numpy as np
import pickle
import os
import json
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from collections import defaultdict, deque
import threading
import time
import random

app = Flask(__name__)

# In-memory storage for alerts and traffic stats
alerts = []
traffic_stats = {
    'total_packets': 0,
    'allowed_packets': 0,
    'blocked_packets': 0,
    'threats_blocked': 0,
    'traffic_history': [],
    'top_sources': defaultdict(int),
    'top_destinations': defaultdict(int),
    'attack_types': defaultdict(int)
}

# Global variables for threat tracking
THREAT_LEVEL = 0  # 0-100, represents current threat level
PROTECTION_ACTIVE = True
LAST_THREAT_UPDATE = time.time()
THREAT_UPDATE_INTERVAL = 5  # seconds

class AISecurityEngine:
    def __init__(self):
        self.models = {}
        self.traffic_baseline = None
        self.load_models()
        self.known_threats = set()
        self.ip_reputation = {}
        self.packet_queue = deque(maxlen=1000)
        self.target_port = 80
        
    def load_models(self):
        """Load pre-trained ML models for different types of analysis"""
        try:
            # Load or train the anomaly detection model
            if not os.path.exists('models/anomaly_detector.pkl'):
                self.train_models()
            
            with open('models/anomaly_detector.pkl', 'rb') as f:
                self.models['anomaly_detector'] = pickle.load(f)
                
        except Exception as e:
            print(f"Error loading models: {e}")
            self.train_models()
    
    def train_models(self):
        """Train machine learning models for threat detection"""
        try:
            if not os.path.exists("simulated_traffic.csv"):
                print("Training data not found. Generating sample traffic...")
                from traffic_simulator import generate_dataset
                generate_dataset()
            
            df = pd.read_csv("simulated_traffic.csv")
            
            # Feature engineering
            df['packet_size'] = df['packet_size'].astype(int)
            df['src_port'] = df['src_port'].astype(int)
            df['dst_port'] = df['dst_port'].astype(int)
            
            # Train anomaly detection model
            X = df[['src_port', 'dst_port', 'packet_size']].values
            model = IsolationForest(contamination=0.1, random_state=42)
            model.fit(X)
            
            # Save the model
            os.makedirs('models', exist_ok=True)
            with open('models/anomaly_detector.pkl', 'wb') as f:
                pickle.dump(model, f)
                
            self.models['anomaly_detector'] = model
            print("AI models trained successfully.")
            
        except Exception as e:
            print(f"Error training models: {e}")
    
    def analyze_packet(self, packet_data):
        """Analyze network packet for potential threats"""
        try:
            # Update traffic statistics
            traffic_stats['total_packets'] += 1
            traffic_stats['allowed_packets'] += 1
            
            # Extract features for analysis
            features = np.array([[
                packet_data.get('src_port', random.randint(1024, 65535)),
                packet_data.get('dst_port', self.target_port),
                packet_data.get('packet_size', 512)
            ]])
            
            # Check for anomalies
            is_anomaly = self.models['anomaly_detector'].predict(features)[0] == -1
            threat_level = self.calculate_threat_level(packet_data, is_anomaly)
            
            # Update traffic stats
            src_ip = packet_data.get('src_ip', 'unknown')
            traffic_stats['top_sources'][src_ip] += 1
            
            # Update attack type stats if this is an attack
            attack_type = packet_data.get('attack_type')
            if attack_type:
                traffic_stats['attack_types'][attack_type] += 1
            
            # Update threat intelligence
            if threat_level > 0.7:  # High confidence threat
                self.known_threats.add(src_ip)
                self.block_ip(src_ip, f"High confidence threat detected: {attack_type}")
                return False, threat_level
                
            return True, threat_level
            
        except Exception as e:
            print(f"Error analyzing packet: {e}")
            return True, 0.0
    
    def calculate_threat_level(self, packet_data, is_anomaly):
        """Calculate threat level based on multiple factors"""
        threat_score = 0.0
        
        # Check for known malicious IPs
        if packet_data.get('src_ip') in self.known_threats:
            threat_score += 0.8
            
        # Check for port scanning behavior
        if self.detect_port_scan(packet_data):
            threat_score += 0.6
            
        # Check for HTTP flood
        if self.detect_http_flood(packet_data):
            threat_score += 0.7
            
        # Consider anomaly detection result
        if is_anomaly:
            threat_score += 0.5
            
        return min(1.0, threat_score)
    
    def detect_port_scan(self, packet_data):
        """Detect potential port scanning activity"""
        src_ip = packet_data.get('src_ip')
        if not src_ip:
            return False
            
        recent_scans = sum(1 for p in self.packet_queue 
                          if p.get('src_ip') == src_ip 
                          and p.get('dst_port') != packet_data.get('dst_port'))
        return recent_scans > 10  # Threshold for port scan detection
    
    def detect_http_flood(self, packet_data):
        """Detect potential HTTP flood attack"""
        src_ip = packet_data.get('src_ip')
        if not src_ip:
            return False
            
        recent_requests = sum(1 for p in self.packet_queue 
                            if p.get('src_ip') == src_ip 
                            and p.get('protocol') == 'http')
        return recent_requests > 50  # Threshold for HTTP flood detection
    
    def block_ip(self, ip, reason):
        """Block an IP address"""
        self.known_threats.add(ip)
        alert = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'threat': 'Blocked IP',
            'source': ip,
            'severity': 'high',
            'details': reason
        }
        alerts.append(alert)
        traffic_stats['blocked_packets'] += 1
        traffic_stats['threats_blocked'] += 1
        traffic_stats['allowed_packets'] -= 1  # Adjust allowed count

# Initialize the AI security engine
security_engine = AISecurityEngine()

def update_traffic_history():
    """Update traffic history for the dashboard"""
    while True:
        try:
            now = datetime.now().strftime("%H:%M:%S")
            traffic_stats['traffic_history'].append({
                'time': now,
                'packets': traffic_stats['total_packets'],
                'threats': traffic_stats['threats_blocked']
            })
            
            # Keep only last 100 data points
            if len(traffic_stats['traffic_history']) > 100:
                traffic_stats['traffic_history'] = traffic_stats['traffic_history'][-100:]
                
        except Exception as e:
            print(f"Error updating traffic history: {e}")
            
        time.sleep(1)

# Start the traffic history updater in background
history_thread = threading.Thread(target=update_traffic_history, daemon=True)
history_thread.start()

# Background thread for continuous protection
def protection_loop():
    global THREAT_LEVEL, LAST_THREAT_UPDATE, PROTECTION_ACTIVE
    
    while True:
        try:
            current_time = time.time()
            
            # Gradually reduce threat level if no recent threats
            if current_time - LAST_THREAT_UPDATE > THREAT_UPDATE_INTERVAL:
                THREAT_LEVEL = max(0, THREAT_LEVEL - 5)  # Reduce by 5% every interval
                
            # Update protection status based on threat level
            if THREAT_LEVEL > 70:
                PROTECTION_ACTIVE = True
                print(f"[!] HIGH THREAT LEVEL: {THREAT_LEVEL}% - Protection MAXIMIZED")
            elif THREAT_LEVEL > 30:
                PROTECTION_ACTIVE = True
                print(f"[!] Elevated threat level: {THREAT_LEVEL}% - Protection active")
            else:
                PROTECTION_ACTIVE = True  # Keep protection always active
                
            time.sleep(1)
            
        except Exception as e:
            print(f"[!] Error in protection loop: {e}")
            time.sleep(5)

# Start protection thread
protection_thread = threading.Thread(target=protection_loop, daemon=True)
protection_thread.start()

def analyze_with_ai(packet_data):
    """Analyze packet data using AI model and heuristics"""
    try:
        # Extract features for AI model
        features = extract_features(packet_data)
        
        # Get prediction from AI model
        prediction = ai_model.predict([features])[0]
        
        # Calculate threat score (0-1)
        threat_score = float(prediction)
        
        # Determine threat type based on packet characteristics
        threat_type = 'unknown'
        
        # Apply heuristics to detect specific attack types
        if is_http_flood(packet_data):
            threat_type = 'http_flood'
            threat_score = max(threat_score, 0.8)  # Ensure high score for detected floods
            
        if is_port_scan(packet_data):
            threat_type = 'port_scan'
            threat_score = max(threat_score, 0.7)  # Ensure high score for port scans
        
        # If threat score is above threshold, mark as threat
        is_threat = threat_score > 0.6
        
        return is_threat, threat_score, threat_type
        
    except Exception as e:
        print(f"[!] Error in AI analysis: {e}")
        return False, 0.0, 'error'

def is_http_flood(packet_data):
    """Detect HTTP flood based on request patterns"""
    # Check for high request rate from same IP (handled by the rate limiter)
    # Additional checks for suspicious patterns
    if packet_data.get('protocol') == 'http':
        if 'user_agent' in packet_data and 'python' in packet_data['user_agent'].lower():
            return True
        if 'path' in packet_data and packet_data['path'] in ['/admin', '/wp-login.php', '/.env']:
            return True
    return False

def is_port_scan(packet_data):
    """Detect port scanning patterns"""
    # Check for connection attempts to multiple ports in short time
    # This is handled by tracking connection patterns in the AI features
    return False

def block_ip(ip_address):
    """Block an IP address using system firewall"""
    if not ip_address or ip_address == '127.0.0.1':
        return False
        
    try:
        # Add to blocked IPs set
        if ip_address not in blocked_ips:
            blocked_ips.add(ip_address)
            print(f"[!] Blocked IP: {ip_address}")
            
            # Here you would add actual firewall rules, e.g.:
            # For Linux: os.system(f'iptables -A INPUT -s {ip_address} -j DROP')
            # For Windows: os.system(f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}')
            
        return True
    except Exception as e:
        print(f"[!] Error blocking IP {ip_address}: {e}")
        return False

@app.route('/')
def index():
    return render_template('index.html', alerts=alerts[-10:], stats=traffic_stats)

@app.route('/api/analyze', methods=['POST'])
def analyze_packet():
    global THREAT_LEVEL, LAST_THREAT_UPDATE
    
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # Update threat timestamp
        LAST_THREAT_UPDATE = time.time()
        
        # Analyze packet using AI model
        is_threat, threat_score, threat_type = analyze_with_ai(data)
        
        # Update threat level
        THREAT_LEVEL = min(100, max(THREAT_LEVEL, threat_score * 100))
        
        # If it's a threat, block it and log
        if is_threat and PROTECTION_ACTIVE:
            block_ip(data.get('src_ip'))
            log_alert(data, threat_type, threat_score)
            return jsonify({
                'status': 'blocked',
                'threat_type': threat_type,
                'threat_score': threat_score,
                'message': f'Blocked {threat_type} attack from {data.get("src_ip")}'
            }), 403
            
        return jsonify({
            'status': 'allowed',
            'threat_score': threat_score,
            'message': 'Packet analyzed and allowed'
        })
        
    except Exception as e:
        print(f"[!] Error analyzing packet: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    # Convert defaultdict to regular dict for JSON serialization
    stats = dict(traffic_stats)
    stats['top_sources'] = dict(traffic_stats['top_sources'])
    stats['top_destinations'] = dict(traffic_stats['top_destinations'])
    stats['attack_types'] = dict(traffic_stats['attack_types'])
    return jsonify(stats)

@app.route('/api/alerts')
def get_alerts():
    return jsonify(alerts[-50:])  # Return last 50 alerts

@app.route('/api/protection/status', methods=['GET'])
def get_protection_status():
    return jsonify({
        'protection_active': PROTECTION_ACTIVE,
        'threat_level': THREAT_LEVEL,
        'last_threat_update': datetime.fromtimestamp(LAST_THREAT_UPDATE).isoformat(),
        'status': 'active' if PROTECTION_ACTIVE else 'inactive',
        'message': 'AI protection is active and monitoring' if PROTECTION_ACTIVE else 'Protection is not active'
    })

if __name__ == '__main__':
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)