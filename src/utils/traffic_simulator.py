"""
Real-Time Network Traffic Simulator
Generates realistic maritime network traffic with occasional attacks for testing
"""

import random
import time
import numpy as np
from datetime import datetime
import threading
import queue

class NetworkTrafficSimulator:
    """Simulates realistic maritime network traffic"""
    
    def __init__(self):
        self.running = False
        self.traffic_queue = queue.Queue(maxsize=1000)
        
        # Attack probability (5% of traffic)
        self.attack_probability = 0.05
        
        # Traffic patterns
        self.attack_types = ['Dos', 'Probe', 'R2L', 'U2R']
        
        # Normal traffic baseline (28 features)
        self.normal_baseline = {
            'protocol_type': 0,  # tcp
            'service': 1,        # http
            'flag': 2,           # SF
            'src_bytes': random.randint(50, 500),
            'dst_bytes': random.randint(50, 500),
            'wrong_fragment': 0,
            'hot': 0,
            'logged_in': 1,
            'num_compromised': 0,
            'count': random.randint(1, 50),
            'srv_count': random.randint(1, 50),
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.9,
            'diff_srv_rate': 0.1,
            'srv_diff_host_rate': 0.05,
            'dst_host_count': random.randint(10, 100),
            'dst_host_srv_count': random.randint(10, 100),
            'dst_host_same_srv_rate': 0.9,
            'dst_host_diff_srv_rate': 0.1,
            'dst_host_same_src_port_rate': 0.8,
            'dst_host_srv_diff_host_rate': 0.1,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
    
    def generate_normal_traffic(self):
        """Generate normal network traffic"""
        traffic = self.normal_baseline.copy()
        
        # Add small variations
        traffic['src_bytes'] = random.randint(50, 500)
        traffic['dst_bytes'] = random.randint(50, 500)
        traffic['count'] = random.randint(1, 50)
        traffic['srv_count'] = random.randint(1, 50)
        traffic['dst_host_count'] = random.randint(10, 100)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'normal',
            'features': list(traffic.values()),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': f'10.0.0.{random.randint(1, 254)}'
        }
    
    def generate_dos_attack(self):
        """Generate DoS attack traffic"""
        traffic = self.normal_baseline.copy()
        
        # DoS characteristics
        traffic['src_bytes'] = random.randint(5000, 50000)  # Large
        traffic['count'] = random.randint(500, 2000)  # High connection count
        traffic['srv_count'] = random.randint(500, 2000)
        traffic['serror_rate'] = random.uniform(0.5, 0.9)
        traffic['srv_serror_rate'] = random.uniform(0.5, 0.9)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'Dos',
            'features': list(traffic.values()),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': f'10.0.0.{random.randint(1, 254)}',
            'severity': 'HIGH'
        }
    
    def generate_probe_attack(self):
        """Generate Probe attack traffic"""
        traffic = self.normal_baseline.copy()
        
        # Probe characteristics
        traffic['dst_host_count'] = random.randint(200, 500)  # Many hosts
        traffic['dst_host_srv_count'] = random.randint(200, 500)
        traffic['dst_host_diff_srv_rate'] = random.uniform(0.7, 0.9)
        traffic['same_srv_rate'] = random.uniform(0.1, 0.3)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'Probe',
            'features': list(traffic.values()),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': f'10.0.0.{random.randint(1, 254)}',
            'severity': 'MEDIUM'
        }
    
    def generate_r2l_attack(self):
        """Generate R2L attack traffic"""
        traffic = self.normal_baseline.copy()
        
        # R2L characteristics
        traffic['logged_in'] = 0
        traffic['num_compromised'] = random.randint(1, 5)
        traffic['hot'] = random.randint(1, 10)
        traffic['wrong_fragment'] = random.randint(1, 3)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'R2L',
            'features': list(traffic.values()),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': f'10.0.0.{random.randint(1, 254)}',
            'severity': 'HIGH'
        }
    
    def generate_u2r_attack(self):
        """Generate U2R attack traffic"""
        traffic = self.normal_baseline.copy()
        
        # U2R characteristics
        traffic['num_compromised'] = random.randint(5, 20)
        traffic['hot'] = random.randint(10, 50)
        traffic['logged_in'] = 1
        
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'U2R',
            'features': list(traffic.values()),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': f'10.0.0.{random.randint(1, 254)}',
            'severity': 'CRITICAL'
        }
    
    def generate_traffic(self):
        """Generate one traffic sample"""
        # Decide if this is an attack
        if random.random() < self.attack_probability:
            attack_type = random.choice(self.attack_types)
            if attack_type == 'Dos':
                return self.generate_dos_attack()
            elif attack_type == 'Probe':
                return self.generate_probe_attack()
            elif attack_type == 'R2L':
                return self.generate_r2l_attack()
            else:
                return self.generate_u2r_attack()
        else:
            return self.generate_normal_traffic()
    
    def run(self, interval=1.0):
        """Start generating traffic continuously"""
        self.running = True
        
        while self.running:
            try:
                traffic = self.generate_traffic()
                
                # Add to queue if not full
                if not self.traffic_queue.full():
                    self.traffic_queue.put(traffic)
                
                time.sleep(interval)
                
            except Exception as e:
                print(f"Error generating traffic: {e}")
                time.sleep(1)
    
    def start(self, interval=1.0):
        """Start simulator in background thread"""
        self.thread = threading.Thread(target=self.run, args=(interval,), daemon=True)
        self.thread.start()
        print(f"✅ Network traffic simulator started (1 sample every {interval}s)")
    
    def stop(self):
        """Stop the simulator"""
        self.running = False
        print("⏹️ Network traffic simulator stopped")
    
    def get_traffic(self):
        """Get one traffic sample from queue"""
        try:
            return self.traffic_queue.get_nowait()
        except queue.Empty:
            return None
    
    def get_stats(self):
        """Get simulator statistics"""
        return {
            'running': self.running,
            'queue_size': self.traffic_queue.qsize(),
            'attack_probability': self.attack_probability
        }


# Test the simulator
if __name__ == "__main__":
    print("Testing Network Traffic Simulator...")
    
    simulator = NetworkTrafficSimulator()
    simulator.start(interval=0.5)
    
    # Generate 20 samples
    for i in range(20):
        time.sleep(0.5)
        traffic = simulator.get_traffic()
        
        if traffic:
            attack_marker = "🔴" if traffic['type'] != 'normal' else "✅"
            print(f"{attack_marker} [{i+1}] {traffic['type']:10s} | {traffic['source_ip']:15s} → {traffic['destination_ip']}")
    
    simulator.stop()
    print("\n✅ Test complete!")
