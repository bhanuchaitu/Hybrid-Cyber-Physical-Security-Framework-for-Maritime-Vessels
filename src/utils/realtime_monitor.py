"""
Real-Time Monitoring System with WebSocket Support
Handles live threat detection and streaming updates
"""

import logging
from datetime import datetime
from collections import deque
import json

# Setup logging
logger = logging.getLogger(__name__)

class RealTimeMonitor:
    """Real-time monitoring and alerting system"""
    
    def __init__(self, detector=None):
        self.detector = detector
        self.active = False
        
        # Statistics tracking
        self.stats = {
            'total_traffic': 0,
            'normal_traffic': 0,
            'attacks_detected': 0,
            'dos_attacks': 0,
            'probe_attacks': 0,
            'r2l_attacks': 0,
            'u2r_attacks': 0,
            'last_attack_time': None
        }
        
        # Recent alerts (keep last 100)
        self.recent_alerts = deque(maxlen=100)
        
        # Live traffic history (keep last 50 for charts)
        self.traffic_history = deque(maxlen=50)
    
    def start(self):
        """Start monitoring"""
        self.active = True
        logger.info("✅ Real-time monitoring started")
    
    def stop(self):
        """Stop monitoring"""
        self.active = False
        logger.info("⏹️ Real-time monitoring stopped")
    
    def process_traffic(self, traffic_data):
        """Process one traffic sample and detect threats"""
        if not self.active:
            return None
        
        try:
            # Extract features
            features = traffic_data.get('features', [])
            
            if not features or len(features) < 28:
                return None
            
            # Make prediction if detector available
            if self.detector:
                prediction = self.detector.predict([features])
                
                # Map prediction to attack type
                attack_types = {0: 'Dos', 1: 'Probe', 2: 'R2L', 3: 'U2R', 4: 'normal'}
                predicted_type = attack_types.get(prediction[0], 'normal')
            else:
                # Use simulated type if no detector
                predicted_type = traffic_data.get('type', 'normal')
            
            # Update statistics
            self.stats['total_traffic'] += 1
            
            if predicted_type == 'normal':
                self.stats['normal_traffic'] += 1
            else:
                self.stats['attacks_detected'] += 1
                self.stats['last_attack_time'] = datetime.now().isoformat()
                
                # Count by attack type
                if predicted_type == 'Dos':
                    self.stats['dos_attacks'] += 1
                elif predicted_type == 'Probe':
                    self.stats['probe_attacks'] += 1
                elif predicted_type == 'R2L':
                    self.stats['r2l_attacks'] += 1
                elif predicted_type == 'U2R':
                    self.stats['u2r_attacks'] += 1
            
            # Create result
            result = {
                'timestamp': traffic_data.get('timestamp', datetime.now().isoformat()),
                'type': predicted_type,
                'source_ip': traffic_data.get('source_ip', 'Unknown'),
                'destination_ip': traffic_data.get('destination_ip', 'Unknown'),
                'severity': self.get_severity(predicted_type),
                'is_attack': predicted_type != 'normal'
            }
            
            # Add to history
            self.traffic_history.append(result)
            
            # Create alert if attack detected
            if result['is_attack']:
                alert = self.create_alert(result)
                self.recent_alerts.append(alert)
                logger.warning(f"🔴 Attack detected: {predicted_type} from {result['source_ip']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing traffic: {e}")
            return None
    
    def get_severity(self, attack_type):
        """Determine severity level"""
        severity_map = {
            'normal': 'INFO',
            'Dos': 'HIGH',
            'Probe': 'MEDIUM',
            'R2L': 'HIGH',
            'U2R': 'CRITICAL'
        }
        return severity_map.get(attack_type, 'INFO')
    
    def create_alert(self, detection_result):
        """Create alert from detection result"""
        return {
            'id': f"ALERT_{self.stats['attacks_detected']}",
            'timestamp': detection_result['timestamp'],
            'type': detection_result['type'],
            'severity': detection_result['severity'],
            'source_ip': detection_result['source_ip'],
            'destination_ip': detection_result['destination_ip'],
            'message': f"{detection_result['type']} attack detected from {detection_result['source_ip']}",
            'recommendations': self.get_recommendations(detection_result['type'])
        }
    
    def get_recommendations(self, attack_type):
        """Get countermeasure recommendations"""
        recommendations = {
            'Dos': [
                'Enable rate limiting on affected services',
                'Block source IP address',
                'Increase connection timeout thresholds',
                'Notify network administrator'
            ],
            'Probe': [
                'Monitor for subsequent attacks',
                'Review firewall rules',
                'Check for vulnerable services',
                'Update intrusion prevention rules'
            ],
            'R2L': [
                'Immediately block source IP',
                'Review authentication logs',
                'Force password reset for affected accounts',
                'Enable two-factor authentication'
            ],
            'U2R': [
                'CRITICAL: Isolate affected system',
                'Initiate incident response protocol',
                'Audit all privileged accounts',
                'Review system access logs'
            ]
        }
        return recommendations.get(attack_type, ['Monitor the situation', 'Review logs'])
    
    def get_stats(self):
        """Get current statistics"""
        # Calculate attack rate
        if self.stats['total_traffic'] > 0:
            attack_rate = (self.stats['attacks_detected'] / self.stats['total_traffic']) * 100
        else:
            attack_rate = 0.0
        
        return {
            **self.stats,
            'attack_rate': round(attack_rate, 2),
            'active': self.active
        }
    
    def get_recent_alerts(self, limit=10):
        """Get recent alerts"""
        alerts = list(self.recent_alerts)
        return alerts[-limit:] if len(alerts) > limit else alerts
    
    def get_traffic_history(self):
        """Get traffic history for charts"""
        return list(self.traffic_history)
    
    def reset_stats(self):
        """Reset all statistics"""
        self.stats = {
            'total_traffic': 0,
            'normal_traffic': 0,
            'attacks_detected': 0,
            'dos_attacks': 0,
            'probe_attacks': 0,
            'r2l_attacks': 0,
            'u2r_attacks': 0,
            'last_attack_time': None
        }
        self.recent_alerts.clear()
        self.traffic_history.clear()
        logger.info("📊 Statistics reset")


# Test the monitor
if __name__ == "__main__":
    print("Testing Real-Time Monitor...")
    
    monitor = RealTimeMonitor()
    monitor.start()
    
    # Simulate some traffic
    test_traffic = [
        {'type': 'normal', 'features': [0]*28, 'source_ip': '192.168.1.1', 'destination_ip': '10.0.0.1'},
        {'type': 'Dos', 'features': [1]*28, 'source_ip': '192.168.1.100', 'destination_ip': '10.0.0.1'},
        {'type': 'normal', 'features': [0]*28, 'source_ip': '192.168.1.2', 'destination_ip': '10.0.0.2'},
        {'type': 'Probe', 'features': [2]*28, 'source_ip': '192.168.1.150', 'destination_ip': '10.0.0.1'},
    ]
    
    for traffic in test_traffic:
        result = monitor.process_traffic(traffic)
        if result:
            marker = "🔴" if result['is_attack'] else "✅"
            print(f"{marker} {result['type']:10s} | Severity: {result['severity']}")
    
    print(f"\n📊 Statistics:")
    stats = monitor.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print(f"\n🚨 Recent Alerts: {len(monitor.get_recent_alerts())}")
    
    monitor.stop()
    print("\n✅ Test complete!")
