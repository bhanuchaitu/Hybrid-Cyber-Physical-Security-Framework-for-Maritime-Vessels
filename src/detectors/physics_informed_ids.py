"""
Physics-Informed Intrusion Detection System (IDS) for Maritime Vessels
Integrates GPS, AIS, NMEA detectors with 5-layer validation architecture
"""
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import maritime detectors
try:
    from src.detectors.gps_spoofing_detector import GPSSpoofingDetector
    from src.detectors.ais_anomaly_detector import AISAnomalyDetector
    from src.detectors.nmea_protocol_validator import NMEAProtocolValidator
except ImportError:
    # For standalone testing
    from gps_spoofing_detector import GPSSpoofingDetector
    from ais_anomaly_detector import AISAnomalyDetector
    from nmea_protocol_validator import NMEAProtocolValidator

logger = logging.getLogger(__name__)


class PhysicsInformedIDS:
    """
    Physics-Informed Intrusion Detection System
    
    5-Layer Architecture:
    1. Protocol Layer - NMEA sentence validation
    2. Data Layer - GPS/AIS data integrity
    3. Physics Layer - Maritime physics constraints
    4. Behavioral Layer - Vessel behavior patterns
    5. Correlation Layer - Cross-layer threat assessment
    """
    
    # Threat severity levels
    SEVERITY_LEVELS = {
        'info': 0,
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }
    
    # Attack patterns
    ATTACK_PATTERNS = {
        'gps_spoofing': {
            'description': 'GPS coordinate manipulation detected',
            'severity': 'high',
            'indicators': ['position_jump', 'impossible_speed', 'trajectory_anomaly']
        },
        'ais_spoofing': {
            'description': 'AIS message tampering detected',
            'severity': 'high',
            'indicators': ['mmsi_invalid', 'speed_violation', 'position_inconsistent']
        },
        'nmea_injection': {
            'description': 'NMEA command injection detected',
            'severity': 'critical',
            'indicators': ['invalid_checksum', 'high_risk_command', 'malformed_sentence']
        },
        'autopilot_takeover': {
            'description': 'Autopilot control takeover attempt',
            'severity': 'critical',
            'indicators': ['control_command', 'heading_override', 'course_manipulation']
        },
        'navigation_disruption': {
            'description': 'Navigation system disruption detected',
            'severity': 'high',
            'indicators': ['multiple_anomalies', 'cross_layer_correlation', 'system_inconsistency']
        },
        'sensor_compromise': {
            'description': 'Maritime sensor data manipulation',
            'severity': 'medium',
            'indicators': ['data_inconsistency', 'sensor_conflict', 'physics_violation']
        }
    }
    
    def __init__(self, history_size: int = 1000):
        """
        Initialize Physics-Informed IDS
        
        Args:
            history_size: Number of events to keep in history
        """
        # Initialize detectors
        self.gps_detector = GPSSpoofingDetector()
        self.ais_detector = AISAnomalyDetector()
        self.nmea_validator = NMEAProtocolValidator()
        
        # Event history
        self.event_history = deque(maxlen=history_size)
        self.threat_history = deque(maxlen=history_size)
        
        # Statistics
        self.total_events = 0
        self.threats_detected = 0
        self.attack_counts = defaultdict(int)
        self.layer_anomalies = defaultdict(int)
        
        # Current vessel state
        self.vessel_state = {
            'last_gps': None,
            'last_ais': None,
            'last_nmea': None,
            'anomaly_count': 0,
            'threat_level': 'normal'
        }
        
        logger.info("Physics-Informed IDS initialized with 5-layer architecture")
    
    def _layer1_protocol_validation(self, nmea_sentence: Optional[str]) -> Dict:
        """
        Layer 1: Protocol Layer - NMEA sentence validation
        
        Args:
            nmea_sentence: NMEA sentence string
        
        Returns:
            Validation result with anomalies
        """
        if not nmea_sentence:
            return {'layer': 1, 'valid': True, 'anomalies': [], 'risk_score': 0.0}
        
        result = self.nmea_validator.validate_sentence(nmea_sentence)
        
        layer_result = {
            'layer': 1,
            'name': 'Protocol Layer',
            'valid': result['valid'],
            'anomalies': result['anomalies'],
            'risk_score': result['risk_score'],
            'sentence_type': result['sentence_type'],
            'details': result
        }
        
        if result['anomalies']:
            self.layer_anomalies['protocol'] += 1
        
        return layer_result
    
    def _layer2_data_integrity(self, gps_data: Optional[Dict], ais_data: Optional[Dict]) -> Dict:
        """
        Layer 2: Data Layer - GPS/AIS data integrity
        
        Args:
            gps_data: GPS data dictionary
            ais_data: AIS message dictionary
        
        Returns:
            Data integrity analysis
        """
        anomalies = []
        risk_score = 0.0
        
        # Check GPS data integrity
        if gps_data:
            # Validate coordinate ranges
            lat = gps_data.get('latitude', 0)
            lon = gps_data.get('longitude', 0)
            
            if not (-90 <= lat <= 90):
                anomalies.append(f"Invalid latitude: {lat}°")
                risk_score += 0.3
            
            if not (-180 <= lon <= 180):
                anomalies.append(f"Invalid longitude: {lon}°")
                risk_score += 0.3
            
            # Check for null island (0,0) - common error
            if abs(lat) < 0.01 and abs(lon) < 0.01:
                anomalies.append("Suspicious null island coordinates (0,0)")
                risk_score += 0.2
        
        # Check AIS data integrity
        if ais_data:
            # Validate MMSI format
            mmsi = ais_data.get('mmsi')
            if mmsi:
                mmsi_str = str(mmsi)
                if len(mmsi_str) != 9:
                    anomalies.append(f"Invalid MMSI length: {len(mmsi_str)}")
                    risk_score += 0.3
        
        # Cross-check GPS and AIS positions if both available
        if gps_data and ais_data:
            gps_lat = gps_data.get('latitude')
            gps_lon = gps_data.get('longitude')
            ais_lat = ais_data.get('latitude')
            ais_lon = ais_data.get('longitude')
            
            if all([gps_lat, gps_lon, ais_lat, ais_lon]):
                # Calculate position difference
                lat_diff = abs(gps_lat - ais_lat)
                lon_diff = abs(gps_lon - ais_lon)
                
                # Allow small difference (0.01° ≈ 1.1 km)
                if lat_diff > 0.05 or lon_diff > 0.05:
                    anomalies.append(f"GPS/AIS position mismatch: {lat_diff:.4f}° lat, {lon_diff:.4f}° lon")
                    risk_score += 0.4
        
        if anomalies:
            self.layer_anomalies['data_integrity'] += 1
        
        return {
            'layer': 2,
            'name': 'Data Integrity Layer',
            'valid': len(anomalies) == 0,
            'anomalies': anomalies,
            'risk_score': min(risk_score, 1.0)
        }
    
    def _layer3_physics_validation(self, gps_data: Optional[Dict], ais_data: Optional[Dict]) -> Dict:
        """
        Layer 3: Physics Layer - Maritime physics constraints
        
        Args:
            gps_data: GPS data dictionary
            ais_data: AIS message dictionary
        
        Returns:
            Physics validation result
        """
        anomalies = []
        risk_score = 0.0
        
        # GPS spoofing detection
        if gps_data:
            gps_result = self.gps_detector.check_gps_spoofing(gps_data)
            
            if gps_result['is_spoofed']:
                anomalies.extend(gps_result['anomalies'])
                risk_score = max(risk_score, gps_result['confidence'])
        
        # AIS anomaly detection
        if ais_data:
            ais_result = self.ais_detector.check_ais_message(ais_data)
            
            if ais_result['is_anomaly']:
                anomalies.extend(ais_result['anomalies'])
                risk_score = max(risk_score, ais_result['confidence'])
        
        if anomalies:
            self.layer_anomalies['physics'] += 1
        
        return {
            'layer': 3,
            'name': 'Physics Layer',
            'valid': len(anomalies) == 0,
            'anomalies': anomalies,
            'risk_score': risk_score
        }
    
    def _layer4_behavioral_analysis(self, gps_data: Optional[Dict], ais_data: Optional[Dict]) -> Dict:
        """
        Layer 4: Behavioral Layer - Vessel behavior patterns
        
        Args:
            gps_data: GPS data dictionary
            ais_data: AIS message dictionary
        
        Returns:
            Behavioral analysis result
        """
        anomalies = []
        risk_score = 0.0
        
        # Check for sudden behavior changes
        if gps_data and self.vessel_state['last_gps']:
            last_gps = self.vessel_state['last_gps']
            
            # Speed change analysis
            if 'speed_knots' in gps_data and 'speed_knots' in last_gps:
                speed_change = abs(gps_data['speed_knots'] - last_gps['speed_knots'])
                time_diff = (gps_data.get('timestamp', datetime.now()) - 
                           last_gps.get('timestamp', datetime.now())).total_seconds()
                
                if time_diff > 0:
                    # Acceleration in knots per second
                    acceleration = speed_change / time_diff
                    
                    # Suspicious rapid acceleration (> 0.5 knots/sec)
                    if acceleration > 0.5:
                        anomalies.append(f"Rapid speed change: {acceleration:.2f} knots/sec")
                        risk_score += 0.3
            
            # Course change analysis
            if 'course' in gps_data and 'course' in last_gps:
                course_change = abs(gps_data['course'] - last_gps['course'])
                # Handle 0/360 wraparound
                if course_change > 180:
                    course_change = 360 - course_change
                
                # Suspicious sharp turn (> 45° in short time)
                if time_diff < 60 and course_change > 45:
                    anomalies.append(f"Sharp course change: {course_change:.1f}° in {time_diff:.0f}s")
                    risk_score += 0.2
        
        # AIS behavioral patterns
        if ais_data and self.vessel_state['last_ais']:
            last_ais = self.vessel_state['last_ais']
            
            # Check for vessel type changes (impossible)
            if ais_data.get('vessel_type') != last_ais.get('vessel_type'):
                anomalies.append(f"Vessel type changed: {last_ais.get('vessel_type')} → {ais_data.get('vessel_type')}")
                risk_score += 0.5
            
            # Check for MMSI changes (highly suspicious)
            if ais_data.get('mmsi') != last_ais.get('mmsi'):
                anomalies.append(f"MMSI changed: {last_ais.get('mmsi')} → {ais_data.get('mmsi')}")
                risk_score += 0.7
        
        # Check anomaly rate
        recent_anomalies = sum(1 for e in list(self.event_history)[-20:] 
                              if e.get('total_anomalies', 0) > 0)
        
        if recent_anomalies > 10:  # More than 50% anomalies in last 20 events
            anomalies.append(f"High anomaly rate: {recent_anomalies}/20 recent events")
            risk_score += 0.3
        
        if anomalies:
            self.layer_anomalies['behavioral'] += 1
        
        return {
            'layer': 4,
            'name': 'Behavioral Layer',
            'valid': len(anomalies) == 0,
            'anomalies': anomalies,
            'risk_score': min(risk_score, 1.0)
        }
    
    def _layer5_correlation_analysis(self, layer_results: List[Dict]) -> Dict:
        """
        Layer 5: Correlation Layer - Cross-layer threat assessment
        
        Args:
            layer_results: Results from layers 1-4
        
        Returns:
            Correlation analysis and threat classification
        """
        # Aggregate anomalies from all layers
        all_anomalies = []
        max_risk = 0.0
        anomaly_layers = []
        
        for result in layer_results:
            if result['anomalies']:
                all_anomalies.extend(result['anomalies'])
                anomaly_layers.append(result['name'])
                max_risk = max(max_risk, result['risk_score'])
        
        # Detect attack patterns
        detected_attacks = []
        
        # Create searchable anomaly text
        anomaly_text = ' '.join(str(a).lower() for a in all_anomalies)
        
        for attack_name, attack_info in self.ATTACK_PATTERNS.items():
            # Check if attack indicators are present
            matching_indicators = 0
            matched_items = []
            
            for indicator in attack_info['indicators']:
                # Check multiple variations of the indicator
                variations = [
                    indicator.replace('_', ' '),
                    indicator.replace('_', '-'),
                    indicator
                ]
                
                if any(var in anomaly_text for var in variations):
                    matching_indicators += 1
                    matched_items.append(indicator)
            
            # Require at least 1 matching indicator (lowered threshold)
            # GPS/AIS attacks often show single strong indicators
            if matching_indicators >= 1:
                confidence = matching_indicators / len(attack_info['indicators'])
                
                # Boost confidence for strong single indicators
                if matching_indicators == 1 and confidence < 0.5:
                    # Check for strong indicators
                    strong_indicators = ['position jump', 'impossible speed', 'mmsi invalid', 
                                       'invalid checksum', 'high risk command']
                    if any(strong in anomaly_text for strong in strong_indicators):
                        confidence = 0.6
                
                detected_attacks.append({
                    'attack': attack_name,
                    'description': attack_info['description'],
                    'severity': attack_info['severity'],
                    'confidence': min(confidence, 1.0),
                    'matched_indicators': matched_items
                })
        
        # Calculate overall threat level
        threat_level = 'normal'
        if len(all_anomalies) == 0:
            threat_level = 'normal'
        elif max_risk < 0.3:
            threat_level = 'low'
        elif max_risk < 0.5:
            threat_level = 'medium'
        elif max_risk < 0.7:
            threat_level = 'high'
        else:
            threat_level = 'critical'
        
        # Increase threat level if multiple layers affected
        if len(anomaly_layers) >= 3:
            if threat_level == 'low':
                threat_level = 'medium'
            elif threat_level == 'medium':
                threat_level = 'high'
        
        # Correlation risk score (weighted by number of affected layers)
        correlation_risk = max_risk * (1 + 0.1 * len(anomaly_layers))
        correlation_risk = min(correlation_risk, 1.0)
        
        if detected_attacks or len(anomaly_layers) >= 2:
            self.layer_anomalies['correlation'] += 1
        
        return {
            'layer': 5,
            'name': 'Correlation Layer',
            'threat_level': threat_level,
            'detected_attacks': detected_attacks,
            'affected_layers': anomaly_layers,
            'correlation_risk': correlation_risk,
            'total_anomalies': len(all_anomalies),
            'cross_layer_correlation': len(anomaly_layers) >= 2
        }
    
    def analyze_maritime_event(self, 
                               gps_data: Optional[Dict] = None,
                               ais_data: Optional[Dict] = None,
                               nmea_sentence: Optional[str] = None) -> Dict:
        """
        Analyze maritime event through 5-layer architecture
        
        Args:
            gps_data: GPS data dictionary
            ais_data: AIS message dictionary
            nmea_sentence: NMEA sentence string
        
        Returns:
            Comprehensive threat analysis
        """
        self.total_events += 1
        timestamp = datetime.now()
        
        # Execute 5-layer validation
        layer_results = []
        
        # Layer 1: Protocol validation
        layer1 = self._layer1_protocol_validation(nmea_sentence)
        layer_results.append(layer1)
        
        # Layer 2: Data integrity
        layer2 = self._layer2_data_integrity(gps_data, ais_data)
        layer_results.append(layer2)
        
        # Layer 3: Physics validation
        layer3 = self._layer3_physics_validation(gps_data, ais_data)
        layer_results.append(layer3)
        
        # Layer 4: Behavioral analysis
        layer4 = self._layer4_behavioral_analysis(gps_data, ais_data)
        layer_results.append(layer4)
        
        # Layer 5: Correlation analysis
        layer5 = self._layer5_correlation_analysis(layer_results)
        layer_results.append(layer5)
        
        # Compile comprehensive analysis
        analysis = {
            'timestamp': timestamp,
            'event_id': self.total_events,
            'layers': layer_results,
            'threat_level': layer5['threat_level'],
            'detected_attacks': layer5['detected_attacks'],
            'total_anomalies': layer5['total_anomalies'],
            'max_risk_score': max(r.get('risk_score', 0) for r in layer_results[:4]),
            'correlation_risk': layer5['correlation_risk'],
            'is_threat': layer5['total_anomalies'] > 0,
            'recommendation': self._generate_recommendation(layer5)
        }
        
        # Update vessel state
        if gps_data:
            self.vessel_state['last_gps'] = gps_data
        if ais_data:
            self.vessel_state['last_ais'] = ais_data
        if nmea_sentence:
            self.vessel_state['last_nmea'] = nmea_sentence
        
        self.vessel_state['anomaly_count'] = layer5['total_anomalies']
        self.vessel_state['threat_level'] = layer5['threat_level']
        
        # Track threats
        if analysis['is_threat']:
            self.threats_detected += 1
            self.threat_history.append(analysis)
            
            # Count attack types
            for attack in layer5['detected_attacks']:
                self.attack_counts[attack['attack']] += 1
        
        # Update event history
        self.event_history.append(analysis)
        
        return analysis
    
    def _generate_recommendation(self, correlation_result: Dict) -> str:
        """
        Generate security recommendation based on threat level
        
        Args:
            correlation_result: Layer 5 correlation analysis
        
        Returns:
            Recommendation string
        """
        threat_level = correlation_result['threat_level']
        attacks = correlation_result['detected_attacks']
        
        if threat_level == 'normal':
            return "No threats detected. Continue normal operations."
        
        elif threat_level == 'low':
            return "Minor anomalies detected. Monitor systems and verify sensor data."
        
        elif threat_level == 'medium':
            return "Potential security issue detected. Verify navigation data and check system logs."
        
        elif threat_level == 'high':
            if attacks:
                attack_names = ', '.join(a['attack'].replace('_', ' ').title() for a in attacks)
                return f"Security threat detected: {attack_names}. Switch to manual navigation and alert crew."
            return "High-risk anomalies detected. Switch to manual control and investigate immediately."
        
        else:  # critical
            if attacks:
                attack_names = ', '.join(a['attack'].replace('_', ' ').title() for a in attacks)
                return f"CRITICAL THREAT: {attack_names}. Engage emergency protocols, switch to backup systems, alert authorities."
            return "CRITICAL: Multiple system anomalies. Engage emergency protocols and switch to backup navigation."
    
    def get_statistics(self) -> Dict:
        """
        Get IDS statistics
        
        Returns:
            Statistics dictionary
        """
        return {
            'total_events': self.total_events,
            'threats_detected': self.threats_detected,
            'threat_rate': f"{(self.threats_detected / self.total_events * 100):.1f}%" 
                          if self.total_events > 0 else "0%",
            'current_threat_level': self.vessel_state['threat_level'],
            'attack_counts': dict(self.attack_counts),
            'layer_anomalies': dict(self.layer_anomalies),
            'recent_threats': len([t for t in self.threat_history 
                                  if (datetime.now() - t['timestamp']).total_seconds() < 300]),
            'detector_stats': {
                'gps': self.gps_detector.get_statistics(),
                'ais': self.ais_detector.get_statistics(),
                'nmea': self.nmea_validator.get_statistics()
            }
        }
    
    def get_threat_summary(self, minutes: int = 60) -> Dict:
        """
        Get threat summary for recent time period
        
        Args:
            minutes: Time period in minutes
        
        Returns:
            Threat summary
        """
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        recent_threats = [t for t in self.threat_history if t['timestamp'] > cutoff_time]
        
        if not recent_threats:
            return {
                'period_minutes': minutes,
                'total_threats': 0,
                'threat_levels': {},
                'attack_types': {},
                'summary': f"No threats detected in the last {minutes} minutes."
            }
        
        # Aggregate threat levels
        threat_levels = defaultdict(int)
        attack_types = defaultdict(int)
        
        for threat in recent_threats:
            threat_levels[threat['threat_level']] += 1
            for attack in threat['detected_attacks']:
                attack_types[attack['attack']] += 1
        
        return {
            'period_minutes': minutes,
            'total_threats': len(recent_threats),
            'threat_levels': dict(threat_levels),
            'attack_types': dict(attack_types),
            'highest_threat': max(recent_threats, key=lambda t: t['correlation_risk']),
            'summary': f"Detected {len(recent_threats)} threats in the last {minutes} minutes."
        }


# Test the Physics-Informed IDS
if __name__ == "__main__":
    print("Testing Physics-Informed IDS Engine...\n")
    
    ids = PhysicsInformedIDS()
    
    # Test 1: Normal maritime operation
    print("1. Normal operation:")
    normal_gps = {
        'latitude': 40.7128,
        'longitude': -74.0060,
        'timestamp': datetime.now(),
        'speed_knots': 12.0,
        'course': 90.0
    }
    normal_ais = {
        'mmsi': 367123456,
        'latitude': 40.7128,
        'longitude': -74.0060,
        'speed': 12.0,
        'course': 90.0,
        'heading': 92.0,
        'vessel_type': 'cargo',
        'timestamp': datetime.now()
    }
    normal_nmea = "$GPGGA,123519,4042.768,N,07400.360,W,1,08,0.9,545.4,M,46.9,M,,*47"
    
    result = ids.analyze_maritime_event(normal_gps, normal_ais, normal_nmea)
    print(f"  Threat Level: {result['threat_level']}")
    print(f"  Anomalies: {result['total_anomalies']}")
    print(f"  Recommendation: {result['recommendation']}")
    
    # Test 2: GPS Spoofing Attack
    print("\n2. GPS Spoofing Attack:")
    spoofed_gps = {
        'latitude': 51.5074,  # London - impossible jump from NYC
        'longitude': -0.1278,
        'timestamp': datetime.now(),
        'speed_knots': 200.0,  # Impossible speed
        'course': 90.0
    }
    
    result = ids.analyze_maritime_event(spoofed_gps, None, None)
    print(f"  Threat Level: {result['threat_level']}")
    print(f"  Detected Attacks: {[a['attack'] for a in result['detected_attacks']]}")
    print(f"  Max Risk Score: {result['max_risk_score']:.2f}")
    print(f"  Recommendation: {result['recommendation']}")
    
    # Test 3: AIS Anomaly
    print("\n3. AIS Anomaly:")
    anomalous_ais = {
        'mmsi': 111111111,  # Invalid MMSI
        'latitude': 40.7128,
        'longitude': -74.0060,
        'speed': 50.0,  # Too fast for cargo
        'course': 90.0,
        'heading': 270.0,  # 180° mismatch
        'vessel_type': 'cargo',
        'timestamp': datetime.now()
    }
    
    result = ids.analyze_maritime_event(None, anomalous_ais, None)
    print(f"  Threat Level: {result['threat_level']}")
    print(f"  Detected Attacks: {[a['attack'] for a in result['detected_attacks']]}")
    print(f"  Affected Layers: {result['layers'][4]['affected_layers']}")
    
    # Test 4: NMEA Injection Attack
    print("\n4. NMEA Injection Attack:")
    malicious_nmea = "$HEROT,720.0,A*XX"  # Invalid checksum, extreme rate of turn
    
    result = ids.analyze_maritime_event(None, None, malicious_nmea)
    print(f"  Threat Level: {result['threat_level']}")
    print(f"  Protocol Risk: {result['layers'][0]['risk_score']:.2f}")
    print(f"  Anomalies: {result['layers'][0]['anomalies']}")
    
    # Test 5: Multi-layer attack (GPS + AIS + NMEA)
    print("\n5. Coordinated Multi-layer Attack:")
    result = ids.analyze_maritime_event(spoofed_gps, anomalous_ais, malicious_nmea)
    print(f"  Threat Level: {result['threat_level']}")
    print(f"  Total Anomalies: {result['total_anomalies']}")
    print(f"  Correlation Risk: {result['correlation_risk']:.2f}")
    print(f"  Detected Attacks: {[a['attack'] for a in result['detected_attacks']]}")
    print(f"  Recommendation: {result['recommendation']}")
    
    # Test 6: Statistics
    print("\n6. IDS Statistics:")
    stats = ids.get_statistics()
    print(f"  Total Events: {stats['total_events']}")
    print(f"  Threats Detected: {stats['threats_detected']}")
    print(f"  Threat Rate: {stats['threat_rate']}")
    print(f"  Current Threat Level: {stats['current_threat_level']}")
    print(f"  Attack Counts: {stats['attack_counts']}")
    
    # Test 7: Threat Summary
    print("\n7. Threat Summary (last 60 minutes):")
    summary = ids.get_threat_summary(60)
    print(f"  {summary['summary']}")
    print(f"  Threat Levels: {summary['threat_levels']}")
    print(f"  Attack Types: {summary['attack_types']}")
    
    print("\n✅ Physics-Informed IDS Engine test complete!")
