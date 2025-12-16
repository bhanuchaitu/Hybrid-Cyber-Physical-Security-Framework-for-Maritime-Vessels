"""
Enhanced Detector Manager
Integrates all new detection capabilities into the application
"""
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Import all enhanced detectors
try:
    from src.detectors.web_attack_detector import WebAttackDetector
    WEB_ATTACK_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Web attack detector not available: {e}")
    WEB_ATTACK_AVAILABLE = False

try:
    from src.detectors.advanced_threat_detector import AdvancedThreatDetector
    ADVANCED_THREAT_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Advanced threat detector not available: {e}")
    ADVANCED_THREAT_AVAILABLE = False

try:
    from src.detectors.maritime_threats import (
        CollisionPredictor, PortSecurityMonitor, CargoTheftDetector,
        BoardingAlertSystem, EngineTamperingDetector, WeatherThreatAssessor
    )
    MARITIME_THREATS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Maritime threats detector not available: {e}")
    MARITIME_THREATS_AVAILABLE = False

try:
    from src.detectors.protocol_validators import (
        DNP3Validator, ModbusValidator, CANBusDetector,
        ZigbeeIoTMonitor, SatelliteCommValidator
    )
    PROTOCOL_VALIDATORS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Protocol validators not available: {e}")
    PROTOCOL_VALIDATORS_AVAILABLE = False

try:
    from src.detectors.behavioral_detection import (
        BehavioralAnalyzer, GeofencingSystem, MultiVesselCorrelator,
        SpeedCoursePredictor, PatternMatcher
    )
    BEHAVIORAL_DETECTION_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Behavioral detection not available: {e}")
    BEHAVIORAL_DETECTION_AVAILABLE = False


class EnhancedDetectorManager:
    """
    Manages all enhanced detection capabilities
    """
    
    def __init__(self):
        """Initialize all available detectors"""
        self.detectors = {}
        self.statistics = {
            'web_attacks': 0,
            'advanced_threats': 0,
            'maritime_threats': 0,
            'protocol_violations': 0,
            'behavioral_anomalies': 0,
            'total_detections': 0
        }
        
        # Initialize web attack detector
        if WEB_ATTACK_AVAILABLE:
            self.detectors['web_attack'] = WebAttackDetector()
            logger.info("✓ Web Attack Detector initialized")
        
        # Initialize advanced threat detector
        if ADVANCED_THREAT_AVAILABLE:
            self.detectors['advanced_threat'] = AdvancedThreatDetector()
            logger.info("✓ Advanced Threat Detector initialized")
        
        # Initialize maritime threat detectors
        if MARITIME_THREATS_AVAILABLE:
            self.detectors['collision'] = CollisionPredictor()
            self.detectors['port_security'] = PortSecurityMonitor()
            self.detectors['cargo_theft'] = CargoTheftDetector()
            self.detectors['boarding_alert'] = BoardingAlertSystem()
            self.detectors['engine_tampering'] = EngineTamperingDetector()
            self.detectors['weather_threat'] = WeatherThreatAssessor()
            logger.info("✓ Maritime Threat Detectors initialized (6 types)")
        
        # Initialize protocol validators
        if PROTOCOL_VALIDATORS_AVAILABLE:
            self.detectors['dnp3'] = DNP3Validator()
            self.detectors['modbus'] = ModbusValidator()
            self.detectors['can_bus'] = CANBusDetector()
            self.detectors['zigbee_iot'] = ZigbeeIoTMonitor()
            self.detectors['satcom'] = SatelliteCommValidator()
            logger.info("✓ Protocol Validators initialized (5 types)")
        
        # Initialize behavioral detection systems
        if BEHAVIORAL_DETECTION_AVAILABLE:
            self.detectors['behavioral'] = BehavioralAnalyzer()
            self.detectors['geofencing'] = GeofencingSystem()
            self.detectors['multi_vessel'] = MultiVesselCorrelator()
            self.detectors['speed_course'] = SpeedCoursePredictor()
            self.detectors['pattern_matcher'] = PatternMatcher()
            logger.info("✓ Behavioral Detection Systems initialized (5 types)")
        
        logger.info(f"Enhanced Detector Manager initialized with {len(self.detectors)} detectors")
    
    def analyze_web_request(self, request_data: Dict) -> Dict:
        """
        Analyze HTTP request for web attacks
        
        Args:
            request_data: Request data (url, params, headers, body)
            
        Returns:
            Analysis results
        """
        if 'web_attack' not in self.detectors:
            return {'available': False}
        
        detector = self.detectors['web_attack']
        result = detector.analyze_request(request_data)
        
        if result.get('attacks_detected', []):
            self.statistics['web_attacks'] += len(result['attacks_detected'])
            self.statistics['total_detections'] += 1
        
        return result
    
    def analyze_advanced_threat(self, threat_data: Dict) -> Dict:
        """
        Analyze for advanced threats (MITM, ransomware, APT, zero-day)
        
        Args:
            threat_data: Threat indicators
            
        Returns:
            Threat analysis results
        """
        if 'advanced_threat' not in self.detectors:
            return {'available': False}
        
        detector = self.detectors['advanced_threat']
        result = detector.analyze_threat(threat_data)
        
        if result.get('threats_detected'):
            self.statistics['advanced_threats'] += len(result['threats_detected'])
            self.statistics['total_detections'] += 1
        
        return result
    
    def check_collision_risk(self, own_ship, target_vessels: Dict) -> List:
        """
        Check for vessel collision risks
        
        Args:
            own_ship: Own vessel position
            target_vessels: Dictionary of nearby vessels
            
        Returns:
            List of collision risks
        """
        if 'collision' not in self.detectors:
            return []
        
        detector = self.detectors['collision']
        risks = detector.monitor_collisions(own_ship, target_vessels)
        
        if risks:
            self.statistics['maritime_threats'] += len(risks)
            self.statistics['total_detections'] += 1
        
        return risks
    
    def check_port_security(self, vessel_id: str, position) -> Optional[Dict]:
        """
        Monitor port security and restricted zones
        
        Args:
            vessel_id: Vessel identifier
            position: Vessel position
            
        Returns:
            Breach information if detected
        """
        if 'port_security' not in self.detectors:
            return None
        
        detector = self.detectors['port_security']
        breach = detector.monitor_access(vessel_id, position)
        
        if breach:
            self.statistics['maritime_threats'] += 1
            self.statistics['total_detections'] += 1
        
        return breach
    
    def validate_protocol(self, protocol_type: str, packet_data: bytes) -> Dict:
        """
        Validate industrial protocol packet
        
        Args:
            protocol_type: 'dnp3', 'modbus', 'can_bus', 'zigbee_iot', 'satcom'
            packet_data: Raw packet bytes or dict
            
        Returns:
            Validation result
        """
        if protocol_type not in self.detectors:
            return {'available': False, 'protocol': protocol_type}
        
        detector = self.detectors[protocol_type]
        
        # Call appropriate validation method based on protocol
        if protocol_type == 'dnp3':
            is_valid, confidence, details = detector.validate_packet(packet_data)
        elif protocol_type == 'modbus':
            is_valid, confidence, details = detector.validate_request(packet_data)
        elif protocol_type == 'can_bus':
            # CAN bus needs ID and data
            is_valid, confidence, details = detector.validate_message(
                packet_data.get('can_id', 0),
                packet_data.get('data', b'')
            )
        elif protocol_type == 'zigbee_iot':
            is_valid, confidence, details = detector.validate_communication(
                packet_data.get('device_id', ''),
                packet_data
            )
        elif protocol_type == 'satcom':
            is_valid, confidence, details = detector.validate_gps_signal(packet_data)
        else:
            return {'available': False, 'protocol': protocol_type}
        
        result = {
            'protocol': protocol_type,
            'is_valid': is_valid,
            'confidence': confidence,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        
        if not is_valid:
            self.statistics['protocol_violations'] += 1
            self.statistics['total_detections'] += 1
        
        return result
    
    def detect_behavioral_anomaly(self, vessel_id: str, current_behavior: Dict) -> Optional[Dict]:
        """
        Detect behavioral anomalies
        
        Args:
            vessel_id: Vessel identifier
            current_behavior: Current behavior data
            
        Returns:
            Anomaly details if detected
        """
        if 'behavioral' not in self.detectors:
            return None
        
        detector = self.detectors['behavioral']
        anomaly = detector.detect_anomaly(vessel_id, current_behavior)
        
        if anomaly:
            self.statistics['behavioral_anomalies'] += 1
            self.statistics['total_detections'] += 1
        
        return anomaly
    
    def check_geofence(self, vessel_id: str, position) -> List[Dict]:
        """
        Check geofence violations
        
        Args:
            vessel_id: Vessel identifier
            position: (latitude, longitude)
            
        Returns:
            List of violations
        """
        if 'geofencing' not in self.detectors:
            return []
        
        detector = self.detectors['geofencing']
        violations = detector.check_position(vessel_id, position)
        
        if violations:
            self.statistics['behavioral_anomalies'] += len(violations)
            self.statistics['total_detections'] += 1
        
        return violations
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        stats = self.statistics.copy()
        
        # Add detector-specific stats
        for name, detector in self.detectors.items():
            if hasattr(detector, 'get_statistics'):
                stats[f'{name}_stats'] = detector.get_statistics()
        
        return stats
    
    def get_available_detectors(self) -> List[str]:
        """Get list of available detectors"""
        return list(self.detectors.keys())
    
    def get_detector(self, detector_name: str):
        """Get specific detector instance"""
        return self.detectors.get(detector_name)
