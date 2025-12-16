"""
AIS Anomaly Detector for Maritime Vessels
Detects anomalies in AIS (Automatic Identification System) messages
"""
import math
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import deque

logger = logging.getLogger(__name__)


class AISAnomalyDetector:
    """
    Detects AIS message anomalies using:
    - Vessel type constraints (speed, dimensions)
    - Position consistency checks
    - Course/heading validation
    - Message rate analysis
    - MMSI (Maritime Mobile Service Identity) validation
    """
    
    # Vessel type speed limits (in knots)
    VESSEL_TYPE_LIMITS = {
        'cargo': {'max_speed': 25, 'typical_speed': 15},
        'tanker': {'max_speed': 20, 'typical_speed': 12},
        'passenger': {'max_speed': 35, 'typical_speed': 25},
        'fishing': {'max_speed': 15, 'typical_speed': 8},
        'military': {'max_speed': 40, 'typical_speed': 20},
        'sailing': {'max_speed': 12, 'typical_speed': 6},
        'pleasure': {'max_speed': 30, 'typical_speed': 15},
        'tug': {'max_speed': 18, 'typical_speed': 10},
        'unknown': {'max_speed': 30, 'typical_speed': 15}
    }
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize AIS anomaly detector
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or self._default_config()
        
        # Track vessels by MMSI
        self.vessel_history = {}  # mmsi -> deque of AIS messages
        
        # Statistics
        self.stats = {
            'total_messages': 0,
            'anomalies_detected': 0,
            'invalid_mmsi': 0,
            'speed_violations': 0,
            'position_jumps': 0,
            'course_anomalies': 0,
            'message_rate_anomalies': 0
        }
        
        logger.info("AIS Anomaly Detector initialized")
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            'history_size': 50,  # Number of messages per vessel
            'min_message_interval_sec': 2,  # Minimum time between messages
            'max_message_interval_sec': 600,  # Maximum time between messages (10 min)
            'max_course_change_per_min': 30,  # Maximum course change per minute
            'max_heading_diff': 30,  # Max difference between course and heading (degrees) - stricter for better detection
            'earth_radius_km': 6371,
            'position_jump_threshold_km': 20  # Suspicious position jump
        }
    
    def check_ais_message(self, ais_data: Dict) -> Dict:
        """
        Check AIS message for anomalies
        
        Args:
            ais_data: Dictionary with AIS message fields:
                - mmsi: int (Maritime Mobile Service Identity)
                - latitude: float
                - longitude: float
                - speed: float (knots)
                - course: float (degrees, 0-360)
                - heading: float (degrees, 0-360, optional)
                - vessel_type: str (cargo, tanker, passenger, etc.)
                - timestamp: datetime
                - name: str (vessel name, optional)
        
        Returns:
            Dictionary with detection results
        """
        self.stats['total_messages'] += 1
        
        result = {
            'is_anomaly': False,
            'confidence': 0.0,
            'anomalies': [],
            'details': {},
            'severity': 'INFO'
        }
        
        try:
            # 1. Validate MMSI
            mmsi_check = self._validate_mmsi(ais_data.get('mmsi'))
            if not mmsi_check['valid']:
                result['anomalies'].append(mmsi_check['reason'])
                result['confidence'] += 0.4
                self.stats['invalid_mmsi'] += 1
            
            # 2. Validate coordinates
            if not self._validate_coordinates(ais_data):
                result['anomalies'].append('Invalid GPS coordinates')
                result['confidence'] += 0.3
                return result
            
            # 3. Check speed against vessel type
            vessel_type = ais_data.get('vessel_type', 'unknown').lower()
            speed = ais_data.get('speed', 0)
            
            speed_check = self._check_speed_violation(vessel_type, speed)
            if speed_check['is_violation']:
                result['anomalies'].append(speed_check['reason'])
                result['confidence'] += 0.5
                result['details']['speed_knots'] = speed
                self.stats['speed_violations'] += 1
            
            # 4. Check course and heading consistency
            if 'course' in ais_data and 'heading' in ais_data:
                heading_check = self._check_course_heading(
                    ais_data['course'],
                    ais_data['heading']
                )
                if heading_check['is_anomaly']:
                    result['anomalies'].append(heading_check['reason'])
                    result['confidence'] += 0.4
                    result['details']['course_heading_diff'] = heading_check['difference']
            
            # 5. Check message history for this vessel
            mmsi = ais_data.get('mmsi')
            if mmsi and mmsi in self.vessel_history:
                history = self.vessel_history[mmsi]
                
                if len(history) > 0:
                    prev_msg = history[-1]
                    
                    # Check position jump
                    position_check = self._check_position_consistency(prev_msg, ais_data)
                    if position_check['is_anomaly']:
                        result['anomalies'].append(position_check['reason'])
                        result['confidence'] += 0.3
                        result['details']['distance_km'] = position_check['distance']
                        self.stats['position_jumps'] += 1
                    
                    # Check course change rate
                    if 'course' in ais_data and 'course' in prev_msg:
                        course_check = self._check_course_change(prev_msg, ais_data)
                        if course_check['is_anomaly']:
                            result['anomalies'].append(course_check['reason'])
                            result['confidence'] += 0.2
                            self.stats['course_anomalies'] += 1
                    
                    # Check message rate
                    rate_check = self._check_message_rate(prev_msg, ais_data)
                    if rate_check['is_anomaly']:
                        result['anomalies'].append(rate_check['reason'])
                        result['confidence'] += 0.1
                        self.stats['message_rate_anomalies'] += 1
            
            # Store message in history
            if mmsi:
                if mmsi not in self.vessel_history:
                    self.vessel_history[mmsi] = deque(maxlen=self.config['history_size'])
                self.vessel_history[mmsi].append(ais_data)
            
            # Determine if anomaly detected (lowered threshold for better detection)
            if result['confidence'] >= 0.3:
                result['is_anomaly'] = True
                self.stats['anomalies_detected'] += 1
                
                # Set severity
                if result['confidence'] >= 0.8:
                    result['severity'] = 'CRITICAL'
                elif result['confidence'] >= 0.6:
                    result['severity'] = 'HIGH'
                else:
                    result['severity'] = 'MEDIUM'
                
                logger.warning(f"AIS anomaly detected for MMSI {mmsi}! Confidence: {result['confidence']:.2f}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in AIS anomaly detection: {e}")
            result['anomalies'].append(f"Detection error: {str(e)}")
            return result
    
    def _validate_mmsi(self, mmsi: Optional[int]) -> Dict:
        """
        Validate MMSI number
        MMSI should be 9 digits, with specific patterns for different vessel types
        """
        if not mmsi:
            return {'valid': False, 'reason': 'Missing MMSI'}
        
        mmsi_str = str(mmsi)
        
        # MMSI should be 9 digits
        if len(mmsi_str) != 9:
            return {'valid': False, 'reason': f'Invalid MMSI length: {len(mmsi_str)} (should be 9)'}
        
        # Check for obviously fake MMSIs (all same digit, sequential, or too few unique digits)
        unique_digits = len(set(mmsi_str))
        if unique_digits == 1:
            return {'valid': False, 'reason': 'MMSI contains all identical digits'}
        
        # Reject if less than 3 unique digits (too repetitive)
        if unique_digits < 3:
            return {'valid': False, 'reason': f'MMSI too repetitive: only {unique_digits} unique digits'}
        
        # Check for sequential digits
        if mmsi_str == ''.join(str(i) for i in range(int(mmsi_str[0]), int(mmsi_str[0]) + 9)):
            return {'valid': False, 'reason': 'MMSI contains sequential digits'}
        
        # First 3 digits are MID (Maritime Identification Digit) - country code
        mid = int(mmsi_str[:3])
        if mid < 200 or mid > 799:
            return {'valid': False, 'reason': f'Invalid MID (country code): {mid}'}
        
        return {'valid': True, 'reason': ''}
    
    def _validate_coordinates(self, ais_data: Dict) -> bool:
        """Validate GPS coordinates"""
        lat = ais_data.get('latitude')
        lon = ais_data.get('longitude')
        
        if lat is None or lon is None:
            return False
        
        if not (-90 <= lat <= 90):
            return False
        
        if not (-180 <= lon <= 180):
            return False
        
        return True
    
    def _check_speed_violation(self, vessel_type: str, speed: float) -> Dict:
        """Check if speed exceeds vessel type limits"""
        limits = self.VESSEL_TYPE_LIMITS.get(vessel_type, self.VESSEL_TYPE_LIMITS['unknown'])
        max_speed = limits['max_speed']
        
        is_violation = speed > max_speed
        
        return {
            'is_violation': is_violation,
            'max_speed': max_speed,
            'actual_speed': speed,
            'reason': f'Speed violation: {speed:.1f} knots exceeds max {max_speed} knots for {vessel_type} vessel'
        }
    
    def _check_course_heading(self, course: float, heading: float) -> Dict:
        """
        Check consistency between course over ground and heading
        Large differences may indicate drift, strong currents, or spoofing
        """
        # Normalize angles to 0-360
        course = course % 360
        heading = heading % 360
        
        # Calculate difference (shortest angle)
        diff = abs(course - heading)
        if diff > 180:
            diff = 360 - diff
        
        max_diff = self.config['max_heading_diff']
        is_anomaly = diff > max_diff
        
        return {
            'is_anomaly': is_anomaly,
            'difference': diff,
            'reason': f'Course/Heading mismatch: {diff:.1f}° difference (max: {max_diff}°)'
        }
    
    def _check_position_consistency(self, prev_msg: Dict, curr_msg: Dict) -> Dict:
        """Check if position change is consistent with reported speed"""
        # Calculate actual distance traveled
        distance_km = self._haversine_distance(
            prev_msg['latitude'], prev_msg['longitude'],
            curr_msg['latitude'], curr_msg['longitude']
        )
        
        # Calculate time difference
        time_diff_sec = (curr_msg['timestamp'] - prev_msg['timestamp']).total_seconds()
        
        if time_diff_sec <= 0:
            return {'is_anomaly': True, 'distance': distance_km, 'reason': 'Invalid timestamp sequence'}
        
        # Calculate expected distance based on reported speed
        avg_speed_knots = (prev_msg.get('speed', 0) + curr_msg.get('speed', 0)) / 2
        expected_distance_km = (avg_speed_knots * 1.852) * (time_diff_sec / 3600)
        
        # Check if actual distance is much different than expected
        distance_ratio = distance_km / max(expected_distance_km, 0.1)
        
        # Allow some tolerance (vessels may not move in straight lines)
        threshold = self.config['position_jump_threshold_km']
        is_anomaly = (distance_km > threshold and distance_ratio > 2.0) or distance_ratio > 5.0
        
        return {
            'is_anomaly': is_anomaly,
            'distance': distance_km,
            'expected_distance': expected_distance_km,
            'ratio': distance_ratio,
            'reason': f'Position jump: {distance_km:.2f} km (expected {expected_distance_km:.2f} km based on speed)'
        }
    
    def _check_course_change(self, prev_msg: Dict, curr_msg: Dict) -> Dict:
        """Check if course change is too rapid"""
        prev_course = prev_msg.get('course', 0)
        curr_course = curr_msg.get('course', 0)
        
        # Calculate course change
        course_change = abs(curr_course - prev_course)
        if course_change > 180:
            course_change = 360 - course_change
        
        # Calculate time difference in minutes
        time_diff_min = (curr_msg['timestamp'] - prev_msg['timestamp']).total_seconds() / 60
        
        if time_diff_min <= 0:
            return {'is_anomaly': False, 'reason': ''}
        
        # Calculate rate of course change
        course_change_rate = course_change / time_diff_min
        
        max_rate = self.config['max_course_change_per_min']
        is_anomaly = course_change_rate > max_rate
        
        return {
            'is_anomaly': is_anomaly,
            'course_change': course_change,
            'rate': course_change_rate,
            'reason': f'Rapid course change: {course_change:.1f}° in {time_diff_min:.1f} min ({course_change_rate:.1f}°/min, max: {max_rate}°/min)'
        }
    
    def _check_message_rate(self, prev_msg: Dict, curr_msg: Dict) -> Dict:
        """Check if message rate is within normal bounds"""
        time_diff_sec = (curr_msg['timestamp'] - prev_msg['timestamp']).total_seconds()
        
        min_interval = self.config['min_message_interval_sec']
        max_interval = self.config['max_message_interval_sec']
        
        is_anomaly = time_diff_sec < min_interval or time_diff_sec > max_interval
        
        if time_diff_sec < min_interval:
            reason = f'Message rate too high: {time_diff_sec:.1f}s interval (min: {min_interval}s)'
        elif time_diff_sec > max_interval:
            reason = f'Message rate too low: {time_diff_sec:.1f}s interval (max: {max_interval}s)'
        else:
            reason = ''
        
        return {
            'is_anomaly': is_anomaly,
            'interval': time_diff_sec,
            'reason': reason
        }
    
    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate geodesic distance between two points"""
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        return self.config['earth_radius_km'] * c
    
    def get_statistics(self) -> Dict:
        """Get detector statistics"""
        anomaly_rate = (self.stats['anomalies_detected'] / self.stats['total_messages'] * 100) if self.stats['total_messages'] > 0 else 0
        
        return {
            **self.stats,
            'anomaly_rate_percent': anomaly_rate,
            'tracked_vessels': len(self.vessel_history)
        }
    
    def reset(self):
        """Reset detector state"""
        self.vessel_history.clear()
        self.stats = {
            'total_messages': 0,
            'anomalies_detected': 0,
            'invalid_mmsi': 0,
            'speed_violations': 0,
            'position_jumps': 0,
            'course_anomalies': 0,
            'message_rate_anomalies': 0
        }
        logger.info("AIS Anomaly Detector reset")


# Test the detector
if __name__ == "__main__":
    print("Testing AIS Anomaly Detector...")
    
    detector = AISAnomalyDetector()
    
    # Test case 1: Normal cargo vessel
    print("\n1. Normal cargo vessel AIS messages:")
    normal_messages = [
        {
            'mmsi': 366123456,
            'latitude': 40.7128,
            'longitude': -74.0060,
            'speed': 15.0,
            'course': 90.0,
            'heading': 92.0,
            'vessel_type': 'cargo',
            'timestamp': datetime.now(),
            'name': 'Test Cargo Ship'
        },
        {
            'mmsi': 366123456,
            'latitude': 40.7135,
            'longitude': -74.0050,
            'speed': 15.5,
            'course': 91.0,
            'heading': 93.0,
            'vessel_type': 'cargo',
            'timestamp': datetime.now() + timedelta(minutes=1),
            'name': 'Test Cargo Ship'
        }
    ]
    
    for msg in normal_messages:
        result = detector.check_ais_message(msg)
        print(f"  MMSI {msg['mmsi']}: Anomaly={result['is_anomaly']}, Confidence={result['confidence']:.2f}")
    
    # Test case 2: Speed violation
    print("\n2. Speed violation (cargo ship too fast):")
    detector.reset()
    speed_violation = {
        'mmsi': 366123457,
        'latitude': 40.7128,
        'longitude': -74.0060,
        'speed': 35.0,  # Way too fast for cargo!
        'course': 90.0,
        'heading': 90.0,
        'vessel_type': 'cargo',
        'timestamp': datetime.now(),
        'name': 'Speedy Cargo'
    }
    
    result = detector.check_ais_message(speed_violation)
    print(f"  Anomaly: {result['is_anomaly']}, Confidence: {result['confidence']:.2f}")
    print(f"  Issues: {result['anomalies']}")
    
    # Test case 3: Invalid MMSI
    print("\n3. Invalid MMSI:")
    invalid_mmsi = {
        'mmsi': 111111111,  # All same digits
        'latitude': 40.7128,
        'longitude': -74.0060,
        'speed': 15.0,
        'course': 90.0,
        'heading': 90.0,
        'vessel_type': 'cargo',
        'timestamp': datetime.now(),
        'name': 'Suspicious Ship'
    }
    
    result = detector.check_ais_message(invalid_mmsi)
    print(f"  Anomaly: {result['is_anomaly']}, Confidence: {result['confidence']:.2f}")
    print(f"  Issues: {result['anomalies']}")
    
    # Test case 4: Course/Heading mismatch
    print("\n4. Course/Heading mismatch:")
    detector.reset()
    heading_mismatch = {
        'mmsi': 366123458,
        'latitude': 40.7128,
        'longitude': -74.0060,
        'speed': 15.0,
        'course': 90.0,
        'heading': 180.0,  # Pointing backwards!
        'vessel_type': 'cargo',
        'timestamp': datetime.now(),
        'name': 'Drifting Ship'
    }
    
    result = detector.check_ais_message(heading_mismatch)
    print(f"  Anomaly: {result['is_anomaly']}, Confidence: {result['confidence']:.2f}")
    print(f"  Issues: {result['anomalies']}")
    
    # Test case 5: Position jump
    print("\n5. Impossible position jump:")
    detector.reset()
    position_messages = [
        {
            'mmsi': 366123459,
            'latitude': 40.7128,
            'longitude': -74.0060,
            'speed': 15.0,
            'course': 90.0,
            'heading': 90.0,
            'vessel_type': 'cargo',
            'timestamp': datetime.now(),
            'name': 'Teleporting Ship'
        },
        {
            'mmsi': 366123459,
            'latitude': 41.0,
            'longitude': -73.0,
            'speed': 15.0,
            'course': 90.0,
            'heading': 90.0,
            'vessel_type': 'cargo',
            'timestamp': datetime.now() + timedelta(seconds=30),  # 30 seconds later, 100 km away!
            'name': 'Teleporting Ship'
        }
    ]
    
    for msg in position_messages:
        result = detector.check_ais_message(msg)
        print(f"  Message {position_messages.index(msg)+1}: Anomaly={result['is_anomaly']}, Confidence={result['confidence']:.2f}")
        if result['anomalies']:
            print(f"  Issues: {result['anomalies']}")
    
    print("\n6. Statistics:")
    stats = detector.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ AIS Anomaly Detector test complete!")
