"""
GPS Spoofing Detector for Maritime Vessels
Detects GPS coordinate manipulation and impossible position changes
"""
import math
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from collections import deque

logger = logging.getLogger(__name__)


class GPSSpoofingDetector:
    """
    Detects GPS spoofing attacks using:
    - Geodesic distance calculations
    - Speed feasibility checks
    - Trajectory consistency validation
    - Acceleration constraints
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize GPS spoofing detector
        
        Args:
            config: Configuration dictionary with detection parameters
        """
        self.config = config or self._default_config()
        
        # Position history for trajectory analysis
        self.position_history = deque(maxlen=self.config['history_size'])
        
        # Statistics
        self.stats = {
            'total_checks': 0,
            'spoofing_detected': 0,
            'impossible_speed': 0,
            'impossible_distance': 0,
            'trajectory_anomaly': 0
        }
        
        logger.info("GPS Spoofing Detector initialized")
    
    def _default_config(self) -> Dict:
        """Default configuration for GPS spoofing detection"""
        return {
            'history_size': 100,  # Number of positions to track
            'max_vessel_speed_knots': 30,  # Maximum reasonable speed for merchant vessels
            'max_acceleration_knots_per_sec': 0.1,  # Maximum acceleration
            'max_position_jump_km': 50,  # Maximum distance between consecutive readings
            'min_time_between_readings_sec': 1,  # Minimum time between GPS updates
            'trajectory_smoothness_threshold': 0.8,  # Trajectory consistency score
            'earth_radius_km': 6371  # Earth's radius for geodesic calculations
        }
    
    def check_gps_spoofing(self, gps_data: Dict) -> Dict:
        """
        Check GPS data for spoofing indicators
        
        Args:
            gps_data: Dictionary with keys:
                - latitude: float
                - longitude: float
                - timestamp: datetime
                - speed_knots: float (optional)
                - course: float (optional, 0-360 degrees)
                - vessel_id: str (optional)
        
        Returns:
            Dictionary with detection results:
                - is_spoofed: bool
                - confidence: float (0-1)
                - anomalies: List[str]
                - details: Dict
        """
        self.stats['total_checks'] += 1
        
        result = {
            'is_spoofed': False,
            'confidence': 0.0,
            'anomalies': [],
            'details': {},
            'severity': 'INFO'
        }
        
        try:
            # Validate GPS data format
            if not self._validate_gps_format(gps_data):
                result['anomalies'].append('Invalid GPS data format')
                result['confidence'] = 0.5
                result['is_spoofed'] = True
                return result
            
            # Add current position to history
            current_position = {
                'lat': gps_data['latitude'],
                'lon': gps_data['longitude'],
                'timestamp': gps_data['timestamp'],
                'speed': gps_data.get('speed_knots', 0),
                'course': gps_data.get('course', 0)
            }
            
            # Check reported speed even without history (single-point validation)
            reported_speed = gps_data.get('speed_knots', 0)
            if reported_speed > self.config['max_vessel_speed_knots']:
                result['anomalies'].append(f"Impossible speed: {reported_speed:.2f} knots (max: {self.config['max_vessel_speed_knots']} knots)")
                result['confidence'] += 0.5
                result['details']['reported_speed_knots'] = reported_speed
                result['is_spoofed'] = True
                self.stats['impossible_speed'] += 1
            
            # Check if we have previous position for comparison
            if len(self.position_history) > 0:
                prev_position = self.position_history[-1]
                
                # 1. Check impossible distance jump
                distance_check = self._check_distance_feasibility(prev_position, current_position)
                if distance_check['is_anomaly']:
                    result['anomalies'].append(distance_check['reason'])
                    result['confidence'] += 0.3
                    result['details']['distance_km'] = distance_check['distance_km']
                    self.stats['impossible_distance'] += 1
                
                # 2. Check impossible speed
                speed_check = self._check_speed_feasibility(prev_position, current_position)
                if speed_check['is_anomaly']:
                    result['anomalies'].append(speed_check['reason'])
                    result['confidence'] += 0.4
                    result['details']['calculated_speed_knots'] = speed_check['speed_knots']
                    self.stats['impossible_speed'] += 1
                
                # 3. Check acceleration constraints
                if len(self.position_history) >= 2:
                    accel_check = self._check_acceleration(
                        self.position_history[-2],
                        prev_position,
                        current_position
                    )
                    if accel_check['is_anomaly']:
                        result['anomalies'].append(accel_check['reason'])
                        result['confidence'] += 0.2
                        result['details']['acceleration'] = accel_check['acceleration']
                
                # 4. Check trajectory consistency
                if len(self.position_history) >= 3:
                    trajectory_check = self._check_trajectory_consistency()
                    if trajectory_check['is_anomaly']:
                        result['anomalies'].append(trajectory_check['reason'])
                        result['confidence'] += 0.1
                        result['details']['trajectory_score'] = trajectory_check['score']
                        self.stats['trajectory_anomaly'] += 1
            
            # Add position to history
            self.position_history.append(current_position)
            
            # Determine if spoofing detected
            if result['confidence'] >= 0.5:
                result['is_spoofed'] = True
                self.stats['spoofing_detected'] += 1
                
                # Set severity based on confidence
                if result['confidence'] >= 0.8:
                    result['severity'] = 'CRITICAL'
                elif result['confidence'] >= 0.6:
                    result['severity'] = 'HIGH'
                else:
                    result['severity'] = 'MEDIUM'
                
                logger.warning(f"GPS spoofing detected! Confidence: {result['confidence']:.2f}, Anomalies: {result['anomalies']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in GPS spoofing detection: {e}")
            result['anomalies'].append(f"Detection error: {str(e)}")
            return result
    
    def _validate_gps_format(self, gps_data: Dict) -> bool:
        """Validate GPS data format and coordinates"""
        required_fields = ['latitude', 'longitude', 'timestamp']
        
        # Check required fields
        if not all(field in gps_data for field in required_fields):
            return False
        
        # Validate coordinate ranges
        lat = gps_data['latitude']
        lon = gps_data['longitude']
        
        if not (-90 <= lat <= 90):
            return False
        
        if not (-180 <= lon <= 180):
            return False
        
        return True
    
    def _check_distance_feasibility(self, prev_pos: Dict, curr_pos: Dict) -> Dict:
        """Check if distance between positions is feasible"""
        # Calculate geodesic distance
        distance_km = self._haversine_distance(
            prev_pos['lat'], prev_pos['lon'],
            curr_pos['lat'], curr_pos['lon']
        )
        
        # Calculate time difference
        time_diff = (curr_pos['timestamp'] - prev_pos['timestamp']).total_seconds()
        
        # Check if distance is too large for the time interval
        max_distance = self.config['max_position_jump_km']
        
        is_anomaly = distance_km > max_distance
        
        return {
            'is_anomaly': is_anomaly,
            'distance_km': distance_km,
            'time_diff_sec': time_diff,
            'reason': f"Impossible position jump: {distance_km:.2f} km in {time_diff:.1f} seconds"
        }
    
    def _check_speed_feasibility(self, prev_pos: Dict, curr_pos: Dict) -> Dict:
        """Check if calculated speed is feasible for a vessel"""
        # Calculate distance
        distance_km = self._haversine_distance(
            prev_pos['lat'], prev_pos['lon'],
            curr_pos['lat'], curr_pos['lon']
        )
        
        # Calculate time difference
        time_diff_hours = (curr_pos['timestamp'] - prev_pos['timestamp']).total_seconds() / 3600
        
        if time_diff_hours <= 0:
            return {'is_anomaly': True, 'reason': 'Invalid time sequence', 'speed_knots': 0}
        
        # Calculate speed in knots (1 knot = 1.852 km/h)
        speed_kmh = distance_km / time_diff_hours
        speed_knots = speed_kmh / 1.852
        
        # Check against maximum vessel speed
        max_speed = self.config['max_vessel_speed_knots']
        is_anomaly = speed_knots > max_speed
        
        return {
            'is_anomaly': is_anomaly,
            'speed_knots': speed_knots,
            'max_speed_knots': max_speed,
            'reason': f"Impossible speed: {speed_knots:.2f} knots (max: {max_speed} knots)"
        }
    
    def _check_acceleration(self, pos1: Dict, pos2: Dict, pos3: Dict) -> Dict:
        """Check if acceleration is within physical constraints"""
        # Calculate speeds between consecutive positions
        time_diff_1_2 = (pos2['timestamp'] - pos1['timestamp']).total_seconds()
        time_diff_2_3 = (pos3['timestamp'] - pos2['timestamp']).total_seconds()
        
        if time_diff_1_2 <= 0 or time_diff_2_3 <= 0:
            return {'is_anomaly': False, 'acceleration': 0, 'reason': ''}
        
        # Calculate distances
        dist_1_2 = self._haversine_distance(pos1['lat'], pos1['lon'], pos2['lat'], pos2['lon'])
        dist_2_3 = self._haversine_distance(pos2['lat'], pos2['lon'], pos3['lat'], pos3['lon'])
        
        # Calculate speeds in knots
        speed_1_2 = (dist_1_2 / (time_diff_1_2 / 3600)) / 1.852
        speed_2_3 = (dist_2_3 / (time_diff_2_3 / 3600)) / 1.852
        
        # Calculate acceleration (change in speed per second)
        acceleration = (speed_2_3 - speed_1_2) / time_diff_2_3
        
        # Check against maximum acceleration
        max_accel = self.config['max_acceleration_knots_per_sec']
        is_anomaly = abs(acceleration) > max_accel
        
        return {
            'is_anomaly': is_anomaly,
            'acceleration': acceleration,
            'max_acceleration': max_accel,
            'reason': f"Impossible acceleration: {acceleration:.4f} knots/sec (max: {max_accel})"
        }
    
    def _check_trajectory_consistency(self) -> Dict:
        """Check if trajectory follows a consistent pattern"""
        if len(self.position_history) < 4:
            return {'is_anomaly': False, 'score': 1.0, 'reason': ''}
        
        # Calculate bearing changes between consecutive segments
        bearing_changes = []
        recent_positions = list(self.position_history)[-5:]  # Last 5 positions
        
        for i in range(len(recent_positions) - 2):
            bearing1 = self._calculate_bearing(
                recent_positions[i]['lat'], recent_positions[i]['lon'],
                recent_positions[i+1]['lat'], recent_positions[i+1]['lon']
            )
            bearing2 = self._calculate_bearing(
                recent_positions[i+1]['lat'], recent_positions[i+1]['lon'],
                recent_positions[i+2]['lat'], recent_positions[i+2]['lon']
            )
            
            # Calculate change in bearing
            bearing_change = abs(bearing2 - bearing1)
            if bearing_change > 180:
                bearing_change = 360 - bearing_change
            
            bearing_changes.append(bearing_change)
        
        # Calculate smoothness score (lower variance = smoother trajectory)
        if bearing_changes:
            variance = sum((x - sum(bearing_changes)/len(bearing_changes))**2 for x in bearing_changes) / len(bearing_changes)
            smoothness_score = 1.0 / (1.0 + variance / 100)  # Normalize
        else:
            smoothness_score = 1.0
        
        threshold = self.config['trajectory_smoothness_threshold']
        is_anomaly = smoothness_score < threshold
        
        return {
            'is_anomaly': is_anomaly,
            'score': smoothness_score,
            'threshold': threshold,
            'reason': f"Erratic trajectory: smoothness score {smoothness_score:.2f} (threshold: {threshold})"
        }
    
    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate geodesic distance between two points using Haversine formula
        
        Returns:
            Distance in kilometers
        """
        # Convert to radians
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        # Haversine formula
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        distance = self.config['earth_radius_km'] * c
        return distance
    
    def _calculate_bearing(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate bearing (direction) from point 1 to point 2
        
        Returns:
            Bearing in degrees (0-360)
        """
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlon = lon2_rad - lon1_rad
        
        y = math.sin(dlon) * math.cos(lat2_rad)
        x = math.cos(lat1_rad) * math.sin(lat2_rad) - math.sin(lat1_rad) * math.cos(lat2_rad) * math.cos(dlon)
        
        bearing_rad = math.atan2(y, x)
        bearing_deg = math.degrees(bearing_rad)
        
        # Normalize to 0-360
        bearing_deg = (bearing_deg + 360) % 360
        
        return bearing_deg
    
    def get_statistics(self) -> Dict:
        """Get detector statistics"""
        detection_rate = (self.stats['spoofing_detected'] / self.stats['total_checks'] * 100) if self.stats['total_checks'] > 0 else 0
        
        return {
            **self.stats,
            'detection_rate_percent': detection_rate,
            'history_size': len(self.position_history),
            'positions_tracked': len(self.position_history)
        }
    
    def reset(self):
        """Reset detector state"""
        self.position_history.clear()
        self.stats = {
            'total_checks': 0,
            'spoofing_detected': 0,
            'impossible_speed': 0,
            'impossible_distance': 0,
            'trajectory_anomaly': 0
        }
        logger.info("GPS Spoofing Detector reset")


# Test the detector
if __name__ == "__main__":
    print("Testing GPS Spoofing Detector...")
    
    detector = GPSSpoofingDetector()
    
    # Test case 1: Normal vessel movement
    print("\n1. Normal vessel movement:")
    normal_gps = [
        {'latitude': 40.7128, 'longitude': -74.0060, 'timestamp': datetime.now(), 'speed_knots': 10},
        {'latitude': 40.7138, 'longitude': -74.0050, 'timestamp': datetime.now() + timedelta(minutes=1), 'speed_knots': 10},
        {'latitude': 40.7148, 'longitude': -74.0040, 'timestamp': datetime.now() + timedelta(minutes=2), 'speed_knots': 10},
    ]
    
    for gps_data in normal_gps:
        result = detector.check_gps_spoofing(gps_data)
        print(f"  Spoofed: {result['is_spoofed']}, Confidence: {result['confidence']:.2f}, Anomalies: {result['anomalies']}")
    
    # Test case 2: Impossible position jump (GPS spoofing)
    print("\n2. Impossible position jump (spoofing):")
    detector.reset()
    spoofed_gps = [
        {'latitude': 40.7128, 'longitude': -74.0060, 'timestamp': datetime.now(), 'speed_knots': 10},
        {'latitude': 51.5074, 'longitude': -0.1278, 'timestamp': datetime.now() + timedelta(minutes=1), 'speed_knots': 10},  # Jump to London!
    ]
    
    for gps_data in spoofed_gps:
        result = detector.check_gps_spoofing(gps_data)
        print(f"  Spoofed: {result['is_spoofed']}, Confidence: {result['confidence']:.2f}")
        print(f"  Anomalies: {result['anomalies']}")
    
    # Test case 3: Impossible speed
    print("\n3. Impossible speed (spoofing):")
    detector.reset()
    high_speed_gps = [
        {'latitude': 40.7128, 'longitude': -74.0060, 'timestamp': datetime.now(), 'speed_knots': 10},
        {'latitude': 41.0, 'longitude': -73.0, 'timestamp': datetime.now() + timedelta(seconds=30), 'speed_knots': 10},  # 100+ km in 30 sec
    ]
    
    for gps_data in high_speed_gps:
        result = detector.check_gps_spoofing(gps_data)
        print(f"  Spoofed: {result['is_spoofed']}, Confidence: {result['confidence']:.2f}")
        print(f"  Anomalies: {result['anomalies']}")
        if 'calculated_speed_knots' in result['details']:
            print(f"  Calculated speed: {result['details']['calculated_speed_knots']:.2f} knots")
    
    print("\n4. Statistics:")
    stats = detector.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ GPS Spoofing Detector test complete!")
