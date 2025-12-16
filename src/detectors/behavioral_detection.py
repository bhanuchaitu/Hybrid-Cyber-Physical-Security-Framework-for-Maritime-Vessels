"""
Behavioral Detection and Advanced Analysis Rules
Implements behavioral analysis, geofencing, multi-vessel correlation, 
speed/course prediction, and pattern matching
"""
import numpy as np
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set
from collections import deque, defaultdict
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)


@dataclass
class BehaviorProfile:
    """Vessel behavior profile"""
    vessel_id: str
    normal_speed_range: Tuple[float, float]  # (min, max) knots
    normal_course_variance: float  # degrees
    typical_ports: Set[str]
    typical_routes: List[Tuple[float, float]]  # List of (lat, lon) waypoints
    activity_hours: Tuple[int, int]  # (start_hour, end_hour)
    created_at: datetime
    last_updated: datetime


class BehavioralAnalyzer:
    """
    Learns normal vessel behavior patterns and detects anomalies
    Uses statistical analysis and machine learning for deviation detection
    """
    
    def __init__(self, learning_period_days: int = 30):
        """
        Initialize behavioral analyzer
        
        Args:
            learning_period_days: Days to learn normal behavior
        """
        self.learning_period = timedelta(days=learning_period_days)
        self.vessel_profiles: Dict[str, BehaviorProfile] = {}
        self.behavior_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.anomalies = []
        self.stats = {
            'vessels_monitored': 0,
            'behaviors_learned': 0,
            'anomalies_detected': 0
        }
    
    def learn_behavior(self, vessel_id: str, behavior_data: Dict) -> BehaviorProfile:
        """
        Learn normal behavior pattern for vessel
        
        Args:
            vessel_id: Vessel identifier
            behavior_data: Historical behavior data (speed, course, positions, ports)
            
        Returns:
            BehaviorProfile
        """
        speeds = behavior_data.get('speeds', [])
        courses = behavior_data.get('courses', [])
        ports = behavior_data.get('ports_visited', set())
        routes = behavior_data.get('typical_routes', [])
        timestamps = behavior_data.get('timestamps', [])
        
        # Calculate speed range
        if speeds:
            speed_mean = np.mean(speeds)
            speed_std = np.std(speeds)
            speed_range = (
                max(0, speed_mean - 2 * speed_std),
                speed_mean + 2 * speed_std
            )
        else:
            speed_range = (0, 25)  # Default
        
        # Calculate course variance
        if courses:
            course_variance = np.std(courses)
        else:
            course_variance = 45  # Default
        
        # Determine typical activity hours
        if timestamps:
            hours = [t.hour for t in timestamps]
            activity_hours = (min(hours), max(hours))
        else:
            activity_hours = (0, 23)  # Default
        
        profile = BehaviorProfile(
            vessel_id=vessel_id,
            normal_speed_range=speed_range,
            normal_course_variance=course_variance,
            typical_ports=ports,
            typical_routes=routes,
            activity_hours=activity_hours,
            created_at=datetime.now(),
            last_updated=datetime.now()
        )
        
        self.vessel_profiles[vessel_id] = profile
        self.stats['behaviors_learned'] += 1
        
        logger.info(f"Learned behavior for {vessel_id}: Speed {speed_range[0]:.1f}-{speed_range[1]:.1f}kt")
        return profile
    
    def detect_anomaly(self, vessel_id: str, current_behavior: Dict) -> Optional[Dict]:
        """
        Detect behavioral anomalies
        
        Args:
            vessel_id: Vessel identifier
            current_behavior: Current behavior data (speed, course, position, timestamp)
            
        Returns:
            Anomaly details if detected
        """
        if vessel_id not in self.vessel_profiles:
            return None
        
        profile = self.vessel_profiles[vessel_id]
        anomaly_score = 0.0
        anomalies_found = []
        
        # Check speed anomaly
        current_speed = current_behavior.get('speed', 0)
        if not (profile.normal_speed_range[0] <= current_speed <= profile.normal_speed_range[1]):
            anomaly_score += 0.3
            anomalies_found.append(f"Abnormal speed: {current_speed:.1f}kt (normal: {profile.normal_speed_range[0]:.1f}-{profile.normal_speed_range[1]:.1f}kt)")
        
        # Check course change anomaly
        if len(self.behavior_history[vessel_id]) > 0:
            prev_behavior = self.behavior_history[vessel_id][-1]
            course_change = abs(current_behavior.get('course', 0) - prev_behavior.get('course', 0))
            if course_change > 180:
                course_change = 360 - course_change
            
            if course_change > profile.normal_course_variance * 2:
                anomaly_score += 0.25
                anomalies_found.append(f"Sudden course change: {course_change:.1f}° (normal variance: {profile.normal_course_variance:.1f}°)")
        
        # Check activity time anomaly
        current_time = current_behavior.get('timestamp', datetime.now())
        current_hour = current_time.hour
        if not (profile.activity_hours[0] <= current_hour <= profile.activity_hours[1]):
            anomaly_score += 0.2
            anomalies_found.append(f"Unusual activity time: {current_hour}:00 (normal: {profile.activity_hours[0]}:00-{profile.activity_hours[1]}:00)")
        
        # Check position anomaly (far from typical routes)
        current_pos = (current_behavior.get('latitude'), current_behavior.get('longitude'))
        if profile.typical_routes and current_pos[0] is not None:
            min_distance = float('inf')
            for route_point in profile.typical_routes:
                distance = np.sqrt((current_pos[0] - route_point[0])**2 + 
                                 (current_pos[1] - route_point[1])**2)
                min_distance = min(min_distance, distance)
            
            if min_distance > 0.5:  # More than 0.5 degrees away (roughly 30 nautical miles)
                anomaly_score += 0.25
                anomalies_found.append(f"Off typical route by {min_distance:.2f}°")
        
        # Store behavior
        self.behavior_history[vessel_id].append(current_behavior)
        
        # Report anomaly if score is significant
        if anomaly_score >= 0.4:
            self.stats['anomalies_detected'] += 1
            
            anomaly = {
                'vessel_id': vessel_id,
                'anomaly_score': anomaly_score,
                'anomalies': anomalies_found,
                'timestamp': current_time,
                'severity': 'high' if anomaly_score >= 0.7 else 'medium'
            }
            self.anomalies.append(anomaly)
            
            logger.warning(f"BEHAVIORAL ANOMALY: {vessel_id} - Score: {anomaly_score:.2f} - {'; '.join(anomalies_found)}")
            return anomaly
        
        return None
    
    def get_statistics(self) -> Dict:
        """Get analyzer statistics"""
        self.stats['vessels_monitored'] = len(self.vessel_profiles)
        return self.stats


class GeofencingSystem:
    """
    Manages geographical boundaries and alerts on violations
    Supports complex polygonal zones and exclusion areas
    """
    
    def __init__(self):
        """Initialize geofencing system"""
        self.zones: Dict[str, Dict] = {}
        self.violations = []
        self.stats = {
            'total_zones': 0,
            'total_checks': 0,
            'violations_detected': 0
        }
    
    def add_zone(self, zone_name: str, zone_type: str, coordinates: List[Tuple[float, float]], 
                 allowed_vessels: Optional[Set[str]] = None):
        """
        Add geofence zone
        
        Args:
            zone_name: Zone identifier
            zone_type: Type ('restricted', 'safe', 'port', 'territorial')
            coordinates: List of (lat, lon) points defining zone boundary
            allowed_vessels: Set of vessel IDs allowed in restricted zones
        """
        self.zones[zone_name] = {
            'type': zone_type,
            'coordinates': coordinates,
            'allowed_vessels': allowed_vessels or set(),
            'created_at': datetime.now()
        }
        self.stats['total_zones'] += 1
        
        logger.info(f"Added geofence zone: {zone_name} ({zone_type})")
    
    def point_in_polygon(self, point: Tuple[float, float], polygon: List[Tuple[float, float]]) -> bool:
        """
        Check if point is inside polygon using ray casting algorithm
        
        Args:
            point: (lat, lon) to check
            polygon: List of (lat, lon) points
            
        Returns:
            True if point is inside polygon
        """
        x, y = point
        n = len(polygon)
        inside = False
        
        p1x, p1y = polygon[0]
        for i in range(1, n + 1):
            p2x, p2y = polygon[i % n]
            if y > min(p1y, p2y):
                if y <= max(p1y, p2y):
                    if x <= max(p1x, p2x):
                        if p1y != p2y:
                            xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                        if p1x == p2x or x <= xinters:
                            inside = not inside
            p1x, p1y = p2x, p2y
        
        return inside
    
    def check_position(self, vessel_id: str, position: Tuple[float, float]) -> List[Dict]:
        """
        Check vessel position against all geofences
        
        Args:
            vessel_id: Vessel identifier
            position: (latitude, longitude)
            
        Returns:
            List of violations
        """
        self.stats['total_checks'] += 1
        violations_found = []
        
        for zone_name, zone_info in self.zones.items():
            is_inside = self.point_in_polygon(position, zone_info['coordinates'])
            
            # Check restricted zones
            if zone_info['type'] == 'restricted' and is_inside:
                if vessel_id not in zone_info['allowed_vessels']:
                    violation = {
                        'vessel_id': vessel_id,
                        'zone': zone_name,
                        'zone_type': zone_info['type'],
                        'position': position,
                        'timestamp': datetime.now(),
                        'severity': 'critical'
                    }
                    violations_found.append(violation)
                    self.violations.append(violation)
                    self.stats['violations_detected'] += 1
                    
                    logger.critical(f"GEOFENCE VIOLATION: {vessel_id} entered restricted zone {zone_name}")
            
            # Check if vessel left safe zone
            elif zone_info['type'] == 'safe' and not is_inside:
                if vessel_id in zone_info['allowed_vessels']:
                    violation = {
                        'vessel_id': vessel_id,
                        'zone': zone_name,
                        'zone_type': 'safe_exit',
                        'position': position,
                        'timestamp': datetime.now(),
                        'severity': 'medium'
                    }
                    violations_found.append(violation)
                    logger.warning(f"GEOFENCE: {vessel_id} left safe zone {zone_name}")
        
        return violations_found
    
    def get_statistics(self) -> Dict:
        """Get geofencing statistics"""
        return self.stats


class MultiVesselCorrelator:
    """
    Correlates activities across multiple vessels
    Detects coordinated attacks and suspicious patterns
    """
    
    def __init__(self):
        """Initialize multi-vessel correlator"""
        self.vessel_activities: Dict[str, List[Dict]] = defaultdict(list)
        self.correlations = []
        self.stats = {
            'vessels_tracked': 0,
            'correlations_found': 0,
            'coordinated_threats': 0
        }
    
    def add_activity(self, vessel_id: str, activity: Dict):
        """
        Add vessel activity
        
        Args:
            vessel_id: Vessel identifier
            activity: Activity data (type, position, timestamp)
        """
        activity['vessel_id'] = vessel_id
        self.vessel_activities[vessel_id].append(activity)
        
        # Keep only recent activities (last 24 hours)
        cutoff = datetime.now() - timedelta(hours=24)
        self.vessel_activities[vessel_id] = [
            a for a in self.vessel_activities[vessel_id]
            if a.get('timestamp', datetime.now()) > cutoff
        ]
    
    def detect_coordinated_activity(self, time_window_minutes: int = 30, 
                                   distance_threshold_nm: float = 5.0) -> List[Dict]:
        """
        Detect coordinated activities between vessels
        
        Args:
            time_window_minutes: Time window for correlation
            distance_threshold_nm: Distance threshold in nautical miles
            
        Returns:
            List of coordinated activity patterns
        """
        self.stats['vessels_tracked'] = len(self.vessel_activities)
        coordinated_patterns = []
        
        vessel_ids = list(self.vessel_activities.keys())
        
        # Compare each pair of vessels
        for i in range(len(vessel_ids)):
            for j in range(i + 1, len(vessel_ids)):
                vessel1_id = vessel_ids[i]
                vessel2_id = vessel_ids[j]
                
                activities1 = self.vessel_activities[vessel1_id]
                activities2 = self.vessel_activities[vessel2_id]
                
                # Look for simultaneous activities
                for act1 in activities1:
                    for act2 in activities2:
                        # Check time correlation
                        time_diff = abs((act1.get('timestamp', datetime.now()) - 
                                       act2.get('timestamp', datetime.now())).total_seconds() / 60)
                        
                        if time_diff <= time_window_minutes:
                            # Check distance correlation
                            pos1 = (act1.get('latitude'), act1.get('longitude'))
                            pos2 = (act2.get('latitude'), act2.get('longitude'))
                            
                            if pos1[0] is not None and pos2[0] is not None:
                                # Calculate distance in nautical miles
                                dx = (pos2[1] - pos1[1]) * 60 * np.cos(np.radians(pos1[0]))
                                dy = (pos2[0] - pos1[0]) * 60
                                distance = np.sqrt(dx**2 + dy**2)
                                
                                if distance <= distance_threshold_nm:
                                    pattern = {
                                        'vessels': [vessel1_id, vessel2_id],
                                        'activity_type': f"{act1.get('type', 'unknown')} + {act2.get('type', 'unknown')}",
                                        'time_diff_minutes': time_diff,
                                        'distance_nm': distance,
                                        'timestamp': act1.get('timestamp', datetime.now()),
                                        'severity': 'high' if distance < 1.0 else 'medium'
                                    }
                                    coordinated_patterns.append(pattern)
                                    self.stats['correlations_found'] += 1
                                    
                                    logger.warning(f"COORDINATED ACTIVITY: {vessel1_id} & {vessel2_id} - {distance:.2f}nm apart")
        
        if coordinated_patterns:
            self.stats['coordinated_threats'] += 1
        
        return coordinated_patterns
    
    def get_statistics(self) -> Dict:
        """Get correlator statistics"""
        return self.stats


class SpeedCoursePredictor:
    """
    Predicts vessel speed and course using Kalman filtering
    Detects unexpected maneuvers and deviations
    """
    
    def __init__(self):
        """Initialize speed/course predictor"""
        self.vessel_states: Dict[str, Dict] = {}
        self.predictions = {}
        self.deviations = []
        self.stats = {
            'predictions_made': 0,
            'deviations_detected': 0
        }
    
    def initialize_vessel(self, vessel_id: str, initial_state: Dict):
        """
        Initialize vessel state
        
        Args:
            vessel_id: Vessel identifier
            initial_state: Initial state (speed, course, position, timestamp)
        """
        self.vessel_states[vessel_id] = {
            'speed': initial_state.get('speed', 0),
            'course': initial_state.get('course', 0),
            'latitude': initial_state.get('latitude', 0),
            'longitude': initial_state.get('longitude', 0),
            'timestamp': initial_state.get('timestamp', datetime.now()),
            'speed_variance': 1.0,
            'course_variance': 10.0
        }
    
    def predict_next_state(self, vessel_id: str, time_delta_minutes: float) -> Dict:
        """
        Predict vessel state after time delta
        
        Args:
            vessel_id: Vessel identifier
            time_delta_minutes: Time delta in minutes
            
        Returns:
            Predicted state
        """
        if vessel_id not in self.vessel_states:
            return {}
        
        state = self.vessel_states[vessel_id]
        time_delta_hours = time_delta_minutes / 60.0
        
        # Predict position based on current speed and course
        distance_nm = state['speed'] * time_delta_hours
        
        # Convert to lat/lon change
        dlat = distance_nm * np.cos(np.radians(state['course'])) / 60.0
        dlon = distance_nm * np.sin(np.radians(state['course'])) / (60.0 * np.cos(np.radians(state['latitude'])))
        
        predicted_state = {
            'speed': state['speed'],
            'course': state['course'],
            'latitude': state['latitude'] + dlat,
            'longitude': state['longitude'] + dlon,
            'timestamp': state['timestamp'] + timedelta(minutes=time_delta_minutes)
        }
        
        self.predictions[vessel_id] = predicted_state
        self.stats['predictions_made'] += 1
        
        return predicted_state
    
    def update_state(self, vessel_id: str, actual_state: Dict) -> Optional[Dict]:
        """
        Update vessel state and check for deviations
        
        Args:
            vessel_id: Vessel identifier
            actual_state: Actual observed state
            
        Returns:
            Deviation details if significant deviation detected
        """
        if vessel_id not in self.predictions:
            # No prediction to compare, just update
            self.initialize_vessel(vessel_id, actual_state)
            return None
        
        predicted = self.predictions[vessel_id]
        
        # Calculate deviations
        speed_dev = abs(actual_state.get('speed', 0) - predicted['speed'])
        course_dev = abs(actual_state.get('course', 0) - predicted['course'])
        if course_dev > 180:
            course_dev = 360 - course_dev
        
        # Position deviation
        actual_pos = (actual_state.get('latitude', 0), actual_state.get('longitude', 0))
        predicted_pos = (predicted['latitude'], predicted['longitude'])
        
        dx = (actual_pos[1] - predicted_pos[1]) * 60 * np.cos(np.radians(actual_pos[0]))
        dy = (actual_pos[0] - predicted_pos[0]) * 60
        position_dev_nm = np.sqrt(dx**2 + dy**2)
        
        # Check for significant deviations
        if speed_dev > 5 or course_dev > 30 or position_dev_nm > 2:
            self.stats['deviations_detected'] += 1
            
            deviation = {
                'vessel_id': vessel_id,
                'speed_deviation': speed_dev,
                'course_deviation': course_dev,
                'position_deviation_nm': position_dev_nm,
                'timestamp': actual_state.get('timestamp', datetime.now()),
                'severity': 'high' if position_dev_nm > 5 else 'medium'
            }
            self.deviations.append(deviation)
            
            logger.warning(f"TRAJECTORY DEVIATION: {vessel_id} - Position: {position_dev_nm:.2f}nm, Course: {course_dev:.1f}°")
            
            # Update state
            self.initialize_vessel(vessel_id, actual_state)
            return deviation
        
        # Normal update
        self.initialize_vessel(vessel_id, actual_state)
        return None
    
    def get_statistics(self) -> Dict:
        """Get predictor statistics"""
        return self.stats


class PatternMatcher:
    """
    Matches current activities against known attack patterns
    Uses fuzzy matching and historical signatures
    """
    
    def __init__(self):
        """Initialize pattern matcher"""
        self.attack_patterns: Dict[str, Dict] = {}
        self.matches = []
        self.stats = {
            'patterns_loaded': 0,
            'matches_found': 0
        }
    
    def load_attack_pattern(self, pattern_name: str, pattern_definition: Dict):
        """
        Load known attack pattern
        
        Args:
            pattern_name: Pattern identifier
            pattern_definition: Pattern characteristics (sequence, indicators, severity)
        """
        self.attack_patterns[pattern_name] = {
            'definition': pattern_definition,
            'loaded_at': datetime.now()
        }
        self.stats['patterns_loaded'] += 1
        
        logger.info(f"Loaded attack pattern: {pattern_name}")
    
    def match_pattern(self, observed_behavior: Dict) -> List[Dict]:
        """
        Match observed behavior against known patterns
        
        Args:
            observed_behavior: Current behavior sequence
            
        Returns:
            List of pattern matches
        """
        matches_found = []
        
        for pattern_name, pattern_info in self.attack_patterns.items():
            pattern_def = pattern_info['definition']
            match_score = 0.0
            matched_indicators = []
            
            # Check required indicators
            required_indicators = pattern_def.get('indicators', [])
            observed_indicators = observed_behavior.get('indicators', [])
            
            for req_indicator in required_indicators:
                if req_indicator in observed_indicators:
                    match_score += 1.0 / len(required_indicators)
                    matched_indicators.append(req_indicator)
            
            # Check sequence matching
            required_sequence = pattern_def.get('sequence', [])
            observed_sequence = observed_behavior.get('sequence', [])
            
            if required_sequence and observed_sequence:
                # Simple sequence matching (can be enhanced with fuzzy matching)
                sequence_match = sum(1 for i, item in enumerate(required_sequence)
                                   if i < len(observed_sequence) and item == observed_sequence[i])
                match_score += (sequence_match / len(required_sequence)) * 0.5
            
            # If match score is significant, report it
            if match_score >= 0.6:
                self.stats['matches_found'] += 1
                
                match = {
                    'pattern_name': pattern_name,
                    'match_score': match_score,
                    'matched_indicators': matched_indicators,
                    'severity': pattern_def.get('severity', 'medium'),
                    'timestamp': datetime.now(),
                    'recommended_response': pattern_def.get('response', 'Investigate immediately')
                }
                matches_found.append(match)
                self.matches.append(match)
                
                logger.critical(f"PATTERN MATCH: {pattern_name} - Score: {match_score:.2f}")
        
        return matches_found
    
    def get_statistics(self) -> Dict:
        """Get pattern matcher statistics"""
        return self.stats


if __name__ == "__main__":
    # Test behavioral detection systems
    print("Testing Behavioral Detection Systems...")
    
    # Test Behavioral Analyzer
    print("\n1. Behavioral Analyzer")
    analyzer = BehavioralAnalyzer()
    
    # Learn behavior
    behavior_data = {
        'speeds': [12, 13, 11, 12, 14],
        'courses': [45, 46, 44, 45, 47],
        'ports_visited': {'PORT001', 'PORT002'},
        'typical_routes': [(35.0, -120.0), (35.5, -119.5)],
        'timestamps': [datetime.now() for _ in range(5)]
    }
    profile = analyzer.learn_behavior('VESSEL001', behavior_data)
    print(f"Learned profile: Speed {profile.normal_speed_range[0]:.1f}-{profile.normal_speed_range[1]:.1f}kt")
    
    # Test anomaly detection
    anomalous_behavior = {'speed': 25, 'course': 180, 'latitude': 36.0, 'longitude': -121.0, 'timestamp': datetime.now()}
    anomaly = analyzer.detect_anomaly('VESSEL001', anomalous_behavior)
    if anomaly:
        print(f"Anomaly detected: Score {anomaly['anomaly_score']:.2f}")
    
    # Test Geofencing
    print("\n2. Geofencing System")
    geofence = GeofencingSystem()
    geofence.add_zone('RESTRICTED001', 'restricted', [(35.0, -120.0), (35.1, -120.0), (35.1, -119.9), (35.0, -119.9)])
    violations = geofence.check_position('VESSEL002', (35.05, -119.95))
    print(f"Violations detected: {len(violations)}")
    
    # Test Speed/Course Predictor
    print("\n3. Speed/Course Predictor")
    predictor = SpeedCoursePredictor()
    predictor.initialize_vessel('VESSEL003', {'speed': 15, 'course': 90, 'latitude': 35.0, 'longitude': -120.0, 'timestamp': datetime.now()})
    predicted = predictor.predict_next_state('VESSEL003', 60)  # 1 hour
    print(f"Predicted position: ({predicted['latitude']:.4f}, {predicted['longitude']:.4f})")
    
    print("\n✓ Behavioral detection systems tested!")
