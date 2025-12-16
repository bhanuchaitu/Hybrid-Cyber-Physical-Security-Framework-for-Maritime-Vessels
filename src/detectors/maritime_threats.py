"""
Maritime Threat Detection System
Detects physical security threats specific to maritime vessels
"""
import numpy as np
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import deque

logger = logging.getLogger(__name__)


@dataclass
class VesselPosition:
    """Vessel position data"""
    latitude: float
    longitude: float
    speed: float  # knots
    course: float  # degrees
    timestamp: datetime


@dataclass
class CollisionRisk:
    """Collision risk assessment"""
    target_vessel: str
    cpa: float  # Closest Point of Approach (nautical miles)
    tcpa: float  # Time to CPA (minutes)
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    recommended_action: str


class CollisionPredictor:
    """
    Predicts and warns about potential vessel collisions
    Uses CPA (Closest Point of Approach) and TCPA (Time to CPA) calculations
    """
    
    def __init__(self, safe_distance=0.5, warning_distance=1.0):
        """
        Initialize collision predictor
        
        Args:
            safe_distance: Safe distance in nautical miles
            warning_distance: Distance to start warnings in nautical miles
        """
        self.safe_distance = safe_distance
        self.warning_distance = warning_distance
        self.tracked_vessels = {}
        self.collision_warnings = []
    
    def calculate_cpa(self, own_ship: VesselPosition, target_ship: VesselPosition) -> Tuple[float, float]:
        """
        Calculate Closest Point of Approach (CPA) and Time to CPA (TCPA)
        
        Args:
            own_ship: Own vessel position
            target_ship: Target vessel position
            
        Returns:
            Tuple of (CPA in nautical miles, TCPA in minutes)
        """
        # Convert to relative motion
        rel_speed_x = target_ship.speed * np.sin(np.radians(target_ship.course)) - \
                     own_ship.speed * np.sin(np.radians(own_ship.course))
        rel_speed_y = target_ship.speed * np.cos(np.radians(target_ship.course)) - \
                     own_ship.speed * np.cos(np.radians(own_ship.course))
        
        # Calculate relative distance
        dx = (target_ship.longitude - own_ship.longitude) * 60 * np.cos(np.radians(own_ship.latitude))
        dy = (target_ship.latitude - own_ship.latitude) * 60
        
        # Calculate TCPA
        if rel_speed_x**2 + rel_speed_y**2 > 0:
            tcpa = -(dx * rel_speed_x + dy * rel_speed_y) / (rel_speed_x**2 + rel_speed_y**2)
            tcpa = max(0, tcpa * 60)  # Convert to minutes
        else:
            tcpa = float('inf')
        
        # Calculate CPA
        if tcpa < float('inf'):
            cpa_x = dx + rel_speed_x * (tcpa / 60)
            cpa_y = dy + rel_speed_y * (tcpa / 60)
            cpa = np.sqrt(cpa_x**2 + cpa_y**2)
        else:
            cpa = np.sqrt(dx**2 + dy**2)
        
        return cpa, tcpa
    
    def assess_collision_risk(self, own_ship: VesselPosition, target_ship: VesselPosition, 
                            target_id: str) -> Optional[CollisionRisk]:
        """
        Assess collision risk with target vessel
        
        Args:
            own_ship: Own vessel position
            target_ship: Target vessel position
            target_id: Target vessel identifier
            
        Returns:
            CollisionRisk object if risk exists, None otherwise
        """
        cpa, tcpa = self.calculate_cpa(own_ship, target_ship)
        
        # Determine risk level
        if cpa <= self.safe_distance and tcpa <= 20:  # Within 20 minutes
            risk_level = 'critical'
            action = "IMMEDIATE EVASIVE ACTION REQUIRED"
        elif cpa <= self.warning_distance and tcpa <= 30:
            risk_level = 'high'
            action = "Alter course or reduce speed"
        elif cpa <= self.warning_distance and tcpa <= 60:
            risk_level = 'medium'
            action = "Monitor closely and prepare to maneuver"
        elif cpa <= self.warning_distance * 1.5 and tcpa <= 90:
            risk_level = 'low'
            action = "Continue monitoring"
        else:
            return None  # No significant risk
        
        return CollisionRisk(
            target_vessel=target_id,
            cpa=cpa,
            tcpa=tcpa,
            risk_level=risk_level,
            recommended_action=action
        )
    
    def monitor_collisions(self, own_ship: VesselPosition, nearby_vessels: Dict[str, VesselPosition]) -> List[CollisionRisk]:
        """
        Monitor all nearby vessels for collision risks
        
        Args:
            own_ship: Own vessel position
            nearby_vessels: Dictionary of nearby vessels {id: position}
            
        Returns:
            List of collision risks
        """
        risks = []
        
        for vessel_id, vessel_pos in nearby_vessels.items():
            risk = self.assess_collision_risk(own_ship, vessel_pos, vessel_id)
            if risk:
                risks.append(risk)
                if risk.risk_level in ['critical', 'high']:
                    logger.warning(f"COLLISION RISK with {vessel_id}: CPA={risk.cpa:.2f}nm, TCPA={risk.tcpa:.1f}min")
        
        return sorted(risks, key=lambda x: x.cpa)


class PortSecurityMonitor:
    """
    Monitors port security and detects breaches
    Tracks vessel movements in restricted zones
    """
    
    def __init__(self):
        """Initialize port security monitor"""
        self.restricted_zones = []
        self.authorized_vessels = set()
        self.breach_log = []
    
    def add_restricted_zone(self, zone_name: str, lat_bounds: Tuple[float, float], 
                          lon_bounds: Tuple[float, float]):
        """
        Add a restricted security zone
        
        Args:
            zone_name: Name of the zone
            lat_bounds: (min_lat, max_lat)
            lon_bounds: (min_lon, max_lon)
        """
        self.restricted_zones.append({
            'name': zone_name,
            'lat_min': lat_bounds[0],
            'lat_max': lat_bounds[1],
            'lon_min': lon_bounds[0],
            'lon_max': lon_bounds[1]
        })
        logger.info(f"Added restricted zone: {zone_name}")
    
    def is_in_restricted_zone(self, position: VesselPosition) -> Optional[str]:
        """
        Check if position is in any restricted zone
        
        Args:
            position: Vessel position
            
        Returns:
            Zone name if in restricted zone, None otherwise
        """
        for zone in self.restricted_zones:
            if (zone['lat_min'] <= position.latitude <= zone['lat_max'] and
                zone['lon_min'] <= position.longitude <= zone['lon_max']):
                return zone['name']
        return None
    
    def monitor_access(self, vessel_id: str, position: VesselPosition) -> Optional[Dict]:
        """
        Monitor vessel access to restricted areas
        
        Args:
            vessel_id: Vessel identifier
            position: Current vessel position
            
        Returns:
            Breach information if unauthorized access detected
        """
        zone = self.is_in_restricted_zone(position)
        
        if zone and vessel_id not in self.authorized_vessels:
            breach = {
                'vessel_id': vessel_id,
                'zone': zone,
                'position': (position.latitude, position.longitude),
                'timestamp': position.timestamp,
                'severity': 'high'
            }
            self.breach_log.append(breach)
            logger.critical(f"SECURITY BREACH: Unauthorized vessel {vessel_id} in {zone}")
            return breach
        
        return None


class CargoTheftDetector:
    """
    Detects cargo theft and tampering
    Monitors cargo weight, container seals, and route deviations
    """
    
    def __init__(self):
        """Initialize cargo theft detector"""
        self.cargo_manifest = {}
        self.alerts = []
        self.weight_tolerance = 0.05  # 5% tolerance
    
    def register_cargo(self, container_id: str, expected_weight: float, seal_id: str):
        """
        Register cargo container
        
        Args:
            container_id: Container identifier
            expected_weight: Expected weight in tons
            seal_id: Container seal ID
        """
        self.cargo_manifest[container_id] = {
            'expected_weight': expected_weight,
            'seal_id': seal_id,
            'last_check': datetime.now()
        }
    
    def check_weight_anomaly(self, container_id: str, current_weight: float) -> Optional[Dict]:
        """
        Check for cargo weight anomalies
        
        Args:
            container_id: Container identifier
            current_weight: Current weight in tons
            
        Returns:
            Alert if anomaly detected
        """
        if container_id not in self.cargo_manifest:
            return None
        
        expected = self.cargo_manifest[container_id]['expected_weight']
        deviation = abs(current_weight - expected) / expected
        
        if deviation > self.weight_tolerance:
            alert = {
                'container_id': container_id,
                'type': 'weight_anomaly',
                'expected_weight': expected,
                'current_weight': current_weight,
                'deviation': deviation * 100,
                'timestamp': datetime.now(),
                'severity': 'high' if deviation > 0.1 else 'medium'
            }
            self.alerts.append(alert)
            logger.warning(f"CARGO THEFT ALERT: Container {container_id} weight deviation: {deviation*100:.1f}%")
            return alert
        
        return None
    
    def check_seal_integrity(self, container_id: str, seal_id: str) -> Optional[Dict]:
        """
        Check container seal integrity
        
        Args:
            container_id: Container identifier
            seal_id: Current seal ID
            
        Returns:
            Alert if seal tampered
        """
        if container_id not in self.cargo_manifest:
            return None
        
        expected_seal = self.cargo_manifest[container_id]['seal_id']
        
        if seal_id != expected_seal:
            alert = {
                'container_id': container_id,
                'type': 'seal_tampering',
                'expected_seal': expected_seal,
                'current_seal': seal_id,
                'timestamp': datetime.now(),
                'severity': 'critical'
            }
            self.alerts.append(alert)
            logger.critical(f"CARGO TAMPERING: Container {container_id} seal mismatch!")
            return alert
        
        return None


class BoardingAlertSystem:
    """
    Detects unauthorized boarding attempts
    Monitors perimeter sensors and crew verification
    """
    
    def __init__(self):
        """Initialize boarding alert system"""
        self.authorized_crew = set()
        self.perimeter_sensors = {}
        self.boarding_alerts = []
    
    def register_crew(self, crew_id: str, access_level: str):
        """
        Register authorized crew member
        
        Args:
            crew_id: Crew member identifier
            access_level: Access level (captain, officer, crew)
        """
        self.authorized_crew.add(crew_id)
        logger.info(f"Registered crew member: {crew_id} ({access_level})")
    
    def check_perimeter_breach(self, sensor_id: str, triggered: bool) -> Optional[Dict]:
        """
        Check perimeter sensor for breach
        
        Args:
            sensor_id: Sensor identifier
            triggered: Whether sensor is triggered
            
        Returns:
            Alert if breach detected
        """
        if triggered:
            alert = {
                'sensor_id': sensor_id,
                'type': 'perimeter_breach',
                'timestamp': datetime.now(),
                'severity': 'critical',
                'recommended_action': 'Security team to investigate immediately'
            }
            self.boarding_alerts.append(alert)
            logger.critical(f"PERIMETER BREACH: Sensor {sensor_id} triggered!")
            return alert
        
        return None
    
    def verify_access(self, person_id: str, access_point: str) -> bool:
        """
        Verify person authorization
        
        Args:
            person_id: Person identifier
            access_point: Access point location
            
        Returns:
            True if authorized, False otherwise
        """
        if person_id not in self.authorized_crew:
            alert = {
                'person_id': person_id,
                'type': 'unauthorized_access',
                'access_point': access_point,
                'timestamp': datetime.now(),
                'severity': 'high'
            }
            self.boarding_alerts.append(alert)
            logger.warning(f"UNAUTHORIZED ACCESS: {person_id} at {access_point}")
            return False
        
        return True


class EngineTamperingDetector:
    """
    Detects engine and machinery tampering
    Monitors RPM, fuel consumption, and system logs
    """
    
    def __init__(self):
        """Initialize engine tampering detector"""
        self.baseline_rpm = None
        self.baseline_fuel_rate = None
        self.engine_history = deque(maxlen=100)
        self.tampering_alerts = []
    
    def set_baseline(self, rpm: float, fuel_rate: float):
        """
        Set baseline engine parameters
        
        Args:
            rpm: Normal RPM
            fuel_rate: Normal fuel consumption rate (L/hour)
        """
        self.baseline_rpm = rpm
        self.baseline_fuel_rate = fuel_rate
        logger.info(f"Engine baseline set: {rpm} RPM, {fuel_rate} L/h")
    
    def detect_anomaly(self, current_rpm: float, current_fuel_rate: float) -> Optional[Dict]:
        """
        Detect engine anomalies
        
        Args:
            current_rpm: Current RPM
            current_fuel_rate: Current fuel rate (L/hour)
            
        Returns:
            Alert if tampering suspected
        """
        if self.baseline_rpm is None:
            return None
        
        rpm_deviation = abs(current_rpm - self.baseline_rpm) / self.baseline_rpm
        fuel_deviation = abs(current_fuel_rate - self.baseline_fuel_rate) / self.baseline_fuel_rate
        
        alert = None
        
        if rpm_deviation > 0.2:  # 20% deviation
            alert = {
                'type': 'rpm_anomaly',
                'current_rpm': current_rpm,
                'baseline_rpm': self.baseline_rpm,
                'deviation': rpm_deviation * 100,
                'timestamp': datetime.now(),
                'severity': 'high'
            }
        elif fuel_deviation > 0.3:  # 30% deviation
            alert = {
                'type': 'fuel_anomaly',
                'current_fuel_rate': current_fuel_rate,
                'baseline_fuel_rate': self.baseline_fuel_rate,
                'deviation': fuel_deviation * 100,
                'timestamp': datetime.now(),
                'severity': 'medium'
            }
        
        if alert:
            self.tampering_alerts.append(alert)
            logger.warning(f"ENGINE TAMPERING: {alert['type']} - {alert['deviation']:.1f}% deviation")
            return alert
        
        return None


class WeatherThreatAssessor:
    """
    Assesses weather threats to vessel safety
    Correlates weather data with vessel position
    """
    
    def __init__(self):
        """Initialize weather threat assessor"""
        self.weather_warnings = []
        self.safe_harbors = {}
    
    def assess_storm_threat(self, vessel_pos: VesselPosition, storm_data: Dict) -> Optional[Dict]:
        """
        Assess storm threat to vessel
        
        Args:
            vessel_pos: Current vessel position
            storm_data: Storm information (center, radius, wind_speed, direction)
            
        Returns:
            Threat assessment
        """
        # Calculate distance to storm center
        storm_lat = storm_data.get('center_lat')
        storm_lon = storm_data.get('center_lon')
        
        if storm_lat is None or storm_lon is None:
            return None
        
        # Simple distance calculation (nautical miles)
        dx = (storm_lon - vessel_pos.longitude) * 60 * np.cos(np.radians(vessel_pos.latitude))
        dy = (storm_lat - vessel_pos.latitude) * 60
        distance = np.sqrt(dx**2 + dy**2)
        
        storm_radius = storm_data.get('radius', 50)  # Default 50nm
        wind_speed = storm_data.get('wind_speed', 0)  # knots
        
        threat_level = 'none'
        if distance < storm_radius:
            if wind_speed > 64:
                threat_level = 'critical'
            elif wind_speed > 48:
                threat_level = 'high'
            else:
                threat_level = 'medium'
        elif distance < storm_radius * 1.5:
            threat_level = 'low'
        
        if threat_level != 'none':
            assessment = {
                'threat_type': 'storm',
                'distance': distance,
                'wind_speed': wind_speed,
                'threat_level': threat_level,
                'recommended_action': self._get_storm_recommendation(threat_level, distance),
                'timestamp': datetime.now()
            }
            self.weather_warnings.append(assessment)
            logger.warning(f"WEATHER THREAT: Storm {distance:.1f}nm away, {wind_speed}kt winds - {threat_level}")
            return assessment
        
        return None
    
    def _get_storm_recommendation(self, threat_level: str, distance: float) -> str:
        """Get recommendation based on threat level"""
        if threat_level == 'critical':
            return "IMMEDIATE: Seek safe harbor or alter course significantly"
        elif threat_level == 'high':
            return "Alter course to avoid storm center"
        elif threat_level == 'medium':
            return "Monitor storm movement and prepare for rough seas"
        else:
            return "Continue monitoring weather"


if __name__ == "__main__":
    # Test maritime threat detection
    print("Testing Maritime Threat Detection...")
    
    # Test Collision Predictor
    print("\n1. Collision Prediction")
    predictor = CollisionPredictor()
    own_vessel = VesselPosition(35.0, -120.0, 15.0, 45.0, datetime.now())
    target_vessel = VesselPosition(35.1, -119.9, 12.0, 225.0, datetime.now())
    
    risk = predictor.assess_collision_risk(own_vessel, target_vessel, "TARGET001")
    if risk:
        print(f"Collision Risk: {risk.risk_level}, CPA: {risk.cpa:.2f}nm, TCPA: {risk.tcpa:.1f}min")
    
    # Test Port Security
    print("\n2. Port Security Monitor")
    port_monitor = PortSecurityMonitor()
    port_monitor.add_restricted_zone("Military Zone", (35.0, 35.2), (-120.5, -120.0))
    
    breach = port_monitor.monitor_access("UNKNOWN001", own_vessel)
    if breach:
        print(f"Security breach detected in {breach['zone']}")
    
    print("\n✓ Maritime threat detection system tested!")
