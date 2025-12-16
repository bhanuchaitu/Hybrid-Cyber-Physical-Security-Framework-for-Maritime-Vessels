"""
Maritime Traffic Simulator
Generates realistic maritime data for testing GPS, AIS, and NMEA detectors
"""
import random
import math
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from collections import deque

logger = logging.getLogger(__name__)


class MaritimeTrafficSimulator:
    """
    Simulates realistic maritime traffic including:
    - GPS position updates
    - AIS messages
    - NMEA sentences
    - Both normal and attack scenarios
    """
    
    # Common maritime routes (start point, direction, length in degrees)
    ROUTES = {
        'transatlantic': {'start': (40.7128, -74.0060), 'direction': 90, 'length': 50},  # NYC to Europe
        'pacific': {'start': (34.0522, -118.2437), 'direction': 270, 'length': 60},  # LA to Asia
        'coastal': {'start': (25.7617, -80.1918), 'direction': 45, 'length': 10},  # Miami coastal
        'mediterranean': {'start': (36.8969, 30.7133), 'direction': 270, 'length': 15}  # Turkey to Greece
    }
    
    VESSEL_TYPES = ['cargo', 'tanker', 'passenger', 'fishing', 'tug']
    VESSEL_NAMES = [
        'SS Maritime', 'Ocean Voyager', 'Neptune Star', 'Sea Princess',
        'Atlantic Glory', 'Pacific Wave', 'Harbor Master', 'Coastal Runner'
    ]
    
    def __init__(self):
        """Initialize maritime traffic simulator"""
        self.vessels = {}  # vessel_id -> vessel_state
        self.attack_probability = 0.05  # 5% chance of attack per update
        
        logger.info("Maritime Traffic Simulator initialized")
    
    def create_vessel(self, vessel_id: Optional[str] = None) -> Dict:
        """
        Create a new vessel with realistic attributes
        
        Returns:
            Vessel state dictionary
        """
        if not vessel_id:
            vessel_id = f"VESSEL_{len(self.vessels) + 1}"
        
        # Select random route
        route_name = random.choice(list(self.ROUTES.keys()))
        route = self.ROUTES[route_name]
        
        # Generate MMSI (9 digits, valid format)
        # MID (Maritime Identification Digit) for USA: 338, 366, 367, 368, 369
        mid = random.choice([338, 366, 367, 368, 369])
        mmsi = int(f"{mid}{random.randint(100000, 999999)}")
        
        # Select vessel type and corresponding speed
        vessel_type = random.choice(self.VESSEL_TYPES)
        
        # Speed ranges by vessel type
        speed_ranges = {
            'cargo': (10, 20),
            'tanker': (8, 15),
            'passenger': (20, 30),
            'fishing': (5, 12),
            'tug': (6, 14)
        }
        base_speed = random.uniform(*speed_ranges[vessel_type])
        
        vessel = {
            'id': vessel_id,
            'mmsi': mmsi,
            'name': random.choice(self.VESSEL_NAMES),
            'type': vessel_type,
            'route': route_name,
            'latitude': route['start'][0],
            'longitude': route['start'][1],
            'speed': base_speed,
            'course': route['direction'],
            'heading': route['direction'] + random.uniform(-5, 5),  # Slight drift
            'last_update': datetime.now(),
            'is_under_attack': False,
            'attack_type': None
        }
        
        self.vessels[vessel_id] = vessel
        logger.info(f"Created vessel {vessel_id}: {vessel['name']} (MMSI: {mmsi}, Type: {vessel_type})")
        
        return vessel
    
    def update_vessel_position(self, vessel_id: str, time_delta_sec: float = 60) -> Dict:
        """
        Update vessel position based on speed and course
        
        Args:
            vessel_id: Vessel identifier
            time_delta_sec: Time elapsed since last update
        
        Returns:
            Updated vessel state
        """
        if vessel_id not in self.vessels:
            raise ValueError(f"Vessel {vessel_id} not found")
        
        vessel = self.vessels[vessel_id]
        
        # Calculate distance traveled (in nautical miles, then convert to degrees)
        # 1 nautical mile ≈ 1.852 km ≈ 0.016667 degrees latitude
        distance_nm = vessel['speed'] * (time_delta_sec / 3600)  # nm
        distance_deg = distance_nm * 0.016667
        
        # Update position based on course
        course_rad = math.radians(vessel['course'])
        
        # Calculate new position
        lat_change = distance_deg * math.cos(course_rad)
        lon_change = distance_deg * math.sin(course_rad) / math.cos(math.radians(vessel['latitude']))
        
        vessel['latitude'] += lat_change
        vessel['longitude'] += lon_change
        
        # Add some realistic variation
        vessel['course'] += random.uniform(-2, 2)  # Course drift
        vessel['course'] = vessel['course'] % 360
        
        vessel['speed'] += random.uniform(-0.5, 0.5)  # Speed variation
        vessel['speed'] = max(0, vessel['speed'])  # Can't go negative
        
        vessel['heading'] = vessel['course'] + random.uniform(-5, 5)  # Heading drift
        vessel['heading'] = vessel['heading'] % 360
        
        vessel['last_update'] = datetime.now()
        
        return vessel
    
    def generate_gps_data(self, vessel_id: str, include_attack: bool = False) -> Dict:
        """
        Generate GPS data for a vessel
        
        Args:
            vessel_id: Vessel identifier
            include_attack: Whether to inject GPS spoofing attack
        
        Returns:
            GPS data dictionary
        """
        vessel = self.vessels[vessel_id]
        
        gps_data = {
            'latitude': vessel['latitude'],
            'longitude': vessel['longitude'],
            'timestamp': datetime.now(),
            'speed_knots': vessel['speed'],
            'course': vessel['course'],
            'vessel_id': vessel_id
        }
        
        # Inject GPS spoofing attack
        if include_attack or (random.random() < self.attack_probability):
            attack_type = random.choice(['position_jump', 'impossible_speed', 'coordinate_drift'])
            
            if attack_type == 'position_jump':
                # Sudden large position jump
                gps_data['latitude'] += random.uniform(0.5, 2.0) * random.choice([-1, 1])
                gps_data['longitude'] += random.uniform(0.5, 2.0) * random.choice([-1, 1])
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'GPS Position Jump'
                
            elif attack_type == 'impossible_speed':
                # Report impossible speed
                gps_data['speed_knots'] = random.uniform(50, 100)
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'GPS Speed Spoofing'
                
            elif attack_type == 'coordinate_drift':
                # Gradual coordinate drift (more subtle)
                gps_data['latitude'] += random.uniform(0.01, 0.05)
                gps_data['longitude'] += random.uniform(0.01, 0.05)
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'GPS Coordinate Drift'
        
        return gps_data
    
    def generate_ais_message(self, vessel_id: str, include_attack: bool = False) -> Dict:
        """
        Generate AIS message for a vessel
        
        Args:
            vessel_id: Vessel identifier
            include_attack: Whether to inject AIS anomaly
        
        Returns:
            AIS message dictionary
        """
        vessel = self.vessels[vessel_id]
        
        ais_message = {
            'mmsi': vessel['mmsi'],
            'name': vessel['name'],
            'latitude': vessel['latitude'],
            'longitude': vessel['longitude'],
            'speed': vessel['speed'],
            'course': vessel['course'],
            'heading': vessel['heading'],
            'vessel_type': vessel['type'],
            'timestamp': datetime.now()
        }
        
        # Inject AIS attack
        if include_attack or (random.random() < self.attack_probability):
            attack_type = random.choice(['mmsi_spoof', 'speed_violation', 'heading_mismatch', 'message_injection'])
            
            if attack_type == 'mmsi_spoof':
                # Use fake/invalid MMSI
                ais_message['mmsi'] = 111111111  # All same digits
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'AIS MMSI Spoofing'
                
            elif attack_type == 'speed_violation':
                # Report impossible speed for vessel type
                ais_message['speed'] = random.uniform(40, 60)
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'AIS Speed Violation'
                
            elif attack_type == 'heading_mismatch':
                # Large mismatch between course and heading
                ais_message['heading'] = (ais_message['course'] + 180) % 360
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'AIS Heading Mismatch'
                
            elif attack_type == 'message_injection':
                # Rapid message injection (simulated by returning same timestamp)
                ais_message['timestamp'] = vessel['last_update']
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'AIS Message Injection'
        
        return ais_message
    
    def generate_nmea_sentence(self, vessel_id: str, sentence_type: str = 'GGA', include_attack: bool = False) -> str:
        """
        Generate NMEA 0183 sentence
        
        Args:
            vessel_id: Vessel identifier
            sentence_type: Type of NMEA sentence (GGA, RMC, HDT, etc.)
            include_attack: Whether to inject NMEA attack
        
        Returns:
            NMEA sentence string
        """
        vessel = self.vessels[vessel_id]
        
        # Convert coordinates to NMEA format (DDMM.MMMM)
        def to_nmea_lat(lat):
            deg = int(abs(lat))
            min = (abs(lat) - deg) * 60
            direction = 'N' if lat >= 0 else 'S'
            return f"{deg:02d}{min:07.4f},{direction}"
        
        def to_nmea_lon(lon):
            deg = int(abs(lon))
            min = (abs(lon) - deg) * 60
            direction = 'E' if lon >= 0 else 'W'
            return f"{deg:03d}{min:07.4f},{direction}"
        
        timestamp = datetime.now()
        time_str = timestamp.strftime("%H%M%S.00")
        date_str = timestamp.strftime("%d%m%y")
        
        if sentence_type == 'GGA':
            # GPS Fix Data
            lat_nmea = to_nmea_lat(vessel['latitude'])
            lon_nmea = to_nmea_lon(vessel['longitude'])
            sentence = f"$GPGGA,{time_str},{lat_nmea},{lon_nmea},1,08,0.9,545.4,M,46.9,M,,*47"
            
        elif sentence_type == 'RMC':
            # Recommended Minimum Navigation Information
            lat_nmea = to_nmea_lat(vessel['latitude'])
            lon_nmea = to_nmea_lon(vessel['longitude'])
            speed_str = f"{vessel['speed']:.1f}"
            course_str = f"{vessel['course']:.1f}"
            sentence = f"$GPRMC,{time_str},A,{lat_nmea},{lon_nmea},{speed_str},{course_str},{date_str},,,A*68"
            
        elif sentence_type == 'HDT':
            # Heading True
            sentence = f"$HEHDT,{vessel['heading']:.1f},T*23"
            
        else:
            sentence = "$GPGGA,000000.00,0000.0000,N,00000.0000,E,0,00,0.0,0.0,M,0.0,M,,*00"
        
        # Inject NMEA attack
        if include_attack or (random.random() < self.attack_probability):
            attack_type = random.choice(['checksum_invalid', 'malformed', 'injection'])
            
            if attack_type == 'checksum_invalid':
                # Corrupt checksum
                sentence = sentence[:-2] + 'XX'
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'NMEA Invalid Checksum'
                
            elif attack_type == 'malformed':
                # Remove critical fields
                parts = sentence.split(',')
                if len(parts) > 3:
                    parts[2] = ''  # Remove latitude
                    sentence = ','.join(parts)
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'NMEA Malformed Sentence'
                
            elif attack_type == 'injection':
                # Inject malicious command (simulate autopilot override)
                sentence = "$HEROT,270.0*00"  # Rate of turn command
                vessel['is_under_attack'] = True
                vessel['attack_type'] = 'NMEA Command Injection'
        
        return sentence
    
    def simulate_scenario(self, duration_min: int = 10, num_vessels: int = 3, attack_rate: float = 0.1) -> List[Dict]:
        """
        Simulate a complete maritime traffic scenario
        
        Args:
            duration_min: Simulation duration in minutes
            num_vessels: Number of vessels to simulate
            attack_rate: Probability of attacks (0-1)
        
        Returns:
            List of all generated data points
        """
        self.attack_probability = attack_rate
        
        # Create vessels
        for i in range(num_vessels):
            self.create_vessel()
        
        all_data = []
        start_time = datetime.now()
        current_time = start_time
        
        logger.info(f"Starting {duration_min}-minute simulation with {num_vessels} vessels")
        
        while (current_time - start_time).total_seconds() < duration_min * 60:
            for vessel_id in list(self.vessels.keys()):
                # Update position
                self.update_vessel_position(vessel_id, time_delta_sec=10)
                
                # Generate data
                gps_data = self.generate_gps_data(vessel_id)
                ais_message = self.generate_ais_message(vessel_id)
                nmea_gga = self.generate_nmea_sentence(vessel_id, 'GGA')
                nmea_rmc = self.generate_nmea_sentence(vessel_id, 'RMC')
                
                data_point = {
                    'timestamp': current_time,
                    'vessel_id': vessel_id,
                    'vessel_name': self.vessels[vessel_id]['name'],
                    'gps': gps_data,
                    'ais': ais_message,
                    'nmea_gga': nmea_gga,
                    'nmea_rmc': nmea_rmc,
                    'is_under_attack': self.vessels[vessel_id]['is_under_attack'],
                    'attack_type': self.vessels[vessel_id]['attack_type']
                }
                
                all_data.append(data_point)
                
                # Reset attack flag
                self.vessels[vessel_id]['is_under_attack'] = False
                self.vessels[vessel_id]['attack_type'] = None
            
            current_time += timedelta(seconds=10)
        
        logger.info(f"Simulation complete. Generated {len(all_data)} data points")
        return all_data
    
    def get_statistics(self) -> Dict:
        """Get simulator statistics"""
        total_attacks = sum(1 for v in self.vessels.values() if v.get('is_under_attack', False))
        
        return {
            'total_vessels': len(self.vessels),
            'active_attacks': total_attacks,
            'vessel_list': [
                {
                    'id': v['id'],
                    'name': v['name'],
                    'mmsi': v['mmsi'],
                    'type': v['type'],
                    'position': (f"{v['latitude']:.4f}", f"{v['longitude']:.4f}"),
                    'speed': f"{v['speed']:.1f} knots"
                }
                for v in self.vessels.values()
            ]
        }


# Test the simulator
if __name__ == "__main__":
    print("Testing Maritime Traffic Simulator...")
    
    simulator = MaritimeTrafficSimulator()
    
    # Test 1: Create vessels
    print("\n1. Creating vessels:")
    for i in range(3):
        vessel = simulator.create_vessel()
        print(f"  {vessel['name']} (MMSI: {vessel['mmsi']}, Type: {vessel['type']})")
    
    # Test 2: Generate normal data
    print("\n2. Normal GPS data:")
    vessel_id = list(simulator.vessels.keys())[0]
    for i in range(3):
        simulator.update_vessel_position(vessel_id, 60)
        gps = simulator.generate_gps_data(vessel_id)
        print(f"  Position: ({gps['latitude']:.4f}, {gps['longitude']:.4f}), Speed: {gps['speed_knots']:.1f} knots")
    
    # Test 3: Generate attack data
    print("\n3. GPS attack data:")
    for i in range(3):
        gps = simulator.generate_gps_data(vessel_id, include_attack=True)
        vessel = simulator.vessels[vessel_id]
        print(f"  Attack: {vessel['attack_type']}")
        print(f"  Position: ({gps['latitude']:.4f}, {gps['longitude']:.4f}), Speed: {gps['speed_knots']:.1f} knots")
    
    # Test 4: AIS messages
    print("\n4. AIS messages (with attacks):")
    for i in range(3):
        ais = simulator.generate_ais_message(vessel_id, include_attack=True)
        vessel = simulator.vessels[vessel_id]
        print(f"  Attack: {vessel['attack_type']}")
        print(f"  MMSI: {ais['mmsi']}, Speed: {ais['speed']:.1f} knots, Course: {ais['course']:.1f}°")
    
    # Test 5: NMEA sentences
    print("\n5. NMEA sentences (with attacks):")
    for i in range(3):
        nmea = simulator.generate_nmea_sentence(vessel_id, 'GGA', include_attack=True)
        vessel = simulator.vessels[vessel_id]
        print(f"  Attack: {vessel['attack_type']}")
        print(f"  Sentence: {nmea}")
    
    # Test 6: Statistics
    print("\n6. Statistics:")
    stats = simulator.get_statistics()
    print(f"  Total vessels: {stats['total_vessels']}")
    print(f"  Active attacks: {stats['active_attacks']}")
    
    print("\n✅ Maritime Traffic Simulator test complete!")
