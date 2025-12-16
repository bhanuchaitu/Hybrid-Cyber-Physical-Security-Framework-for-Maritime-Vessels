"""
Maritime Real-Time Monitor
Integrates maritime traffic simulator with Physics-Informed IDS for real-time threat detection
"""
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.utils.maritime_traffic_simulator import MaritimeTrafficSimulator
from src.detectors.physics_informed_ids import PhysicsInformedIDS

logger = logging.getLogger(__name__)


class MaritimeRealTimeMonitor:
    """
    Real-time maritime security monitoring system
    
    Continuously generates simulated maritime traffic and analyzes it
    for security threats using the Physics-Informed IDS
    """
    
    def __init__(self, 
                 num_vessels: int = 3,
                 update_interval: int = 10,
                 attack_probability: float = 0.1):
        """
        Initialize maritime real-time monitor
        
        Args:
            num_vessels: Number of vessels to simulate
            update_interval: Seconds between updates
            attack_probability: Probability of attacks (0-1)
        """
        self.simulator = MaritimeTrafficSimulator()
        self.ids = PhysicsInformedIDS()
        
        self.num_vessels = num_vessels
        self.update_interval = update_interval
        self.attack_probability = attack_probability
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Event callbacks
        self.threat_callbacks = []
        self.update_callbacks = []
        
        # Statistics
        self.total_updates = 0
        self.total_threats = 0
        self.start_time = None
        
        logger.info(f"Maritime Real-Time Monitor initialized with {num_vessels} vessels")
    
    def add_threat_callback(self, callback: Callable[[Dict], None]):
        """
        Add callback function to be called when threat is detected
        
        Args:
            callback: Function that takes threat analysis dict
        """
        self.threat_callbacks.append(callback)
    
    def add_update_callback(self, callback: Callable[[Dict], None]):
        """
        Add callback function to be called on each update
        
        Args:
            callback: Function that takes update dict
        """
        self.update_callbacks.append(callback)
    
    def _generate_maritime_data(self, vessel_id: str) -> Dict:
        """
        Generate complete maritime data for a vessel
        
        Args:
            vessel_id: Vessel identifier
        
        Returns:
            Dictionary with GPS, AIS, and NMEA data
        """
        # Update vessel position
        self.simulator.update_vessel_position(vessel_id, self.update_interval)
        
        # Generate data with potential attacks
        gps_data = self.simulator.generate_gps_data(vessel_id)
        ais_data = self.simulator.generate_ais_message(vessel_id)
        nmea_gga = self.simulator.generate_nmea_sentence(vessel_id, 'GGA')
        nmea_rmc = self.simulator.generate_nmea_sentence(vessel_id, 'RMC')
        nmea_hdt = self.simulator.generate_nmea_sentence(vessel_id, 'HDT')
        
        vessel = self.simulator.vessels[vessel_id]
        
        return {
            'vessel_id': vessel_id,
            'vessel_name': vessel['name'],
            'vessel_type': vessel['type'],
            'mmsi': vessel['mmsi'],
            'gps': gps_data,
            'ais': ais_data,
            'nmea': {
                'gga': nmea_gga,
                'rmc': nmea_rmc,
                'hdt': nmea_hdt
            },
            'timestamp': datetime.now(),
            'is_under_attack': vessel.get('is_under_attack', False),
            'attack_type': vessel.get('attack_type')
        }
    
    def _analyze_vessel_data(self, vessel_data: Dict) -> Dict:
        """
        Analyze vessel data through Physics-Informed IDS
        
        Args:
            vessel_data: Complete vessel data dictionary
        
        Returns:
            IDS analysis result
        """
        # Run through 5-layer IDS
        analysis = self.ids.analyze_maritime_event(
            gps_data=vessel_data['gps'],
            ais_data=vessel_data['ais'],
            nmea_sentence=vessel_data['nmea']['gga']  # Use GGA as primary NMEA
        )
        
        # Add vessel context
        analysis['vessel_id'] = vessel_data['vessel_id']
        analysis['vessel_name'] = vessel_data['vessel_name']
        analysis['vessel_type'] = vessel_data['vessel_type']
        analysis['mmsi'] = vessel_data['mmsi']
        analysis['simulated_attack'] = vessel_data['is_under_attack']
        analysis['simulated_attack_type'] = vessel_data['attack_type']
        
        return analysis
    
    def _monitoring_loop(self):
        """Main monitoring loop that runs in separate thread"""
        logger.info("Maritime monitoring started")
        
        # Create vessels
        vessel_ids = []
        for i in range(self.num_vessels):
            vessel = self.simulator.create_vessel()
            vessel_ids.append(vessel['id'])
        
        self.simulator.attack_probability = self.attack_probability
        
        while self.is_monitoring:
            try:
                self.total_updates += 1
                update_data = {
                    'update_id': self.total_updates,
                    'timestamp': datetime.now(),
                    'vessels': [],
                    'threats': []
                }
                
                # Process each vessel
                for vessel_id in vessel_ids:
                    # Generate maritime data
                    vessel_data = self._generate_maritime_data(vessel_id)
                    
                    # Analyze through IDS
                    analysis = self._analyze_vessel_data(vessel_data)
                    
                    # Store analysis
                    update_data['vessels'].append({
                        'vessel_id': vessel_id,
                        'vessel_name': vessel_data['vessel_name'],
                        'position': (vessel_data['gps']['latitude'], 
                                   vessel_data['gps']['longitude']),
                        'speed': vessel_data['gps']['speed_knots'],
                        'course': vessel_data['gps']['course'],
                        'threat_level': analysis['threat_level'],
                        'anomaly_count': analysis['total_anomalies']
                    })
                    
                    # Handle threats
                    if analysis['is_threat']:
                        self.total_threats += 1
                        update_data['threats'].append(analysis)
                        
                        # Trigger threat callbacks
                        for callback in self.threat_callbacks:
                            try:
                                callback(analysis)
                            except Exception as e:
                                logger.error(f"Error in threat callback: {e}")
                
                # Trigger update callbacks
                for callback in self.update_callbacks:
                    try:
                        callback(update_data)
                    except Exception as e:
                        logger.error(f"Error in update callback: {e}")
                
                # Wait for next update
                time.sleep(self.update_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                time.sleep(self.update_interval)
        
        logger.info("Maritime monitoring stopped")
    
    def start_monitoring(self):
        """Start real-time maritime monitoring"""
        if self.is_monitoring:
            logger.warning("Monitoring already running")
            return
        
        self.is_monitoring = True
        self.start_time = datetime.now()
        self.total_updates = 0
        self.total_threats = 0
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Maritime real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time maritime monitoring"""
        if not self.is_monitoring:
            logger.warning("Monitoring not running")
            return
        
        self.is_monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=self.update_interval + 5)
        
        logger.info("Maritime real-time monitoring stopped")
    
    def get_current_status(self) -> Dict:
        """
        Get current monitoring status
        
        Returns:
            Status dictionary
        """
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            'is_monitoring': self.is_monitoring,
            'uptime_seconds': uptime,
            'total_updates': self.total_updates,
            'total_threats': self.total_threats,
            'threat_rate': f"{(self.total_threats / self.total_updates * 100):.1f}%" 
                          if self.total_updates > 0 else "0%",
            'num_vessels': len(self.simulator.vessels),
            'vessel_list': [
                {
                    'id': v['id'],
                    'name': v['name'],
                    'type': v['type'],
                    'mmsi': v['mmsi']
                }
                for v in self.simulator.vessels.values()
            ],
            'ids_stats': self.ids.get_statistics(),
            'current_threat_level': self.ids.vessel_state['threat_level']
        }
    
    def get_vessel_info(self, vessel_id: str) -> Optional[Dict]:
        """
        Get detailed information about a specific vessel
        
        Args:
            vessel_id: Vessel identifier
        
        Returns:
            Vessel information or None
        """
        if vessel_id not in self.simulator.vessels:
            return None
        
        vessel = self.simulator.vessels[vessel_id]
        return {
            'id': vessel['id'],
            'name': vessel['name'],
            'mmsi': vessel['mmsi'],
            'type': vessel['type'],
            'position': {
                'latitude': vessel['latitude'],
                'longitude': vessel['longitude']
            },
            'speed': vessel['speed'],
            'course': vessel['course'],
            'heading': vessel['heading'],
            'last_update': vessel['last_update'],
            'route': vessel['route'],
            'threat_status': {
                'is_under_attack': vessel.get('is_under_attack', False),
                'attack_type': vessel.get('attack_type')
            }
        }


# Test the maritime real-time monitor
if __name__ == "__main__":
    print("Testing Maritime Real-Time Monitor...\n")
    
    # Create monitor
    monitor = MaritimeRealTimeMonitor(
        num_vessels=2,
        update_interval=5,  # 5 seconds for testing
        attack_probability=0.2  # 20% attack probability
    )
    
    # Define callback functions
    threat_count = [0]  # Use list for mutable counter in closure
    
    def on_threat(analysis: Dict):
        """Called when threat is detected"""
        threat_count[0] += 1
        print(f"\n⚠️  THREAT #{threat_count[0]} DETECTED!")
        print(f"   Vessel: {analysis['vessel_name']} (MMSI: {analysis['mmsi']})")
        print(f"   Threat Level: {analysis['threat_level'].upper()}")
        print(f"   Anomalies: {analysis['total_anomalies']}")
        
        if analysis['detected_attacks']:
            attacks = ', '.join(a['attack'].replace('_', ' ').title() 
                              for a in analysis['detected_attacks'])
            print(f"   Detected Attacks: {attacks}")
        
        print(f"   Recommendation: {analysis['recommendation']}")
        
        if analysis['simulated_attack']:
            print(f"   [Simulated Attack: {analysis['simulated_attack_type']}]")
    
    def on_update(update: Dict):
        """Called on each monitoring update"""
        print(f"\n📡 Update #{update['update_id']} - {update['timestamp'].strftime('%H:%M:%S')}")
        for vessel in update['vessels']:
            status = "🔴" if vessel['threat_level'] in ['high', 'critical'] else \
                     "🟡" if vessel['threat_level'] == 'medium' else \
                     "🟢"
            print(f"   {status} {vessel['vessel_name']}: "
                  f"Position ({vessel['position'][0]:.4f}, {vessel['position'][1]:.4f}), "
                  f"Speed {vessel['speed']:.1f}kt, "
                  f"Threat: {vessel['threat_level']}")
    
    # Register callbacks
    monitor.add_threat_callback(on_threat)
    monitor.add_update_callback(on_update)
    
    # Start monitoring
    print("Starting maritime monitoring for 30 seconds...\n")
    print("=" * 70)
    
    monitor.start_monitoring()
    
    try:
        # Monitor for 30 seconds
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n\nMonitoring interrupted by user")
    finally:
        # Stop monitoring
        monitor.stop_monitoring()
    
    # Show final statistics
    print("\n" + "=" * 70)
    print("\n📊 Final Statistics:")
    status = monitor.get_current_status()
    print(f"   Monitoring Duration: {status['uptime_seconds']:.0f} seconds")
    print(f"   Total Updates: {status['total_updates']}")
    print(f"   Total Threats: {status['total_threats']}")
    print(f"   Threat Rate: {status['threat_rate']}")
    print(f"   Final Threat Level: {status['current_threat_level'].upper()}")
    
    print("\n   IDS Statistics:")
    ids_stats = status['ids_stats']
    print(f"   - Total Events: {ids_stats['total_events']}")
    print(f"   - Threats Detected: {ids_stats['threats_detected']}")
    print(f"   - Attack Counts: {ids_stats['attack_counts']}")
    
    print("\n✅ Maritime Real-Time Monitor test complete!")
