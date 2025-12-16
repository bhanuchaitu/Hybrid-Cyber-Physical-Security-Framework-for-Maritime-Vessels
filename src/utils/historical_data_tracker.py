"""
Historical Data Tracker for Maritime Threats
Stores and analyzes threat history for replay and analysis
"""
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import csv

logger = logging.getLogger(__name__)


class HistoricalDataTracker:
    """
    Track and analyze historical maritime threat data
    """
    
    def __init__(self, storage_dir: str = "data/maritime_history"):
        """
        Initialize historical data tracker
        
        Args:
            storage_dir: Directory to store historical data
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.current_session = {
            'start_time': None,
            'end_time': None,
            'threats': [],
            'updates': [],
            'vessels': {},
            'statistics': {}
        }
        
        logger.info(f"Historical Data Tracker initialized. Storage: {self.storage_dir}")
    
    def start_session(self):
        """Start a new monitoring session"""
        self.current_session = {
            'start_time': datetime.now(),
            'end_time': None,
            'threats': [],
            'updates': [],
            'vessels': {},
            'statistics': {
                'total_updates': 0,
                'total_threats': 0,
                'total_vessels': 0,
                'attack_types': {}
            }
        }
        logger.info("Started new historical data session")
    
    def end_session(self):
        """End current session and save to disk"""
        if self.current_session['start_time']:
            self.current_session['end_time'] = datetime.now()
            self._save_session()
            logger.info("Ended and saved historical data session")
    
    def record_update(self, update_data: Dict):
        """
        Record a maritime update
        
        Args:
            update_data: Update data from maritime monitor
        """
        if not self.current_session['start_time']:
            self.start_session()
        
        self.current_session['updates'].append({
            'timestamp': datetime.now().isoformat(),
            'update_id': update_data.get('update_id'),
            'vessels': update_data.get('vessels', []),
            'threat_count': len(update_data.get('threats', []))
        })
        
        self.current_session['statistics']['total_updates'] += 1
        
        # Update vessel info
        for vessel in update_data.get('vessels', []):
            vessel_id = vessel['vessel_id']
            if vessel_id not in self.current_session['vessels']:
                self.current_session['vessels'][vessel_id] = {
                    'vessel_name': vessel['vessel_name'],
                    'first_seen': datetime.now().isoformat(),
                    'positions': [],
                    'threat_history': []
                }
            
            self.current_session['vessels'][vessel_id]['positions'].append({
                'timestamp': datetime.now().isoformat(),
                'latitude': vessel['position'][0],
                'longitude': vessel['position'][1],
                'speed': vessel['speed'],
                'course': vessel['course'],
                'threat_level': vessel['threat_level']
            })
    
    def record_threat(self, threat_data: Dict):
        """
        Record a maritime threat
        
        Args:
            threat_data: Threat data from Physics-Informed IDS
        """
        if not self.current_session['start_time']:
            self.start_session()
        
        threat_record = {
            'timestamp': threat_data.get('timestamp', datetime.now()).isoformat(),
            'vessel_id': threat_data.get('vessel_id'),
            'vessel_name': threat_data.get('vessel_name'),
            'mmsi': threat_data.get('mmsi'),
            'threat_level': threat_data.get('threat_level'),
            'anomalies': threat_data.get('anomalies'),
            'detected_attacks': threat_data.get('detected_attacks', []),
            'max_risk_score': threat_data.get('max_risk_score'),
            'recommendation': threat_data.get('recommendation')
        }
        
        self.current_session['threats'].append(threat_record)
        self.current_session['statistics']['total_threats'] += 1
        
        # Track attack types
        for attack in threat_data.get('detected_attacks', []):
            attack_type = attack['attack']
            if attack_type not in self.current_session['statistics']['attack_types']:
                self.current_session['statistics']['attack_types'][attack_type] = 0
            self.current_session['statistics']['attack_types'][attack_type] += 1
        
        # Add to vessel threat history
        vessel_id = threat_data.get('vessel_id')
        if vessel_id in self.current_session['vessels']:
            self.current_session['vessels'][vessel_id]['threat_history'].append({
                'timestamp': threat_record['timestamp'],
                'threat_level': threat_record['threat_level'],
                'attacks': [a['attack'] for a in threat_record['detected_attacks']]
            })
    
    def _save_session(self):
        """Save current session to disk"""
        if not self.current_session['start_time']:
            return
        
        # Generate filename
        start_time = self.current_session['start_time']
        filename = f"session_{start_time.strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.storage_dir / filename
        
        # Convert datetime objects to ISO strings
        session_data = {
            'start_time': self.current_session['start_time'].isoformat(),
            'end_time': self.current_session['end_time'].isoformat() if self.current_session['end_time'] else None,
            'threats': self.current_session['threats'],
            'vessels': self.current_session['vessels'],
            'statistics': self.current_session['statistics'],
            'summary': {
                'duration_seconds': (self.current_session['end_time'] - self.current_session['start_time']).total_seconds() if self.current_session['end_time'] else 0,
                'total_updates': self.current_session['statistics']['total_updates'],
                'total_threats': self.current_session['statistics']['total_threats'],
                'total_vessels': len(self.current_session['vessels']),
                'threat_rate': f"{(self.current_session['statistics']['total_threats'] / max(self.current_session['statistics']['total_updates'], 1) * 100):.1f}%"
            }
        }
        
        # Save to JSON
        with open(filepath, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        logger.info(f"Saved session to {filepath}")
    
    def export_threats_csv(self, output_file: Optional[str] = None) -> str:
        """
        Export threats to CSV file
        
        Args:
            output_file: Output file path (optional)
        
        Returns:
            Path to exported file
        """
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.storage_dir / f"threats_{timestamp}.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Timestamp', 'Vessel ID', 'Vessel Name', 'MMSI', 
                'Threat Level', 'Anomalies', 'Detected Attacks', 
                'Max Risk Score', 'Recommendation'
            ])
            
            for threat in self.current_session['threats']:
                attacks = '; '.join([f"{a['attack']}({a['confidence']:.0%})" 
                                   for a in threat['detected_attacks']])
                
                writer.writerow([
                    threat['timestamp'],
                    threat['vessel_id'],
                    threat['vessel_name'],
                    threat['mmsi'],
                    threat['threat_level'],
                    threat['anomalies'],
                    attacks,
                    threat['max_risk_score'],
                    threat['recommendation']
                ])
        
        logger.info(f"Exported {len(self.current_session['threats'])} threats to {output_file}")
        return str(output_file)
    
    def export_vessel_trajectories_csv(self, output_file: Optional[str] = None) -> str:
        """
        Export vessel trajectories to CSV
        
        Args:
            output_file: Output file path (optional)
        
        Returns:
            Path to exported file
        """
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.storage_dir / f"trajectories_{timestamp}.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Timestamp', 'Vessel ID', 'Vessel Name', 
                'Latitude', 'Longitude', 'Speed', 'Course', 'Threat Level'
            ])
            
            for vessel_id, vessel_data in self.current_session['vessels'].items():
                for position in vessel_data['positions']:
                    writer.writerow([
                        position['timestamp'],
                        vessel_id,
                        vessel_data['vessel_name'],
                        position['latitude'],
                        position['longitude'],
                        position['speed'],
                        position['course'],
                        position['threat_level']
                    ])
        
        logger.info(f"Exported vessel trajectories to {output_file}")
        return str(output_file)
    
    def get_session_summary(self) -> Dict:
        """Get summary of current session"""
        if not self.current_session['start_time']:
            return {'error': 'No active session'}
        
        duration = datetime.now() - self.current_session['start_time']
        
        return {
            'start_time': self.current_session['start_time'].isoformat(),
            'duration_seconds': duration.total_seconds(),
            'total_updates': self.current_session['statistics']['total_updates'],
            'total_threats': self.current_session['statistics']['total_threats'],
            'total_vessels': len(self.current_session['vessels']),
            'attack_types': self.current_session['statistics']['attack_types'],
            'vessels': {
                vid: {
                    'name': vdata['vessel_name'],
                    'first_seen': vdata['first_seen'],
                    'total_positions': len(vdata['positions']),
                    'total_threats': len(vdata['threat_history'])
                }
                for vid, vdata in self.current_session['vessels'].items()
            }
        }
    
    def load_session(self, session_file: str) -> Dict:
        """
        Load a historical session from file
        
        Args:
            session_file: Path to session JSON file
        
        Returns:
            Session data
        """
        filepath = Path(session_file)
        if not filepath.exists():
            filepath = self.storage_dir / session_file
        
        with open(filepath, 'r') as f:
            session_data = json.load(f)
        
        logger.info(f"Loaded session from {filepath}")
        return session_data
    
    def list_sessions(self) -> List[Dict]:
        """
        List all saved sessions
        
        Returns:
            List of session metadata
        """
        sessions = []
        for file in self.storage_dir.glob("session_*.json"):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    sessions.append({
                        'filename': file.name,
                        'start_time': data['start_time'],
                        'end_time': data.get('end_time'),
                        'total_threats': data['statistics']['total_threats'],
                        'total_vessels': len(data['vessels'])
                    })
            except Exception as e:
                logger.error(f"Error reading session file {file}: {e}")
        
        return sorted(sessions, key=lambda x: x['start_time'], reverse=True)


# Test the historical data tracker
if __name__ == "__main__":
    print("Testing Historical Data Tracker...\n")
    
    tracker = HistoricalDataTracker()
    
    # Start session
    tracker.start_session()
    print("✅ Session started")
    
    # Simulate some updates and threats
    for i in range(5):
        tracker.record_update({
            'update_id': i + 1,
            'vessels': [
                {
                    'vessel_id': 'VESSEL_1',
                    'vessel_name': 'Test Vessel',
                    'position': (40.7128 + i * 0.01, -74.0060 + i * 0.01),
                    'speed': 12.0,
                    'course': 90.0,
                    'threat_level': 'normal'
                }
            ]
        })
    
    tracker.record_threat({
        'vessel_id': 'VESSEL_1',
        'vessel_name': 'Test Vessel',
        'mmsi': 367123456,
        'threat_level': 'high',
        'anomalies': 3,
        'detected_attacks': [
            {'attack': 'gps_spoofing', 'confidence': 0.8},
            {'attack': 'nmea_injection', 'confidence': 0.6}
        ],
        'max_risk_score': 0.8,
        'recommendation': 'Switch to manual navigation'
    })
    
    print("✅ Recorded updates and threats")
    
    # Get summary
    summary = tracker.get_session_summary()
    print(f"\n📊 Session Summary:")
    print(f"   Duration: {summary['duration_seconds']:.0f}s")
    print(f"   Updates: {summary['total_updates']}")
    print(f"   Threats: {summary['total_threats']}")
    print(f"   Vessels: {summary['total_vessels']}")
    
    # Export to CSV
    threats_file = tracker.export_threats_csv()
    print(f"\n✅ Exported threats to: {threats_file}")
    
    trajectories_file = tracker.export_vessel_trajectories_csv()
    print(f"✅ Exported trajectories to: {trajectories_file}")
    
    # End and save session
    tracker.end_session()
    print("\n✅ Session ended and saved")
    
    # List sessions
    sessions = tracker.list_sessions()
    print(f"\n📂 Total saved sessions: {len(sessions)}")
    if sessions:
        print(f"   Latest: {sessions[0]['filename']}")
    
    print("\n✅ Historical Data Tracker test complete!")
