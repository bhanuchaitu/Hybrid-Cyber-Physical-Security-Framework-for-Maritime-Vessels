"""
Alert Management System
Handles alert lifecycle, acknowledgment, and escalation
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class AlertManager:
    """Manage alert lifecycle and acknowledgment"""
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize alert manager
        
        Args:
            storage_path: Path to store alert data
        """
        self.storage_path = Path(storage_path) if storage_path else Path('data/alerts')
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.alerts = {}  # Active alerts by ID
        self.acknowledged_alerts = {}  # Acknowledged alerts
        self.resolved_alerts = {}  # Resolved alerts
        
        self.alert_rules = self._load_default_rules()
        self.subscribers = defaultdict(list)  # Alert subscribers by severity
        
        # Load existing alerts
        self._load_alerts()
    
    def _load_default_rules(self) -> Dict:
        """Load default alert rules and thresholds"""
        return {
            'thresholds': {
                'dos_connection_count': 500,
                'probe_host_count': 200,
                'attack_rate_percent': 10.0,
                'alerts_per_minute': 5
            },
            'auto_resolve': {
                'normal_traffic_duration_minutes': 30,
                'no_attacks_duration_minutes': 15
            },
            'escalation': {
                'CRITICAL': {
                    'escalate_after_minutes': 5,
                    'escalate_to': ['admin', 'security_team']
                },
                'HIGH': {
                    'escalate_after_minutes': 15,
                    'escalate_to': ['security_team']
                },
                'MEDIUM': {
                    'escalate_after_minutes': 60,
                    'escalate_to': []
                }
            }
        }
    
    def create_alert(self, alert_data: Dict) -> str:
        """
        Create new alert
        
        Args:
            alert_data: Alert information dictionary
            
        Returns:
            Alert ID
        """
        alert_id = alert_data.get('id', f"ALERT_{len(self.alerts) + 1}_{datetime.now().strftime('%Y%m%d%H%M%S')}")
        
        alert = {
            'id': alert_id,
            'created_at': datetime.now().isoformat(),
            'status': 'active',
            'acknowledged': False,
            'acknowledged_by': None,
            'acknowledged_at': None,
            'resolved': False,
            'resolved_by': None,
            'resolved_at': None,
            'escalated': False,
            'escalated_at': None,
            'notes': [],
            **alert_data
        }
        
        self.alerts[alert_id] = alert
        self._save_alert(alert)
        
        logger.info(f"Alert created: {alert_id} - {alert.get('type')} ({alert.get('severity')})")
        return alert_id
    
    def acknowledge_alert(self, alert_id: str, user: str, notes: Optional[str] = None) -> bool:
        """
        Acknowledge an alert
        
        Args:
            alert_id: Alert ID
            user: Username acknowledging the alert
            notes: Optional acknowledgment notes
            
        Returns:
            True if acknowledged, False if not found
        """
        if alert_id not in self.alerts:
            logger.warning(f"Alert {alert_id} not found")
            return False
        
        alert = self.alerts[alert_id]
        
        if alert['acknowledged']:
            logger.info(f"Alert {alert_id} already acknowledged")
            return True
        
        alert['acknowledged'] = True
        alert['acknowledged_by'] = user
        alert['acknowledged_at'] = datetime.now().isoformat()
        alert['status'] = 'acknowledged'
        
        if notes:
            alert['notes'].append({
                'timestamp': datetime.now().isoformat(),
                'user': user,
                'type': 'acknowledgment',
                'text': notes
            })
        
        self.acknowledged_alerts[alert_id] = alert
        self._save_alert(alert)
        
        logger.info(f"Alert {alert_id} acknowledged by {user}")
        return True
    
    def resolve_alert(self, alert_id: str, user: str, resolution_notes: str) -> bool:
        """
        Resolve an alert
        
        Args:
            alert_id: Alert ID
            user: Username resolving the alert
            resolution_notes: Resolution notes
            
        Returns:
            True if resolved, False if not found
        """
        if alert_id not in self.alerts and alert_id not in self.acknowledged_alerts:
            logger.warning(f"Alert {alert_id} not found")
            return False
        
        alert = self.alerts.get(alert_id) or self.acknowledged_alerts.get(alert_id)
        
        if alert['resolved']:
            logger.info(f"Alert {alert_id} already resolved")
            return True
        
        alert['resolved'] = True
        alert['resolved_by'] = user
        alert['resolved_at'] = datetime.now().isoformat()
        alert['status'] = 'resolved'
        
        alert['notes'].append({
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'type': 'resolution',
            'text': resolution_notes
        })
        
        # Move to resolved alerts
        self.resolved_alerts[alert_id] = alert
        if alert_id in self.alerts:
            del self.alerts[alert_id]
        if alert_id in self.acknowledged_alerts:
            del self.acknowledged_alerts[alert_id]
        
        self._save_alert(alert)
        
        logger.info(f"Alert {alert_id} resolved by {user}")
        return True
    
    def add_note(self, alert_id: str, user: str, note: str) -> bool:
        """
        Add note to alert
        
        Args:
            alert_id: Alert ID
            user: Username adding the note
            note: Note text
            
        Returns:
            True if added, False if alert not found
        """
        alert = self._get_alert(alert_id)
        
        if not alert:
            return False
        
        alert['notes'].append({
            'timestamp': datetime.now().isoformat(),
            'user': user,
            'type': 'note',
            'text': note
        })
        
        self._save_alert(alert)
        logger.info(f"Note added to alert {alert_id} by {user}")
        return True
    
    def check_escalation(self) -> List[Dict]:
        """
        Check for alerts that need escalation
        
        Returns:
            List of alerts that should be escalated
        """
        escalations = []
        
        for alert_id, alert in self.alerts.items():
            if alert['escalated'] or alert['acknowledged']:
                continue
            
            severity = alert.get('severity', 'INFO')
            escalation_rules = self.alert_rules['escalation'].get(severity, {})
            
            if not escalation_rules:
                continue
            
            escalate_after_minutes = escalation_rules.get('escalate_after_minutes', 0)
            
            if escalate_after_minutes > 0:
                created_at = datetime.fromisoformat(alert['created_at'])
                elapsed = (datetime.now() - created_at).total_seconds() / 60
                
                if elapsed >= escalate_after_minutes:
                    alert['escalated'] = True
                    alert['escalated_at'] = datetime.now().isoformat()
                    self._save_alert(alert)
                    
                    escalations.append({
                        'alert': alert,
                        'escalate_to': escalation_rules.get('escalate_to', [])
                    })
                    
                    logger.warning(f"Alert {alert_id} escalated after {elapsed:.1f} minutes")
        
        return escalations
    
    def get_alert(self, alert_id: str) -> Optional[Dict]:
        """Get alert by ID"""
        return self._get_alert(alert_id)
    
    def get_active_alerts(self, severity: Optional[str] = None) -> List[Dict]:
        """Get all active alerts, optionally filtered by severity"""
        alerts = list(self.alerts.values())
        
        if severity:
            alerts = [a for a in alerts if a.get('severity') == severity]
        
        return sorted(alerts, key=lambda x: x['created_at'], reverse=True)
    
    def get_acknowledged_alerts(self) -> List[Dict]:
        """Get all acknowledged alerts"""
        return sorted(self.acknowledged_alerts.values(), key=lambda x: x['acknowledged_at'], reverse=True)
    
    def get_resolved_alerts(self, days: int = 7) -> List[Dict]:
        """Get resolved alerts from last N days"""
        cutoff = datetime.now() - timedelta(days=days)
        
        alerts = [
            a for a in self.resolved_alerts.values()
            if datetime.fromisoformat(a['resolved_at']) > cutoff
        ]
        
        return sorted(alerts, key=lambda x: x['resolved_at'], reverse=True)
    
    def get_statistics(self) -> Dict:
        """Get alert statistics"""
        stats = {
            'active': len(self.alerts),
            'acknowledged': len(self.acknowledged_alerts),
            'resolved': len(self.resolved_alerts),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'average_resolution_time_minutes': 0
        }
        
        # Count by severity and type
        for alert in list(self.alerts.values()) + list(self.acknowledged_alerts.values()):
            stats['by_severity'][alert.get('severity', 'INFO')] += 1
            stats['by_type'][alert.get('type', 'Unknown')] += 1
        
        # Calculate average resolution time
        resolution_times = []
        for alert in self.resolved_alerts.values():
            created = datetime.fromisoformat(alert['created_at'])
            resolved = datetime.fromisoformat(alert['resolved_at'])
            resolution_times.append((resolved - created).total_seconds() / 60)
        
        if resolution_times:
            stats['average_resolution_time_minutes'] = sum(resolution_times) / len(resolution_times)
        
        return stats
    
    def subscribe(self, severity: str, callback):
        """Subscribe to alerts of specific severity"""
        self.subscribers[severity].append(callback)
        logger.info(f"Subscriber added for {severity} alerts")
    
    def _get_alert(self, alert_id: str) -> Optional[Dict]:
        """Get alert from any storage"""
        return (
            self.alerts.get(alert_id) or
            self.acknowledged_alerts.get(alert_id) or
            self.resolved_alerts.get(alert_id)
        )
    
    def _save_alert(self, alert: Dict):
        """Save alert to file"""
        try:
            alert_file = self.storage_path / f"{alert['id']}.json"
            with open(alert_file, 'w') as f:
                json.dump(alert, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")
    
    def _load_alerts(self):
        """Load alerts from storage"""
        try:
            for alert_file in self.storage_path.glob('*.json'):
                with open(alert_file, 'r') as f:
                    alert = json.load(f)
                    
                    if alert['resolved']:
                        self.resolved_alerts[alert['id']] = alert
                    elif alert['acknowledged']:
                        self.acknowledged_alerts[alert['id']] = alert
                    else:
                        self.alerts[alert['id']] = alert
            
            logger.info(f"Loaded {len(self.alerts)} active, {len(self.acknowledged_alerts)} acknowledged, {len(self.resolved_alerts)} resolved alerts")
        except Exception as e:
            logger.error(f"Failed to load alerts: {e}")


# Test the alert manager
if __name__ == "__main__":
    print("Testing Alert Manager...")
    
    manager = AlertManager()
    
    # Create test alert
    alert_id = manager.create_alert({
        'type': 'Dos',
        'severity': 'HIGH',
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'message': 'DoS attack detected'
    })
    
    print(f"\n1. Created alert: {alert_id}")
    
    # Add note
    manager.add_note(alert_id, 'admin', 'Investigating the source')
    print("2. Added note")
    
    # Acknowledge
    manager.acknowledge_alert(alert_id, 'admin', 'Acknowledged and blocking source IP')
    print("3. Acknowledged alert")
    
    # Resolve
    manager.resolve_alert(alert_id, 'admin', 'Source IP blocked, attack stopped')
    print("4. Resolved alert")
    
    # Statistics
    stats = manager.get_statistics()
    print(f"\n5. Statistics: {json.dumps(stats, indent=2)}")
    
    print("\n✅ Test complete!")
