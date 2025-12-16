"""
Advanced Threat Detector - MITM, Ransomware, APT, Zero-day Detection
Part of Enhanced Attack Detection Capabilities
"""
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class AdvancedThreatDetector:
    """
    Detects advanced threats including MITM, Ransomware, APT, Zero-day exploits
    """
    
    def __init__(self):
        """Initialize advanced threat detector"""
        self.known_ransomware_signatures = [
            'wannacry', 'cryptolocker', 'locky', 'petya', 'notpetya',
            'ryuk', 'maze', 'revil', 'darkside', 'blackmatter'
        ]
        
        self.ransomware_behaviors = [
            'mass_file_encryption',
            'rapid_file_modification',
            'extension_changes',
            'ransom_note_creation',
            'shadow_copy_deletion'
        ]
        
        self.apt_indicators = {
            'persistence_mechanisms': ['registry_modification', 'scheduled_task', 'service_creation'],
            'lateral_movement': ['psexec', 'wmic', 'rdp_brute_force'],
            'credential_theft': ['mimikatz', 'hashdump', 'keylogger'],
            'data_exfiltration': ['large_upload', 'dns_tunneling', 'encrypted_channel']
        }
        
        self.connection_history = defaultdict(list)
        self.threat_scores = defaultdict(float)
        self.attack_statistics = {
            'mitm': 0,
            'ransomware': 0,
            'apt': 0,
            'zero_day': 0,
            'total_analyzed': 0
        }
    
    def detect_mitm(self, connection_data: Dict) -> Tuple[bool, float, str]:
        """
        Detect Man-in-the-Middle attacks
        
        Args:
            connection_data: Dictionary with connection details
            
        Returns:
            Tuple of (is_attack, confidence, details)
        """
        confidence = 0.0
        indicators = []
        
        # Check for SSL certificate anomalies
        if connection_data.get('ssl_cert_mismatch'):
            confidence += 0.4
            indicators.append("SSL certificate mismatch")
        
        # Check for ARP spoofing indicators
        if connection_data.get('arp_conflict'):
            confidence += 0.3
            indicators.append("ARP conflict detected")
        
        # Check for unexpected DNS responses
        if connection_data.get('dns_response_mismatch'):
            confidence += 0.3
            indicators.append("DNS response anomaly")
        
        # Check for traffic pattern anomalies
        src_ip = connection_data.get('source_ip', '')
        dst_ip = connection_data.get('dest_ip', '')
        
        if src_ip and dst_ip:
            key = f"{src_ip}_{dst_ip}"
            self.connection_history[key].append(datetime.now())
            
            # Remove old entries (older than 5 minutes)
            cutoff = datetime.now() - timedelta(minutes=5)
            self.connection_history[key] = [
                t for t in self.connection_history[key] if t > cutoff
            ]
            
            # Check for rapid connection pattern changes
            if len(self.connection_history[key]) > 50:
                confidence += 0.2
                indicators.append("Unusual connection frequency")
        
        # Check for protocol downgrade
        if connection_data.get('protocol_downgrade'):
            confidence += 0.3
            indicators.append("Protocol downgrade detected")
        
        if confidence >= 0.5:
            self.attack_statistics['mitm'] += 1
            details = f"MITM attack indicators: {', '.join(indicators)}"
            logger.warning(f"MITM attack detected: {details}")
            return True, min(confidence, 1.0), details
        
        return False, confidence, ""
    
    def detect_ransomware(self, system_behavior: Dict) -> Tuple[bool, float, str]:
        """
        Detect ransomware activity
        
        Args:
            system_behavior: Dictionary with system behavior metrics
            
        Returns:
            Tuple of (is_attack, confidence, details)
        """
        confidence = 0.0
        indicators = []
        
        # Check for known ransomware signatures
        process_names = system_behavior.get('process_names', [])
        for process in process_names:
            for signature in self.known_ransomware_signatures:
                if signature.lower() in process.lower():
                    confidence += 0.5
                    indicators.append(f"Known ransomware signature: {signature}")
        
        # Check for ransomware behaviors
        behaviors = system_behavior.get('behaviors', [])
        
        if 'rapid_file_modifications' in behaviors:
            file_mod_rate = system_behavior.get('file_modification_rate', 0)
            if file_mod_rate > 100:  # More than 100 files/second
                confidence += 0.3
                indicators.append(f"Rapid file modification: {file_mod_rate}/sec")
        
        if 'extension_changes' in behaviors:
            confidence += 0.25
            indicators.append("Mass file extension changes detected")
        
        if 'ransom_note_creation' in behaviors:
            confidence += 0.4
            indicators.append("Ransom note file detected")
        
        if 'shadow_copy_deletion' in behaviors:
            confidence += 0.3
            indicators.append("Shadow copy deletion detected")
        
        if 'encryption_activity' in behaviors:
            confidence += 0.25
            indicators.append("High encryption activity detected")
        
        if confidence >= 0.6:
            self.attack_statistics['ransomware'] += 1
            details = f"Ransomware indicators: {', '.join(indicators)}"
            logger.critical(f"RANSOMWARE DETECTED: {details}")
            return True, min(confidence, 1.0), details
        
        return False, confidence, ""
    
    def detect_apt(self, activity_data: Dict) -> Tuple[bool, float, str]:
        """
        Detect Advanced Persistent Threat (APT) activity
        
        Args:
            activity_data: Dictionary with system activity data
            
        Returns:
            Tuple of (is_attack, confidence, details)
        """
        confidence = 0.0
        indicators = []
        threat_level = 0
        
        # Check for persistence mechanisms
        persistence = activity_data.get('persistence_indicators', [])
        for mechanism in persistence:
            if mechanism in self.apt_indicators['persistence_mechanisms']:
                threat_level += 1
                indicators.append(f"Persistence: {mechanism}")
        
        # Check for lateral movement
        lateral_mov = activity_data.get('lateral_movement', [])
        for technique in lateral_mov:
            if technique in self.apt_indicators['lateral_movement']:
                threat_level += 2
                indicators.append(f"Lateral movement: {technique}")
        
        # Check for credential theft
        cred_theft = activity_data.get('credential_theft', [])
        for tool in cred_theft:
            if tool in self.apt_indicators['credential_theft']:
                threat_level += 2
                indicators.append(f"Credential theft: {tool}")
        
        # Check for data exfiltration
        exfiltration = activity_data.get('exfiltration', [])
        for method in exfiltration:
            if method in self.apt_indicators['data_exfiltration']:
                threat_level += 3
                indicators.append(f"Data exfiltration: {method}")
        
        # Calculate confidence based on threat level
        confidence = min(threat_level * 0.15, 1.0)
        
        # Check for long-term presence
        if activity_data.get('persistence_duration_days', 0) > 30:
            confidence += 0.2
            indicators.append("Long-term persistence detected")
        
        if confidence >= 0.5 or threat_level >= 3:
            self.attack_statistics['apt'] += 1
            details = f"APT activity detected: {', '.join(indicators)}"
            logger.critical(f"APT THREAT DETECTED: {details}")
            return True, min(confidence, 1.0), details
        
        return False, confidence, ""
    
    def detect_zero_day(self, exploit_data: Dict) -> Tuple[bool, float, str]:
        """
        Detect potential zero-day exploits
        
        Args:
            exploit_data: Dictionary with exploit characteristics
            
        Returns:
            Tuple of (is_attack, confidence, details)
        """
        confidence = 0.0
        indicators = []
        
        # Check for unknown vulnerability exploitation
        if exploit_data.get('unknown_vulnerability'):
            confidence += 0.4
            indicators.append("Unknown vulnerability targeted")
        
        # Check for unusual system call patterns
        if exploit_data.get('unusual_syscalls'):
            confidence += 0.25
            indicators.append("Unusual system call patterns")
        
        # Check for memory corruption indicators
        if exploit_data.get('memory_corruption'):
            confidence += 0.3
            indicators.append("Memory corruption detected")
        
        # Check for privilege escalation
        if exploit_data.get('privilege_escalation'):
            confidence += 0.3
            indicators.append("Privilege escalation attempt")
        
        # Check for code execution in unexpected locations
        if exploit_data.get('unexpected_code_execution'):
            confidence += 0.25
            indicators.append("Code execution in unexpected memory region")
        
        # Check if exploit is not in known signatures
        exploit_hash = exploit_data.get('exploit_hash', '')
        if exploit_hash and not exploit_data.get('matches_known_signature'):
            confidence += 0.2
            indicators.append("No matching known exploit signature")
        
        if confidence >= 0.6:
            self.attack_statistics['zero_day'] += 1
            details = f"Potential zero-day exploit: {', '.join(indicators)}"
            logger.critical(f"ZERO-DAY THREAT DETECTED: {details}")
            return True, min(confidence, 1.0), details
        
        return False, confidence, ""
    
    def analyze_threat(self, threat_data: Dict) -> Dict:
        """
        Comprehensive threat analysis
        
        Args:
            threat_data: Dictionary containing various threat indicators
            
        Returns:
            Dictionary with complete threat analysis
        """
        self.attack_statistics['total_analyzed'] += 1
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'threats_detected': [],
            'max_confidence': 0.0,
            'threat_level': 'low',
            'recommended_actions': []
        }
        
        # Check for MITM
        if 'connection' in threat_data:
            is_mitm, mitm_conf, mitm_details = self.detect_mitm(threat_data['connection'])
            if is_mitm:
                results['threats_detected'].append({
                    'type': 'Man-in-the-Middle (MITM)',
                    'confidence': mitm_conf,
                    'details': mitm_details
                })
                results['max_confidence'] = max(results['max_confidence'], mitm_conf)
                results['recommended_actions'].append("Verify SSL certificates and check network configuration")
        
        # Check for Ransomware
        if 'system_behavior' in threat_data:
            is_ransom, ransom_conf, ransom_details = self.detect_ransomware(threat_data['system_behavior'])
            if is_ransom:
                results['threats_detected'].append({
                    'type': 'Ransomware',
                    'confidence': ransom_conf,
                    'details': ransom_details
                })
                results['max_confidence'] = max(results['max_confidence'], ransom_conf)
                results['recommended_actions'].append("IMMEDIATE: Isolate system, backup important data")
        
        # Check for APT
        if 'activity' in threat_data:
            is_apt, apt_conf, apt_details = self.detect_apt(threat_data['activity'])
            if is_apt:
                results['threats_detected'].append({
                    'type': 'Advanced Persistent Threat (APT)',
                    'confidence': apt_conf,
                    'details': apt_details
                })
                results['max_confidence'] = max(results['max_confidence'], apt_conf)
                results['recommended_actions'].append("Full forensic investigation required")
        
        # Check for Zero-day
        if 'exploit' in threat_data:
            is_zero, zero_conf, zero_details = self.detect_zero_day(threat_data['exploit'])
            if is_zero:
                results['threats_detected'].append({
                    'type': 'Zero-Day Exploit',
                    'confidence': zero_conf,
                    'details': zero_details
                })
                results['max_confidence'] = max(results['max_confidence'], zero_conf)
                results['recommended_actions'].append("Alert security team and apply emergency patches")
        
        # Determine threat level
        if results['max_confidence'] >= 0.8:
            results['threat_level'] = 'critical'
        elif results['max_confidence'] >= 0.6:
            results['threat_level'] = 'high'
        elif results['max_confidence'] >= 0.4:
            results['threat_level'] = 'medium'
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get threat detection statistics"""
        return self.attack_statistics


if __name__ == "__main__":
    # Test the detector
    detector = AdvancedThreatDetector()
    
    # Test MITM detection
    mitm_data = {
        'connection': {
            'ssl_cert_mismatch': True,
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'protocol_downgrade': True
        }
    }
    
    result = detector.analyze_threat(mitm_data)
    print(f"MITM Test: {len(result['threats_detected'])} threats detected")
    print(f"Threat Level: {result['threat_level']}")
    print(f"Confidence: {result['max_confidence']}")
    print(f"\nStatistics: {detector.get_statistics()}")
