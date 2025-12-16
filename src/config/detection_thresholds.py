"""
Configurable Detection Thresholds for Maritime Security Framework
Allows fine-tuning of alert sensitivity to reduce false positives
"""
import json
from pathlib import Path
from typing import Dict, Any

class DetectionThresholds:
    """Manages configurable detection thresholds"""
    
    # Default thresholds
    DEFAULT_THRESHOLDS = {
        # GPS Spoofing Detector
        'gps': {
            'max_speed_knots': 30.0,  # Maximum realistic speed for merchant vessels
            'max_acceleration_knots_per_sec': 0.1,  # Maximum realistic acceleration
            'position_jump_threshold_km': 100.0,  # Maximum realistic movement distance
            'min_time_between_positions_sec': 1.0,  # Minimum time between position updates
            'speed_threshold_multiplier': 1.5,  # Allow 50% over max speed before flagging
        },
        
        # AIS Anomaly Detector
        'ais': {
            'mmsi_validation': {
                'check_pattern': True,  # Check for suspicious MMSI patterns
                'check_country_code': True,  # Validate country codes
                'allow_test_mmsi': False,  # Allow test MMSI numbers
            },
            'speed_limits': {
                'cargo': 25.0,
                'tanker': 20.0,
                'passenger': 30.0,
                'fishing': 15.0,
                'tug': 12.0,
                'unknown': 20.0,
            },
            'heading_mismatch_threshold_degrees': 45.0,  # Max acceptable course/heading difference
            'anomaly_confidence_threshold': 0.3,  # Minimum confidence to flag anomaly
        },
        
        # NMEA Protocol Validator
        'nmea': {
            'require_checksum': True,  # Require valid checksums
            'allow_proprietary_sentences': True,  # Allow proprietary sentences
            'high_risk_commands': ['ROT', 'RMB', 'APB', 'APA'],  # High-risk control commands
            'risk_scoring': {
                'invalid_checksum': 0.8,
                'malformed_structure': 0.7,
                'high_risk_command': 0.6,
                'proprietary_sentence': 0.3,
                'unknown_sentence_type': 0.2,
            },
            'risk_threshold': 0.5,  # Minimum risk score to flag as threat
        },
        
        # Physics-Informed IDS
        'ids': {
            'threat_levels': {
                'critical': 0.8,  # Confidence >= 0.8
                'high': 0.6,      # Confidence >= 0.6
                'medium': 0.4,    # Confidence >= 0.4
                'low': 0.2,       # Confidence >= 0.2
            },
            'cross_layer_correlation': {
                'enabled': True,
                'min_layers_for_critical': 3,  # Anomalies in 3+ layers = critical
                'confidence_boost_per_layer': 0.1,  # Add 10% confidence per layer
            },
            'attack_classification': {
                'gps_spoofing': {
                    'min_position_jump_km': 50.0,
                    'min_speed_violation_multiplier': 1.5,
                },
                'ais_spoofing': {
                    'min_mmsi_violations': 1,
                },
                'nmea_injection': {
                    'min_risk_score': 0.5,
                },
            },
        },
    }
    
    def __init__(self, config_file: str = None):
        """
        Initialize detection thresholds
        
        Args:
            config_file: Path to custom config file (JSON)
        """
        self.config_file = config_file or 'config/detection_thresholds.json'
        self.thresholds = self.load_thresholds()
    
    def load_thresholds(self) -> Dict[str, Any]:
        """Load thresholds from config file or use defaults"""
        config_path = Path(self.config_file)
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    custom_thresholds = json.load(f)
                    # Merge with defaults
                    return self._merge_configs(self.DEFAULT_THRESHOLDS.copy(), custom_thresholds)
            except Exception as e:
                print(f"Warning: Failed to load config from {config_path}: {e}")
                print("Using default thresholds")
        
        return self.DEFAULT_THRESHOLDS.copy()
    
    def save_thresholds(self) -> bool:
        """Save current thresholds to config file"""
        config_path = Path(self.config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(config_path, 'w') as f:
                json.dump(self.thresholds, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config to {config_path}: {e}")
            return False
    
    def update_threshold(self, path: str, value: Any) -> bool:
        """
        Update a specific threshold value
        
        Args:
            path: Dot-separated path to threshold (e.g., 'gps.max_speed_knots')
            value: New value
        
        Returns:
            True if successful
        """
        keys = path.split('.')
        config = self.thresholds
        
        # Navigate to parent dict
        for key in keys[:-1]:
            if key not in config:
                print(f"Error: Invalid path '{path}'")
                return False
            config = config[key]
        
        # Update value
        final_key = keys[-1]
        if final_key not in config:
            print(f"Error: Invalid path '{path}'")
            return False
        
        config[final_key] = value
        return True
    
    def get_threshold(self, path: str, default: Any = None) -> Any:
        """
        Get a specific threshold value
        
        Args:
            path: Dot-separated path to threshold
            default: Default value if path not found
        
        Returns:
            Threshold value or default
        """
        keys = path.split('.')
        config = self.thresholds
        
        try:
            for key in keys:
                config = config[key]
            return config
        except (KeyError, TypeError):
            return default
    
    def reset_to_defaults(self):
        """Reset all thresholds to default values"""
        self.thresholds = self.DEFAULT_THRESHOLDS.copy()
    
    def _merge_configs(self, base: Dict, custom: Dict) -> Dict:
        """Recursively merge custom config into base config"""
        for key, value in custom.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = self._merge_configs(base[key], value)
            else:
                base[key] = value
        return base
    
    def export_to_dict(self) -> Dict[str, Any]:
        """Export thresholds as dictionary"""
        return self.thresholds.copy()
    
    def import_from_dict(self, config: Dict[str, Any]):
        """Import thresholds from dictionary"""
        self.thresholds = self._merge_configs(self.DEFAULT_THRESHOLDS.copy(), config)


# Global thresholds instance
_thresholds_instance = None

def get_thresholds() -> DetectionThresholds:
    """Get global thresholds instance"""
    global _thresholds_instance
    if _thresholds_instance is None:
        _thresholds_instance = DetectionThresholds()
    return _thresholds_instance


def update_global_threshold(path: str, value: Any) -> bool:
    """Update a global threshold value"""
    return get_thresholds().update_threshold(path, value)


def get_global_threshold(path: str, default: Any = None) -> Any:
    """Get a global threshold value"""
    return get_thresholds().get_threshold(path, default)


# Example usage and testing
if __name__ == "__main__":
    print("=== Detection Thresholds Configuration ===\n")
    
    # Create thresholds instance
    thresholds = DetectionThresholds()
    
    # Display default thresholds
    print("GPS Thresholds:")
    print(f"  Max Speed: {thresholds.get_threshold('gps.max_speed_knots')} knots")
    print(f"  Max Acceleration: {thresholds.get_threshold('gps.max_acceleration_knots_per_sec')} knots/sec")
    print(f"  Position Jump Threshold: {thresholds.get_threshold('gps.position_jump_threshold_km')} km")
    
    print("\nAIS Thresholds:")
    cargo_speed = thresholds.get_threshold('ais.speed_limits.cargo')
    print(f"  Cargo Speed Limit: {cargo_speed} knots")
    print(f"  Heading Mismatch Threshold: {thresholds.get_threshold('ais.heading_mismatch_threshold_degrees')}°")
    
    print("\nNMEA Thresholds:")
    print(f"  Require Checksum: {thresholds.get_threshold('nmea.require_checksum')}")
    print(f"  Risk Threshold: {thresholds.get_threshold('nmea.risk_threshold')}")
    
    print("\nIDS Thresholds:")
    print(f"  Critical Threat Level: {thresholds.get_threshold('ids.threat_levels.critical')}")
    print(f"  High Threat Level: {thresholds.get_threshold('ids.threat_levels.high')}")
    
    # Test updating threshold
    print("\n=== Testing Threshold Update ===")
    print(f"Original GPS Max Speed: {thresholds.get_threshold('gps.max_speed_knots')} knots")
    
    thresholds.update_threshold('gps.max_speed_knots', 35.0)
    print(f"Updated GPS Max Speed: {thresholds.get_threshold('gps.max_speed_knots')} knots")
    
    # Test saving and loading
    print("\n=== Testing Save/Load ===")
    save_success = thresholds.save_thresholds()
    print(f"Save successful: {save_success}")
    
    # Load into new instance
    thresholds2 = DetectionThresholds()
    print(f"Loaded GPS Max Speed: {thresholds2.get_threshold('gps.max_speed_knots')} knots")
    
    # Reset to defaults
    thresholds2.reset_to_defaults()
    print(f"After reset: {thresholds2.get_threshold('gps.max_speed_knots')} knots")
    
    print("\n=== Configuration Complete ===")
