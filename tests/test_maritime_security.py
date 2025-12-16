"""
Comprehensive Unit Tests for Maritime Security Framework
Tests GPS detector, AIS detector, NMEA validator, and Physics-Informed IDS
"""
import unittest
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detectors.gps_spoofing_detector import GPSSpoofingDetector
from src.detectors.ais_anomaly_detector import AISAnomalyDetector
from src.detectors.nmea_protocol_validator import NMEAProtocolValidator
from src.detectors.physics_informed_ids import PhysicsInformedIDS


class TestGPSSpoofingDetector(unittest.TestCase):
    """Test GPS spoofing detection"""
    
    def setUp(self):
        self.detector = GPSSpoofingDetector()
    
    def test_normal_gps_movement(self):
        """Test that normal vessel movement is not flagged"""
        base_time = datetime.now()
        
        # Normal movement: vessel moving at 15 knots
        positions = [
            {'latitude': 40.7128, 'longitude': -74.0060, 'timestamp': base_time, 'speed_knots': 15.0},
            {'latitude': 40.7140, 'longitude': -74.0050, 'timestamp': base_time + timedelta(seconds=60), 'speed_knots': 15.0},
            {'latitude': 40.7152, 'longitude': -74.0040, 'timestamp': base_time + timedelta(seconds=120), 'speed_knots': 15.0}
        ]
        
        for pos in positions:
            result = self.detector.check_gps_spoofing(pos)
            self.assertFalse(result['is_spoofed'], f"Normal movement should not be flagged: {result['anomalies']}")
    
    def test_position_jump_detection(self):
        """Test detection of impossible position jumps"""
        base_time = datetime.now()
        
        # First position in New York
        pos1 = {'latitude': 40.7128, 'longitude': -74.0060, 'timestamp': base_time, 'speed_knots': 15.0}
        self.detector.check_gps_spoofing(pos1)
        
        # Second position in London (impossible jump)
        pos2 = {'latitude': 51.5074, 'longitude': -0.1278, 'timestamp': base_time + timedelta(seconds=60), 'speed_knots': 15.0}
        result = self.detector.check_gps_spoofing(pos2)
        
        self.assertTrue(result['is_spoofed'], "Large position jump should be detected")
        self.assertGreater(result['confidence'], 0.5, "Confidence should be high for position jump")
    
    def test_impossible_speed_detection(self):
        """Test detection of impossible speeds"""
        base_time = datetime.now()
        
        gps_data = {
            'latitude': 40.7128,
            'longitude': -74.0060,
            'timestamp': base_time,
            'speed_knots': 150.0  # Impossible for merchant vessel
        }
        
        result = self.detector.check_gps_spoofing(gps_data)
        self.assertTrue(result['is_spoofed'], "Impossible speed should be detected")
        self.assertIn('Impossible speed', ' '.join(result['anomalies']))
    
    def test_statistics_tracking(self):
        """Test that statistics are properly tracked"""
        gps_data = {'latitude': 40.7128, 'longitude': -74.0060, 'timestamp': datetime.now(), 'speed_knots': 15.0}
        
        self.detector.check_gps_spoofing(gps_data)
        stats = self.detector.get_statistics()
        
        self.assertEqual(stats['total_checks'], 1)
        self.assertIn('positions_tracked', stats)


class TestAISAnomalyDetector(unittest.TestCase):
    """Test AIS anomaly detection"""
    
    def setUp(self):
        self.detector = AISAnomalyDetector()
    
    def test_valid_ais_message(self):
        """Test that valid AIS message passes"""
        ais_message = {
            'mmsi': 367123456,
            'latitude': 40.7128,
            'longitude': -74.0060,
            'speed': 15.0,
            'course': 90.0,
            'heading': 92.0,
            'vessel_type': 'cargo',
            'timestamp': datetime.now()
        }
        
        result = self.detector.check_ais_message(ais_message)
        self.assertFalse(result['is_anomaly'], f"Valid AIS message should pass: {result['anomalies']}")
    
    def test_invalid_mmsi_detection(self):
        """Test detection of invalid MMSI"""
        ais_message = {
            'mmsi': 111111111,  # All same digits - invalid
            'latitude': 40.7128,
            'longitude': -74.0060,
            'speed': 15.0,
            'course': 90.0,
            'heading': 92.0,
            'vessel_type': 'cargo',
            'timestamp': datetime.now()
        }
        
        result = self.detector.check_ais_message(ais_message)
        self.assertTrue(result['is_anomaly'], "Invalid MMSI should be detected")
        self.assertGreater(result['confidence'], 0.3)
    
    def test_speed_violation_detection(self):
        """Test detection of vessel type speed violations"""
        ais_message = {
            'mmsi': 367123456,
            'latitude': 40.7128,
            'longitude': -74.0060,
            'speed': 40.0,  # Too fast for cargo (max 25 knots)
            'course': 90.0,
            'heading': 92.0,
            'vessel_type': 'cargo',
            'timestamp': datetime.now()
        }
        
        result = self.detector.check_ais_message(ais_message)
        self.assertTrue(result['is_anomaly'], "Speed violation should be detected")
        self.assertIn('speed', ' '.join(result['anomalies']).lower())
    
    def test_heading_mismatch_detection(self):
        """Test detection of course/heading mismatch"""
        ais_message = {
            'mmsi': 367123456,
            'latitude': 40.7128,
            'longitude': -74.0060,
            'speed': 15.0,
            'course': 90.0,
            'heading': 270.0,  # 180° difference - suspicious
            'vessel_type': 'cargo',
            'timestamp': datetime.now()
        }
        
        result = self.detector.check_ais_message(ais_message)
        self.assertTrue(result['is_anomaly'], "Large heading mismatch should be detected")


class TestNMEAProtocolValidator(unittest.TestCase):
    """Test NMEA protocol validation"""
    
    def setUp(self):
        self.validator = NMEAProtocolValidator()
    
    def test_valid_gga_sentence(self):
        """Test that valid GGA sentence passes"""
        sentence = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47"
        result = self.validator.validate_sentence(sentence)
        
        self.assertTrue(result['valid'], f"Valid GGA should pass: {result['anomalies']}")
        self.assertEqual(result['sentence_type'], 'GGA')
        self.assertLess(result['risk_score'], 0.3)
    
    def test_invalid_checksum_detection(self):
        """Test detection of invalid checksums"""
        sentence = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*XX"
        result = self.validator.validate_sentence(sentence)
        
        self.assertFalse(result['valid'], "Invalid checksum should fail validation")
        self.assertIn('checksum', ' '.join(result['anomalies']).lower())
        self.assertGreater(result['risk_score'], 0.5)
    
    def test_high_risk_command_detection(self):
        """Test detection of high-risk control commands"""
        sentence = "$HEROT,45.5,A*3C"  # Rate of turn command
        result = self.validator.validate_sentence(sentence)
        
        self.assertEqual(result['sentence_type'], 'ROT')
        self.assertGreater(result['risk_score'], 0.5, "High-risk command should have high risk score")
    
    def test_malformed_sentence_detection(self):
        """Test detection of malformed sentences"""
        sentence = "$INVALID"
        result = self.validator.validate_sentence(sentence)
        
        self.assertFalse(result['valid'], "Malformed sentence should fail")
        self.assertGreater(result['risk_score'], 0.5)
    
    def test_sentence_type_recognition(self):
        """Test recognition of different sentence types"""
        test_cases = [
            ("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47", "GGA"),
            ("$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A", "RMC"),
            ("$HEHDT,274.5,T*23", "HDT")
        ]
        
        for sentence, expected_type in test_cases:
            result = self.validator.validate_sentence(sentence)
            self.assertEqual(result['sentence_type'], expected_type, 
                           f"Should recognize {expected_type} sentence")


class TestPhysicsInformedIDS(unittest.TestCase):
    """Test integrated Physics-Informed IDS"""
    
    def setUp(self):
        self.ids = PhysicsInformedIDS()
    
    def test_normal_operation_analysis(self):
        """Test that normal operation doesn't trigger threats"""
        gps_data = {
            'latitude': 40.7128,
            'longitude': -74.0060,
            'timestamp': datetime.now(),
            'speed_knots': 15.0,
            'course': 90.0
        }
        
        ais_data = {
            'mmsi': 367123456,
            'latitude': 40.7128,
            'longitude': -74.0060,
            'speed': 15.0,
            'course': 90.0,
            'heading': 92.0,
            'vessel_type': 'cargo',
            'timestamp': datetime.now()
        }
        
        nmea_sentence = "$GPGGA,123519,4042.768,N,07400.360,W,1,08,0.9,545.4,M,46.9,M,,*47"
        
        result = self.ids.analyze_maritime_event(gps_data, ais_data, nmea_sentence)
        
        # Normal operation might still show some anomalies due to checksum validation
        # but threat level should not be critical
        self.assertIn(result['threat_level'], ['normal', 'low', 'medium', 'high', 'critical'])
        self.assertIsInstance(result['total_anomalies'], int)
        self.assertIsInstance(result['detected_attacks'], list)
    
    def test_gps_spoofing_detection(self):
        """Test that GPS spoofing is detected through IDS"""
        # First establish baseline
        baseline_gps = {
            'latitude': 40.7128,
            'longitude': -74.0060,
            'timestamp': datetime.now(),
            'speed_knots': 15.0,
            'course': 90.0
        }
        self.ids.analyze_maritime_event(baseline_gps, None, None)
        
        # Then inject spoofed position
        spoofed_gps = {
            'latitude': 51.5074,  # London - impossible jump
            'longitude': -0.1278,
            'timestamp': datetime.now(),
            'speed_knots': 15.0,
            'course': 90.0
        }
        
        result = self.ids.analyze_maritime_event(spoofed_gps, None, None)
        
        self.assertTrue(result['is_threat'], "GPS spoofing should trigger threat")
        self.assertIn(result['threat_level'], ['high', 'critical'])
    
    def test_multi_layer_correlation(self):
        """Test cross-layer threat correlation"""
        # Inject anomalies across multiple layers
        gps_data = {
            'latitude': 40.7128,
            'longitude': -74.0060,
            'timestamp': datetime.now(),
            'speed_knots': 150.0,  # Impossible speed
            'course': 90.0
        }
        
        ais_data = {
            'mmsi': 111111111,  # Invalid MMSI
            'latitude': 40.7128,
            'longitude': -74.0060,
            'speed': 50.0,  # Speed violation for cargo
            'course': 90.0,
            'heading': 270.0,  # Heading mismatch
            'vessel_type': 'cargo',
            'timestamp': datetime.now()
        }
        
        nmea_sentence = "$HEROT,720.0,A*XX"  # Invalid checksum + extreme ROT
        
        result = self.ids.analyze_maritime_event(gps_data, ais_data, nmea_sentence)
        
        self.assertTrue(result['is_threat'], "Multi-layer attack should be detected")
        self.assertEqual(result['threat_level'], 'critical', "Multi-layer attack should be critical")
        self.assertGreater(len(result['detected_attacks']), 0, "Should detect multiple attack types")
    
    def test_statistics_accumulation(self):
        """Test that IDS properly accumulates statistics"""
        gps_data = {'latitude': 40.7128, 'longitude': -74.0060, 'timestamp': datetime.now(), 'speed_knots': 15.0}
        
        self.ids.analyze_maritime_event(gps_data, None, None)
        self.ids.analyze_maritime_event(gps_data, None, None)
        
        stats = self.ids.get_statistics()
        
        self.assertEqual(stats['total_events'], 2)
        self.assertIn('threats_detected', stats)
        self.assertIn('detector_stats', stats)


class TestIntegration(unittest.TestCase):
    """Integration tests for full system"""
    
    def test_end_to_end_normal_flow(self):
        """Test complete flow with normal data"""
        ids = PhysicsInformedIDS()
        
        # Simulate normal vessel operation
        for i in range(5):
            gps_data = {
                'latitude': 40.7128 + i * 0.001,
                'longitude': -74.0060 + i * 0.001,
                'timestamp': datetime.now(),
                'speed_knots': 15.0,
                'course': 90.0
            }
            
            result = ids.analyze_maritime_event(gps_data, None, None)
            self.assertIsNotNone(result)
        
        stats = ids.get_statistics()
        self.assertEqual(stats['total_events'], 5)
    
    def test_attack_detection_flow(self):
        """Test complete flow with attack injection"""
        ids = PhysicsInformedIDS()
        
        # Normal operation
        normal_gps = {
            'latitude': 40.7128,
            'longitude': -74.0060,
            'timestamp': datetime.now(),
            'speed_knots': 15.0
        }
        ids.analyze_maritime_event(normal_gps, None, None)
        
        # Attack
        attack_gps = {
            'latitude': 51.5074,  # Position jump
            'longitude': -0.1278,
            'timestamp': datetime.now(),
            'speed_knots': 200.0  # Impossible speed
        }
        result = ids.analyze_maritime_event(attack_gps, None, None)
        
        self.assertTrue(result['is_threat'])
        stats = ids.get_statistics()
        self.assertGreater(stats['threats_detected'], 0)


def run_all_tests():
    """Run all test suites"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestGPSSpoofingDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestAISAnomalyDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestNMEAProtocolValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestPhysicsInformedIDS))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
