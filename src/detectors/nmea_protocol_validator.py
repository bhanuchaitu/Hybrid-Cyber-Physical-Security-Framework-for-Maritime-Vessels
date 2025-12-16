"""
NMEA Protocol Validator
Validates NMEA 0183 sentences and detects protocol anomalies
"""
import re
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class NMEAProtocolValidator:
    """
    Validates NMEA 0183 protocol sentences and detects anomalies
    
    Features:
    - Sentence structure validation
    - Checksum verification
    - Field format validation
    - Command risk scoring
    - Message rate monitoring
    - Protocol anomaly detection
    """
    
    # NMEA sentence types with their risk levels
    SENTENCE_TYPES = {
        # GPS Sentences (Low Risk - Read-only)
        'GGA': {'name': 'Global Positioning System Fix Data', 'risk': 1, 'category': 'gps'},
        'GLL': {'name': 'Geographic Position - Latitude/Longitude', 'risk': 1, 'category': 'gps'},
        'GSA': {'name': 'GPS DOP and Active Satellites', 'risk': 1, 'category': 'gps'},
        'GSV': {'name': 'GPS Satellites in View', 'risk': 1, 'category': 'gps'},
        'RMC': {'name': 'Recommended Minimum Navigation Information', 'risk': 1, 'category': 'gps'},
        'VTG': {'name': 'Track Made Good and Ground Speed', 'risk': 1, 'category': 'gps'},
        
        # Heading/Compass Sentences (Low-Medium Risk)
        'HDG': {'name': 'Heading - Deviation & Variation', 'risk': 2, 'category': 'heading'},
        'HDM': {'name': 'Heading - Magnetic', 'risk': 2, 'category': 'heading'},
        'HDT': {'name': 'Heading - True', 'risk': 2, 'category': 'heading'},
        
        # Speed/Depth Sentences (Low-Medium Risk)
        'VHW': {'name': 'Water Speed and Heading', 'risk': 2, 'category': 'speed'},
        'VLW': {'name': 'Distance Traveled through Water', 'risk': 2, 'category': 'speed'},
        'DPT': {'name': 'Depth of Water', 'risk': 2, 'category': 'depth'},
        'DBT': {'name': 'Depth Below Transducer', 'risk': 2, 'category': 'depth'},
        
        # Navigation/Waypoint Sentences (Medium Risk)
        'APB': {'name': 'Autopilot Sentence B', 'risk': 3, 'category': 'navigation'},
        'BOD': {'name': 'Bearing - Waypoint to Waypoint', 'risk': 3, 'category': 'navigation'},
        'BWC': {'name': 'Bearing & Distance to Waypoint', 'risk': 3, 'category': 'navigation'},
        'RTE': {'name': 'Routes', 'risk': 3, 'category': 'navigation'},
        'WPL': {'name': 'Waypoint Location', 'risk': 3, 'category': 'navigation'},
        'XTE': {'name': 'Cross-Track Error', 'risk': 3, 'category': 'navigation'},
        
        # Autopilot/Control Sentences (HIGH RISK - Control commands)
        'APA': {'name': 'Autopilot Sentence A', 'risk': 5, 'category': 'control'},
        'ROT': {'name': 'Rate of Turn', 'risk': 5, 'category': 'control'},
        'RSA': {'name': 'Rudder Sensor Angle', 'risk': 5, 'category': 'control'},
        'HTC': {'name': 'Heading/Track Control Command', 'risk': 5, 'category': 'control'},
        
        # AIS Sentences (Medium Risk)
        'VDM': {'name': 'AIS VHF Data-link Message', 'risk': 3, 'category': 'ais'},
        'VDO': {'name': 'AIS VHF Data-link Own-vessel Report', 'risk': 3, 'category': 'ais'},
        
        # Wind/Weather Sentences (Low Risk)
        'MWV': {'name': 'Wind Speed and Angle', 'risk': 1, 'category': 'weather'},
        'MWD': {'name': 'Wind Direction & Speed', 'risk': 1, 'category': 'weather'},
        
        # System Sentences (Medium Risk)
        'ZDA': {'name': 'Time & Date', 'risk': 2, 'category': 'system'},
        'TXT': {'name': 'Text Transmission', 'risk': 3, 'category': 'system'},
    }
    
    # Talker IDs (first 2 characters after $)
    TALKER_IDS = {
        'GP': 'GPS',
        'GL': 'GLONASS',
        'GA': 'Galileo',
        'GB': 'BeiDou',
        'GN': 'GNSS (combined)',
        'HE': 'Heading/Gyro',
        'II': 'Integrated Instrumentation',
        'IN': 'Integrated Navigation',
        'AI': 'AIS',
        'CD': 'DSC',
        'EC': 'ECDIS',
        'SD': 'Sounder/Depth',
        'YX': 'Transducer',
        'ZA': 'Time',
    }
    
    def __init__(self, max_history: int = 1000):
        """
        Initialize NMEA protocol validator
        
        Args:
            max_history: Maximum number of sentences to keep in history
        """
        self.max_history = max_history
        self.sentence_history = deque(maxlen=max_history)
        self.message_counts = defaultdict(int)
        self.anomaly_counts = defaultdict(int)
        
        # Statistics
        self.total_sentences = 0
        self.valid_sentences = 0
        self.invalid_checksums = 0
        self.malformed_sentences = 0
        self.high_risk_commands = 0
        
        logger.info("NMEA Protocol Validator initialized")
    
    def _calculate_checksum(self, sentence: str) -> str:
        """
        Calculate NMEA checksum
        
        Args:
            sentence: NMEA sentence without $ and checksum
        
        Returns:
            Checksum as hex string (2 characters)
        """
        checksum = 0
        for char in sentence:
            checksum ^= ord(char)
        return f"{checksum:02X}"
    
    def _verify_checksum(self, sentence: str) -> bool:
        """
        Verify NMEA sentence checksum
        
        Args:
            sentence: Complete NMEA sentence with checksum
        
        Returns:
            True if checksum is valid
        """
        if '*' not in sentence:
            return False
        
        try:
            # Split sentence and checksum
            data, checksum = sentence.split('*')
            data = data.lstrip('$')
            
            # Calculate expected checksum
            expected = self._calculate_checksum(data)
            
            return checksum.upper() == expected.upper()
        except Exception as e:
            logger.debug(f"Checksum verification error: {e}")
            return False
    
    def _parse_sentence(self, sentence: str) -> Optional[Dict]:
        """
        Parse NMEA sentence into components
        
        Args:
            sentence: NMEA sentence string
        
        Returns:
            Dictionary with parsed components or None if invalid
        """
        # Basic format check
        if not sentence or not sentence.startswith('$'):
            return None
        
        try:
            # Remove $ and split by *
            if '*' in sentence:
                data, checksum = sentence[1:].split('*')
            else:
                data = sentence[1:]
                checksum = None
            
            # Split data by comma
            fields = data.split(',')
            
            if len(fields) == 0:
                return None
            
            # Extract talker ID and sentence type
            header = fields[0]
            
            # Check if header has at least 5 characters (e.g., GPGGA)
            if len(header) < 3:
                return None
            
            # Talker ID is first 2 characters, sentence type is remaining
            talker_id = header[:2]
            sentence_type = header[2:]
            
            # Validate that sentence type is recognized (basic sanity check)
            valid_sentence_types = [
                'GGA', 'RMC', 'GSA', 'GSV', 'VTG', 'GLL', 'HDT', 'HDG', 'HDM',
                'ROT', 'RSA', 'VBW', 'VHW', 'VLW', 'VPW', 'VWR', 'VWT', 'XTE',
                'ZDA', 'DBT', 'DPT', 'MTW', 'MWV', 'MWD', 'TXT', 'APB', 'APA',
                'BOD', 'BWC', 'BWR', 'RMB', 'WCV', 'WNC', 'WPL', 'XDR', 'XTR',
                'ZTG', 'HTC', 'HTD', 'OSD', 'RMA', 'RTE', 'TRF', 'STN', 'VDM'
            ]
            
            # If sentence type is not recognized and not a proprietary sentence, it's likely malformed
            if sentence_type not in valid_sentence_types and not sentence_type.startswith('P'):
                logger.debug(f"Unknown/invalid sentence type: {sentence_type}")
                return None
            
            return {
                'raw': sentence,
                'talker_id': talker_id,
                'sentence_type': sentence_type,
                'fields': fields[1:],  # Exclude header
                'checksum': checksum,
                'timestamp': datetime.now()
            }
        except Exception as e:
            logger.debug(f"Sentence parsing error: {e}")
            return None
    
    def _validate_field_format(self, parsed: Dict) -> List[str]:
        """
        Validate field formats for specific sentence types
        
        Args:
            parsed: Parsed sentence dictionary
        
        Returns:
            List of validation errors
        """
        errors = []
        sentence_type = parsed['sentence_type']
        fields = parsed['fields']
        
        # GGA - GPS Fix Data
        if sentence_type == 'GGA':
            if len(fields) < 14:
                errors.append(f"GGA requires at least 14 fields, got {len(fields)}")
            else:
                # Time field (HHMMSS.SS)
                if fields[0] and not re.match(r'^\d{6}(\.\d{2})?$', fields[0]):
                    errors.append("Invalid time format in GGA")
                
                # Latitude (DDMM.MMMM)
                if fields[1] and not re.match(r'^\d{2,4}\.\d+$', fields[1]):
                    errors.append("Invalid latitude format in GGA")
                
                # N/S indicator
                if fields[2] and fields[2] not in ['N', 'S']:
                    errors.append("Invalid latitude direction in GGA")
                
                # Longitude (DDDMM.MMMM)
                if fields[3] and not re.match(r'^\d{2,5}\.\d+$', fields[3]):
                    errors.append("Invalid longitude format in GGA")
                
                # E/W indicator
                if fields[4] and fields[4] not in ['E', 'W']:
                    errors.append("Invalid longitude direction in GGA")
                
                # Fix quality (0-8)
                if fields[5] and not re.match(r'^[0-8]$', fields[5]):
                    errors.append("Invalid fix quality in GGA")
        
        # RMC - Recommended Minimum Navigation Information
        elif sentence_type == 'RMC':
            if len(fields) < 12:
                errors.append(f"RMC requires at least 12 fields, got {len(fields)}")
            else:
                # Status (A=Active, V=Void)
                if fields[1] and fields[1] not in ['A', 'V']:
                    errors.append("Invalid status in RMC")
                
                # Speed over ground (knots)
                if fields[6]:
                    try:
                        speed = float(fields[6])
                        if speed < 0 or speed > 200:  # Unrealistic speed
                            errors.append(f"Unrealistic speed in RMC: {speed} knots")
                    except ValueError:
                        errors.append("Invalid speed format in RMC")
                
                # Course over ground (degrees)
                if fields[7]:
                    try:
                        course = float(fields[7])
                        if course < 0 or course >= 360:
                            errors.append(f"Invalid course in RMC: {course}°")
                    except ValueError:
                        errors.append("Invalid course format in RMC")
        
        # HDT - Heading True
        elif sentence_type == 'HDT':
            if len(fields) < 2:
                errors.append(f"HDT requires at least 2 fields, got {len(fields)}")
            else:
                # Heading (degrees)
                if fields[0]:
                    try:
                        heading = float(fields[0])
                        if heading < 0 or heading >= 360:
                            errors.append(f"Invalid heading in HDT: {heading}°")
                    except ValueError:
                        errors.append("Invalid heading format in HDT")
        
        # ROT - Rate of Turn (HIGH RISK)
        elif sentence_type == 'ROT':
            if len(fields) < 2:
                errors.append(f"ROT requires at least 2 fields, got {len(fields)}")
            else:
                # Rate of turn (degrees per minute)
                if fields[0]:
                    try:
                        rot = float(fields[0])
                        if abs(rot) > 720:  # Extremely high rate of turn
                            errors.append(f"Extreme rate of turn in ROT: {rot}°/min")
                    except ValueError:
                        errors.append("Invalid rate of turn format in ROT")
        
        return errors
    
    def _calculate_risk_score(self, parsed: Dict, validation_errors: List[str]) -> Tuple[float, str]:
        """
        Calculate risk score for NMEA sentence
        
        Args:
            parsed: Parsed sentence dictionary
            validation_errors: List of validation errors
        
        Returns:
            Tuple of (risk_score, risk_description)
        """
        base_risk = 0.0
        risk_factors = []
        
        sentence_type = parsed['sentence_type']
        
        # Base risk from sentence type
        if sentence_type in self.SENTENCE_TYPES:
            type_info = self.SENTENCE_TYPES[sentence_type]
            base_risk = type_info['risk'] * 0.1  # Scale 1-5 to 0.1-0.5
            
            if type_info['risk'] >= 5:
                risk_factors.append("High-risk control command")
        else:
            base_risk = 0.3
            risk_factors.append("Unknown sentence type")
        
        # Add risk for validation errors
        if validation_errors:
            base_risk += len(validation_errors) * 0.15
            risk_factors.append(f"{len(validation_errors)} validation errors")
        
        # Add risk for unknown talker ID
        if parsed['talker_id'] not in self.TALKER_IDS:
            base_risk += 0.1
            risk_factors.append("Unknown talker ID")
        
        # Add risk for missing checksum
        if not parsed['checksum']:
            base_risk += 0.2
            risk_factors.append("Missing checksum")
        
        # High-risk sentence types
        if sentence_type in ['ROT', 'RSA', 'APA', 'HTC']:
            base_risk += 0.3
            risk_factors.append("Autopilot/control command")
        
        # Check for unusual field patterns
        fields = parsed['fields']
        empty_fields = sum(1 for f in fields if not f)
        if empty_fields > len(fields) * 0.5:  # More than 50% empty
            base_risk += 0.15
            risk_factors.append("Many empty fields")
        
        # Cap at 1.0
        risk_score = min(base_risk, 1.0)
        
        risk_description = "; ".join(risk_factors) if risk_factors else "Normal"
        
        return risk_score, risk_description
    
    def _check_message_rate(self, sentence_type: str) -> Optional[str]:
        """
        Check if message rate is suspicious
        
        Args:
            sentence_type: Type of NMEA sentence
        
        Returns:
            Warning message if rate is suspicious, None otherwise
        """
        # Count recent messages of this type (last 100)
        recent_count = sum(1 for s in list(self.sentence_history)[-100:] 
                          if s.get('sentence_type') == sentence_type)
        
        # Expected rates (messages per 100 total)
        expected_rates = {
            'GGA': (5, 20),   # GPS fix: 5-20 per 100 messages
            'RMC': (5, 20),   # Navigation: 5-20 per 100 messages
            'HDT': (5, 15),   # Heading: 5-15 per 100 messages
            'ROT': (0, 5),    # Rate of turn: 0-5 per 100 messages (rare)
            'VDM': (1, 10),   # AIS: 1-10 per 100 messages
        }
        
        if sentence_type in expected_rates:
            min_rate, max_rate = expected_rates[sentence_type]
            if recent_count > max_rate:
                return f"High message rate: {recent_count} {sentence_type} in last 100 messages"
            elif recent_count < min_rate and len(self.sentence_history) >= 100:
                return f"Low message rate: {recent_count} {sentence_type} in last 100 messages"
        
        return None
    
    def validate_sentence(self, sentence: str) -> Dict:
        """
        Validate NMEA sentence and detect anomalies
        
        Args:
            sentence: NMEA sentence string
        
        Returns:
            Validation result dictionary
        """
        self.total_sentences += 1
        
        result = {
            'valid': False,
            'sentence': sentence,
            'timestamp': datetime.now(),
            'anomalies': [],
            'risk_score': 0.0,
            'risk_description': '',
            'sentence_type': None,
            'talker_id': None
        }
        
        # Parse sentence
        parsed = self._parse_sentence(sentence)
        if not parsed:
            self.malformed_sentences += 1
            result['anomalies'].append("Malformed sentence structure")
            result['risk_score'] = 0.8
            result['risk_description'] = "Malformed sentence"
            result['valid'] = False
            return result
        
        result['sentence_type'] = parsed['sentence_type']
        result['talker_id'] = parsed['talker_id']
        
        # Verify checksum
        if parsed['checksum']:
            if not self._verify_checksum(sentence):
                self.invalid_checksums += 1
                result['anomalies'].append("Invalid checksum")
                result['risk_score'] = 0.7
                result['risk_description'] = "Checksum verification failed"
                self.anomaly_counts['invalid_checksum'] += 1
        
        # Validate field formats
        validation_errors = self._validate_field_format(parsed)
        if validation_errors:
            result['anomalies'].extend(validation_errors)
            self.anomaly_counts['format_errors'] += 1
        
        # Calculate risk score
        risk_score, risk_description = self._calculate_risk_score(parsed, validation_errors)
        result['risk_score'] = max(result['risk_score'], risk_score)
        if risk_description != "Normal":
            if result['risk_description']:
                result['risk_description'] += f"; {risk_description}"
            else:
                result['risk_description'] = risk_description
        
        # Check message rate
        rate_warning = self._check_message_rate(parsed['sentence_type'])
        if rate_warning:
            result['anomalies'].append(rate_warning)
            result['risk_score'] = min(result['risk_score'] + 0.1, 1.0)
            self.anomaly_counts['rate_anomaly'] += 1
        
        # Mark as valid if no critical errors
        if not any('malformed' in a.lower() or 'checksum' in a.lower() 
                   for a in result['anomalies']):
            result['valid'] = True
            self.valid_sentences += 1
        
        # Track high-risk commands
        if parsed['sentence_type'] in ['ROT', 'RSA', 'APA', 'HTC']:
            self.high_risk_commands += 1
            result['anomalies'].append(f"High-risk control command: {parsed['sentence_type']}")
        
        # Update statistics
        self.message_counts[parsed['sentence_type']] += 1
        self.sentence_history.append(parsed)
        
        return result
    
    def validate_batch(self, sentences: List[str]) -> List[Dict]:
        """
        Validate multiple NMEA sentences
        
        Args:
            sentences: List of NMEA sentence strings
        
        Returns:
            List of validation results
        """
        return [self.validate_sentence(s) for s in sentences]
    
    def get_statistics(self) -> Dict:
        """
        Get validator statistics
        
        Returns:
            Statistics dictionary
        """
        return {
            'total_sentences': self.total_sentences,
            'valid_sentences': self.valid_sentences,
            'invalid_checksums': self.invalid_checksums,
            'malformed_sentences': self.malformed_sentences,
            'high_risk_commands': self.high_risk_commands,
            'anomaly_counts': dict(self.anomaly_counts),
            'message_type_counts': dict(self.message_counts),
            'success_rate': f"{(self.valid_sentences / self.total_sentences * 100):.1f}%" 
                           if self.total_sentences > 0 else "0%"
        }
    
    def get_sentence_info(self, sentence_type: str) -> Optional[Dict]:
        """
        Get information about a sentence type
        
        Args:
            sentence_type: NMEA sentence type (e.g., 'GGA', 'RMC')
        
        Returns:
            Sentence type information or None
        """
        return self.SENTENCE_TYPES.get(sentence_type)


# Test the validator
if __name__ == "__main__":
    print("Testing NMEA Protocol Validator...\n")
    
    validator = NMEAProtocolValidator()
    
    # Test 1: Valid NMEA sentences
    print("1. Valid NMEA sentences:")
    valid_sentences = [
        "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47",
        "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A",
        "$HEHDT,274.5,T*23",
    ]
    
    for sentence in valid_sentences:
        result = validator.validate_sentence(sentence)
        print(f"  Sentence: {sentence[:50]}...")
        print(f"  Valid: {result['valid']}, Type: {result['sentence_type']}, Risk: {result['risk_score']:.2f}")
        if result['anomalies']:
            print(f"  Anomalies: {result['anomalies']}")
    
    # Test 2: Invalid checksum
    print("\n2. Invalid checksum:")
    invalid_checksum = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*XX"
    result = validator.validate_sentence(invalid_checksum)
    print(f"  Valid: {result['valid']}, Risk: {result['risk_score']:.2f}")
    print(f"  Anomalies: {result['anomalies']}")
    
    # Test 3: Malformed sentence
    print("\n3. Malformed sentence:")
    malformed = "$GPGGA,,,,,,,,,,,,,*00"
    result = validator.validate_sentence(malformed)
    print(f"  Valid: {result['valid']}, Risk: {result['risk_score']:.2f}")
    print(f"  Anomalies: {result['anomalies']}")
    
    # Test 4: High-risk control command
    print("\n4. High-risk control command:")
    control_cmd = "$HEROT,45.5,A*00"
    result = validator.validate_sentence(control_cmd)
    print(f"  Valid: {result['valid']}, Type: {result['sentence_type']}, Risk: {result['risk_score']:.2f}")
    print(f"  Description: {result['risk_description']}")
    print(f"  Anomalies: {result['anomalies']}")
    
    # Test 5: Unrealistic speed
    print("\n5. Unrealistic speed:")
    high_speed = "$GPRMC,123519,A,4807.038,N,01131.000,E,150.0,084.4,230394,003.1,W*00"
    result = validator.validate_sentence(high_speed)
    print(f"  Valid: {result['valid']}, Risk: {result['risk_score']:.2f}")
    print(f"  Anomalies: {result['anomalies']}")
    
    # Test 6: Missing checksum
    print("\n6. Missing checksum:")
    no_checksum = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,"
    result = validator.validate_sentence(no_checksum)
    print(f"  Valid: {result['valid']}, Risk: {result['risk_score']:.2f}")
    print(f"  Description: {result['risk_description']}")
    
    # Test 7: Statistics
    print("\n7. Validator statistics:")
    stats = validator.get_statistics()
    print(f"  Total sentences: {stats['total_sentences']}")
    print(f"  Valid sentences: {stats['valid_sentences']}")
    print(f"  Invalid checksums: {stats['invalid_checksums']}")
    print(f"  High-risk commands: {stats['high_risk_commands']}")
    print(f"  Success rate: {stats['success_rate']}")
    
    # Test 8: Sentence info lookup
    print("\n8. Sentence type information:")
    for stype in ['GGA', 'RMC', 'ROT', 'HDT']:
        info = validator.get_sentence_info(stype)
        if info:
            print(f"  {stype}: {info['name']} (Risk: {info['risk']}/5, Category: {info['category']})")
    
    print("\n✅ NMEA Protocol Validator test complete!")
