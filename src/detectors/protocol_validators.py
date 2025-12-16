"""
Industrial Protocol Validators for Maritime Systems
Validates DNP3, Modbus, CAN bus, Zigbee/IoT, and Satellite communications
"""
import struct
import logging
from typing import Dict, Tuple, List, Optional
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class DNP3FunctionCode(Enum):
    """DNP3 Function Codes"""
    CONFIRM = 0x00
    READ = 0x01
    WRITE = 0x02
    SELECT = 0x03
    OPERATE = 0x04
    DIRECT_OPERATE = 0x05
    DIRECT_OPERATE_NR = 0x06
    FREEZE = 0x07
    FREEZE_NR = 0x08
    COLD_RESTART = 0x0D
    WARM_RESTART = 0x0E


class ModbusFunctionCode(Enum):
    """Modbus Function Codes"""
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_REGISTERS = 0x10


class DNP3Validator:
    """
    Validates DNP3 (Distributed Network Protocol 3) communications
    Used in SCADA systems for critical maritime infrastructure
    """
    
    def __init__(self):
        """Initialize DNP3 validator"""
        self.valid_function_codes = [fc.value for fc in DNP3FunctionCode]
        self.allowed_operations = set(self.valid_function_codes)
        self.suspicious_activities = []
        self.stats = {
            'total_packets': 0,
            'valid_packets': 0,
            'invalid_packets': 0,
            'security_violations': 0
        }
    
    def restrict_operations(self, allowed_codes: List[int]):
        """
        Restrict allowed DNP3 operations
        
        Args:
            allowed_codes: List of allowed function codes
        """
        self.allowed_operations = set(allowed_codes)
        logger.info(f"DNP3 operations restricted to: {allowed_codes}")
    
    def validate_packet(self, packet_data: bytes) -> Tuple[bool, float, str]:
        """
        Validate DNP3 packet
        
        Args:
            packet_data: Raw DNP3 packet bytes
            
        Returns:
            Tuple of (is_valid, confidence, details)
        """
        self.stats['total_packets'] += 1
        confidence = 1.0
        details = []
        
        if len(packet_data) < 10:
            self.stats['invalid_packets'] += 1
            return False, 0.0, "Packet too short"
        
        # Check DNP3 start bytes (0x05 0x64)
        if packet_data[0] != 0x05 or packet_data[1] != 0x64:
            self.stats['invalid_packets'] += 1
            return False, 0.0, "Invalid DNP3 start bytes"
        
        # Extract function code
        try:
            function_code = packet_data[11] if len(packet_data) > 11 else 0
            
            # Check if function code is valid
            if function_code not in self.valid_function_codes:
                confidence -= 0.3
                details.append(f"Unknown function code: {hex(function_code)}")
            
            # Check if operation is allowed
            if function_code not in self.allowed_operations:
                self.stats['security_violations'] += 1
                confidence -= 0.5
                details.append(f"Restricted operation: {hex(function_code)}")
                
                # Log security violation
                violation = {
                    'type': 'dnp3_restricted_operation',
                    'function_code': hex(function_code),
                    'timestamp': datetime.now()
                }
                self.suspicious_activities.append(violation)
                logger.warning(f"DNP3 Security Violation: Restricted operation {hex(function_code)}")
            
            # Check for critical commands
            if function_code in [DNP3FunctionCode.COLD_RESTART.value, 
                                DNP3FunctionCode.WARM_RESTART.value]:
                details.append("CRITICAL: System restart command detected")
                logger.critical(f"DNP3 CRITICAL: Restart command detected!")
            
        except Exception as e:
            self.stats['invalid_packets'] += 1
            return False, 0.0, f"Packet parsing error: {str(e)}"
        
        is_valid = confidence >= 0.5
        
        if is_valid:
            self.stats['valid_packets'] += 1
        else:
            self.stats['invalid_packets'] += 1
        
        return is_valid, confidence, "; ".join(details) if details else "Valid DNP3 packet"
    
    def get_statistics(self) -> Dict:
        """Get validation statistics"""
        return self.stats


class ModbusValidator:
    """
    Validates Modbus protocol communications
    Used in industrial control systems and maritime automation
    """
    
    def __init__(self):
        """Initialize Modbus validator"""
        self.valid_function_codes = [fc.value for fc in ModbusFunctionCode]
        self.register_access_log = []
        self.anomalies = []
        self.stats = {
            'total_requests': 0,
            'valid_requests': 0,
            'invalid_requests': 0,
            'write_operations': 0,
            'suspicious_writes': 0
        }
    
    def validate_request(self, request_data: bytes) -> Tuple[bool, float, str]:
        """
        Validate Modbus request
        
        Args:
            request_data: Raw Modbus request bytes
            
        Returns:
            Tuple of (is_valid, confidence, details)
        """
        self.stats['total_requests'] += 1
        confidence = 1.0
        details = []
        
        if len(request_data) < 8:
            self.stats['invalid_requests'] += 1
            return False, 0.0, "Request too short"
        
        try:
            # Parse Modbus TCP/RTU header
            function_code = request_data[7] if len(request_data) > 7 else request_data[1]
            
            # Validate function code
            if function_code not in self.valid_function_codes:
                confidence -= 0.4
                details.append(f"Invalid function code: {hex(function_code)}")
            
            # Check for write operations
            if function_code in [ModbusFunctionCode.WRITE_SINGLE_COIL.value,
                               ModbusFunctionCode.WRITE_SINGLE_REGISTER.value,
                               ModbusFunctionCode.WRITE_MULTIPLE_COILS.value,
                               ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS.value]:
                self.stats['write_operations'] += 1
                
                # Extract register address if possible
                if len(request_data) >= 10:
                    register_addr = struct.unpack('>H', request_data[8:10])[0]
                    
                    # Check for critical registers (example: 0x1000-0x1FFF)
                    if 0x1000 <= register_addr <= 0x1FFF:
                        self.stats['suspicious_writes'] += 1
                        confidence -= 0.3
                        details.append(f"Write to critical register: {hex(register_addr)}")
                        
                        anomaly = {
                            'type': 'modbus_critical_write',
                            'function_code': hex(function_code),
                            'register': hex(register_addr),
                            'timestamp': datetime.now()
                        }
                        self.anomalies.append(anomaly)
                        logger.warning(f"MODBUS: Write to critical register {hex(register_addr)}")
            
        except Exception as e:
            self.stats['invalid_requests'] += 1
            return False, 0.0, f"Parsing error: {str(e)}"
        
        is_valid = confidence >= 0.5
        
        if is_valid:
            self.stats['valid_requests'] += 1
        else:
            self.stats['invalid_requests'] += 1
        
        return is_valid, confidence, "; ".join(details) if details else "Valid Modbus request"
    
    def get_statistics(self) -> Dict:
        """Get validation statistics"""
        return self.stats


class CANBusDetector:
    """
    Validates CAN bus (Controller Area Network) messages
    Used in vehicle networks and maritime engine control systems
    """
    
    def __init__(self):
        """Initialize CAN bus detector"""
        self.known_ids = set()
        self.message_rates = {}
        self.anomalies = []
        self.stats = {
            'total_messages': 0,
            'valid_messages': 0,
            'unknown_ids': 0,
            'rate_anomalies': 0
        }
    
    def register_known_id(self, can_id: int, expected_rate: float = None):
        """
        Register known CAN ID
        
        Args:
            can_id: CAN identifier
            expected_rate: Expected message rate (messages/second)
        """
        self.known_ids.add(can_id)
        if expected_rate:
            self.message_rates[can_id] = {
                'expected': expected_rate,
                'count': 0,
                'last_check': datetime.now()
            }
    
    def validate_message(self, can_id: int, data: bytes, timestamp: datetime = None) -> Tuple[bool, float, str]:
        """
        Validate CAN message
        
        Args:
            can_id: CAN identifier
            data: Message data (up to 8 bytes)
            timestamp: Message timestamp
            
        Returns:
            Tuple of (is_valid, confidence, details)
        """
        self.stats['total_messages'] += 1
        confidence = 1.0
        details = []
        timestamp = timestamp or datetime.now()
        
        # Check data length
        if len(data) > 8:
            return False, 0.0, "CAN data exceeds 8 bytes"
        
        # Check if ID is known
        if can_id not in self.known_ids:
            self.stats['unknown_ids'] += 1
            confidence -= 0.4
            details.append(f"Unknown CAN ID: {hex(can_id)}")
            
            anomaly = {
                'type': 'can_unknown_id',
                'can_id': hex(can_id),
                'timestamp': timestamp
            }
            self.anomalies.append(anomaly)
            logger.warning(f"CAN: Unknown ID {hex(can_id)}")
        
        # Check message rate
        if can_id in self.message_rates:
            rate_info = self.message_rates[can_id]
            rate_info['count'] += 1
            
            # Check if enough time has passed for rate calculation
            time_diff = (timestamp - rate_info['last_check']).total_seconds()
            if time_diff >= 1.0:  # Check every second
                actual_rate = rate_info['count'] / time_diff
                expected_rate = rate_info['expected']
                
                # Check for rate anomalies (>50% deviation)
                if abs(actual_rate - expected_rate) / expected_rate > 0.5:
                    self.stats['rate_anomalies'] += 1
                    confidence -= 0.3
                    details.append(f"Rate anomaly: {actual_rate:.1f} msg/s (expected {expected_rate:.1f})")
                    
                    anomaly = {
                        'type': 'can_rate_anomaly',
                        'can_id': hex(can_id),
                        'expected_rate': expected_rate,
                        'actual_rate': actual_rate,
                        'timestamp': timestamp
                    }
                    self.anomalies.append(anomaly)
                
                # Reset counter
                rate_info['count'] = 0
                rate_info['last_check'] = timestamp
        
        is_valid = confidence >= 0.5
        
        if is_valid:
            self.stats['valid_messages'] += 1
        
        return is_valid, confidence, "; ".join(details) if details else "Valid CAN message"
    
    def get_statistics(self) -> Dict:
        """Get validation statistics"""
        return self.stats


class ZigbeeIoTMonitor:
    """
    Monitors Zigbee and IoT device communications
    Used in maritime sensor networks and automation
    """
    
    def __init__(self):
        """Initialize Zigbee/IoT monitor"""
        self.registered_devices = {}
        self.device_activity = {}
        self.security_events = []
        self.stats = {
            'total_packets': 0,
            'authenticated': 0,
            'unauthenticated': 0,
            'encryption_failures': 0
        }
    
    def register_device(self, device_id: str, device_type: str, encryption_key: Optional[bytes] = None):
        """
        Register IoT device
        
        Args:
            device_id: Device identifier
            device_type: Type of device (sensor, actuator, gateway)
            encryption_key: Optional encryption key
        """
        self.registered_devices[device_id] = {
            'type': device_type,
            'encryption_key': encryption_key,
            'registered_at': datetime.now()
        }
        logger.info(f"Registered IoT device: {device_id} ({device_type})")
    
    def validate_communication(self, device_id: str, packet_data: Dict) -> Tuple[bool, float, str]:
        """
        Validate IoT device communication
        
        Args:
            device_id: Device identifier
            packet_data: Packet information (encrypted, authenticated, signal_strength)
            
        Returns:
            Tuple of (is_valid, confidence, details)
        """
        self.stats['total_packets'] += 1
        confidence = 1.0
        details = []
        
        # Check if device is registered
        if device_id not in self.registered_devices:
            confidence -= 0.5
            details.append(f"Unregistered device: {device_id}")
            
            event = {
                'type': 'iot_unregistered_device',
                'device_id': device_id,
                'timestamp': datetime.now()
            }
            self.security_events.append(event)
            logger.warning(f"IoT: Unregistered device {device_id}")
        
        # Check authentication
        if not packet_data.get('authenticated', False):
            self.stats['unauthenticated'] += 1
            confidence -= 0.4
            details.append("Packet not authenticated")
        else:
            self.stats['authenticated'] += 1
        
        # Check encryption
        if device_id in self.registered_devices:
            device_info = self.registered_devices[device_id]
            if device_info['encryption_key'] and not packet_data.get('encrypted', False):
                self.stats['encryption_failures'] += 1
                confidence -= 0.3
                details.append("Expected encrypted packet")
                
                event = {
                    'type': 'iot_encryption_missing',
                    'device_id': device_id,
                    'timestamp': datetime.now()
                }
                self.security_events.append(event)
        
        # Check signal strength (weak signal may indicate spoofing)
        signal_strength = packet_data.get('signal_strength', -50)
        if signal_strength < -80:  # Very weak signal
            confidence -= 0.2
            details.append(f"Weak signal: {signal_strength} dBm")
        
        is_valid = confidence >= 0.5
        
        return is_valid, confidence, "; ".join(details) if details else "Valid IoT communication"
    
    def get_statistics(self) -> Dict:
        """Get validation statistics"""
        return self.stats


class SatelliteCommValidator:
    """
    Validates satellite communications (INMARSAT, Iridium, GPS)
    Critical for maritime navigation and communication
    """
    
    def __init__(self):
        """Initialize satellite communication validator"""
        self.valid_satellites = {}
        self.gps_integrity = True
        self.comm_log = []
        self.stats = {
            'total_messages': 0,
            'valid_messages': 0,
            'integrity_failures': 0,
            'authentication_failures': 0
        }
    
    def register_satellite(self, satellite_id: str, comm_type: str):
        """
        Register valid satellite
        
        Args:
            satellite_id: Satellite identifier
            comm_type: Communication type (GPS, INMARSAT, Iridium)
        """
        self.valid_satellites[satellite_id] = {
            'type': comm_type,
            'registered_at': datetime.now()
        }
        logger.info(f"Registered satellite: {satellite_id} ({comm_type})")
    
    def validate_gps_signal(self, gps_data: Dict) -> Tuple[bool, float, str]:
        """
        Validate GPS signal integrity
        
        Args:
            gps_data: GPS data (satellites, hdop, signal_strength)
            
        Returns:
            Tuple of (is_valid, confidence, details)
        """
        self.stats['total_messages'] += 1
        confidence = 1.0
        details = []
        
        # Check number of satellites
        num_satellites = gps_data.get('num_satellites', 0)
        if num_satellites < 4:
            confidence -= 0.3
            details.append(f"Insufficient satellites: {num_satellites}")
        
        # Check HDOP (Horizontal Dilution of Precision)
        hdop = gps_data.get('hdop', 999)
        if hdop > 5:
            confidence -= 0.2
            details.append(f"Poor HDOP: {hdop}")
        
        # Check for GPS spoofing indicators
        if gps_data.get('signal_strength', 0) > 50:  # Unusually strong signal
            confidence -= 0.4
            details.append("Possible GPS spoofing (signal too strong)")
            self.stats['integrity_failures'] += 1
        
        # Check time consistency
        if 'timestamp_drift' in gps_data:
            drift = abs(gps_data['timestamp_drift'])
            if drift > 1.0:  # More than 1 second drift
                confidence -= 0.3
                details.append(f"Time drift: {drift:.2f}s")
        
        is_valid = confidence >= 0.5
        
        if is_valid:
            self.stats['valid_messages'] += 1
        else:
            self.stats['integrity_failures'] += 1
        
        return is_valid, confidence, "; ".join(details) if details else "Valid GPS signal"
    
    def validate_satcom_message(self, satellite_id: str, message_data: Dict) -> Tuple[bool, float, str]:
        """
        Validate satellite communication message
        
        Args:
            satellite_id: Satellite identifier
            message_data: Message data (encrypted, authenticated, signal_quality)
            
        Returns:
            Tuple of (is_valid, confidence, details)
        """
        self.stats['total_messages'] += 1
        confidence = 1.0
        details = []
        
        # Check if satellite is registered
        if satellite_id not in self.valid_satellites:
            confidence -= 0.4
            details.append(f"Unknown satellite: {satellite_id}")
        
        # Check authentication
        if not message_data.get('authenticated', False):
            self.stats['authentication_failures'] += 1
            confidence -= 0.5
            details.append("Message not authenticated")
        
        # Check encryption
        if not message_data.get('encrypted', False):
            confidence -= 0.3
            details.append("Message not encrypted")
        
        # Check signal quality
        signal_quality = message_data.get('signal_quality', 0)
        if signal_quality < 3:  # Quality scale 1-5
            confidence -= 0.2
            details.append(f"Poor signal quality: {signal_quality}/5")
        
        is_valid = confidence >= 0.5
        
        if is_valid:
            self.stats['valid_messages'] += 1
        
        return is_valid, confidence, "; ".join(details) if details else "Valid satellite communication"
    
    def get_statistics(self) -> Dict:
        """Get validation statistics"""
        return self.stats


if __name__ == "__main__":
    # Test protocol validators
    print("Testing Industrial Protocol Validators...")
    
    # Test DNP3
    print("\n1. DNP3 Validator")
    dnp3 = DNP3Validator()
    # Simulate DNP3 packet (simplified)
    test_packet = bytes([0x05, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
    is_valid, conf, details = dnp3.validate_packet(test_packet)
    print(f"Valid: {is_valid}, Confidence: {conf:.2f}, Details: {details}")
    
    # Test Modbus
    print("\n2. Modbus Validator")
    modbus = ModbusValidator()
    test_request = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
    is_valid, conf, details = modbus.validate_request(test_request)
    print(f"Valid: {is_valid}, Confidence: {conf:.2f}, Details: {details}")
    
    # Test CAN Bus
    print("\n3. CAN Bus Detector")
    can = CANBusDetector()
    can.register_known_id(0x100, expected_rate=10.0)
    is_valid, conf, details = can.validate_message(0x100, bytes([0x01, 0x02, 0x03, 0x04]))
    print(f"Valid: {is_valid}, Confidence: {conf:.2f}, Details: {details}")
    
    # Test Satellite
    print("\n4. Satellite Communication Validator")
    satcom = SatelliteCommValidator()
    gps_data = {'num_satellites': 8, 'hdop': 1.2, 'signal_strength': 35}
    is_valid, conf, details = satcom.validate_gps_signal(gps_data)
    print(f"Valid GPS: {is_valid}, Confidence: {conf:.2f}, Details: {details}")
    
    print("\n✓ All protocol validators tested!")
