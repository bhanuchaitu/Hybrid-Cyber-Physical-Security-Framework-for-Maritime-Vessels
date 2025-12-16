"""
Web Attack Detector - SQL Injection, XSS, and Web-based Attacks
Part of Enhanced Attack Detection Capabilities
"""
import re
import logging
from datetime import datetime
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class WebAttackDetector:
    """
    Detects web-based attacks including SQL Injection, XSS, CSRF, etc.
    """
    
    def __init__(self):
        """Initialize web attack detector with patterns"""
        self.sql_injection_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"exec(\s|\+)+(s|x)p\w+",
            r"UNION.*SELECT",
            r"INSERT.*INTO",
            r"DELETE.*FROM",
            r"DROP.*TABLE",
            r"UPDATE.*SET",
            r"SELECT.*FROM.*WHERE"
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"eval\(",
            r"expression\(",
            r"vbscript:",
            r"<img[^>]+src[^>]*>",
        ]
        
        self.command_injection_patterns = [
            r";\s*(ls|cat|wget|curl|nc|bash|sh|cmd)",
            r"\|\s*(ls|cat|wget|curl|nc|bash|sh|cmd)",
            r"&&\s*(ls|cat|wget|curl|nc|bash|sh|cmd)",
            r"`.*`",
            r"\$\(.*\)",
        ]
        
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e/",
            r"%2e%2e\\",
            r"file://",
        ]
        
        self.attack_statistics = {
            'sql_injection': 0,
            'xss': 0,
            'command_injection': 0,
            'path_traversal': 0,
            'csrf': 0,
            'total_checked': 0
        }
    
    def detect_sql_injection(self, input_data: str) -> Tuple[bool, float, str]:
        """
        Detect SQL injection attempts
        
        Args:
            input_data: Input string to analyze
            
        Returns:
            Tuple of (is_attack, confidence, attack_details)
        """
        if not input_data:
            return False, 0.0, ""
        
        matches = []
        confidence = 0.0
        
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                matches.append(pattern)
                confidence += 0.2
        
        if matches:
            confidence = min(confidence, 1.0)
            self.attack_statistics['sql_injection'] += 1
            details = f"SQL Injection detected: {len(matches)} patterns matched"
            logger.warning(f"SQL Injection detected: {input_data[:100]}")
            return True, confidence, details
        
        return False, 0.0, ""
    
    def detect_xss(self, input_data: str) -> Tuple[bool, float, str]:
        """
        Detect Cross-Site Scripting (XSS) attempts
        
        Args:
            input_data: Input string to analyze
            
        Returns:
            Tuple of (is_attack, confidence, attack_details)
        """
        if not input_data:
            return False, 0.0, ""
        
        matches = []
        confidence = 0.0
        
        for pattern in self.xss_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                matches.append(pattern)
                confidence += 0.25
        
        if matches:
            confidence = min(confidence, 1.0)
            self.attack_statistics['xss'] += 1
            details = f"XSS attack detected: {len(matches)} patterns matched"
            logger.warning(f"XSS detected: {input_data[:100]}")
            return True, confidence, details
        
        return False, 0.0, ""
    
    def detect_command_injection(self, input_data: str) -> Tuple[bool, float, str]:
        """
        Detect command injection attempts
        
        Args:
            input_data: Input string to analyze
            
        Returns:
            Tuple of (is_attack, confidence, attack_details)
        """
        if not input_data:
            return False, 0.0, ""
        
        matches = []
        confidence = 0.0
        
        for pattern in self.command_injection_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                matches.append(pattern)
                confidence += 0.3
        
        if matches:
            confidence = min(confidence, 1.0)
            self.attack_statistics['command_injection'] += 1
            details = f"Command injection detected: {len(matches)} patterns matched"
            logger.warning(f"Command injection detected: {input_data[:100]}")
            return True, confidence, details
        
        return False, 0.0, ""
    
    def detect_path_traversal(self, input_data: str) -> Tuple[bool, float, str]:
        """
        Detect path traversal attempts
        
        Args:
            input_data: Input string to analyze
            
        Returns:
            Tuple of (is_attack, confidence, attack_details)
        """
        if not input_data:
            return False, 0.0, ""
        
        matches = []
        confidence = 0.0
        
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                matches.append(pattern)
                confidence += 0.25
        
        if matches:
            confidence = min(confidence, 1.0)
            self.attack_statistics['path_traversal'] += 1
            details = f"Path traversal detected: {len(matches)} patterns matched"
            logger.warning(f"Path traversal detected: {input_data[:100]}")
            return True, confidence, details
        
        return False, 0.0, ""
    
    def analyze_request(self, request_data: Dict) -> Dict:
        """
        Analyze a complete HTTP request for all web attack types
        
        Args:
            request_data: Dictionary containing request components
            
        Returns:
            Dictionary with detection results
        """
        self.attack_statistics['total_checked'] += 1
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'is_malicious': False,
            'attacks_detected': [],
            'max_confidence': 0.0,
            'recommendations': []
        }
        
        # Combine all request data
        combined_data = ' '.join([
            str(request_data.get('url', '')),
            str(request_data.get('params', '')),
            str(request_data.get('headers', '')),
            str(request_data.get('body', ''))
        ])
        
        # Check for SQL injection
        is_sqli, sqli_conf, sqli_details = self.detect_sql_injection(combined_data)
        if is_sqli:
            results['attacks_detected'].append({
                'type': 'SQL Injection',
                'confidence': sqli_conf,
                'details': sqli_details
            })
            results['is_malicious'] = True
            results['max_confidence'] = max(results['max_confidence'], sqli_conf)
            results['recommendations'].append("Block request and sanitize database inputs")
        
        # Check for XSS
        is_xss, xss_conf, xss_details = self.detect_xss(combined_data)
        if is_xss:
            results['attacks_detected'].append({
                'type': 'Cross-Site Scripting (XSS)',
                'confidence': xss_conf,
                'details': xss_details
            })
            results['is_malicious'] = True
            results['max_confidence'] = max(results['max_confidence'], xss_conf)
            results['recommendations'].append("Sanitize output and implement CSP headers")
        
        # Check for command injection
        is_cmd, cmd_conf, cmd_details = self.detect_command_injection(combined_data)
        if is_cmd:
            results['attacks_detected'].append({
                'type': 'Command Injection',
                'confidence': cmd_conf,
                'details': cmd_details
            })
            results['is_malicious'] = True
            results['max_confidence'] = max(results['max_confidence'], cmd_conf)
            results['recommendations'].append("Block request and review command execution code")
        
        # Check for path traversal
        is_path, path_conf, path_details = self.detect_path_traversal(combined_data)
        if is_path:
            results['attacks_detected'].append({
                'type': 'Path Traversal',
                'confidence': path_conf,
                'details': path_details
            })
            results['is_malicious'] = True
            results['max_confidence'] = max(results['max_confidence'], path_conf)
            results['recommendations'].append("Validate and sanitize file paths")
        
        if results['is_malicious']:
            logger.warning(f"Malicious request detected with {len(results['attacks_detected'])} attack types")
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get attack detection statistics"""
        return {
            **self.attack_statistics,
            'detection_rate': self.attack_statistics['sql_injection'] + 
                            self.attack_statistics['xss'] + 
                            self.attack_statistics['command_injection'] + 
                            self.attack_statistics['path_traversal']
        }
    
    def reset_statistics(self):
        """Reset attack statistics"""
        for key in self.attack_statistics:
            self.attack_statistics[key] = 0


if __name__ == "__main__":
    # Test the detector
    detector = WebAttackDetector()
    
    # Test SQL injection
    test_requests = [
        {
            'url': '/login?username=admin&password=\' OR 1=1--',
            'params': {},
            'headers': {},
            'body': ''
        },
        {
            'url': '/search?q=<script>alert("XSS")</script>',
            'params': {},
            'headers': {},
            'body': ''
        },
        {
            'url': '/file?path=../../etc/passwd',
            'params': {},
            'headers': {},
            'body': ''
        }
    ]
    
    for req in test_requests:
        result = detector.analyze_request(req)
        print(f"\nRequest: {req['url']}")
        print(f"Malicious: {result['is_malicious']}")
        print(f"Attacks: {[a['type'] for a in result['attacks_detected']]}")
    
    print(f"\nStatistics: {detector.get_statistics()}")
