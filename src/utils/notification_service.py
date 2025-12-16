"""
Notification Service for Alert Distribution
Supports Email, SMS, and In-App notifications
"""

import smtplib
import logging
from email.message import EmailMessage
from datetime import datetime
from typing import List, Dict, Optional
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class NotificationService:
    """Handle multi-channel alert notifications"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize notification service
        
        Args:
            config_path: Path to notification configuration file
        """
        self.config = self._load_config(config_path)
        self.notification_history = []
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load notification configuration"""
        default_config = {
            'email': {
                'enabled': False,  # Email disabled - only in-app notifications
                'provider': 'mailtrap',  # Using Mailtrap for testing - no password needed!
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'api_key': '',  # Get free token from mailtrap.io
                'from_address': 'maritime-ids@example.com',
                'use_tls': True,
                'domain': ''  # For Mailgun
            },
            'sms': {
                'enabled': False,  # SMS disabled - only in-app notifications
                'provider': 'twilio',
                'account_sid': '',
                'auth_token': '',
                'from_number': ''
            },
            'notification_rules': {
                'CRITICAL': {
                    'channels': ['in-app'],  # Only web dashboard notifications
                    'immediate': True,
                    'escalate_after_minutes': 5
                },
                'HIGH': {
                    'channels': ['in-app'],  # Only web dashboard notifications
                    'immediate': True,
                    'escalate_after_minutes': 15
                },
                'MEDIUM': {
                    'channels': ['in-app'],
                    'immediate': False,
                    'batch_interval_minutes': 30
                },
                'INFO': {
                    'channels': ['in-app'],
                    'immediate': False,
                    'batch_interval_minutes': 60
                }
            }
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    # Merge with defaults
                    default_config.update(user_config)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return default_config
    
    def send_email(self, to_addresses: List[str], subject: str, body: str, html_body: Optional[str] = None) -> bool:
        """
        Send email notification
        
        Args:
            to_addresses: List of recipient email addresses
            subject: Email subject
            body: Plain text body
            html_body: Optional HTML body
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.config['email']['enabled']:
            logger.info("Email notifications disabled")
            return False
        
        email_config = self.config['email']
        provider = email_config.get('provider', 'smtp')
        
        try:
            if provider == 'smtp':
                return self._send_email_smtp(to_addresses, subject, body, html_body)
            elif provider == 'sendgrid':
                return self._send_email_sendgrid(to_addresses, subject, body, html_body)
            elif provider == 'mailgun':
                return self._send_email_mailgun(to_addresses, subject, body, html_body)
            elif provider == 'mailtrap':
                return self._send_email_mailtrap(to_addresses, subject, body, html_body)
            else:
                logger.error(f"Unsupported email provider: {provider}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            self._log_notification('email', to_addresses, subject, 'failed', str(e))
            return False
    
    def _send_email_smtp(self, to_addresses: List[str], subject: str, body: str, html_body: Optional[str] = None) -> bool:
        """Send email via SMTP"""
        email_config = self.config['email']
        
        # Check if credentials are configured
        if not email_config['username'] or not email_config['password']:
            logger.warning("SMTP credentials not configured - skipping email")
            return False
        
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = email_config['from_address']
            msg['To'] = ', '.join(to_addresses)
            
            msg.set_content(body)
            
            if html_body:
                msg.add_alternative(html_body, subtype='html')
            
            # Connect to SMTP server
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                if email_config['use_tls']:
                    server.starttls()
                
                server.login(email_config['username'], email_config['password'])
                server.send_message(msg)
            
            logger.info(f"Email sent via SMTP to {len(to_addresses)} recipients")
            self._log_notification('email', to_addresses, subject, 'sent')
            return True
            
        except Exception as e:
            logger.error(f"SMTP email failed: {e}")
            return False
    
    def _send_email_sendgrid(self, to_addresses: List[str], subject: str, body: str, html_body: Optional[str] = None) -> bool:
        """Send email via SendGrid API"""
        email_config = self.config['email']
        
        if not email_config.get('api_key'):
            logger.warning("SendGrid API key not configured")
            return False
        
        try:
            import requests
            
            url = "https://api.sendgrid.com/v3/mail/send"
            headers = {
                "Authorization": f"Bearer {email_config['api_key']}",
                "Content-Type": "application/json"
            }
            
            data = {
                "personalizations": [{"to": [{"email": addr} for addr in to_addresses]}],
                "from": {"email": email_config['from_address']},
                "subject": subject,
                "content": [
                    {"type": "text/plain", "value": body}
                ]
            }
            
            if html_body:
                data["content"].append({"type": "text/html", "value": html_body})
            
            response = requests.post(url, json=data, headers=headers)
            
            if response.status_code == 202:
                logger.info(f"Email sent via SendGrid to {len(to_addresses)} recipients")
                self._log_notification('email', to_addresses, subject, 'sent')
                return True
            else:
                logger.error(f"SendGrid error: {response.status_code} - {response.text}")
                return False
                
        except ImportError:
            logger.error("requests package not installed. Run: pip install requests")
            return False
        except Exception as e:
            logger.error(f"SendGrid email failed: {e}")
            return False
    
    def _send_email_mailgun(self, to_addresses: List[str], subject: str, body: str, html_body: Optional[str] = None) -> bool:
        """Send email via Mailgun API"""
        email_config = self.config['email']
        
        if not email_config.get('api_key'):
            logger.warning("Mailgun API key not configured")
            return False
        
        if not email_config.get('domain'):
            logger.warning("Mailgun domain not configured")
            return False
        
        try:
            import requests
            
            domain = email_config['domain']
            url = f"https://api.mailgun.net/v3/{domain}/messages"
            
            data = {
                "from": email_config['from_address'],
                "to": to_addresses,
                "subject": subject,
                "text": body
            }
            
            if html_body:
                data["html"] = html_body
            
            response = requests.post(
                url,
                auth=("api", email_config['api_key']),
                data=data
            )
            
            if response.status_code == 200:
                logger.info(f"Email sent via Mailgun to {len(to_addresses)} recipients")
                self._log_notification('email', to_addresses, subject, 'sent')
                return True
            else:
                logger.error(f"Mailgun error: {response.status_code} - {response.text}")
                return False
                
        except ImportError:
            logger.error("requests package not installed. Run: pip install requests")
            return False
        except Exception as e:
            logger.error(f"Mailgun email failed: {e}")
            return False
    
    def _send_email_mailtrap(self, to_addresses: List[str], subject: str, body: str, html_body: Optional[str] = None) -> bool:
        """Send email via Mailtrap (testing service)"""
        email_config = self.config['email']
        
        if not email_config.get('api_key'):
            logger.warning("Mailtrap API key not configured")
            return False
        
        try:
            import requests
            
            url = "https://send.api.mailtrap.io/api/send"
            headers = {
                "Authorization": f"Bearer {email_config['api_key']}",
                "Content-Type": "application/json"
            }
            
            data = {
                "from": {"email": email_config['from_address']},
                "to": [{"email": addr} for addr in to_addresses],
                "subject": subject,
                "text": body
            }
            
            if html_body:
                data["html"] = html_body
            
            response = requests.post(url, json=data, headers=headers)
            
            if response.status_code == 200:
                logger.info(f"Email sent via Mailtrap to {len(to_addresses)} recipients")
                self._log_notification('email', to_addresses, subject, 'sent')
                return True
            else:
                logger.error(f"Mailtrap error: {response.status_code} - {response.text}")
                return False
                
        except ImportError:
            logger.error("requests package not installed. Run: pip install requests")
            return False
        except Exception as e:
            logger.error(f"Mailtrap email failed: {e}")
            return False
    
    def send_sms(self, to_numbers: List[str], message: str) -> bool:
        """
        Send SMS notification
        
        Args:
            to_numbers: List of phone numbers
            message: SMS message text
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.config['sms']['enabled']:
            logger.info("SMS notifications disabled")
            return False
        
        sms_config = self.config['sms']
        
        # Check if configured
        if not sms_config['account_sid'] or not sms_config['auth_token']:
            logger.warning("SMS credentials not configured - skipping SMS")
            return False
        
        try:
            # Twilio integration (requires twilio package)
            if sms_config['provider'] == 'twilio':
                try:
                    from twilio.rest import Client  # type: ignore
                    
                    client = Client(sms_config['account_sid'], sms_config['auth_token'])
                    
                    for number in to_numbers:
                        message_obj = client.messages.create(
                            body=message,
                            from_=sms_config['from_number'],
                            to=number
                        )
                        logger.info(f"SMS sent to {number}: {message_obj.sid}")
                    
                    self._log_notification('sms', to_numbers, message, 'sent')
                    return True
                    
                except ImportError:
                    logger.error("Twilio package not installed. Run: pip install twilio")
                    return False
            else:
                logger.error(f"Unsupported SMS provider: {sms_config['provider']}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send SMS: {e}")
            self._log_notification('sms', to_numbers, message, 'failed', str(e))
            return False
    
    def send_alert_notification(self, alert: Dict, recipients: Dict[str, List[str]]) -> Dict[str, bool]:
        """
        Send alert notification through appropriate channels
        
        Args:
            alert: Alert dictionary with type, severity, message, etc.
            recipients: Dict with 'email' and 'sms' keys containing recipient lists
            
        Returns:
            Dict with channel names and success status
        """
        severity = alert.get('severity', 'INFO')
        rules = self.config['notification_rules'].get(severity, {})
        channels = rules.get('channels', ['in-app'])
        
        results = {}
        
        # Email notification
        if 'email' in channels and recipients.get('email'):
            subject = f"[{severity}] Maritime IDS Alert: {alert.get('type', 'Unknown')} Attack"
            body = self._format_email_body(alert)
            html_body = self._format_html_email_body(alert)
            
            results['email'] = self.send_email(
                recipients['email'],
                subject,
                body,
                html_body
            )
        
        # SMS notification
        if 'sms' in channels and recipients.get('sms'):
            sms_message = self._format_sms_body(alert)
            results['sms'] = self.send_sms(recipients['sms'], sms_message)
        
        # In-app notification (always enabled, handled by WebSocket)
        results['in-app'] = True
        
        return results
    
    def _format_email_body(self, alert: Dict) -> str:
        """Format plain text email body"""
        return f"""
Maritime Intrusion Detection System Alert

Alert ID: {alert.get('id', 'N/A')}
Severity: {alert.get('severity', 'UNKNOWN')}
Attack Type: {alert.get('type', 'Unknown')}
Timestamp: {alert.get('timestamp', datetime.now().isoformat())}

Source IP: {alert.get('source_ip', 'Unknown')}
Destination IP: {alert.get('destination_ip', 'Unknown')}

Message:
{alert.get('message', 'No details available')}

Recommended Actions:
{chr(10).join(f"- {rec}" for rec in alert.get('recommendations', ['Monitor the situation']))}

---
This is an automated alert from the Maritime Intrusion Detection System.
Please review the dashboard for more details: http://localhost:5000/realtime_monitor
"""
    
    def _format_html_email_body(self, alert: Dict) -> str:
        """Format HTML email body"""
        severity_colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#f59e0b',
            'MEDIUM': '#eab308',
            'INFO': '#3b82f6'
        }
        color = severity_colors.get(alert.get('severity', 'INFO'), '#3b82f6')
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: {color}; color: white; padding: 20px; border-radius: 5px; }}
        .content {{ background: #f9fafb; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .field {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #4b5563; }}
        .value {{ color: #1f2937; }}
        .recommendations {{ background: white; padding: 15px; border-left: 4px solid {color}; }}
        .footer {{ text-align: center; color: #6b7280; font-size: 12px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🚨 Maritime IDS Alert</h2>
            <p>{alert.get('severity', 'UNKNOWN')} Severity</p>
        </div>
        
        <div class="content">
            <div class="field">
                <span class="label">Alert ID:</span>
                <span class="value">{alert.get('id', 'N/A')}</span>
            </div>
            <div class="field">
                <span class="label">Attack Type:</span>
                <span class="value">{alert.get('type', 'Unknown')}</span>
            </div>
            <div class="field">
                <span class="label">Timestamp:</span>
                <span class="value">{alert.get('timestamp', datetime.now().isoformat())}</span>
            </div>
            <div class="field">
                <span class="label">Source IP:</span>
                <span class="value">{alert.get('source_ip', 'Unknown')}</span>
            </div>
            <div class="field">
                <span class="label">Destination IP:</span>
                <span class="value">{alert.get('destination_ip', 'Unknown')}</span>
            </div>
        </div>
        
        <div class="recommendations">
            <h3>Recommended Actions:</h3>
            <ul>
                {''.join(f"<li>{rec}</li>" for rec in alert.get('recommendations', ['Monitor the situation']))}
            </ul>
        </div>
        
        <div class="footer">
            <p>This is an automated alert from the Maritime Intrusion Detection System.</p>
            <p><a href="http://localhost:5000/realtime_monitor">View Dashboard</a></p>
        </div>
    </div>
</body>
</html>
"""
    
    def _format_sms_body(self, alert: Dict) -> str:
        """Format SMS body (keep it short)"""
        return f"[{alert.get('severity')}] Maritime IDS: {alert.get('type')} attack from {alert.get('source_ip')}. Check dashboard immediately."
    
    def _log_notification(self, channel: str, recipients: List[str], content: str, status: str, error: Optional[str] = None):
        """Log notification attempt"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'channel': channel,
            'recipients': recipients,
            'content': content[:100],  # Truncate
            'status': status,
            'error': error
        }
        self.notification_history.append(log_entry)
        
        # Keep last 1000 entries
        if len(self.notification_history) > 1000:
            self.notification_history = self.notification_history[-1000:]
    
    def get_notification_history(self, limit: int = 50) -> List[Dict]:
        """Get recent notification history"""
        return self.notification_history[-limit:]
    
    def update_config(self, config_updates: Dict):
        """Update notification configuration"""
        self.config.update(config_updates)
        logger.info("Notification configuration updated")
    
    def test_email(self, to_address: str) -> bool:
        """Send test email to verify configuration"""
        return self.send_email(
            [to_address],
            "Maritime IDS - Test Email",
            "This is a test email from the Maritime Intrusion Detection System. If you received this, email notifications are working correctly.",
            "<html><body><h2>Test Email</h2><p>Email notifications are configured correctly!</p></body></html>"
        )
    
    def test_sms(self, to_number: str) -> bool:
        """Send test SMS to verify configuration"""
        return self.send_sms(
            [to_number],
            "Maritime IDS: Test SMS - Notifications working correctly!"
        )


# Test the notification service
if __name__ == "__main__":
    print("Testing Notification Service...")
    
    service = NotificationService()
    
    # Test alert
    test_alert = {
        'id': 'TEST_001',
        'severity': 'HIGH',
        'type': 'Dos',
        'timestamp': datetime.now().isoformat(),
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'message': 'DoS attack detected from external source',
        'recommendations': [
            'Enable rate limiting',
            'Block source IP',
            'Notify network administrator'
        ]
    }
    
    print("\n1. Email Body Preview:")
    print("-" * 80)
    print(service._format_email_body(test_alert))
    
    print("\n2. SMS Body Preview:")
    print("-" * 80)
    print(service._format_sms_body(test_alert))
    
    print("\n3. Notification Rules:")
    print("-" * 80)
    for severity, rules in service.config['notification_rules'].items():
        print(f"{severity}: {rules['channels']}")
    
    print("\n4. Supported Email Providers:")
    print("-" * 80)
    print("- smtp: Traditional SMTP (requires username/password)")
    print("- sendgrid: SendGrid API (requires API key)")
    print("- mailgun: Mailgun API (requires API key + domain)")
    print("- mailtrap: Mailtrap API (requires API key, for testing)")
    
    print("\n✅ Test complete!")
