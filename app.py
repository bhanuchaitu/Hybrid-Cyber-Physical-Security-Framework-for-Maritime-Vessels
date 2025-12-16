"""
Refactored Flask application for Maritime Intrusion Detection System
Phase 2: Real-Time Monitoring with WebSocket Support
"""
import os
import sys
from pathlib import Path
import random
import logging
import sqlite3
import smtplib
from datetime import datetime
from email.message import EmailMessage
import threading
import time

import numpy as np
import pandas as pd
import joblib
from flask import Flask, request, jsonify, render_template, session
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from config.config import FLASK_CONFIG, MODEL_DIR, LOG_DIR
from src.utils.traffic_simulator import NetworkTrafficSimulator
from src.utils.realtime_monitor import RealTimeMonitor
from src.utils.notification_service import NotificationService
from src.utils.alert_manager import AlertManager
from src.monitors.maritime_real_time_monitor import MaritimeRealTimeMonitor
from src.config.detection_thresholds import DetectionThresholds, get_thresholds
from src.integration.enhanced_detector_manager import EnhancedDetectorManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'flask_app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_CONFIG['SECRET_KEY']

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global variables for OTP
otp_storage = {}

# Global real-time monitoring components
traffic_simulator = None
realtime_monitor = None
monitoring_active = False

# Phase 4: Maritime monitoring components
maritime_monitor = None
maritime_monitoring_active = False

# Phase 3: Alert & Notification System
notification_service = NotificationService()
alert_manager = AlertManager()

# Phase 4.5: Detection Thresholds Configuration
detection_thresholds = None

# Phase 5: Enhanced Detection Capabilities
enhanced_detector = None


class IntrustionDetector:
    """
    Intrusion detection predictor
    """
    
    def __init__(self, model_path=None):
        """
        Initialize with trained model
        """
        if model_path is None:
            model_path = MODEL_DIR / 'mlp_model.pkl'
        
        self.model = None
        self.load_model(model_path)
        
        # Attack type mapping
        self.attack_mapping = {
            0: ('Normal', 'There is No Attack Detected and Its Normal!'),
            1: ('Dos', 'Attack is Detected and its DoS Attack!'),
            2: ('Probe', 'Attack is Detected and its Probe Attack!'),
            3: ('R2L', 'Attack is Detected and its R2L Attack!'),
            4: ('U2R', 'Attack is Detected and its U2R Attack!')
        }
    
    def load_model(self, model_path):
        """
        Load trained model
        """
        try:
            self.model = joblib.load(model_path)
            logger.info(f"Model loaded successfully from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            self.model = None
    
    def predict(self, features):
        """
        Predict intrusion type
        
        Args:
            features: List or array of feature values
            
        Returns:
            Prediction result dictionary
        """
        if self.model is None:
            return {
                'error': 'Model not loaded',
                'prediction': -1,
                'attack_type': 'Unknown',
                'message': 'Prediction model is not available'
            }
        
        try:
            # Convert to numpy array and reshape
            feature_array = np.array(features).reshape(1, -1)
            
            # Make prediction
            prediction = self.model.predict(feature_array)[0]
            
            # Get attack info
            attack_type, message = self.attack_mapping.get(
                prediction, 
                ('Unknown', 'Unknown attack type')
            )
            
            logger.info(f"Prediction made: {attack_type}")
            
            return {
                'prediction': int(prediction),
                'attack_type': attack_type,
                'message': message,
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return {
                'error': str(e),
                'prediction': -1,
                'attack_type': 'Error',
                'message': 'Error during prediction'
            }


class DatabaseManager:
    """
    Database management for user authentication
    """
    
    def __init__(self, db_path=None):
        """
        Initialize database connection
        """
        if db_path is None:
            db_path = FLASK_CONFIG['DATABASE_PATH']
        
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """
        Initialize database with user table
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    mobile TEXT,
                    name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
            # Create default test users
            self.create_default_users()
        
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
    
    def create_default_users(self):
        """
        Create default test users for development/demo
        WARNING: These are test credentials only - change in production!
        """
        default_users = [
            {
                'username': 'admin',
                'email': 'admin@maritime-ids.local',
                'password': 'admin123',
                'mobile': '+1-555-0001',
                'name': 'System Administrator'
            },
            {
                'username': 'captain',
                'email': 'captain@maritime-ids.local',
                'password': 'captain123',
                'mobile': '+1-555-0002',
                'name': 'Captain John Smith'
            },
            {
                'username': 'security',
                'email': 'security@maritime-ids.local',
                'password': 'security123',
                'mobile': '+1-555-0003',
                'name': 'Security Officer Jane Doe'
            },
            {
                'username': 'demo',
                'email': 'demo@maritime-ids.local',
                'password': 'demo123',
                'mobile': '+1-555-0004',
                'name': 'Demo User'
            }
        ]
        
        for user_data in default_users:
            try:
                # Check if user already exists
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT user FROM info WHERE user = ?", (user_data['username'],))
                if cursor.fetchone() is None:
                    # User doesn't exist, create it
                    self.create_user(
                        user_data['username'],
                        user_data['email'],
                        user_data['password'],
                        user_data['mobile'],
                        user_data['name']
                    )
                    logger.info(f"Default user created: {user_data['username']}")
                conn.close()
            except Exception as e:
                logger.error(f"Error creating default user {user_data['username']}: {str(e)}")
    
    def create_user(self, username, email, password, mobile, name):
        """
        Create a new user
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Hash password
            hashed_password = generate_password_hash(password)
            
            cursor.execute(
                "INSERT INTO info (user, email, password, mobile, name) VALUES (?, ?, ?, ?, ?)",
                (username, email, hashed_password, mobile, name)
            )
            
            conn.commit()
            conn.close()
            logger.info(f"User created: {username}")
            return True
        
        except sqlite3.IntegrityError:
            logger.warning(f"User already exists: {username}")
            return False
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            return False
    
    def verify_user(self, username, password):
        """
        Verify user credentials
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT user, password FROM info WHERE user = ?",
                (username,)
            )
            
            result = cursor.fetchone()
            conn.close()
            
            if result and check_password_hash(result[1], password):
                logger.info(f"User authenticated: {username}")
                return True
            
            logger.warning(f"Authentication failed for: {username}")
            return False
        
        except Exception as e:
            logger.error(f"Error verifying user: {str(e)}")
            return False


class EmailService:
    """
    Email service for OTP
    """
    
    @staticmethod
    def send_otp(email, otp):
        """
        Send OTP via email
        """
        try:
            msg = EmailMessage()
            msg.set_content(f"Your OTP for Maritime IDS is: {otp}")
            msg['Subject'] = 'OTP Verification - Maritime IDS'
            msg['From'] = FLASK_CONFIG['EMAIL_SENDER']
            msg['To'] = email
            
            server = smtplib.SMTP(FLASK_CONFIG['SMTP_SERVER'], FLASK_CONFIG['SMTP_PORT'])
            server.starttls()
            server.login(FLASK_CONFIG['EMAIL_SENDER'], FLASK_CONFIG['EMAIL_PASSWORD'])
            server.send_message(msg)
            server.quit()
            
            logger.info(f"OTP sent to {email}")
            return True
        
        except Exception as e:
            logger.error(f"Error sending OTP: {str(e)}")
            return False


# Initialize services
detector = IntrustionDetector()
db_manager = DatabaseManager()


# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')


@app.route('/home')
def home():
    """Dashboard home"""
    return render_template('home.html')


@app.route('/logon')
def logon():
    """Signup page"""
    return render_template('signup.html')


@app.route('/login')
def login():
    """Login page"""
    return render_template('signin.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handle user signup (OTP verification disabled)
    """
    if request.method == 'POST':
        data = request.get_json()
    else:
        data = request.args
    
    username = data.get('user', '')
    name = data.get('name', '')
    email = data.get('email', '')
    mobile = data.get('mobile', '')
    password = data.get('password', '')
    
    # Direct signup without OTP verification
    try:
        # Create new user using DatabaseManager
        success = db_manager.create_user(username, email, password, mobile, name)
        
        if success:
            logger.info(f"New user registered: {email}")
            # Return success message or redirect to login
            return jsonify({
                'success': True,
                'message': 'Account created successfully! Please login.',
                'redirect': '/logon'
            }), 200
        else:
            return jsonify({'error': 'User already exists'}), 400
        
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({'error': 'Signup failed'}), 500


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    """
    Verify OTP and complete signup
    """
    data = request.form
    email = data.get('email', '')
    entered_otp = data.get('otp', '')
    
    if email in otp_storage:
        stored_data = otp_storage[email]
        
        if str(stored_data['otp']) == str(entered_otp):
            # Create user
            success = db_manager.create_user(
                stored_data['username'],
                email,
                stored_data['password'],
                stored_data['mobile'],
                stored_data['name']
            )
            
            # Clean up
            del otp_storage[email]
            
            if success:
                return render_template('signin.html', message='Signup successful!')
            else:
                return render_template('signup.html', error='User already exists')
        else:
            return render_template('val.html', email=email, error='Invalid OTP')
    
    return render_template('signup.html', error='Session expired')


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    """
    Handle user signin
    """
    if request.method == 'POST':
        data = request.form
    else:
        data = request.args
    
    username = data.get('user', '')
    password = data.get('password', '')
    
    if db_manager.verify_user(username, password):
        session['username'] = username
        return render_template('home.html', username=username)
    else:
        return render_template('signin.html', error='Invalid credentials')


@app.route('/logout')
def logout():
    """
    Handle user logout
    """
    session.pop('username', None)
    return render_template('index.html', message='Logged out successfully')


@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict intrusion from network features
    """
    try:
        # Get features from form
        features = [float(x) for x in request.form.values()]
        
        logger.info(f"Received {len(features)} features for prediction")
        
        # Make prediction
        result = detector.predict(features)
        
        return render_template('prediction.html', 
                             output=result['message'],
                             attack_type=result['attack_type'],
                             timestamp=result.get('timestamp', ''))
    
    except Exception as e:
        logger.error(f"Prediction endpoint error: {str(e)}")
        return render_template('prediction.html', 
                             output=f'Error: {str(e)}',
                             attack_type='Error',
                             timestamp=datetime.now().isoformat())


@app.route('/api/predict', methods=['POST'])
def api_predict():
    """
    API endpoint for intrusion prediction
    """
    try:
        data = request.get_json()
        features = data.get('features', [])
        
        if not features:
            return jsonify({'error': 'No features provided'}), 400
        
        result = detector.predict(features)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"API prediction error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    """
    return jsonify({
        'status': 'healthy',
        'model_loaded': detector.model is not None,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/predict_page')
def predict_page():
    """
    Prediction form page
    """
    return render_template('predict_form.html')


@app.route('/realtime_monitor')
def realtime_monitor():
    """
    Real-time monitoring page
    """
    return render_template('realtime_monitor.html')


@app.route('/alert_history')
def alert_history():
    """
    Alert history page - redirects to alerts management
    """
    return render_template('alerts.html')


@app.route('/reports')
def reports():
    """
    Reports page
    """
    return render_template('reports.html')


# ============================================================================
# Real-Time Monitoring WebSocket Routes (Phase 2)
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"✅ Client connected: {request.sid}")
    emit('connection_response', {'status': 'connected', 'message': 'WebSocket connected successfully'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"❌ Client disconnected: {request.sid}")


@socketio.on('start_monitoring')
def handle_start_monitoring():
    """Start real-time monitoring"""
    global monitoring_active, traffic_simulator, realtime_monitor
    
    try:
        if not monitoring_active:
            # Initialize components
            if traffic_simulator is None:
                traffic_simulator = NetworkTrafficSimulator()
            
            if realtime_monitor is None:
                realtime_monitor = RealTimeMonitor(detector=detector)
            
            # Start monitoring
            realtime_monitor.start()
            traffic_simulator.start(interval=1.0)
            monitoring_active = True
            
            # Start background thread for monitoring
            thread = threading.Thread(target=monitoring_loop, daemon=True)
            thread.start()
            
            logger.info("🔴 Real-time monitoring started")
            emit('monitoring_started', {'status': 'success', 'message': 'Monitoring started'})
        else:
            emit('monitoring_started', {'status': 'info', 'message': 'Monitoring already active'})
            
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        emit('error', {'message': str(e)})


@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    """Stop real-time monitoring"""
    global monitoring_active, traffic_simulator, realtime_monitor
    
    try:
        if monitoring_active:
            monitoring_active = False
            
            if traffic_simulator:
                traffic_simulator.stop()
            
            if realtime_monitor:
                realtime_monitor.stop()
            
            logger.info("⏹️ Real-time monitoring stopped")
            emit('monitoring_stopped', {'status': 'success', 'message': 'Monitoring stopped'})
        else:
            emit('monitoring_stopped', {'status': 'info', 'message': 'Monitoring not active'})
            
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        emit('error', {'message': str(e)})


@socketio.on('get_stats')
def handle_get_stats():
    """Get current monitoring statistics"""
    global realtime_monitor
    
    try:
        if realtime_monitor:
            stats = realtime_monitor.get_stats()
            emit('stats_update', stats)
        else:
            emit('stats_update', {
                'total_traffic': 0,
                'attacks_detected': 0,
                'attack_rate': 0.0,
                'active': False
            })
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        emit('error', {'message': str(e)})


@socketio.on('get_recent_alerts')
def handle_get_recent_alerts(data):
    """Get recent alerts"""
    global realtime_monitor
    
    try:
        limit = data.get('limit', 10) if data else 10
        
        if realtime_monitor:
            alerts = realtime_monitor.get_recent_alerts(limit=limit)
            emit('alerts_update', {'alerts': alerts})
        else:
            emit('alerts_update', {'alerts': []})
            
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        emit('error', {'message': str(e)})


def monitoring_loop():
    """Background thread for continuous monitoring"""
    global monitoring_active, traffic_simulator, realtime_monitor
    
    logger.info("🔄 Monitoring loop started")
    
    while monitoring_active:
        try:
            # Get traffic from simulator
            traffic = traffic_simulator.get_traffic()
            
            if traffic:
                # Process through monitor
                result = realtime_monitor.process_traffic(traffic)
                
                if result:
                    # Emit to all connected clients
                    socketio.emit('traffic_update', result)
                    
                    # If attack detected, emit alert and create managed alert
                    if result['is_attack']:
                        alert = realtime_monitor.recent_alerts[-1] if realtime_monitor.recent_alerts else None
                        if alert:
                            # Create managed alert in alert manager
                            alert_id = alert_manager.create_alert(alert)
                            alert['id'] = alert_id
                            
                            # Emit to WebSocket
                            socketio.emit('new_alert', alert)
                            
                            # Send notifications for HIGH and CRITICAL alerts
                            severity = alert.get('severity', 'INFO')
                            if severity in ['HIGH', 'CRITICAL']:
                                # Get notification recipients (from session or config)
                                recipients = {
                                    'email': [],  # Configure in production
                                    'sms': []
                                }
                                # Uncomment when configured:
                                # notification_service.send_alert_notification(alert, recipients)
                    
                    # Emit updated stats every 10 packets
                    if realtime_monitor.stats['total_traffic'] % 10 == 0:
                        stats = realtime_monitor.get_stats()
                        socketio.emit('stats_update', stats)
            
            time.sleep(0.1)  # Small delay
            
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            time.sleep(1)
    
    logger.info("⏹️ Monitoring loop stopped")


# API Routes for monitoring
@app.route('/api/monitoring/status', methods=['GET'])
def get_monitoring_status():
    """Get monitoring status"""
    global monitoring_active, realtime_monitor
    
    status = {
        'active': monitoring_active,
        'stats': realtime_monitor.get_stats() if realtime_monitor else {}
    }
    return jsonify(status)


@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring_api():
    """Start monitoring via API"""
    global monitoring_active, traffic_simulator, realtime_monitor
    
    try:
        if not monitoring_active:
            if traffic_simulator is None:
                traffic_simulator = NetworkTrafficSimulator()
            
            if realtime_monitor is None:
                realtime_monitor = RealTimeMonitor(detector=detector)
            
            realtime_monitor.start()
            traffic_simulator.start(interval=1.0)
            monitoring_active = True
            
            thread = threading.Thread(target=monitoring_loop, daemon=True)
            thread.start()
            
            return jsonify({'status': 'success', 'message': 'Monitoring started'})
        else:
            return jsonify({'status': 'info', 'message': 'Already monitoring'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring_api():
    """Stop monitoring via API"""
    global monitoring_active, traffic_simulator, realtime_monitor
    
    try:
        if monitoring_active:
            monitoring_active = False
            
            if traffic_simulator:
                traffic_simulator.stop()
            
            if realtime_monitor:
                realtime_monitor.stop()
            
            return jsonify({'status': 'success', 'message': 'Monitoring stopped'})
        else:
            return jsonify({'status': 'info', 'message': 'Not monitoring'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================================
# Phase 4: Maritime Monitoring Routes & WebSocket Handlers
# ============================================================================

@app.route('/maritime')
def maritime_dashboard():
    """Maritime monitoring dashboard"""
    return render_template('maritime_dashboard.html')


@app.route('/api/maritime/status', methods=['GET'])
def get_maritime_status():
    """Get maritime monitoring status"""
    global maritime_monitoring_active, maritime_monitor
    
    if maritime_monitor:
        status = maritime_monitor.get_current_status()
        status['active'] = maritime_monitoring_active
        return jsonify(status)
    else:
        return jsonify({
            'active': False,
            'num_vessels': 0,
            'total_updates': 0,
            'total_threats': 0
        })


@app.route('/api/maritime/vessel/<vessel_id>', methods=['GET'])
def get_vessel_info(vessel_id):
    """Get detailed vessel information"""
    global maritime_monitor
    
    if maritime_monitor:
        vessel_info = maritime_monitor.get_vessel_info(vessel_id)
        if vessel_info:
            return jsonify(vessel_info)
        else:
            return jsonify({'error': 'Vessel not found'}), 404
    else:
        return jsonify({'error': 'Maritime monitoring not initialized'}), 400


@socketio.on('start_maritime_monitoring')
def handle_start_maritime():
    """Start maritime monitoring"""
    global maritime_monitoring_active, maritime_monitor
    
    try:
        if not maritime_monitoring_active:
            # Initialize maritime monitor
            if maritime_monitor is None:
                maritime_monitor = MaritimeRealTimeMonitor(
                    num_vessels=10,
                    update_interval=8,
                    attack_probability=0.12
                )
                
                # Add callbacks for WebSocket emission
                def on_maritime_threat(analysis):
                    """Emit maritime threat through WebSocket"""
                    socketio.emit('maritime_threat', {
                        'vessel_id': analysis['vessel_id'],
                        'vessel_name': analysis['vessel_name'],
                        'mmsi': analysis['mmsi'],
                        'threat_level': analysis['threat_level'],
                        'anomalies': analysis['total_anomalies'],
                        'detected_attacks': [
                            {
                                'attack': a['attack'],
                                'description': a['description'],
                                'severity': a['severity'],
                                'confidence': a['confidence']
                            }
                            for a in analysis['detected_attacks']
                        ],
                        'recommendation': analysis['recommendation'],
                        'timestamp': analysis['timestamp'].isoformat(),
                        'max_risk_score': analysis['max_risk_score']
                    })
                    
                    # Also create alert in alert manager
                    alert = alert_manager.create_alert(
                        alert_type='maritime_threat',
                        severity=analysis['threat_level'],
                        message=f"Maritime threat on {analysis['vessel_name']}: {analysis['recommendation']}",
                        details={
                            'vessel_id': analysis['vessel_id'],
                            'vessel_name': analysis['vessel_name'],
                            'mmsi': str(analysis['mmsi']),
                            'detected_attacks': [a['attack'] for a in analysis['detected_attacks']],
                            'threat_level': analysis['threat_level']
                        }
                    )
                    socketio.emit('new_alert', alert)
                
                def on_maritime_update(update):
                    """Emit maritime update through WebSocket"""
                    socketio.emit('maritime_update', {
                        'update_id': update['update_id'],
                        'timestamp': update['timestamp'].isoformat(),
                        'vessels': update['vessels'],
                        'threat_count': len(update['threats'])
                    })
                
                maritime_monitor.add_threat_callback(on_maritime_threat)
                maritime_monitor.add_update_callback(on_maritime_update)
            
            # Start monitoring
            maritime_monitor.start_monitoring()
            maritime_monitoring_active = True
            
            emit('maritime_status', {
                'status': 'started',
                'message': 'Maritime monitoring started',
                'vessels': maritime_monitor.get_current_status()['vessel_list']
            })
            logger.info("🚢 Maritime monitoring started via WebSocket")
        else:
            emit('maritime_status', {
                'status': 'already_running',
                'message': 'Maritime monitoring already active'
            })
    
    except Exception as e:
        logger.error(f"Error starting maritime monitoring: {e}")
        emit('error', {'message': str(e)})


@socketio.on('stop_maritime_monitoring')
def handle_stop_maritime():
    """Stop maritime monitoring"""
    global maritime_monitoring_active, maritime_monitor
    
    try:
        if maritime_monitoring_active and maritime_monitor:
            maritime_monitor.stop_monitoring()
            maritime_monitoring_active = False
            
            emit('maritime_status', {
                'status': 'stopped',
                'message': 'Maritime monitoring stopped'
            })
            logger.info("🚢 Maritime monitoring stopped via WebSocket")
        else:
            emit('maritime_status', {
                'status': 'not_running',
                'message': 'Maritime monitoring not active'
            })
    
    except Exception as e:
        logger.error(f"Error stopping maritime monitoring: {e}")
        emit('error', {'message': str(e)})


@socketio.on('get_maritime_stats')
def handle_get_maritime_stats():
    """Get maritime statistics"""
    global maritime_monitor
    
    try:
        if maritime_monitor:
            stats = maritime_monitor.get_current_status()
            emit('maritime_stats', stats)
        else:
            emit('maritime_stats', {
                'total_updates': 0,
                'total_threats': 0,
                'num_vessels': 0
            })
    except Exception as e:
        logger.error(f"Error getting maritime stats: {e}")
        emit('error', {'message': str(e)})


# ============================================================================
# Phase 3: Alert & Notification System Routes
# ============================================================================

@app.route('/alerts')
def alerts_page():
    """Alert management page"""
    return render_template('alerts.html')


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts with filtering"""
    try:
        status = request.args.get('status', 'all')  # all, active, acknowledged, resolved
        severity = request.args.get('severity')  # CRITICAL, HIGH, MEDIUM, INFO
        
        if status == 'active':
            alerts = alert_manager.get_active_alerts(severity)
        elif status == 'acknowledged':
            alerts = alert_manager.get_acknowledged_alerts()
        elif status == 'resolved':
            days = int(request.args.get('days', 7))
            alerts = alert_manager.get_resolved_alerts(days)
        else:
            # All alerts
            alerts = (
                alert_manager.get_active_alerts() +
                alert_manager.get_acknowledged_alerts() +
                alert_manager.get_resolved_alerts()
            )
        
        return jsonify({'alerts': alerts, 'count': len(alerts)})
    
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert(alert_id):
    """Get specific alert details"""
    try:
        alert = alert_manager.get_alert(alert_id)
        
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        return jsonify({'alert': alert})
    
    except Exception as e:
        logger.error(f"Error getting alert {alert_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        data = request.get_json()
        user = data.get('user', 'anonymous')
        notes = data.get('notes')
        
        success = alert_manager.acknowledge_alert(alert_id, user, notes)
        
        if success:
            # Emit to WebSocket clients
            socketio.emit('alert_acknowledged', {
                'alert_id': alert_id,
                'user': user,
                'timestamp': datetime.now().isoformat()
            })
            
            return jsonify({'status': 'success', 'message': 'Alert acknowledged'})
        else:
            return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
    
    except Exception as e:
        logger.error(f"Error acknowledging alert {alert_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve an alert"""
    try:
        data = request.get_json()
        user = data.get('user', 'anonymous')
        notes = data.get('notes', 'Resolved')
        
        success = alert_manager.resolve_alert(alert_id, user, notes)
        
        if success:
            # Emit to WebSocket clients
            socketio.emit('alert_resolved', {
                'alert_id': alert_id,
                'user': user,
                'timestamp': datetime.now().isoformat()
            })
            
            return jsonify({'status': 'success', 'message': 'Alert resolved'})
        else:
            return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
    
    except Exception as e:
        logger.error(f"Error resolving alert {alert_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/notes', methods=['POST'])
def add_alert_note(alert_id):
    """Add note to alert"""
    try:
        data = request.get_json()
        user = data.get('user', 'anonymous')
        note = data.get('note', '')
        
        if not note:
            return jsonify({'error': 'Note text required'}), 400
        
        success = alert_manager.add_note(alert_id, user, note)
        
        if success:
            return jsonify({'status': 'success', 'message': 'Note added'})
        else:
            return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
    
    except Exception as e:
        logger.error(f"Error adding note to alert {alert_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/statistics', methods=['GET'])
def get_alert_statistics():
    """Get alert statistics"""
    try:
        stats = alert_manager.get_statistics()
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error getting alert statistics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/notifications/config', methods=['GET', 'POST'])
def notification_config():
    """Get or update notification configuration"""
    try:
        if request.method == 'GET':
            # Return current config (sanitize passwords)
            config = notification_service.config.copy()
            if 'email' in config and 'password' in config['email']:
                config['email']['password'] = '***' if config['email']['password'] else ''
            if 'sms' in config and 'auth_token' in config['sms']:
                config['sms']['auth_token'] = '***' if config['sms']['auth_token'] else ''
            
            return jsonify(config)
        
        else:  # POST
            data = request.get_json()
            notification_service.update_config(data)
            return jsonify({'status': 'success', 'message': 'Configuration updated'})
    
    except Exception as e:
        logger.error(f"Error with notification config: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/notifications/test/email', methods=['POST'])
def test_email_notification():
    """Test email notification"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email address required'}), 400
        
        success = notification_service.test_email(email)
        
        if success:
            return jsonify({'status': 'success', 'message': f'Test email sent to {email}'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to send email. Check configuration and logs.'}), 500
    
    except Exception as e:
        logger.error(f"Error testing email: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/notifications/test/sms', methods=['POST'])
def test_sms_notification():
    """Test SMS notification"""
    try:
        data = request.get_json()
        phone = data.get('phone')
        
        if not phone:
            return jsonify({'error': 'Phone number required'}), 400
        
        success = notification_service.test_sms(phone)
        
        if success:
            return jsonify({'status': 'success', 'message': f'Test SMS sent to {phone}'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to send SMS. Check configuration and logs.'}), 500
    
    except Exception as e:
        logger.error(f"Error testing SMS: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/notifications/history', methods=['GET'])
def get_notification_history():
    """Get notification history"""
    try:
        limit = int(request.args.get('limit', 50))
        history = notification_service.get_notification_history(limit)
        return jsonify({'history': history, 'count': len(history)})
    
    except Exception as e:
        logger.error(f"Error getting notification history: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Phase 4.5: Detection Threshold Configuration Routes
# ============================================================================

@app.route('/threshold-config')
def threshold_config_page():
    """Threshold configuration page"""
    return render_template('threshold_config.html')


@app.route('/api/thresholds', methods=['GET'])
def get_thresholds_api():
    """Get current detection thresholds"""
    global detection_thresholds
    
    try:
        if detection_thresholds is None:
            detection_thresholds = get_thresholds()
        
        return jsonify(detection_thresholds.export_to_dict())
    
    except Exception as e:
        logger.error(f"Error getting thresholds: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/thresholds', methods=['POST'])
def update_thresholds_api():
    """Update detection thresholds"""
    global detection_thresholds
    
    try:
        if detection_thresholds is None:
            detection_thresholds = get_thresholds()
        
        data = request.get_json()
        detection_thresholds.import_from_dict(data)
        
        # Save to file
        success = detection_thresholds.save_thresholds()
        
        if success:
            logger.info("Detection thresholds updated successfully")
            return jsonify({
                'status': 'success',
                'message': 'Thresholds updated successfully',
                'thresholds': detection_thresholds.export_to_dict()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to save thresholds'
            }), 500
    
    except Exception as e:
        logger.error(f"Error updating thresholds: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/thresholds/reset', methods=['POST'])
def reset_thresholds_api():
    """Reset thresholds to defaults"""
    global detection_thresholds
    
    try:
        if detection_thresholds is None:
            detection_thresholds = get_thresholds()
        
        detection_thresholds.reset_to_defaults()
        detection_thresholds.save_thresholds()
        
        logger.info("Detection thresholds reset to defaults")
        return jsonify({
            'status': 'success',
            'message': 'Thresholds reset to defaults',
            'thresholds': detection_thresholds.export_to_dict()
        })
    
    except Exception as e:
        logger.error(f"Error resetting thresholds: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Phase 5: Enhanced Detection Capabilities Routes
# ============================================================================

@app.route('/api/enhanced/web-attack-check', methods=['POST'])
def check_web_attack():
    """Check HTTP request for web attacks"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        data = request.get_json()
        result = enhanced_detector.analyze_web_request(data)
        
        # Create alert if attacks detected
        if result.get('attacks_detected'):
            for attack in result['attacks_detected']:
                alert_manager.create_alert(
                    alert_type='web_attack',
                    severity='HIGH' if attack['confidence'] > 0.7 else 'MEDIUM',
                    message=f"Web attack detected: {attack['type']}",
                    details=attack
                )
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error checking web attack: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/enhanced/advanced-threat-check', methods=['POST'])
def check_advanced_threat():
    """Check for advanced threats (MITM, ransomware, APT, zero-day)"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        data = request.get_json()
        result = enhanced_detector.analyze_advanced_threat(data)
        
        # Create alerts for detected threats
        if result.get('threats_detected'):
            for threat in result['threats_detected']:
                alert_manager.create_alert(
                    alert_type='advanced_threat',
                    severity='CRITICAL',
                    message=f"Advanced threat detected: {threat['type']}",
                    details=threat
                )
                
                # Emit to WebSocket
                socketio.emit('advanced_threat_alert', threat)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error checking advanced threat: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/enhanced/protocol-validate', methods=['POST'])
def validate_protocol():
    """Validate industrial protocol packet"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        data = request.get_json()
        protocol_type = data.get('protocol_type')
        packet_data = data.get('packet_data')
        
        if not protocol_type or not packet_data:
            return jsonify({'error': 'protocol_type and packet_data required'}), 400
        
        result = enhanced_detector.validate_protocol(protocol_type, packet_data)
        
        # Create alert for invalid packets
        if not result.get('is_valid'):
            alert_manager.create_alert(
                alert_type='protocol_violation',
                severity='HIGH',
                message=f"Protocol violation: {protocol_type}",
                details=result
            )
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error validating protocol: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/enhanced/behavioral-check', methods=['POST'])
def check_behavioral_anomaly():
    """Check for behavioral anomalies"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        data = request.get_json()
        vessel_id = data.get('vessel_id')
        behavior = data.get('behavior')
        
        if not vessel_id or not behavior:
            return jsonify({'error': 'vessel_id and behavior required'}), 400
        
        anomaly = enhanced_detector.detect_behavioral_anomaly(vessel_id, behavior)
        
        if anomaly:
            alert_manager.create_alert(
                alert_type='behavioral_anomaly',
                severity=anomaly.get('severity', 'MEDIUM').upper(),
                message=f"Behavioral anomaly: {vessel_id}",
                details=anomaly
            )
            
            socketio.emit('behavioral_anomaly', anomaly)
        
        return jsonify({'anomaly': anomaly, 'detected': anomaly is not None})
    
    except Exception as e:
        logger.error(f"Error checking behavioral anomaly: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/enhanced/geofence-check', methods=['POST'])
def check_geofence():
    """Check geofence violations"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        data = request.get_json()
        vessel_id = data.get('vessel_id')
        position = tuple(data.get('position', []))
        
        if not vessel_id or not position:
            return jsonify({'error': 'vessel_id and position required'}), 400
        
        violations = enhanced_detector.check_geofence(vessel_id, position)
        
        # Create alerts for violations
        for violation in violations:
            alert_manager.create_alert(
                alert_type='geofence_violation',
                severity=violation.get('severity', 'HIGH').upper(),
                message=f"Geofence violation: {vessel_id} in {violation['zone']}",
                details=violation
            )
            
            socketio.emit('geofence_violation', violation)
        
        return jsonify({'violations': violations, 'count': len(violations)})
    
    except Exception as e:
        logger.error(f"Error checking geofence: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/enhanced/collision-risk', methods=['POST'])
def check_collision_risk():
    """Check vessel collision risks"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        data = request.get_json()
        own_ship = data.get('own_ship')
        target_vessels = data.get('target_vessels', {})
        
        if not own_ship:
            return jsonify({'error': 'own_ship required'}), 400
        
        # Convert to VesselPosition objects if needed
        from src.detectors.maritime_threats import VesselPosition
        if isinstance(own_ship, dict):
            own_ship = VesselPosition(**own_ship)
        
        target_vessel_objs = {}
        for vid, vdata in target_vessels.items():
            if isinstance(vdata, dict):
                target_vessel_objs[vid] = VesselPosition(**vdata)
            else:
                target_vessel_objs[vid] = vdata
        
        risks = enhanced_detector.check_collision_risk(own_ship, target_vessel_objs)
        
        # Create alerts for high/critical risks
        for risk in risks:
            if risk.risk_level in ['high', 'critical']:
                alert_manager.create_alert(
                    alert_type='collision_risk',
                    severity=risk.risk_level.upper(),
                    message=f"Collision risk with {risk.target_vessel}",
                    details={
                        'target': risk.target_vessel,
                        'cpa': risk.cpa,
                        'tcpa': risk.tcpa,
                        'action': risk.recommended_action
                    }
                )
                
                socketio.emit('collision_risk', {
                    'target': risk.target_vessel,
                    'risk_level': risk.risk_level,
                    'cpa': risk.cpa,
                    'tcpa': risk.tcpa,
                    'action': risk.recommended_action
                })
        
        return jsonify({
            'risks': [
                {
                    'target': r.target_vessel,
                    'cpa': r.cpa,
                    'tcpa': r.tcpa,
                    'risk_level': r.risk_level,
                    'action': r.recommended_action
                }
                for r in risks
            ],
            'count': len(risks)
        })
    
    except Exception as e:
        logger.error(f"Error checking collision risk: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/enhanced/statistics', methods=['GET'])
def get_enhanced_statistics():
    """Get enhanced detection statistics"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        stats = enhanced_detector.get_statistics()
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error getting enhanced statistics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/enhanced/detectors', methods=['GET'])
def get_available_detectors():
    """Get list of available detectors"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        detectors = enhanced_detector.get_available_detectors()
        return jsonify({'detectors': detectors, 'count': len(detectors)})
    
    except Exception as e:
        logger.error(f"Error getting detectors: {e}")
        return jsonify({'error': str(e)}), 500


# WebSocket handlers for enhanced detection
@socketio.on('enhanced_detection_start')
def handle_enhanced_detection_start():
    """Start enhanced detection monitoring"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        emit('enhanced_detection_status', {
            'status': 'started',
            'detectors': enhanced_detector.get_available_detectors(),
            'message': 'Enhanced detection active'
        })
        
        logger.info("Enhanced detection monitoring started")
    
    except Exception as e:
        logger.error(f"Error starting enhanced detection: {e}")
        emit('error', {'message': str(e)})


@socketio.on('get_enhanced_stats')
def handle_get_enhanced_stats():
    """Get enhanced detection statistics via WebSocket"""
    global enhanced_detector
    
    try:
        if enhanced_detector is None:
            enhanced_detector = EnhancedDetectorManager()
        
        stats = enhanced_detector.get_statistics()
        emit('enhanced_stats_update', stats)
    
    except Exception as e:
        logger.error(f"Error getting enhanced stats: {e}")
        emit('error', {'message': str(e)})


if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info("🚢 Maritime Intrusion Detection System")
    logger.info("=" * 80)
    
    # Initialize enhanced detector manager
    enhanced_detector = EnhancedDetectorManager()
    logger.info(f"✅ Enhanced detectors initialized: {len(enhanced_detector.get_available_detectors())} types")
    
    # Check for trained models
    model_path = MODEL_DIR / 'mlp_model.pkl'
    if not model_path.exists():
        logger.warning("⚠️  Trained models not found!")
        logger.warning("📋 To train models, run: python train.py")
        logger.warning("📂 Models will be saved to: trained_models/")
        logger.info("")
    else:
        logger.info("✅ Models loaded successfully")
    
    logger.info(f"🌐 Server starting at http://{FLASK_CONFIG['HOST']}:{FLASK_CONFIG['PORT']}")
    logger.info(f"📝 Access the application at: http://localhost:{FLASK_CONFIG['PORT']}")
    logger.info("🔴 Real-Time Monitoring: http://localhost:{}/realtime_monitor".format(FLASK_CONFIG['PORT']))
    logger.info("=" * 80)
    
    socketio.run(
        app,
        host=FLASK_CONFIG['HOST'],
        port=FLASK_CONFIG['PORT'],
        debug=FLASK_CONFIG['DEBUG']
    )
