"""
Configuration settings for Maritime Intrusion Detection System
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Data directories
DATA_DIR = BASE_DIR / 'data'
RAW_DATA_DIR = DATA_DIR / 'raw'
PROCESSED_DATA_DIR = DATA_DIR / 'processed'

# Model directories
MODEL_DIR = BASE_DIR / 'trained_models'

# Log directory
LOG_DIR = BASE_DIR / 'logs'

# Dataset paths
TRAIN_DATA_PATH = RAW_DATA_DIR / 'KDDTrain+.txt'
TEST_DATA_PATH = RAW_DATA_DIR / 'KDDTest+.txt'
PROCESSED_DATA_PATH = PROCESSED_DATA_DIR / 'kdd_processed.csv'

# Feature columns
FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty"
]

# Selected features after feature selection
SELECTED_FEATURES = [
    'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'wrong_fragment',
    'hot', 'logged_in', 'num_compromised', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# Attack label mapping
ATTACK_LABEL_MAPPING = {
    'Dos': ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 'processtable', 
            'smurf', 'teardrop', 'udpstorm', 'worm'],
    'R2L': ['ftp_write', 'guess_passwd', 'httptunnel', 'imap', 'multihop', 'named', 
            'phf', 'sendmail', 'snmpgetattack', 'snmpguess', 'spy', 'warezclient', 
            'warezmaster', 'xlock', 'xsnoop'],
    'Probe': ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan'],
    'U2R': ['buffer_overflow', 'loadmodule', 'perl', 'ps', 'rootkit', 'sqlattack', 'xterm']
}

# Attack types (for classification)
ATTACK_TYPES = ['normal', 'Dos', 'Probe', 'R2L', 'U2R']
NUM_CLASSES = len(ATTACK_TYPES)

# Model hyperparameters
MODEL_CONFIG = {
    'NUM_CLASSES': NUM_CLASSES,
    'test_size': 0.20,
    'random_state': 42,
    'mlp': {
        'max_iter': 300,
        'random_state': 1
    },
    'cnn': {
        'filters': 128,
        'kernel_size': 2,
        'pool_size': 2,
        'dropout_rate': 0.2,
        'epochs': 100,
        'batch_size': 64,
        'verbose': 1
    },
    'gru': {
        'units': [32, 64, 128, 256],
        'dropout_rate': 0.25,
        'learning_rate': 0.001,
        'decay': 0.00001,
        'epochs': 100,
        'batch_size': 64,
        'verbose': 1
    },
    'autoencoder': {
        'feature_dims': [25, 20, 15, 10],
        'epochs': 150,
        'batch_size': 100,
        'optimizer': 'adadelta',
        'loss': 'mse'
    }
}

# Flask app configuration
FLASK_CONFIG = {
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
    'DATABASE_PATH': BASE_DIR / 'data' / 'signup.db',
    'SMTP_SERVER': 'smtp.gmail.com',
    'SMTP_PORT': 587,
    'EMAIL_SENDER': os.environ.get('EMAIL_SENDER', 'your-email@gmail.com'),
    'EMAIL_PASSWORD': os.environ.get('EMAIL_PASSWORD', 'your-app-password'),
    'HOST': '0.0.0.0',
    'PORT': 5000,
    'DEBUG': False
}

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': LOG_DIR / 'app.log',
            'formatter': 'standard',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
    },
    'loggers': {
        '': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True
        }
    }
}

# Create directories if they don't exist
for directory in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, MODEL_DIR, LOG_DIR]:
    directory.mkdir(parents=True, exist_ok=True)
