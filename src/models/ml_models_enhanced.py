"""
Enhanced ML Models for Maritime Cyber Security
Implements Random Forest, XGBoost, LSTM, Ensemble, and Isolation Forest
"""
import numpy as np
import logging
from sklearn.ensemble import RandomForestClassifier, IsolationForest, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from typing import Dict, Tuple, List
import joblib
import os

logger = logging.getLogger(__name__)

# Try to import TensorFlow for LSTM
try:
    import tensorflow as tf
    import keras
    from keras.models import Sequential
    from keras.layers import LSTM, Dense, Dropout
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logger.warning("TensorFlow not available, LSTM model will be disabled")

# Try to import XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    logger.warning("XGBoost not available, using Random Forest as fallback")


class RandomForestDetector:
    """
    Random Forest classifier for network intrusion detection
    Often achieves better accuracy than neural networks for tabular data
    """
    
    def __init__(self, n_estimators=100, max_depth=20, random_state=42):
        """
        Initialize Random Forest detector
        
        Args:
            n_estimators: Number of trees in the forest
            max_depth: Maximum depth of the trees
            random_state: Random seed for reproducibility
        """
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,  # Use all CPU cores
            class_weight='balanced'  # Handle imbalanced data
        )
        self.is_trained = False
        self.feature_importance = None
    
    def train(self, X_train, y_train, X_test, y_test) -> Dict:
        """
        Train the Random Forest model
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary with training metrics
        """
        logger.info("Training Random Forest model...")
        
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        # Get feature importance
        self.feature_importance = self.model.feature_importances_
        
        # Evaluate on test set
        y_pred = self.model.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_test, y_pred, average='weighted', zero_division=0)
        }
        
        logger.info(f"Random Forest Accuracy: {metrics['accuracy']:.4f}")
        return metrics
    
    def predict(self, X) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict labels and probabilities
        
        Args:
            X: Input features
            
        Returns:
            Tuple of (predictions, probabilities)
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        return predictions, probabilities
    
    def save_model(self, filepath: str):
        """Save model to disk"""
        joblib.dump(self.model, filepath)
        logger.info(f"Random Forest model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model from disk"""
        self.model = joblib.load(filepath)
        self.is_trained = True
        logger.info(f"Random Forest model loaded from {filepath}")


class XGBoostDetector:
    """
    XGBoost classifier for network intrusion detection
    Excellent for structured data with high performance
    """
    
    def __init__(self, n_estimators=100, max_depth=6, learning_rate=0.3):
        """
        Initialize XGBoost detector
        
        Args:
            n_estimators: Number of boosting rounds
            max_depth: Maximum tree depth
            learning_rate: Boosting learning rate
        """
        if not XGBOOST_AVAILABLE:
            logger.error("XGBoost not installed. Install with: pip install xgboost")
            self.model = None
            return
        
        self.model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            objective='multi:softmax',
            n_jobs=-1,
            random_state=42
        )
        self.is_trained = False
    
    def train(self, X_train, y_train, X_test, y_test) -> Dict:
        """
        Train the XGBoost model
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary with training metrics
        """
        if self.model is None:
            return {'error': 'XGBoost not available'}
        
        logger.info("Training XGBoost model...")
        
        self.model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False
        )
        self.is_trained = True
        
        # Evaluate on test set
        y_pred = self.model.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_test, y_pred, average='weighted', zero_division=0)
        }
        
        logger.info(f"XGBoost Accuracy: {metrics['accuracy']:.4f}")
        return metrics
    
    def predict(self, X) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict labels and probabilities
        
        Args:
            X: Input features
            
        Returns:
            Tuple of (predictions, probabilities)
        """
        if not self.is_trained or self.model is None:
            raise ValueError("Model not trained yet")
        
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)
        
        return predictions, probabilities
    
    def save_model(self, filepath: str):
        """Save model to disk"""
        if self.model is not None:
            self.model.save_model(filepath)
            logger.info(f"XGBoost model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model from disk"""
        if XGBOOST_AVAILABLE:
            self.model = xgb.XGBClassifier()
            self.model.load_model(filepath)
            self.is_trained = True
            logger.info(f"XGBoost model loaded from {filepath}")


class LSTMDetector:
    """
    LSTM (Long Short-Term Memory) network for temporal pattern detection
    Excellent for time-series attack pattern recognition
    """
    
    def __init__(self, input_shape: Tuple, num_classes: int, lstm_units=128):
        """
        Initialize LSTM detector
        
        Args:
            input_shape: Shape of input data (timesteps, features)
            num_classes: Number of output classes
            lstm_units: Number of LSTM units
        """
        if not TENSORFLOW_AVAILABLE:
            logger.error("TensorFlow not installed. Install with: pip install tensorflow")
            self.model = None
            return
        
        self.model = Sequential([
            LSTM(lstm_units, return_sequences=True, input_shape=input_shape),
            Dropout(0.3),
            LSTM(lstm_units // 2, return_sequences=False),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dropout(0.2),
            Dense(num_classes, activation='softmax')
        ])
        
        self.model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        self.is_trained = False
    
    def train(self, X_train, y_train, X_test, y_test, epochs=50, batch_size=128) -> Dict:
        """
        Train the LSTM model
        
        Args:
            X_train: Training features (should be 3D: samples, timesteps, features)
            y_train: Training labels
            X_test: Test features
            y_test: Test labels
            epochs: Number of training epochs
            batch_size: Batch size
            
        Returns:
            Dictionary with training metrics
        """
        if self.model is None:
            return {'error': 'TensorFlow not available'}
        
        logger.info("Training LSTM model...")
        
        # Early stopping callback
        from keras.callbacks import EarlyStopping
        early_stop = EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )
        
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_test, y_test),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[early_stop],
            verbose=0
        )
        self.is_trained = True
        
        # Evaluate on test set
        test_loss, test_accuracy = self.model.evaluate(X_test, y_test, verbose=0)
        
        metrics = {
            'accuracy': test_accuracy,
            'loss': test_loss,
            'epochs_trained': len(history.history['loss'])
        }
        
        logger.info(f"LSTM Accuracy: {metrics['accuracy']:.4f}")
        return metrics
    
    def predict(self, X) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict labels and probabilities
        
        Args:
            X: Input features (3D: samples, timesteps, features)
            
        Returns:
            Tuple of (predictions, probabilities)
        """
        if not self.is_trained or self.model is None:
            raise ValueError("Model not trained yet")
        
        probabilities = self.model.predict(X)
        predictions = np.argmax(probabilities, axis=1)
        
        return predictions, probabilities
    
    def save_model(self, filepath: str):
        """Save model to disk"""
        if self.model is not None:
            self.model.save(filepath)
            logger.info(f"LSTM model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model from disk"""
        if TENSORFLOW_AVAILABLE:
            from keras.models import load_model
            self.model = load_model(filepath)
            self.is_trained = True
            logger.info(f"LSTM model loaded from {filepath}")


class EnsembleDetector:
    """
    Ensemble model combining multiple classifiers for robust detection
    Uses voting mechanism to combine predictions
    """
    
    def __init__(self, models: Dict = None):
        """
        Initialize Ensemble detector
        
        Args:
            models: Dictionary of models to ensemble (name: model)
        """
        self.models = models or {}
        self.ensemble = None
        self.is_trained = False
    
    def add_model(self, name: str, model):
        """Add a model to the ensemble"""
        self.models[name] = model
    
    def train(self, X_train, y_train, X_test, y_test) -> Dict:
        """
        Train the ensemble model
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary with training metrics
        """
        if not self.models:
            raise ValueError("No models added to ensemble")
        
        logger.info(f"Training Ensemble with {len(self.models)} models...")
        
        # Train each model individually
        individual_metrics = {}
        for name, model in self.models.items():
            logger.info(f"Training {name}...")
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            individual_metrics[name] = acc
            logger.info(f"{name} accuracy: {acc:.4f}")
        
        # Create voting classifier
        estimators = [(name, model) for name, model in self.models.items()]
        self.ensemble = VotingClassifier(estimators=estimators, voting='soft')
        self.ensemble.fit(X_train, y_train)
        self.is_trained = True
        
        # Evaluate ensemble
        y_pred = self.ensemble.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_test, y_pred, average='weighted', zero_division=0),
            'individual_models': individual_metrics
        }
        
        logger.info(f"Ensemble Accuracy: {metrics['accuracy']:.4f}")
        return metrics
    
    def predict(self, X) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict labels and probabilities using ensemble
        
        Args:
            X: Input features
            
        Returns:
            Tuple of (predictions, probabilities)
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        predictions = self.ensemble.predict(X)
        probabilities = self.ensemble.predict_proba(X)
        
        return predictions, probabilities


class AnomalyDetector:
    """
    Isolation Forest for unsupervised anomaly detection
    Detects novel attack patterns without labeled training data
    """
    
    def __init__(self, contamination=0.1, n_estimators=100):
        """
        Initialize Anomaly Detector
        
        Args:
            contamination: Expected proportion of outliers (0.0-0.5)
            n_estimators: Number of isolation trees
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1
        )
        self.is_trained = False
        self.threshold = None
    
    def train(self, X_train) -> Dict:
        """
        Train the anomaly detector (unsupervised)
        
        Args:
            X_train: Training features (normal traffic)
            
        Returns:
            Dictionary with training metrics
        """
        logger.info("Training Isolation Forest anomaly detector...")
        
        self.model.fit(X_train)
        self.is_trained = True
        
        # Calculate anomaly scores on training data
        scores = self.model.decision_function(X_train)
        self.threshold = np.percentile(scores, 10)  # 10th percentile as threshold
        
        metrics = {
            'samples_trained': len(X_train),
            'threshold': self.threshold,
            'model': 'Isolation Forest'
        }
        
        logger.info(f"Anomaly detector trained on {len(X_train)} samples")
        return metrics
    
    def detect_anomalies(self, X) -> Tuple[np.ndarray, np.ndarray]:
        """
        Detect anomalies in new data
        
        Args:
            X: Input features
            
        Returns:
            Tuple of (predictions [-1=anomaly, 1=normal], anomaly_scores)
        """
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        predictions = self.model.predict(X)  # -1 for anomalies, 1 for normal
        anomaly_scores = self.model.decision_function(X)
        
        return predictions, anomaly_scores
    
    def save_model(self, filepath: str):
        """Save model to disk"""
        joblib.dump(self.model, filepath)
        logger.info(f"Anomaly detector saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model from disk"""
        self.model = joblib.load(filepath)
        self.is_trained = True
        logger.info(f"Anomaly detector loaded from {filepath}")


if __name__ == "__main__":
    # Test the models with dummy data
    print("Testing Enhanced ML Models...")
    
    # Generate dummy data
    np.random.seed(42)
    X_train = np.random.randn(1000, 10)
    y_train = np.random.randint(0, 2, 1000)
    X_test = np.random.randn(200, 10)
    y_test = np.random.randint(0, 2, 200)
    
    # Test Random Forest
    print("\n1. Random Forest Detector")
    rf_detector = RandomForestDetector(n_estimators=50)
    rf_metrics = rf_detector.train(X_train, y_train, X_test, y_test)
    print(f"Accuracy: {rf_metrics['accuracy']:.4f}")
    
    # Test XGBoost if available
    if XGBOOST_AVAILABLE:
        print("\n2. XGBoost Detector")
        xgb_detector = XGBoostDetector(n_estimators=50)
        xgb_metrics = xgb_detector.train(X_train, y_train, X_test, y_test)
        print(f"Accuracy: {xgb_metrics['accuracy']:.4f}")
    
    # Test Anomaly Detector
    print("\n3. Anomaly Detector")
    anomaly_detector = AnomalyDetector(contamination=0.1)
    anomaly_metrics = anomaly_detector.train(X_train)
    predictions, scores = anomaly_detector.detect_anomalies(X_test)
    anomalies = np.sum(predictions == -1)
    print(f"Anomalies detected: {anomalies}/{len(X_test)}")
    
    print("\n✓ All available models tested successfully!")
