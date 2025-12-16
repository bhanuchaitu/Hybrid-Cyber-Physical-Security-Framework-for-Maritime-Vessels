"""
Machine Learning Model - Multi-Layer Perceptron (MLP)
"""
import numpy as np
from sklearn.neural_network import MLPClassifier
import joblib
import logging

logger = logging.getLogger(__name__)


class MLPModel:
    """
    Multi-Layer Perceptron model for intrusion detection
    """
    
    def __init__(self, random_state=1, max_iter=300, hidden_layer_sizes=(100,)):
        """
        Initialize MLP model
        
        Args:
            random_state: Random seed for reproducibility
            max_iter: Maximum number of iterations
            hidden_layer_sizes: Tuple of hidden layer sizes
        """
        self.model = MLPClassifier(
            random_state=random_state,
            max_iter=max_iter,
            hidden_layer_sizes=hidden_layer_sizes,
            verbose=True
        )
        logger.info(f"Initialized MLP model with {hidden_layer_sizes} hidden layers")
    
    def train(self, X_train, y_train):
        """
        Train the MLP model
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        logger.info("Training MLP model...")
        self.model.fit(X_train, y_train)
        logger.info("MLP training completed")
    
    def predict(self, X_test):
        """
        Make predictions
        
        Args:
            X_test: Test features
            
        Returns:
            Predictions
        """
        logger.info("Making predictions with MLP model")
        return self.model.predict(X_test)
    
    def save_model(self, filepath):
        """
        Save the trained model
        
        Args:
            filepath: Path to save the model
        """
        logger.info(f"Saving MLP model to {filepath}")
        joblib.dump(self.model, filepath)
    
    @staticmethod
    def load_model(filepath):
        """
        Load a trained model
        
        Args:
            filepath: Path to the saved model
            
        Returns:
            Loaded model
        """
        logger.info(f"Loading MLP model from {filepath}")
        return joblib.load(filepath)
