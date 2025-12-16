"""
Deep Learning Model - Convolutional Neural Network (CNN)
"""
import numpy as np
import tensorflow as tf
from keras.models import Sequential, load_model
from keras.layers import Conv1D, MaxPooling1D, Dense, Dropout, Flatten
from keras.utils import to_categorical
import logging

logger = logging.getLogger(__name__)


class CNNModel:
    """
    1D CNN model for intrusion detection
    """
    
    def __init__(self, input_shape, num_classes=5, filters=128, kernel_size=2, 
                 pool_size=2, dropout_rate=0.2):
        """
        Initialize CNN model
        
        Args:
            input_shape: Shape of input data (features, 1)
            num_classes: Number of output classes
            filters: Number of CNN filters
            kernel_size: Size of convolutional kernel
            pool_size: Size of max pooling
            dropout_rate: Dropout rate
        """
        self.input_shape = input_shape
        self.num_classes = num_classes
        self.filters = filters
        self.kernel_size = kernel_size
        self.pool_size = pool_size
        self.dropout_rate = dropout_rate
        self.model = None
        self.history = None
        
        logger.info(f"Initialized CNN model with input shape {input_shape}")
    
    def build_model(self):
        """
        Build the CNN architecture
        """
        logger.info("Building CNN model architecture")
        
        self.model = Sequential([
            Conv1D(filters=self.filters, kernel_size=self.kernel_size, 
                   activation='relu', input_shape=self.input_shape),
            MaxPooling1D(pool_size=self.pool_size),
            Dropout(rate=self.dropout_rate),
            Flatten(),
            Dense(self.num_classes, activation='softmax')
        ])
        
        self.model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        logger.info("CNN model architecture built")
        self.model.summary()
    
    def prepare_data(self, X_train, X_test, y_train, y_test):
        """
        Prepare data for CNN training (reshape and one-hot encode)
        
        Args:
            X_train: Training features
            X_test: Test features
            y_train: Training labels
            y_test: Test labels
            
        Returns:
            Prepared data
        """
        logger.info("Preparing data for CNN training")
        
        # Convert to numpy arrays if needed
        if not isinstance(X_train, np.ndarray):
            X_train = X_train.values
            X_test = X_test.values
        
        # Reshape for CNN input (samples, features, 1)
        X_train = X_train.reshape(-1, X_train.shape[1], 1)
        X_test = X_test.reshape(-1, X_test.shape[1], 1)
        
        # One-hot encode labels
        y_train = to_categorical(y_train, num_classes=self.num_classes)
        y_test = to_categorical(y_test, num_classes=self.num_classes)
        
        logger.info(f"Data prepared - X_train: {X_train.shape}, y_train: {y_train.shape}")
        
        return X_train, X_test, y_train, y_test
    
    def train(self, X_train, y_train, epochs=100, batch_size=64, 
              validation_split=0.2, verbose=1):
        """
        Train the CNN model
        
        Args:
            X_train: Training features (already reshaped)
            y_train: Training labels (already one-hot encoded)
            epochs: Number of training epochs
            batch_size: Batch size
            validation_split: Validation data split ratio
            verbose: Verbosity level
            
        Returns:
            Training history
        """
        if self.model is None:
            raise ValueError("Model not built. Call build_model() first.")
        
        logger.info(f"Training CNN model for {epochs} epochs")
        
        self.history = self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            verbose=verbose
        )
        
        logger.info("CNN training completed")
        return self.history
    
    def predict(self, X_test):
        """
        Make predictions
        
        Args:
            X_test: Test features (already reshaped)
            
        Returns:
            Predicted class labels
        """
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        logger.info("Making predictions with CNN model")
        predictions = self.model.predict(X_test, verbose=0)
        return np.argmax(predictions, axis=1)
    
    def save_model(self, filepath):
        """
        Save the trained model
        
        Args:
            filepath: Path to save the model
        """
        if self.model is None:
            raise ValueError("No model to save")
        
        logger.info(f"Saving CNN model to {filepath}")
        self.model.save(filepath)
    
    def load_saved_model(self, filepath):
        """
        Load a trained model
        
        Args:
            filepath: Path to the saved model
        """
        logger.info(f"Loading CNN model from {filepath}")
        self.model = load_model(filepath)
