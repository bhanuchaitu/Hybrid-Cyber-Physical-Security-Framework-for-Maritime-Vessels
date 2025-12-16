"""
Deep Learning Model - Gated Recurrent Unit (GRU)
"""
import numpy as np
import tensorflow as tf
from keras.models import Sequential, load_model
from keras.layers import Dense, GRU, Bidirectional, Dropout
from keras.utils import to_categorical
import logging

logger = logging.getLogger(__name__)


class GRUModel:
    """
    Bidirectional GRU model for intrusion detection
    """
    
    def __init__(self, input_shape, num_classes=5, units=[32, 64, 128, 256], 
                 dropout_rate=0.25, learning_rate=0.001, decay=0.00001):
        """
        Initialize GRU model
        
        Args:
            input_shape: Shape of input data (features, 1)
            num_classes: Number of output classes
            units: List of GRU units for each layer
            dropout_rate: Dropout rate
            learning_rate: Learning rate for optimizer
            decay: Learning rate decay
        """
        self.input_shape = input_shape
        self.num_classes = num_classes
        self.units = units
        self.dropout_rate = dropout_rate
        self.learning_rate = learning_rate
        self.decay = decay
        self.model = None
        self.history = None
        
        logger.info(f"Initialized GRU model with input shape {input_shape}")
    
    def build_model(self):
        """
        Build the GRU architecture
        """
        logger.info("Building GRU model architecture")
        
        self.model = Sequential()
        
        # First Bidirectional GRU layer
        self.model.add(Bidirectional(
            GRU(self.units[0], input_shape=self.input_shape, 
                activation='relu', return_sequences=True)
        ))
        self.model.add(Dropout(self.dropout_rate))
        
        # Additional GRU layers
        for unit in self.units[1:-1]:
            self.model.add(GRU(unit, activation='relu', return_sequences=True))
            self.model.add(Dropout(self.dropout_rate))
        
        # Last GRU layer (no return_sequences)
        self.model.add(GRU(self.units[-1], activation='relu', return_sequences=False))
        self.model.add(Dropout(self.dropout_rate))
        
        # Dense layers
        self.model.add(Dense(32, kernel_initializer="uniform", activation='relu'))
        self.model.add(Dense(self.num_classes, kernel_initializer="uniform", activation='softmax'))
        
        # Compile model
        optimizer = tf.keras.optimizers.Adam(
            learning_rate=self.learning_rate
        )
        
        self.model.compile(
            loss='categorical_crossentropy',
            optimizer=optimizer,
            metrics=['accuracy']
        )
        
        logger.info("GRU model architecture built")
        self.model.summary()
    
    def prepare_data(self, X_train, X_test, y_train, y_test):
        """
        Prepare data for GRU training (reshape and one-hot encode)
        
        Args:
            X_train: Training features
            X_test: Test features
            y_train: Training labels
            y_test: Test labels
            
        Returns:
            Prepared data
        """
        logger.info("Preparing data for GRU training")
        
        # Convert to numpy arrays if needed
        if not isinstance(X_train, np.ndarray):
            X_train = X_train.values
            X_test = X_test.values
        
        # Reshape for GRU input (samples, timesteps/features, 1)
        X_train = X_train.reshape(-1, X_train.shape[1], 1)
        X_test = X_test.reshape(-1, X_test.shape[1], 1)
        
        # One-hot encode labels
        y_train = to_categorical(y_train, num_classes=self.num_classes)
        y_test = to_categorical(y_test, num_classes=self.num_classes)
        
        logger.info(f"Data prepared - X_train: {X_train.shape}, y_train: {y_train.shape}")
        
        return X_train, X_test, y_train, y_test
    
    def train(self, X_train, y_train, X_test=None, y_test=None, 
              epochs=100, batch_size=64, verbose=1):
        """
        Train the GRU model
        
        Args:
            X_train: Training features (already reshaped)
            y_train: Training labels (already one-hot encoded)
            X_test: Test features for validation (optional)
            y_test: Test labels for validation (optional)
            epochs: Number of training epochs
            batch_size: Batch size
            verbose: Verbosity level
            
        Returns:
            Training history
        """
        if self.model is None:
            raise ValueError("Model not built. Call build_model() first.")
        
        logger.info(f"Training GRU model for {epochs} epochs")
        
        validation_data = None
        if X_test is not None and y_test is not None:
            validation_data = (X_test, y_test)
        
        self.history = self.model.fit(
            X_train, y_train,
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            verbose=verbose
        )
        
        logger.info("GRU training completed")
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
        
        logger.info("Making predictions with GRU model")
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
        
        logger.info(f"Saving GRU model to {filepath}")
        self.model.save(filepath)
    
    def load_saved_model(self, filepath):
        """
        Load a trained model
        
        Args:
            filepath: Path to the saved model
        """
        logger.info(f"Loading GRU model from {filepath}")
        self.model = load_model(filepath)
