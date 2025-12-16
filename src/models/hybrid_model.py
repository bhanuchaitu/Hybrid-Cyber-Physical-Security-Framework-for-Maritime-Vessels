"""
Hybrid Model - CNN + MLP with Autoencoder
"""
import numpy as np
from keras.models import Sequential, Model, load_model
from keras.layers import Input, Dense
from sklearn.neural_network import MLPClassifier
import logging

logger = logging.getLogger(__name__)


class AutoencoderCNNMLP:
    """
    Hybrid model combining Autoencoder for feature extraction with MLP for classification
    """
    
    def __init__(self, input_dim, feature_dims=[25, 20, 15, 10], 
                 optimizer='adadelta', loss='mse'):
        """
        Initialize the hybrid model
        
        Args:
            input_dim: Number of input features
            feature_dims: List of dimensions for autoencoder layers
            optimizer: Optimizer for autoencoder
            loss: Loss function for autoencoder
        """
        self.input_dim = input_dim
        self.feature_dims = feature_dims
        self.optimizer = optimizer
        self.loss = loss
        self.autoencoder = None
        self.feature_extractor = None
        self.classifier = None
        
        logger.info(f"Initialized Autoencoder-CNN-MLP with input dim {input_dim}")
    
    def build_autoencoder(self):
        """
        Build the autoencoder for feature extraction
        """
        logger.info("Building autoencoder")
        
        inputs = Input(shape=(self.input_dim,))
        
        # Encoder
        encoded = inputs
        for dim in self.feature_dims:
            encoded = Dense(dim, kernel_initializer="uniform")(encoded)
        
        # Decoder
        decoded = encoded
        for dim in reversed(self.feature_dims[:-1]):
            decoded = Dense(dim, kernel_initializer="uniform")(decoded)
        decoded = Dense(self.input_dim, kernel_initializer="uniform")(decoded)
        
        # Create autoencoder model
        self.autoencoder = Model(inputs, decoded)
        self.autoencoder.compile(optimizer=self.optimizer, loss=self.loss)
        
        logger.info("Autoencoder built")
        self.autoencoder.summary()
    
    def train_autoencoder(self, X_train, X_test, epochs=150, batch_size=100):
        """
        Train the autoencoder
        
        Args:
            X_train: Training features
            X_test: Test features
            epochs: Number of epochs
            batch_size: Batch size
        """
        if self.autoencoder is None:
            raise ValueError("Autoencoder not built. Call build_autoencoder() first.")
        
        logger.info(f"Training autoencoder for {epochs} epochs")
        
        # Convert to numpy if needed
        if not isinstance(X_train, np.ndarray):
            X_train = X_train.values
            X_test = X_test.values
        
        self.autoencoder.fit(
            X_train, X_train,
            verbose=1,
            epochs=epochs,
            batch_size=batch_size,
            shuffle=True,
            validation_data=(X_test, X_test)
        )
        
        logger.info("Autoencoder training completed")
    
    def build_feature_extractor(self):
        """
        Build feature extractor from trained autoencoder
        """
        if self.autoencoder is None:
            raise ValueError("Autoencoder not trained")
        
        logger.info("Building feature extractor from autoencoder")
        
        self.feature_extractor = Sequential()
        
        # Extract encoder layers and build model
        for i, dim in enumerate(self.feature_dims):
            if i == 0:
                self.feature_extractor.add(
                    Dense(dim, input_shape=(self.input_dim,))
                )
            else:
                self.feature_extractor.add(Dense(dim))
        
        # Compile first to build the model
        self.feature_extractor.compile(optimizer=self.optimizer, loss=self.loss)
        
        # Now copy weights from autoencoder after model is built
        for i, dim in enumerate(self.feature_dims):
            layer_weights = self.autoencoder.layers[i + 1].get_weights()
            self.feature_extractor.layers[i].set_weights(layer_weights)
        
        logger.info("Feature extractor built")
    
    def train_classifier(self, X_train, y_train, max_iter=300, random_state=1):
        """
        Train MLP classifier on extracted features
        
        Args:
            X_train: Training features
            y_train: Training labels
            max_iter: Maximum iterations for MLP
            random_state: Random seed
        """
        if self.feature_extractor is None:
            raise ValueError("Feature extractor not built")
        
        logger.info("Extracting features for training")
        
        # Convert to numpy if needed
        if not isinstance(X_train, np.ndarray):
            X_train = X_train.values
        
        # Extract features
        extracted_features = self.feature_extractor.predict(X_train)
        
        logger.info("Training MLP classifier on extracted features")
        
        self.classifier = MLPClassifier(random_state=random_state, max_iter=max_iter)
        self.classifier.fit(extracted_features, y_train)
        
        logger.info("Classifier training completed")
    
    def predict(self, X_test):
        """
        Make predictions
        
        Args:
            X_test: Test features
            
        Returns:
            Predictions
        """
        if self.feature_extractor is None or self.classifier is None:
            raise ValueError("Model not fully trained")
        
        logger.info("Making predictions with hybrid model")
        
        # Convert to numpy if needed
        if not isinstance(X_test, np.ndarray):
            X_test = X_test.values
        
        # Extract features
        extracted_features = self.feature_extractor.predict(X_test)
        
        # Predict
        predictions = self.classifier.predict(extracted_features)
        
        return predictions
    
    def save_models(self, autoencoder_path, feature_extractor_path, classifier_path):
        """
        Save all model components
        
        Args:
            autoencoder_path: Path to save autoencoder
            feature_extractor_path: Path to save feature extractor
            classifier_path: Path to save classifier
        """
        logger.info("Saving all model components")
        
        if self.autoencoder:
            self.autoencoder.save(autoencoder_path)
            logger.info(f"Autoencoder saved to {autoencoder_path}")
        
        if self.feature_extractor:
            self.feature_extractor.save(feature_extractor_path)
            logger.info(f"Feature extractor saved to {feature_extractor_path}")
        
        if self.classifier:
            import joblib
            joblib.dump(self.classifier, classifier_path)
            logger.info(f"Classifier saved to {classifier_path}")
    
    def load_models(self, autoencoder_path, feature_extractor_path, classifier_path):
        """
        Load all model components
        
        Args:
            autoencoder_path: Path to autoencoder
            feature_extractor_path: Path to feature extractor
            classifier_path: Path to classifier
        """
        logger.info("Loading all model components")
        
        self.autoencoder = load_model(autoencoder_path)
        self.feature_extractor = load_model(feature_extractor_path)
        
        import joblib
        self.classifier = joblib.load(classifier_path)
        
        logger.info("All models loaded successfully")
