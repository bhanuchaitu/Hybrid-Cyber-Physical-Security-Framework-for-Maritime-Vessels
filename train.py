"""
Main training pipeline for intrusion detection models
"""
import sys
import os
import logging
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from config.config import (
    TRAIN_DATA_PATH, FEATURE_COLUMNS, ATTACK_LABEL_MAPPING,
    SELECTED_FEATURES, MODEL_CONFIG, MODEL_DIR, LOG_DIR, ATTACK_TYPES
)
from src.utils.data_preprocessing import DataPreprocessor
from src.utils.evaluation import ModelEvaluator, TrainingVisualizer
from src.models.mlp_model import MLPModel
from src.models.cnn_model import CNNModel
from src.models.gru_model import GRUModel
from src.models.hybrid_model import AutoencoderCNNMLP

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def train_mlp(X_train, X_test, y_train, y_test, evaluator):
    """
    Train MLP model
    """
    logger.info("=" * 80)
    logger.info("Training MLP Model")
    logger.info("=" * 80)
    
    mlp = MLPModel(
        random_state=MODEL_CONFIG['mlp']['random_state'],
        max_iter=MODEL_CONFIG['mlp']['max_iter']
    )
    
    mlp.train(X_train, y_train)
    y_pred = mlp.predict(X_test)
    
    # Evaluate
    metrics = evaluator.calculate_metrics(y_test, y_pred, 'MLP')
    evaluator.print_classification_report(y_test, y_pred, target_names=ATTACK_TYPES)
    
    # Save model
    model_path = MODEL_DIR / 'mlp_model.pkl'
    mlp.save_model(model_path)
    logger.info(f"MLP model saved to {model_path}")
    
    return metrics


def train_cnn(X_train, X_test, y_train, y_test, evaluator):
    """
    Train CNN model
    """
    logger.info("=" * 80)
    logger.info("Training CNN Model")
    logger.info("=" * 80)
    
    input_shape = (X_train.shape[1], 1)
    
    cnn = CNNModel(
        input_shape=input_shape,
        num_classes=MODEL_CONFIG['NUM_CLASSES'],
        filters=MODEL_CONFIG['cnn']['filters'],
        kernel_size=MODEL_CONFIG['cnn']['kernel_size'],
        pool_size=MODEL_CONFIG['cnn']['pool_size'],
        dropout_rate=MODEL_CONFIG['cnn']['dropout_rate']
    )
    
    cnn.build_model()
    
    # Prepare data
    X_train_cnn, X_test_cnn, y_train_cnn, y_test_cnn = cnn.prepare_data(
        X_train, X_test, y_train, y_test
    )
    
    # Train
    history = cnn.train(
        X_train_cnn, y_train_cnn,
        epochs=MODEL_CONFIG['cnn']['epochs'],
        batch_size=MODEL_CONFIG['cnn']['batch_size'],
        validation_split=0.2,
        verbose=MODEL_CONFIG['cnn']['verbose']
    )
    
    # Visualize training
    visualizer = TrainingVisualizer()
    visualizer.plot_training_history(history, save_path=LOG_DIR / 'cnn_training_history.png')
    
    # Predict and evaluate
    y_pred = cnn.predict(X_test_cnn)
    
    metrics = evaluator.calculate_metrics(y_test, y_pred, 'CNN')
    evaluator.print_classification_report(y_test, y_pred, target_names=ATTACK_TYPES)
    
    # Save model
    model_path = MODEL_DIR / 'cnn_model.h5'
    cnn.save_model(model_path)
    logger.info(f"CNN model saved to {model_path}")
    
    return metrics


def train_gru(X_train, X_test, y_train, y_test, evaluator):
    """
    Train GRU model
    """
    logger.info("=" * 80)
    logger.info("Training GRU Model")
    logger.info("=" * 80)
    
    input_shape = (X_train.shape[1], 1)
    
    gru = GRUModel(
        input_shape=input_shape,
        num_classes=MODEL_CONFIG['NUM_CLASSES'],
        units=MODEL_CONFIG['gru']['units'],
        dropout_rate=MODEL_CONFIG['gru']['dropout_rate'],
        learning_rate=MODEL_CONFIG['gru']['learning_rate'],
        decay=MODEL_CONFIG['gru']['decay']
    )
    
    gru.build_model()
    
    # Prepare data
    X_train_gru, X_test_gru, y_train_gru, y_test_gru = gru.prepare_data(
        X_train, X_test, y_train, y_test
    )
    
    # Train
    history = gru.train(
        X_train_gru, y_train_gru,
        X_test_gru, y_test_gru,
        epochs=MODEL_CONFIG['gru']['epochs'],
        batch_size=MODEL_CONFIG['gru']['batch_size'],
        verbose=MODEL_CONFIG['gru']['verbose']
    )
    
    # Visualize training
    visualizer = TrainingVisualizer()
    visualizer.plot_training_history(history, save_path=LOG_DIR / 'gru_training_history.png')
    
    # Predict and evaluate
    y_pred = gru.predict(X_test_gru)
    
    metrics = evaluator.calculate_metrics(y_test, y_pred, 'GRU')
    evaluator.print_classification_report(y_test, y_pred, target_names=ATTACK_TYPES)
    
    # Save model
    model_path = MODEL_DIR / 'gru_model.h5'
    gru.save_model(model_path)
    logger.info(f"GRU model saved to {model_path}")
    
    return metrics


def train_hybrid(X_train, X_test, y_train, y_test, evaluator):
    """
    Train Hybrid CNN-MLP model with Autoencoder
    """
    logger.info("=" * 80)
    logger.info("Training Hybrid CNN-MLP Model")
    logger.info("=" * 80)
    
    hybrid = AutoencoderCNNMLP(
        input_dim=X_train.shape[1],
        feature_dims=MODEL_CONFIG['autoencoder']['feature_dims'],
        optimizer=MODEL_CONFIG['autoencoder']['optimizer'],
        loss=MODEL_CONFIG['autoencoder']['loss']
    )
    
    # Build and train autoencoder
    hybrid.build_autoencoder()
    hybrid.train_autoencoder(
        X_train, X_test,
        epochs=MODEL_CONFIG['autoencoder']['epochs'],
        batch_size=MODEL_CONFIG['autoencoder']['batch_size']
    )
    
    # Build feature extractor
    hybrid.build_feature_extractor()
    
    # Train classifier
    hybrid.train_classifier(X_train, y_train, max_iter=300, random_state=1)
    
    # Predict and evaluate
    y_pred = hybrid.predict(X_test)
    
    metrics = evaluator.calculate_metrics(y_test, y_pred, 'CNN-MLP')
    evaluator.print_classification_report(y_test, y_pred, target_names=ATTACK_TYPES)
    
    # Save models
    hybrid.save_models(
        MODEL_DIR / 'autoencoder.h5',
        MODEL_DIR / 'feature_extractor.h5',
        MODEL_DIR / 'hybrid_classifier.pkl'
    )
    logger.info("Hybrid model components saved")
    
    return metrics


def main():
    """
    Main training pipeline
    """
    logger.info("=" * 80)
    logger.info("Starting Maritime Intrusion Detection System Training Pipeline")
    logger.info("=" * 80)
    
    # Initialize preprocessor
    preprocessor = DataPreprocessor(FEATURE_COLUMNS, ATTACK_LABEL_MAPPING)
    
    # Preprocess data
    logger.info("Loading and preprocessing data...")
    df = preprocessor.preprocess_dataset(
        TRAIN_DATA_PATH,
        sample_size=10000,  # Use 10000 samples for quick training
        drop_columns=['difficulty']
    )
    
    # Split data
    X_train, X_test, y_train, y_test = preprocessor.prepare_train_test_split(
        df,
        selected_features=SELECTED_FEATURES,
        test_size=MODEL_CONFIG['test_size'],
        random_state=MODEL_CONFIG['random_state']
    )
    
    logger.info(f"Data split complete - Train: {len(X_train)}, Test: {len(X_test)}")
    logger.info(f"Label mapping: {preprocessor.get_label_mapping()}")
    
    # Initialize evaluator
    evaluator = ModelEvaluator()
    
    # Train all models
    try:
        train_mlp(X_train, X_test, y_train, y_test, evaluator)
    except Exception as e:
        logger.error(f"MLP training failed: {str(e)}")
    
    try:
        train_cnn(X_train, X_test, y_train, y_test, evaluator)
    except Exception as e:
        logger.error(f"CNN training failed: {str(e)}")
    
    try:
        train_gru(X_train, X_test, y_train, y_test, evaluator)
    except Exception as e:
        logger.error(f"GRU training failed: {str(e)}")
    
    try:
        train_hybrid(X_train, X_test, y_train, y_test, evaluator)
    except Exception as e:
        logger.error(f"Hybrid training failed: {str(e)}")
    
    # Display results
    logger.info("=" * 80)
    logger.info("Training Complete - Results Summary")
    logger.info("=" * 80)
    
    results_df = evaluator.get_results_dataframe()
    print("\n" + results_df.to_string(index=False))
    
    # Save results
    results_path = LOG_DIR / 'training_results.csv'
    results_df.to_csv(results_path, index=False)
    logger.info(f"Results saved to {results_path}")
    
    # Plot comparisons
    evaluator.plot_all_metrics_comparison(save_path=LOG_DIR / 'model_comparison.png')
    
    logger.info("=" * 80)
    logger.info("Training Pipeline Completed Successfully")
    logger.info("=" * 80)


if __name__ == "__main__":
    main()
