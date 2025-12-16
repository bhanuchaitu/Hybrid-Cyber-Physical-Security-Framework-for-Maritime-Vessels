"""
Utility functions for model evaluation and visualization
"""
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import logging

logger = logging.getLogger(__name__)


class ModelEvaluator:
    """
    Handles model evaluation and performance metrics
    """
    
    def __init__(self):
        self.results = []
        
    def calculate_metrics(self, y_true, y_pred, model_name, average='weighted'):
        """
        Calculate classification metrics
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            model_name: Name of the model
            average: Averaging method for multi-class metrics
            
        Returns:
            Dictionary of metrics
        """
        logger.info(f"Calculating metrics for {model_name}")
        
        metrics = {
            'model': model_name,
            'accuracy': round(accuracy_score(y_true, y_pred), 3),
            'precision': round(precision_score(y_true, y_pred, average=average, zero_division=0), 3),
            'recall': round(recall_score(y_true, y_pred, average=average, zero_division=0), 3),
            'f1_score': round(f1_score(y_true, y_pred, average=average, zero_division=0), 3)
        }
        
        self.results.append(metrics)
        
        logger.info(f"{model_name} - Accuracy: {metrics['accuracy']}, "
                   f"Precision: {metrics['precision']}, "
                   f"Recall: {metrics['recall']}, "
                   f"F1-Score: {metrics['f1_score']}")
        
        return metrics
    
    def get_results_dataframe(self):
        """
        Get results as a pandas DataFrame
        
        Returns:
            DataFrame with all model results
        """
        return pd.DataFrame(self.results)
    
    def print_classification_report(self, y_true, y_pred, target_names=None):
        """
        Print detailed classification report
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            target_names: List of target class names
        """
        logger.info("Generating classification report")
        
        report = classification_report(y_true, y_pred, target_names=target_names, zero_division=0)
        print("\nClassification Report:")
        print(report)
        
    def plot_confusion_matrix(self, y_true, y_pred, target_names=None, save_path=None):
        """
        Plot confusion matrix
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            target_names: List of target class names
            save_path: Path to save the plot
        """
        logger.info("Plotting confusion matrix")
        
        cm = confusion_matrix(y_true, y_pred)
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=target_names, yticklabels=target_names)
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Confusion matrix saved to {save_path}")
        
        plt.show()
        
    def plot_model_comparison(self, metric='accuracy', save_path=None):
        """
        Plot comparison of models based on a specific metric
        
        Args:
            metric: Metric to compare ('accuracy', 'precision', 'recall', 'f1_score')
            save_path: Path to save the plot
        """
        logger.info(f"Plotting model comparison for {metric}")
        
        df = self.get_results_dataframe()
        
        if df.empty:
            logger.warning("No results to plot")
            return
        
        plt.figure(figsize=(10, 6))
        plt.barh(df['model'], df[metric], color='skyblue', alpha=0.8)
        plt.xlabel(metric.capitalize())
        plt.title(f'Model Comparison - {metric.capitalize()}')
        plt.xlim(0, 1)
        
        # Add value labels on bars
        for i, v in enumerate(df[metric]):
            plt.text(v + 0.01, i, str(v), va='center')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Comparison plot saved to {save_path}")
        
        plt.show()
        
    def plot_all_metrics_comparison(self, save_path=None):
        """
        Plot comparison of all metrics for all models
        
        Args:
            save_path: Path to save the plot
        """
        logger.info("Plotting all metrics comparison")
        
        df = self.get_results_dataframe()
        
        if df.empty:
            logger.warning("No results to plot")
            return
        
        metrics = ['accuracy', 'precision', 'recall', 'f1_score']
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        axes = axes.ravel()
        
        colors = ['blue', 'red', 'green', 'orange']
        
        for idx, metric in enumerate(metrics):
            axes[idx].barh(df['model'], df[metric], color=colors[idx], alpha=0.7)
            axes[idx].set_xlabel(metric.capitalize())
            axes[idx].set_title(f'{metric.capitalize()} Comparison')
            axes[idx].set_xlim(0, 1)
            
            # Add value labels
            for i, v in enumerate(df[metric]):
                axes[idx].text(v + 0.01, i, str(v), va='center')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"All metrics comparison saved to {save_path}")
        
        plt.show()
        

class TrainingVisualizer:
    """
    Handles visualization of training history
    """
    
    @staticmethod
    def plot_training_history(history, save_path=None):
        """
        Plot training and validation loss/accuracy
        
        Args:
            history: Keras training history object
            save_path: Path to save the plot
        """
        logger.info("Plotting training history")
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 5))
        
        # Plot loss
        ax1.plot(history.history['loss'], label='Train Loss')
        if 'val_loss' in history.history:
            ax1.plot(history.history['val_loss'], label='Validation Loss')
        ax1.set_xlabel('Epoch')
        ax1.set_ylabel('Loss')
        ax1.set_title('Model Loss')
        ax1.legend()
        ax1.grid(True)
        
        # Plot accuracy
        ax2.plot(history.history['accuracy'], label='Train Accuracy')
        if 'val_accuracy' in history.history:
            ax2.plot(history.history['val_accuracy'], label='Validation Accuracy')
        ax2.set_xlabel('Epoch')
        ax2.set_ylabel('Accuracy')
        ax2.set_title('Model Accuracy')
        ax2.legend()
        ax2.grid(True)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Training history saved to {save_path}")
        
        plt.show()
