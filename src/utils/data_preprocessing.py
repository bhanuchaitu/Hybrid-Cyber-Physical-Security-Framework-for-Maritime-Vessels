"""
Data preprocessing utilities for intrusion detection system
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import logging

logger = logging.getLogger(__name__)


class DataPreprocessor:
    """
    Handles data loading, cleaning, and preprocessing for the IDS
    """
    
    def __init__(self, feature_columns, attack_mapping):
        """
        Initialize the preprocessor
        
        Args:
            feature_columns: List of feature column names
            attack_mapping: Dictionary mapping attack types to specific attacks
        """
        self.feature_columns = feature_columns
        self.attack_mapping = attack_mapping
        self.std_scaler = StandardScaler()
        self.label_encoders = {}
        
    def load_data(self, filepath, sample_size=None):
        """
        Load data from CSV file
        
        Args:
            filepath: Path to the data file
            sample_size: Optional, number of samples to load
            
        Returns:
            pandas DataFrame
        """
        logger.info(f"Loading data from {filepath}")
        
        try:
            data = pd.read_csv(filepath, names=self.feature_columns)
            
            if sample_size:
                data = data.head(sample_size)
                logger.info(f"Loaded {sample_size} samples")
            else:
                logger.info(f"Loaded {len(data)} samples")
                
            return data
        except Exception as e:
            logger.error(f"Error loading data: {str(e)}")
            raise
    
    def change_labels(self, df):
        """
        Convert specific attack types to broader categories
        
        Args:
            df: pandas DataFrame with 'label' column
            
        Returns:
            Modified DataFrame
        """
        logger.info("Converting attack labels to categories")
        
        for category, attacks in self.attack_mapping.items():
            df['label'].replace(attacks, category, inplace=True)
        
        return df
    
    def standardize_features(self, df, numeric_columns):
        """
        Standardize numeric features using StandardScaler
        
        Args:
            df: pandas DataFrame
            numeric_columns: List of numeric column names
            
        Returns:
            DataFrame with standardized numeric features
        """
        logger.info(f"Standardizing {len(numeric_columns)} numeric features")
        
        for col in numeric_columns:
            if col in df.columns:
                arr = df[col].values.reshape(-1, 1)
                df[col] = self.std_scaler.fit_transform(arr)
        
        return df
    
    def encode_categorical_features(self, df, categorical_columns):
        """
        Encode categorical features using LabelEncoder
        
        Args:
            df: pandas DataFrame
            categorical_columns: List of categorical column names
            
        Returns:
            DataFrame with encoded categorical features
        """
        logger.info(f"Encoding {len(categorical_columns)} categorical features")
        
        for col in categorical_columns:
            if col in df.columns:
                self.label_encoders[col] = LabelEncoder()
                df[col] = self.label_encoders[col].fit_transform(df[col])
        
        return df
    
    def encode_labels(self, df, label_column='label'):
        """
        Encode target labels
        
        Args:
            df: pandas DataFrame
            label_column: Name of the label column
            
        Returns:
            DataFrame with encoded labels
        """
        logger.info("Encoding target labels")
        
        self.label_encoders['target'] = LabelEncoder()
        df['intrusion'] = self.label_encoders['target'].fit_transform(df[label_column])
        
        return df
    
    def preprocess_dataset(self, filepath, sample_size=None, drop_columns=None):
        """
        Complete preprocessing pipeline
        
        Args:
            filepath: Path to the data file
            sample_size: Optional, number of samples to load
            drop_columns: List of columns to drop
            
        Returns:
            Preprocessed DataFrame
        """
        logger.info("Starting preprocessing pipeline")
        
        # Load data
        df = self.load_data(filepath, sample_size)
        
        # Drop unnecessary columns
        if drop_columns:
            df.drop(drop_columns, axis=1, inplace=True, errors='ignore')
        
        # Change labels
        df = self.change_labels(df)
        
        # Identify numeric and categorical columns
        numeric_cols = df.select_dtypes(include=['number']).columns.tolist()
        categorical_cols = ['protocol_type', 'service', 'flag']
        
        # Standardize numeric features
        df = self.standardize_features(df, numeric_cols)
        
        # Encode categorical features
        df = self.encode_categorical_features(df, categorical_cols)
        
        # Encode labels
        df = self.encode_labels(df)
        
        # Drop original label column
        if 'label' in df.columns:
            df.drop(['label'], axis=1, inplace=True)
        
        logger.info("Preprocessing completed")
        return df
    
    def prepare_train_test_split(self, df, selected_features, target_column='intrusion', 
                                 test_size=0.2, random_state=42):
        """
        Split data into training and testing sets
        
        Args:
            df: Preprocessed DataFrame
            selected_features: List of feature columns to use
            target_column: Name of the target column
            test_size: Proportion of test set
            random_state: Random seed
            
        Returns:
            X_train, X_test, y_train, y_test
        """
        logger.info("Splitting data into train and test sets")
        
        X = df[selected_features]
        y = df[target_column]
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state
        )
        
        logger.info(f"Train set: {X_train.shape}, Test set: {X_test.shape}")
        
        return X_train, X_test, y_train, y_test
    
    def get_label_mapping(self):
        """
        Get the mapping of encoded labels to original labels
        
        Returns:
            Dictionary of label mappings
        """
        if 'target' in self.label_encoders:
            encoder = self.label_encoders['target']
            return dict(enumerate(encoder.classes_))
        return {}
