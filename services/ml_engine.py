import logging
import json
import pickle
import numpy as np
from typing import Dict, Optional
from pathlib import Path
import tensorflow as tf
from config import settings

logger = logging.getLogger(__name__)


class MLEngine:
    """
    Singleton class for loading and managing ML models.
    Loaded once at FastAPI startup via lifespan.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MLEngine, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.cnn_gru_model = None
        self.cnn_gru_scaler = None
        self.char_cnn_model = None
        self.char_cnn_vocab = None
        self.if_model = None
        self.if_scaler = None
        self.if_features = None
        self.if_report = None
        
        self.errors = {
            "cnn_gru": None,
            "char_cnn": None,
            "isolation_forest": None
        }
        
        self._initialized = True
        self.load_models()
    
    def load_models(self):
        """Load all ML models from disk"""
        logger.info("Starting model loading...")
        
        # Load CNN-GRU model and scaler
        self._load_cnn_gru()
        
        # Load Char-CNN model and vocabulary
        self._load_char_cnn()
        
        # Load Isolation Forest model, scaler, and features
        self._load_isolation_forest()
        
        logger.info("Model loading completed")
    
    def _load_cnn_gru(self):
        """Load CNN-GRU model and its scaler"""
        try:
            model_path = Path(settings.CNN_GRU_MODEL_PATH)
            scaler_path = Path(settings.CNN_GRU_SCALER_PATH)
            
            if not model_path.exists():
                raise FileNotFoundError(f"CNN-GRU model not found at {model_path}")
            if not scaler_path.exists():
                raise FileNotFoundError(f"CNN-GRU scaler not found at {scaler_path}")
            
            # Load model
            self.cnn_gru_model = tf.keras.models.load_model(str(model_path))
            
            # Load scaler
            with open(scaler_path, "rb") as f:
                self.cnn_gru_scaler = pickle.load(f)
            
            logger.info("CNN-GRU model loaded successfully")
            self.errors["cnn_gru"] = None
        except Exception as e:
            logger.error(f"Failed to load CNN-GRU model: {e}")
            self.errors["cnn_gru"] = str(e)
    
    def _load_char_cnn(self):
        """Load Char-CNN model and vocabulary"""
        try:
            model_path = Path(settings.CHAR_CNN_MODEL_PATH)
            vocab_path = Path(settings.CHAR_CNN_VOCAB_PATH)
            
            if not model_path.exists():
                raise FileNotFoundError(f"Char-CNN model not found at {model_path}")
            if not vocab_path.exists():
                raise FileNotFoundError(f"Char-CNN vocabulary not found at {vocab_path}")
            
            # Load model
            self.char_cnn_model = tf.keras.models.load_model(str(model_path))
            
            # Load vocabulary
            with open(vocab_path, "r") as f:
                self.char_cnn_vocab = json.load(f)
            
            logger.info("Char-CNN model loaded successfully")
            self.errors["char_cnn"] = None
        except Exception as e:
            logger.error(f"Failed to load Char-CNN model: {e}")
            self.errors["char_cnn"] = str(e)
    
    def _load_isolation_forest(self):
        """Load Isolation Forest model, scaler, features, and report"""
        try:
            model_path = Path(settings.IF_MODEL_PATH)
            scaler_path = Path(settings.IF_SCALER_PATH)
            features_path = Path(settings.IF_FEATURES_PATH)
            report_path = Path(settings.IF_REPORT_PATH)
            
            if not model_path.exists():
                raise FileNotFoundError(f"IF model not found at {model_path}")
            if not scaler_path.exists():
                raise FileNotFoundError(f"IF scaler not found at {scaler_path}")
            if not features_path.exists():
                raise FileNotFoundError(f"IF features not found at {features_path}")
            if not report_path.exists():
                raise FileNotFoundError(f"IF report not found at {report_path}")
            
            # Load model
            with open(model_path, "rb") as f:
                self.if_model = pickle.load(f)
            
            # Load scaler
            with open(scaler_path, "rb") as f:
                self.if_scaler = pickle.load(f)
            
            # Load features list
            with open(features_path, "rb") as f:
                self.if_features = pickle.load(f)
            
            # Load report
            with open(report_path, "r") as f:
                self.if_report = json.load(f)
            
            logger.info("Isolation Forest model loaded successfully")
            self.errors["isolation_forest"] = None
        except Exception as e:
            logger.error(f"Failed to load Isolation Forest model: {e}")
            self.errors["isolation_forest"] = str(e)
    
    def predict_url(self, url: str) -> Dict:
        """
        Predict if URL is phishing using Char-CNN.
        
        Returns:
            dict: {score, is_phishing, verdict, model_used}
        """
        if not self.char_cnn_model or self.errors["char_cnn"]:
            logger.warning("Char-CNN model not available")
            return {
                "score": 0.0,
                "is_phishing": False,
                "verdict": "UNKNOWN",
                "model_used": "CHAR_CNN"
            }
        
        try:
            # Encode URL
            url_lower = url.lower()
            encoded = self._encode_url_for_char_cnn(url_lower)
            
            # Predict
            prediction = self.char_cnn_model.predict(encoded, verbose=0)
            
            # Extract phishing score (class 1 probability)
            score = float(prediction[0][1])
            is_phishing = score > settings.THREAT_THRESHOLD_URL
            
            verdict = "PHISHING" if is_phishing else "SAFE"
            
            return {
                "score": score,
                "is_phishing": is_phishing,
                "verdict": verdict,
                "model_used": "CHAR_CNN"
            }
        except Exception as e:
            logger.error(f"Char-CNN prediction error: {e}")
            return {
                "score": 0.0,
                "is_phishing": False,
                "verdict": "UNKNOWN",
                "model_used": "CHAR_CNN"
            }
    
    def _encode_url_for_char_cnn(self, url: str, max_length: int = 200) -> np.ndarray:
        """
        Encode URL for Char-CNN model.
        Vocabulary: {"<PAD>":0,"<UNK>":1,"a":2,...,",":52} — 53 entries
        """
        # Truncate or pad to max_length
        if len(url) > max_length:
            url = url[:max_length]
        
        # Encode each character
        encoded = []
        for char in url:
            if char in self.char_cnn_vocab:
                encoded.append(self.char_cnn_vocab[char])
            else:
                encoded.append(self.char_cnn_vocab["<UNK>"])  # Unknown character
        
        # Pad to max_length
        while len(encoded) < max_length:
            encoded.append(self.char_cnn_vocab["<PAD>"])  # Pad character
        
        return np.array([encoded])
    
    def predict_network_cnn(self, feature_values: list) -> Dict:
        """
        Predict if network traffic is malicious using CNN-GRU on 68 features.
        
        Args:
            feature_values: list of 68 float values in order
        
        Returns:
            dict: {score, is_malicious, verdict, model_used}
        """
        if not self.cnn_gru_model or self.errors["cnn_gru"]:
            logger.warning("CNN-GRU model not available")
            return {
                "score": 0.0,
                "is_malicious": False,
                "verdict": "UNKNOWN",
                "model_used": "CNN_GRU"
            }
        
        try:
            # Convert to numpy array
            features_array = np.array(feature_values, dtype=np.float32).reshape(1, 68)
            
            # Scale using the scaler (expects shape (1, 68))
            scaled = self.cnn_gru_scaler.transform(features_array)
            
            # Reshape for LSTM: (1, 68, 1)
            scaled_reshaped = scaled.reshape(1, 68, 1)
            
            # Predict
            prediction = self.cnn_gru_model.predict(scaled_reshaped, verbose=0)
            score = float(prediction[0][0])
            
            is_malicious = score > settings.THREAT_THRESHOLD_NETWORK
            verdict = "MALICIOUS" if is_malicious else "SAFE"
            
            return {
                "score": score,
                "is_malicious": is_malicious,
                "verdict": verdict,
                "model_used": "CNN_GRU"
            }
        except Exception as e:
            logger.error(f"CNN-GRU prediction error: {e}")
            return {
                "score": 0.0,
                "is_malicious": False,
                "verdict": "UNKNOWN",
                "model_used": "CNN_GRU"
            }
    
    def predict_anomaly_if(self, features_dict: Dict[str, float]) -> Dict:
        """
        Predict anomaly using Isolation Forest on 78 features.
        
        Args:
            features_dict: dict of feature_name → value (any subset of 78 features)
        
        Returns:
            dict: {score, is_anomaly, verdict, model_used}
        """
        if not self.if_model or self.errors["isolation_forest"]:
            logger.warning("Isolation Forest model not available")
            return {
                "score": 0.0,
                "is_anomaly": False,
                "verdict": "UNKNOWN",
                "model_used": "ISOLATION_FOREST"
            }
        
        try:
            # Build 78-element array in the order of self.if_features
            features_array_78 = np.zeros(78, dtype=np.float32)
            for i, feature_name in enumerate(self.if_features):
                if feature_name in features_dict:
                    features_array_78[i] = features_dict[feature_name]
            
            # Reshape for scaling: (1, 78)
            features_reshaped = features_array_78.reshape(1, 78)
            
            # Scale using the 78-column scaler
            scaled = self.if_scaler.transform(features_reshaped)
            
            # Select top 30 features using the order from if_report.json
            top_features = self.if_report["architecture"]["top_features"]
            top_indices = [self.if_features.index(name) for name in top_features]
            scaled_top_30 = scaled[0, top_indices].reshape(1, 30)
            
            # Get decision function score (negative = more anomalous)
            raw_score = self.if_model.decision_function(scaled_top_30)[0]
            
            # Normalize: invert score so that higher values = more anomalous
            inv_score = -raw_score
            
            # Sigmoid normalization to [0, 1]
            norm_score = 1.0 / (1.0 + np.exp(-inv_score * 2))
            score = float(norm_score)
            
            threshold = float(self.if_report["training"]["optimal_threshold"])
            is_anomaly = score > threshold
            verdict = "ANOMALY" if is_anomaly else "SAFE"
            
            return {
                "score": score,
                "is_anomaly": is_anomaly,
                "verdict": verdict,
                "model_used": "ISOLATION_FOREST"
            }
        except Exception as e:
            logger.error(f"Isolation Forest prediction error: {e}")
            return {
                "score": 0.0,
                "is_anomaly": False,
                "verdict": "UNKNOWN",
                "model_used": "ISOLATION_FOREST"
            }
    
    def get_status(self) -> Dict:
        """Get status of all loaded models"""
        return {
            "cnn_gru_loaded": self.cnn_gru_model is not None and not self.errors["cnn_gru"],
            "char_cnn_loaded": self.char_cnn_model is not None and not self.errors["char_cnn"],
            "if_loaded": self.if_model is not None and not self.errors["isolation_forest"],
            "errors": self.errors
        }


# Global singleton instance
_ml_engine_instance: Optional[MLEngine] = None


def get_ml_engine() -> MLEngine:
    """Get or create the ML engine singleton"""
    global _ml_engine_instance
    if _ml_engine_instance is None:
        _ml_engine_instance = MLEngine()
    return _ml_engine_instance
