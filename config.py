import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application configuration from .env file"""
    
    # Database
    DATABASE_URL: str
    
    # JWT Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    
    # API
    API_PORT: int = 8765
    
    # ML Models
    CNN_GRU_MODEL_PATH: str = "models/cnn_gru/model.keras"
    CNN_GRU_SCALER_PATH: str = "models/cnn_gru/scaler.pkl"
    CHAR_CNN_MODEL_PATH: str = "models/char_cnn/model.keras"
    CHAR_CNN_VOCAB_PATH: str = "models/char_cnn/vocab.json"
    IF_MODEL_PATH: str = "models/isolation_forest/model.pkl"
    IF_SCALER_PATH: str = "models/isolation_forest/scaler.pkl"
    IF_FEATURES_PATH: str = "models/isolation_forest/features.pkl"
    IF_REPORT_PATH: str = "models/isolation_forest/if_report.json"
    
    # Threat Thresholds
    THREAT_THRESHOLD_URL: float = 0.5
    THREAT_THRESHOLD_NETWORK: float = 0.5
    THREAT_THRESHOLD_IF: float = 0.61607
    
    # Signature Database
    SIGNATURE_DB_PATH: str = "signatures/malware_hashes.db"
    
    # Features
    ENABLE_PROCESS_MONITOR: bool = True
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
