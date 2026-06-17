"""
================================================================================
CONFIG VALIDATOR — Pydantic Schema for config.yaml
================================================================================
Purpose:
  Defines the complete Pydantic schema for config.yaml validation. Every
  section of the config has a corresponding BaseModel with type constraints,
  defaults, and field validators.

Usage:
  from core.config_validator import validate_config
  if not validate_config(raw_config_dict):
      logger.warning("config.yaml failed validation")

Sections:
  NetworkConfig    — interface, home_net, capture_timeout, max_packets
  FeaturesConfig   — flow_timeout, selected_features (docs mirror only)
  ModelConfig      — type, rf/ae weights, threshold, paths
  AlertsConfig     — severity_levels (low/medium/high thresholds)
  DashboardConfig  — host, ports, refresh_interval
  ThreatIntelConfig — feed URLs
  RetentionConfig  — data retention days
  LoggingConfig    — level (validated), log_file
  RedisConfig      — host, port, db, active toggle
  NIDSConfig       — top-level container for all sections

Note:
  This is for TYPE validation (values are in range). Business logic
  validation (e.g., "home_net overlaps") is NOT done here.
================================================================================
"""

from typing import Optional
from pathlib import Path
from loguru import logger
from pydantic import BaseModel, Field, field_validator


class NetworkConfig(BaseModel):
    interface: str = "eth0"
    home_net: list[str] = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    capture_timeout: int = Field(default=10, ge=1)
    max_packets: int = Field(default=1000, ge=1)


class FeaturesConfig(BaseModel):
    flow_timeout: int = Field(default=60, ge=1)
    selected_features: list[str] = []


class ModelConfig(BaseModel):
    type: str = "ensemble"
    rf_n_estimators: int = Field(default=200, ge=1)
    rf_max_depth: int = Field(default=20, ge=1)
    rf_weight: float = Field(default=0.65, ge=0, le=1)
    ae_weight: float = Field(default=0.35, ge=0, le=1)
    anomaly_threshold: float = Field(default=0.5, ge=0, le=1)
    model_path: str = "data/models/nids_model.joblib"
    scaler_path: str = "data/models/scaler.joblib"
    label_encoder_path: str = "data/models/label_encoder.joblib"


class SeverityLevels(BaseModel):
    low: float = Field(default=0.65, ge=0, le=1)
    medium: float = Field(default=0.80, ge=0, le=1)
    high: float = Field(default=0.92, ge=0, le=1)


class AlertsConfig(BaseModel):
    severity_levels: SeverityLevels = SeverityLevels()
    log_path: str = "data/alerts.jsonl"


class ApiConfig(BaseModel):
    key: str = ""


class DashboardConfig(BaseModel):
    api_host: str = "0.0.0.0"
    api_port: int = Field(default=8000, ge=1, le=65535)
    frontend_port: int = Field(default=3000, ge=1, le=65535)
    refresh_interval: int = Field(default=3, ge=1)


class ThreatIntelConfig(BaseModel):
    feeds: dict[str, str] = {}


class RetentionConfig(BaseModel):
    days: int = Field(default=30, ge=0)


class LoggingConfig(BaseModel):
    level: str = "INFO"
    log_file: str = "data/nids.log"

    @field_validator("level")
    def validate_level(cls, v):
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"logging.level must be one of {allowed}")
        return v.upper()


class RedisConfig(BaseModel):
    host: str = "localhost"
    port: int = Field(default=6379, ge=1, le=65535)
    db: int = Field(default=0, ge=0)
    active: bool = True


class NIDSConfig(BaseModel):
    network: NetworkConfig = NetworkConfig()
    features: FeaturesConfig = FeaturesConfig()
    model: ModelConfig = ModelConfig()
    alerts: AlertsConfig = AlertsConfig()
    api: ApiConfig = ApiConfig()
    dashboard: DashboardConfig = DashboardConfig()
    threat_intel: ThreatIntelConfig = ThreatIntelConfig()
    retention: RetentionConfig = RetentionConfig()
    logging: LoggingConfig = LoggingConfig()
    redis: RedisConfig = RedisConfig()


def validate_config(config: dict) -> bool:
    try:
        NIDSConfig(**config)
        return True
    except Exception as e:
        logger.error(f"Config validation failed: {e}")
        return False
