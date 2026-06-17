"""
================================================================================
REDIS CLIENT — Singleton Connection Manager
================================================================================
Purpose:
  Centralized singleton for Redis connection management. Loads config from
  config.yaml, creates a pooled connection with decode_responses=True (critical
  for JSON pub/sub), and falls back gracefully when Redis is disabled or the
  library is missing.

Usage:
  from core.redis_client import get_redis_client
  client = get_redis_client()  # returns redis.Redis or None

Design:
  - RedisClient._instance is the singleton — get_client() returns it or creates
  - Config loaded from config.yaml:redis section
  - Returns None if redis.active=false, redis library not installed, or connect
    fails — consumers handle None everywhere (in-memory fallback)
  - socket_timeout=2s, retry_on_timeout=True for resilience
  - decode_responses=True is essential for JSON serialization compatibility
================================================================================
"""

import yaml
from pathlib import Path
from loguru import logger

try:
    import redis
except ImportError:
    redis = None

class RedisClient:
    """
    Centralized Redis client with configuration loading and connection pooling.
    If Redis is disabled in config or the library is missing, it returns None.
    """
    
    _instance = None
    _config = {}

    @classmethod
    def get_client(cls):
        if cls._instance is not None:
            return cls._instance

        # Load config
        config_path = Path("config.yaml")
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    full_cfg = yaml.safe_load(f)
                    cls._config = full_cfg.get("redis", {})
            except Exception as e:
                logger.error(f"RedisClient: Failed to load config: {e}")

        if not cls._config.get("active", False):
            logger.info("RedisClient: Redis is disabled in config. Using in-memory mode.")
            return None

        if redis is None:
            logger.warning("RedisClient: 'redis' library not installed. Falling back to in-memory.")
            return None

        try:
            host = cls._config.get("host", "localhost")
            port = cls._config.get("port", 6379)
            db = cls._config.get("db", 0)
            
            cls._instance = redis.Redis(
                host=host,
                port=port,
                db=db,
                decode_responses=True, # Critical for JSON Pub/Sub
                socket_timeout=2.0,
                retry_on_timeout=True
            )
            # Test connection
            cls._instance.ping()
            logger.info(f"RedisClient: Connected to {host}:{port}/db{db}")
            return cls._instance
        except Exception as e:
            logger.error(f"RedisClient: Failed to connect to Redis: {e}")
            cls._instance = None
            return None

def get_redis_client():
    return RedisClient.get_client()
