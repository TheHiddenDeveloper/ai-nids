"""
Event Bus
---------
Thread-safe queue that decouples the capture/inference thread from
all consumers (dashboard, logger, stats tracker).

Producer  : run_monitor.py  (calls bus.publish)
Consumers : AlertLogger, StatsTracker, dashboard feed  (call bus.subscribe)

Usage:
    bus = EventBus()
    bus.subscribe("alert", my_handler)
    bus.publish("alert", alert_dict)
"""

import json
import threading
from typing import Callable, Dict, List
from loguru import logger
from .redis_client import get_redis_client


import uuid

class EventBus:
    """
    Distributed Pub/Sub bus. If Redis is active, it broadcasts events
    across the network. Local subscribers are notified via a daemon thread.
    """

    TOPICS = ("alert", "flow", "stats", "error")
    REDIS_PREFIX = "nids:"

    def __init__(self):
        self._lock = threading.Lock()
        self._handlers: Dict[str, List[Callable]] = {t: [] for t in self.TOPICS}
        self.redis = get_redis_client()
        self._stop_event = threading.Event()
        self._listener_thread = None
        self._instance_id = str(uuid.uuid4())[:8] # Unique ID for this process

    def subscribe(self, topic: str, handler: Callable) -> None:
        if topic not in self.TOPICS:
            raise ValueError(f"Unknown topic '{topic}'. Valid: {self.TOPICS}")
        
        with self._lock:
            self._handlers[topic].append(handler)
        
        logger.debug(f"EventBus: subscribed {handler.__name__} to '{topic}'")
        
        # If Redis is active and we haven't started a listener yet, start one
        if self.redis and self._listener_thread is None:
            self._start_listener()

    def _start_listener(self):
        """Starts a background thread to bridge Redis events to local handlers."""
        self._listener_thread = threading.Thread(target=self._redis_listener, daemon=True)
        self._listener_thread.start()
        logger.info(f"EventBus: Started Redis listener thread (ID: {self._instance_id})")

    def _redis_listener(self):
        pubsub = self.redis.pubsub()
        # Subscribe to all NIDS channels
        pubsub.psubscribe(f"{self.REDIS_PREFIX}*")
        
        for message in pubsub.listen():
            if self._stop_event.is_set():
                break
            if message["type"] == "pmessage":
                try:
                    # channel name is "nids:alert", so topic is "alert"
                    topic = message["channel"].split(":", 1)[1]
                    data = json.loads(message["data"])
                    
                    # IGNORE messages from our own instance to avoid double-processing
                    if data.get("_sender") == self._instance_id:
                        continue

                    payload = data.get("payload")
                    
                    # Trigger local handlers for this topic
                    with self._lock:
                        handlers = list(self._handlers.get(topic, []))
                    for h in handlers:
                        try:
                            h(payload)
                        except Exception as e:
                            logger.error(f"EventBus: Local handler {h.__name__} failed: {e}")
                except Exception as e:
                    logger.error(f"EventBus: Failed to process Redis message: {e}")

    def publish(self, topic: str, payload: dict) -> None:
        if topic not in self.TOPICS:
            logger.warning(f"EventBus: unknown topic '{topic}' — dropping")
            return

        # 1. Local handlers (fastest path)
        with self._lock:
            handlers = list(self._handlers[topic])
        
        for h in handlers:
            try:
                h(payload)
            except Exception as exc:
                logger.error(f"EventBus: Local handler {h.__name__} raised: {exc}")

        # 2. Redis broadcast (for external consumers)
        if self.redis:
            try:
                # Wrap payload with sender metadata
                envelope = {
                    "_sender": self._instance_id,
                    "payload": payload
                }
                self.redis.publish(f"{self.REDIS_PREFIX}{topic}", json.dumps(envelope))
            except Exception as e:
                logger.error(f"EventBus: Redis publish failed: {e}")

    def stop(self):
        self._stop_event.set()
        if self.redis:
            # We don't necessarily want to close the shared redis client here
            pass

    def subscriber_count(self, topic: str) -> int:
        return len(self._handlers.get(topic, []))


# Module-level singleton
bus = EventBus()
