"""
================================================================================
EVENT BUS — Pub/Sub Decoupling Layer
================================================================================
Purpose:
  Decouples the capture/inference thread from all consumers (dashboard, logger,
  stats tracker). Uses a ThreadPoolExecutor so slow handlers never block the
  producer or other subscribers.

Topics:
  - "alert" : fired when a flow exceeds the severity threshold
  - "flow"  : published for every scored flow (includes score + metadata)
  - "stats" : periodic health snapshot
  - "error" : error events

Usage:
  bus = EventBus()
  bus.subscribe("alert", my_handler)
  bus.publish("alert", alert_dict)

Design:
  - B1: handlers dispatched via ThreadPoolExecutor (max 4 workers)
  - If Redis is active, broadcasts events across the network via Redis pub/sub
  - Redis listener bridges remote events to local subscribers with sender-ID
    dedup (events from the same instance are skipped to avoid double processing)
  - Uses NumpyEncoder for safe serialization of numpy types to JSON
================================================================================
"""

import json
import threading
import concurrent.futures
from typing import Callable, Dict, List, Optional
from loguru import logger
from .redis_client import get_redis_client
from .json_utils import NumpyEncoder

import uuid

class EventBus:
    """
    Distributed Pub/Sub bus. If Redis is active, it broadcasts events
    across the network. Local subscribers are notified via a daemon thread.

    B1: handlers are dispatched via a ThreadPoolExecutor so a slow handler
    never blocks other subscribers or the publisher.
    """

    TOPICS = ("alert", "flow", "stats", "error")
    REDIS_PREFIX = "nids:"

    def __init__(self):
        self._lock = threading.Lock()
        self._handlers: Dict[str, List[Callable]] = {t: [] for t in self.TOPICS}
        self.redis = get_redis_client()
        self._stop_event = threading.Event()
        self._listener_thread: Optional[threading.Thread] = None
        self._pubsub = None
        self._instance_id = str(uuid.uuid4())[:8]
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="nids-bus")

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
        self._pubsub = self.redis.pubsub()
        self._pubsub.psubscribe(f"{self.REDIS_PREFIX}*")
        
        while not self._stop_event.is_set():
            message = self._pubsub.get_message(timeout=1.0)
            if message is None or message["type"] != "pmessage":
                continue
            try:
                # channel name is "nids:alert", so topic is "alert"
                topic = message["channel"].split(":", 1)[1]
                data = json.loads(message["data"])
                
                # Ignore messages from our own instance to avoid double-processing
                if data.get("_sender") == self._instance_id:
                    continue

                payload = data.get("payload")
                
                with self._lock:
                    handlers = list(self._handlers.get(topic, []))
                for h in handlers:
                    self._executor.submit(self._safe_dispatch, h, payload)
            except Exception as e:
                logger.error(f"EventBus: Failed to process Redis message: {e}")

    def publish(self, topic: str, payload: dict) -> None:
        if topic not in self.TOPICS:
            logger.warning(f"EventBus: unknown topic '{topic}' — dropping")
            return

        # 1. Local handlers (async via executor — B1)
        with self._lock:
            handlers = list(self._handlers[topic])
        for h in handlers:
            self._executor.submit(self._safe_dispatch, h, payload)

        # 2. Redis broadcast (for external consumers)
        if self.redis:
            try:
                envelope = {
                    "_sender": self._instance_id,
                    "payload": payload
                }
                self.redis.publish(f"{self.REDIS_PREFIX}{topic}", json.dumps(envelope, cls=NumpyEncoder))
            except Exception as e:
                logger.error(f"EventBus: Redis publish failed: {e}")

    @staticmethod
    def _safe_dispatch(handler: Callable, payload: dict):
        try:
            handler(payload)
        except Exception as exc:
            logger.error(f"EventBus: Handler {handler.__name__} raised: {exc}")

    def stop(self):
        self._stop_event.set()
        if self._pubsub:
            try:
                self._pubsub.unsubscribe()
                self._pubsub.close()
            except Exception:
                pass
        if self._listener_thread and self._listener_thread is not threading.current_thread():
            self._listener_thread.join(timeout=5)
        self._executor.shutdown(wait=False)

    def subscriber_count(self, topic: str) -> int:
        return len(self._handlers.get(topic, []))



