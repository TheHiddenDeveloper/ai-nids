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

import threading
import queue
from typing import Callable, Dict, List
from loguru import logger


class EventBus:
    """
    Lightweight pub/sub bus backed by thread-safe queues.
    All handlers are called synchronously in the publisher's thread,
    keeping latency low without spawning extra threads per event.
    """

    TOPICS = ("alert", "flow", "stats", "error")

    def __init__(self):
        self._lock = threading.Lock()
        self._handlers: Dict[str, List[Callable]] = {t: [] for t in self.TOPICS}

    def subscribe(self, topic: str, handler: Callable) -> None:
        if topic not in self.TOPICS:
            raise ValueError(f"Unknown topic '{topic}'. Valid: {self.TOPICS}")
        with self._lock:
            self._handlers[topic].append(handler)
        logger.debug(f"EventBus: subscribed {handler.__name__} to '{topic}'")

    def publish(self, topic: str, payload: dict) -> None:
        if topic not in self.TOPICS:
            logger.warning(f"EventBus: unknown topic '{topic}' — dropping")
            return
        with self._lock:
            handlers = list(self._handlers[topic])
        for h in handlers:
            try:
                h(payload)
            except Exception as exc:
                logger.error(f"EventBus handler {h.__name__} raised: {exc}")

    def subscriber_count(self, topic: str) -> int:
        return len(self._handlers.get(topic, []))


# Module-level singleton — import and use directly
bus = EventBus()
